package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devansh/fda/agent/capture"
)

// Config for the agent.
type AgentConfig struct {
	Interface  string
	APIURL     string
	BatchSize  int
	FlushEvery time.Duration
	// Retry buffer: events are kept here when the server is unreachable and
	// re-sent later, so a deploy or network blip does not lose detections.
	MaxBuffered int
	MaxRetries  int
}

// apiPort extracts the port from the API URL. The agent must exclude its
// own POST traffic: capturing on loopback, every POST to the API generates
// packets that get captured, batched, and POSTed again — an amplification
// loop that grows until the agent (and server) die. Exclude by port so the
// fix holds regardless of what port the API runs on.
func apiPort(apiURL string) int {
	u, err := url.Parse(apiURL)
	if err != nil || u.Port() == "" {
		return 0
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return p
}

// isSelfTraffic reports whether a captured packet belongs to the agent's
// own API conversation (POST or its response).
func isSelfTraffic(pkt capture.Packet, port int) bool {
	return port != 0 && (pkt.SrcPort == port || pkt.DstPort == port)
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("invalid %s=%q, using default %d", key, v, def)
	}
	return def
}

func envSeconds(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		log.Printf("invalid %s=%q, using default %s", key, v, def)
	}
	return def
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// bufferedShipper accumulates JSON events and ships them in batches.
// Failed POSTs are re-queued (bounded) instead of dropped, so short
// outages cost latency, not data.
type bufferedShipper struct {
	url      string
	client   *http.Client
	mu       sync.Mutex
	pending  [][]byte // marshalled events awaiting delivery
	capacity int
	maxTries int
}

func newBufferedShipper(url string, capacity, maxTries int) *bufferedShipper {
	return &bufferedShipper{
		url:      url,
		client:   &http.Client{Timeout: 10 * time.Second},
		pending:  make([][]byte, 0, capacity),
		capacity: capacity,
		maxTries: maxTries,
	}
}

// add enqueues one marshalled event, dropping the OLDEST when full.
func (s *bufferedShipper) add(payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= s.capacity {
		s.pending = s.pending[1:]
	}
	s.pending = append(s.pending, payload)
}

// flushPOST drains up to len(batch) events into one POST. Returns the
// number successfully sent and an error if the batch failed.
func (s *bufferedShipper) flushPOST() (int, error) {
	s.mu.Lock()
	n := len(s.pending)
	if n == 0 {
		s.mu.Unlock()
		return 0, nil
	}
	batch := s.pending[:n]
	body := marshalBatch(batch)
	s.mu.Unlock()

	resp, err := s.client.Post(s.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("POST %s: %w", s.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return 0, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(b))
	}
	s.mu.Lock()
	if n <= len(s.pending) {
		s.pending = s.pending[n:]
	} else {
		s.pending = s.pending[:0]
	}
	s.mu.Unlock()
	return n, nil
}

// flush drains the buffer with bounded retries; keeps data on failure.
func (s *bufferedShipper) flush() error {
	var lastErr error
	for attempt := 0; attempt < s.maxTries; attempt++ {
		sent, err := s.flushPOST()
		if err == nil {
			if sent > 0 {
				return nil
			}
			return nil // buffer empty
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 2 * time.Second) // 2s, 4s, 6s...
	}
	return lastErr
}

func marshalBatch(batch [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, b := range batch {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func main() {
	cfg := AgentConfig{
		Interface:   envOr("FDA_AGENT_INTERFACE", "lo"),
		APIURL:      envOr("FDA_API_URL", "http://127.0.0.1:8000"),
		BatchSize:   envInt("FDA_AGENT_BATCH_SIZE", 10),
		FlushEvery:  envSeconds("FDA_AGENT_FLUSH_SECONDS", 2*time.Second),
		MaxBuffered: envInt("FDA_AGENT_MAX_BUFFERED", 50000),
		MaxRetries:  envInt("FDA_AGENT_MAX_RETRIES", 3),
	}

	apiURL := strings.TrimRight(cfg.APIURL, "/") + "/api/events/ingest"
	selfPort := apiPort(cfg.APIURL)
	host := hostname()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down agent...")
		cancel()
	}()

	// Event channel
	eventCh := make(chan capture.Packet, 1000)
	errCh := make(chan error, 10)

	captureCfg := &capture.Config{
		Interface: cfg.Interface,
		EventChan: eventCh,
		ErrChan:   errCh,
		Stats:     &capture.Stats{},
	}

	// Start capture in background. Surface fatal capture errors (missing
	// CAP_NET_RAW, bad interface name) instead of idling silently forever.
	go func() {
		if err := capture.Capture(ctx, captureCfg); err != nil {
			log.Printf("CAPTURE FATAL: %v (AF_PACKET needs root or CAP_NET_RAW; check FDA_AGENT_INTERFACE=%s)", err, cfg.Interface)
			cancel()
		}
	}()

	shipper := newBufferedShipper(apiURL, cfg.MaxBuffered, cfg.MaxRetries)

	ticker := time.NewTicker(cfg.FlushEvery)
	defer ticker.Stop()

	log.Printf("FDA agent: iface=%s -> %s (self-port %d excluded) batch=%d flush=%s buffer=%d host=%s",
		cfg.Interface, apiURL, selfPort, cfg.BatchSize, cfg.FlushEvery, cfg.MaxBuffered, host)

	lastErrLog := time.Time{}
	logIfRateLimited := func(err error, what string) {
		if time.Since(lastErrLog) > 30*time.Second {
			log.Printf("%s: %v (buffered=%d)", what, err, len(shipper.pending))
			lastErrLog = time.Now()
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Final flush: try hard once, log if the server is still down.
			if err := shipper.flush(); err != nil {
				log.Printf("final flush: %v (%d events remain buffered)", err, len(shipper.pending))
			} else {
				log.Printf("shutdown flush complete (%d events shipped)", len(shipper.pending))
			}
			return
		case pkt := <-eventCh:
			if isSelfTraffic(pkt, selfPort) {
				continue // never feed our own POSTs back into the pipeline
			}
			shipper.add(marshalEvent(packetToEvent(pkt, host)))
			if len(shipper.pending) >= cfg.BatchSize {
				if err := shipper.flush(); err != nil {
					logIfRateLimited(err, "ingest failed (events kept in buffer)")
				}
			}
		case err := <-errCh:
			log.Printf("Capture error: %v", err)
		case <-ticker.C:
			if len(shipper.pending) > 0 {
				if err := shipper.flush(); err != nil {
					logIfRateLimited(err, "ingest failed (events kept in buffer)")
				}
			}
		}
	}
}

// marshalEvent converts a capture.Packet to a JSON event object with
// hostname enrichment and the agent source tag the server's detector uses.
func marshalEvent(ev map[string]interface{}) []byte {
	b, err := json.Marshal(ev)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// packetToEvent converts a capture.Packet to a JSON-serializable map.
// source stays "capture" — that is the logical source the server's
// port-scan detector queries; index_name carries the wire index.
func packetToEvent(p capture.Packet, host string) map[string]interface{} {
	return map[string]interface{}{
		"source":           "capture",
		"index_name":       "fda-agent-capture",
		"title":            fmt.Sprintf("%s -> %s", p.SrcIP, p.DstIP),
		"severity":         "medium",
		"source_ip":        p.SrcIP,
		"destination_ip":   p.DstIP,
		"source_port":      p.SrcPort,
		"destination_port": p.DstPort,
		"protocol":         p.Protocol,
		"network_transport": p.Protocol,
		"tcp_flags":        p.TCPFlags,
		"engine":           "agent",
		"host_name":        host,
		"technique_ids":    []string{},
		"raw":              map[string]interface{}{"captured": true},
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// postEvents is retained for the final-flush path used by tests.
func postEvents(apiURL string, batch []map[string]interface{}) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("POST %s: %w", apiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
