package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
}

func main() {
	cfg := AgentConfig{
		Interface:  envOr("FDA_AGENT_INTERFACE", "lo"),
		APIURL:     envOr("FDA_API_URL", "http://127.0.0.1:8123"),
		BatchSize:  10,
		FlushEvery: 2 * time.Second,
	}

	apiURL := strings.TrimRight(cfg.APIURL, "/") + "/api/events/ingest"

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

	// Start capture in background
	go capture.Capture(ctx, captureCfg)

	// Batch buffer
	batch := make([]map[string]interface{}, 0, cfg.BatchSize)
	ticker := time.NewTicker(cfg.FlushEvery)
	defer ticker.Stop()

	log.Printf("FDA Agent capturing on %s -> %s", cfg.Interface, apiURL)

	for {
		select {
		case <-ctx.Done():
			// Flush remaining
			if len(batch) > 0 {
				postEvents(apiURL, batch)
			}
			return
		case pkt := <-eventCh:
			batch = append(batch, packetToEvent(pkt))
			if len(batch) >= cfg.BatchSize {
				postEvents(apiURL, batch)
				batch = batch[:0]
			}
		case err := <-errCh:
			log.Printf("Capture error: %v", err)
		case <-ticker.C:
			if len(batch) > 0 {
				postEvents(apiURL, batch)
				batch = batch[:0]
			}
		}
	}
}

// packetToEvent converts a capture.Packet to a JSON-serializable map.
func packetToEvent(p capture.Packet) map[string]interface{} {
	return map[string]interface{}{
		"source":             "capture-agent",
		"index_name":         "fda-agent-capture",
		"title":              fmt.Sprintf("%s -> %s", p.SrcIP, p.DstIP),
		"severity":           "medium",
		"source_ip":          p.SrcIP,
		"destination_ip":     p.DstIP,
		"source_port":        p.SrcPort,
		"destination_port":   p.DstPort,
		"protocol":           p.Protocol,
		"engine":             "agent",
		"technique_ids":      []string{},
		"raw":                map[string]interface{}{"captured": true},

		"timestamp":          time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// postEvents sends a batch of events to the API.
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
