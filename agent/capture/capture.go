package capture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// htons converts a 16-bit value from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// Config holds capture configuration.
type Config struct {
	Interface string
	BPF       string
	EventChan chan<- Packet
	ErrChan   chan<- error
	Stats     *Stats
	Done      <-chan struct{} // optional: for clean shutdown
}

// Stats holds capture statistics.
type Stats struct {
	mu              sync.RWMutex
	PacketsReceived uint64
	PacketsDropped  uint64
	BytesReceived   uint64
	LastPacketTime  time.Time
	StartedAt       time.Time
}

// Capture starts an AF_PACKET capture loop.
// Runs until ctx is cancelled or an unrecoverable error occurs.
// Uses a 1-second recv timeout so ctx cancellation is respected.
func Capture(ctx context.Context, cfg *Config) error {
	if cfg.EventChan == nil && cfg.ErrChan == nil {
		return fmt.Errorf("at least one of EventChan or ErrChan must be set")
	}

	// AF_PACKET protocol is in network byte order (big-endian).
	// ETH_P_ALL (0x0003) captures all protocols.
	// On little-endian hosts, htons(3) = 0x0300 = 768.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	if cfg.Interface != "" {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			return fmt.Errorf("interface %s: %w", cfg.Interface, err)
		}
		sll := syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
			Ifindex:  iface.Index,
		}
		if err := syscall.Bind(fd, &sll); err != nil {
			return fmt.Errorf("bind: %w", err)
		}
	}

	if cfg.Stats != nil {
		cfg.Stats.StartedAt = time.Now()
	}

	// Use a 1-second timeout so we can check ctx cancellation
	tv := &syscall.Timeval{Sec: 1, Usec: 0}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, tv)

	buf := make([]byte, 65536)

	// Channel for graceful shutdown signaling
	done := make(chan struct{})
	defer close(done)

	// Watch for context cancellation
	go func() {
		<-ctx.Done()
		syscall.Close(fd) // force recvfrom to return EBADF
	}()

	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful
			}
			// EAGAIN/EWOULDBLOCK from timeout — not fatal, continue
			if cfg.ErrChan != nil {
				select {
				case cfg.ErrChan <- fmt.Errorf("recv: %v", err):
				default:
				}
			}
			continue
		}

		// Allocate a fresh buffer each iteration. Reusing a slice variable
		// causes data races and corrupts frame offsets.
		got := make([]byte, n)
		copy(got, buf[:n])

			if len(got) < 14 {
			continue
		}

		pkt, perr := DecodePacket(got)
		if perr != nil {
			if cfg.ErrChan != nil {
				select {
				case cfg.ErrChan <- fmt.Errorf("decode: %v", perr):
				default:
				}
			}
			continue
		}
		if pkt == nil {
			continue
		}

		now := time.Now()
		pkt.Timestamp = now.UnixNano()

		if cfg.Stats != nil {
			cfg.Stats.mu.Lock()
			cfg.Stats.PacketsReceived++
			cfg.Stats.BytesReceived += uint64(n)
			cfg.Stats.LastPacketTime = now
			cfg.Stats.mu.Unlock()
		}

		if cfg.EventChan != nil {
			select {
			case cfg.EventChan <- *pkt:
			default:
				if cfg.Stats != nil {
					cfg.Stats.mu.Lock()
					cfg.Stats.PacketsDropped++
					cfg.Stats.mu.Unlock()
				}
			}
		}
	}
}
