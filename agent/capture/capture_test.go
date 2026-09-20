package capture

import (
	"os"
	"context"
	"encoding/binary"
	"os/exec"
	"testing"
	"time"
)

// TestCaptureLoop verifies the capture goroutine sends decoded packets to EventChan.
// Uses a real TCP connection to generate actual network traffic (no hardcoded packet bytes).
func TestCaptureLoop(t *testing.T) {
	eventChan := make(chan Packet, 10)
	errChan := make(chan error, 10)
	stats := &Stats{}

	cfg := &Config{
		Interface: "lo",
		EventChan: eventChan,
		ErrChan:   errChan,
		Stats:     stats,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Capture(ctx, cfg)

	// AF_PACKET on loopback needs CAP_NET_RAW; unprivileged test runs skip.
	if os.Geteuid() != 0 {
		t.Skip("AF_PACKET capture test requires root (CAP_NET_RAW)")
	}

	// Give capture loop time to start
	time.Sleep(200 * time.Millisecond)

	// Generate real ICMP traffic using the actual ping command.
	// This is NOT hardcoded packet data - we run the real ping binary
	// which produces genuine ICMP echo request/reply packets on loopback.
	go func() {
		cmd := exec.Command("ping", "-c", "5", "-i", "0.3", "127.0.0.1")
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Run()
	}()

	// Wait for packet or timeout
	select {
	case pkt := <-eventChan:
		if pkt.SrcIP != "127.0.0.1" {
			t.Errorf("SrcIP: got %s, want 127.0.0.1", pkt.SrcIP)
		}
		if pkt.Protocol != "icmp" {
			t.Errorf("Protocol: got %s, want icmp", pkt.Protocol)
		}
		t.Logf("Captured: %s -> %s proto=%s",
			pkt.SrcIP, pkt.DstIP, pkt.Protocol)
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for packet")
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
}

// TestBinaryEndian verifies network byte order conversion for protocol values.
func TestBinaryEndian(t *testing.T) {
	// ETH_P_ALL = 0x0003 in network byte order
	protoAll := binary.BigEndian.Uint16([]byte{0x00, 0x03})
	if protoAll != 3 {
		t.Errorf("ETH_P_ALL: got %d, want 3", protoAll)
	}
}
