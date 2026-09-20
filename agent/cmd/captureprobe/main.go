package main

import (
	"context"
	"fmt"
	"time"
)

import "github.com/devansh/fda/agent/capture"

func main() {
	ch := make(chan capture.Packet, 100)
	errCh := make(chan error, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cfg := &capture.Config{
		Interface: "docker0",
		EventChan: ch,
		ErrChan:   errCh,
		Stats:     &capture.Stats{},
	}
	go func() {
		if err := capture.Capture(ctx, cfg); err != nil {
			fmt.Println("CAPTURE ERR:", err)
		}
	}()

	n := 0
	deadline := time.After(40 * time.Second)
	for {
		select {
		case pkt := <-ch:
			n++
			if n <= 6 {
				fmt.Printf("pkt %d: %s:%d -> %s:%d proto=%s flags=0x%02x framelen=%d payloadlen=%d\n",
					n, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol, pkt.TCPFlags, pkt.FrameLen, len(pkt.Payload))
			}
		case err := <-errCh:
			fmt.Println("errCh:", err)
		case <-deadline:
			fmt.Println("total packets decoded:", n)
			return
		}
	}
}
