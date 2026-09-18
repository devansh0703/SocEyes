package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestDecodeEthernetFrame verifies Ethernet II frame parsing.
func TestDecodeEthernetFrame(t *testing.T) {
	// Build a minimal Ethernet II frame: dstMAC(6) + srcMAC(6) + etherType(2) + payload
	dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcMAC := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	etherType := []byte{0x08, 0x00} // IPv4

	frame := append(dstMAC, srcMAC...)
	frame = append(frame, etherType...)
	frame = append(frame, []byte("payload")...)

	dframe, err := DecodeEthernetFrame(frame)
	if err != nil {
		t.Fatalf("DecodeEthernetFrame failed: %v", err)
	}

	if !bytes.Equal(dframe.DstMAC, dstMAC) {
		t.Errorf("DstMAC mismatch: got %x, want %x", dframe.DstMAC, dstMAC)
	}
	if !bytes.Equal(dframe.SrcMAC, srcMAC) {
		t.Errorf("SrcMAC mismatch: got %x, want %x", dframe.SrcMAC, srcMAC)
	}
	if dframe.EtherType != 0x0800 {
		t.Errorf("EtherType mismatch: got 0x%04x, want 0x0800", dframe.EtherType)
	}
}

// TestDecodeIPv4Header verifies IPv4 header parsing.
func TestDecodeIPv4Header(t *testing.T) {
	// Build a minimal IPv4 header (20 bytes, no options)
	header := make([]byte, 20)
	header[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	header[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(header[2:4], 40) // Total length
	binary.BigEndian.PutUint16(header[4:6], 0)  // ID
	binary.BigEndian.PutUint16(header[6:8], 0)  // Flags/Fragment
	header[8] = 64   // TTL
	header[9] = 6    // Protocol: TCP
	binary.BigEndian.PutUint16(header[10:12], 0) // checksum (ignored)
	copy(header[12:16], net.ParseIP("192.168.1.1").To4())
	copy(header[16:20], net.ParseIP("10.0.0.1").To4())

	packet, err := DecodeIPv4Header(header)
	if err != nil {
		t.Fatalf("DecodeIPv4Header failed: %v", err)
	}

	if packet.Version != 4 {
		t.Errorf("Version: got %d, want 4", packet.Version)
	}
	if packet.Protocol != 6 {
		t.Errorf("Protocol: got %d, want 6 (TCP)", packet.Protocol)
	}
	if packet.SrcIP.String() != "192.168.1.1" {
		t.Errorf("SrcIP: got %s, want 192.168.1.1", packet.SrcIP)
	}
	if packet.DstIP.String() != "10.0.0.1" {
		t.Errorf("DstIP: got %s, want 10.0.0.1", packet.DstIP)
	}
}

// TestDecodeTCPHeader verifies TCP header parsing.
func TestDecodeTCPHeader(t *testing.T) {
	// Build a minimal TCP header (20 bytes, no options)
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 12345) // Src port
	binary.BigEndian.PutUint16(header[2:4], 80)      // Dst port
	binary.BigEndian.PutUint32(header[4:8], 1)       // Seq
	binary.BigEndian.PutUint32(header[8:12], 0)      // Ack
	header[12] = 0x50                                // Data offset: 5 (20 bytes)
	header[13] = 0x02                                // Flags: SYN
	binary.BigEndian.PutUint16(header[14:16], 65535) // Window
	binary.BigEndian.PutUint16(header[16:18], 0)     // Checksum
	binary.BigEndian.PutUint16(header[18:20], 0)     // Urgent

	seg, err := DecodeTCPHeader(header)
	if err != nil {
		t.Fatalf("DecodeTCPHeader failed: %v", err)
	}

	if seg.SrcPort != 12345 {
		t.Errorf("SrcPort: got %d, want 12345", seg.SrcPort)
	}
	if seg.DstPort != 80 {
		t.Errorf("DstPort: got %d, want 80", seg.DstPort)
	}
	if seg.Flags != 0x02 {
		t.Errorf("Flags: got 0x%02x, want 0x02 (SYN)", seg.Flags)
	}
}

// TestDecodePacketEndToEnd verifies full Ethernet+IP+TCP decode.
func TestDecodePacketEndToEnd(t *testing.T) {
	dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcMAC := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}

	eth := append(dstMAC, srcMAC...)
	eth = append(eth, 0x08, 0x00) // IPv4

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	ipHeader[8] = 64
	ipHeader[9] = 6 // TCP
	copy(ipHeader[12:16], net.ParseIP("203.0.113.1").To4())
	copy(ipHeader[16:20], net.ParseIP("198.51.100.1").To4())

	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 443)
	binary.BigEndian.PutUint16(tcpHeader[2:4], 54321)
	tcpHeader[13] = 0x12 // SYN+ACK

	full := append(eth, ipHeader...)
	full = append(full, tcpHeader...)

	ev, err := DecodePacket(full)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}

	if ev.SrcIP != "203.0.113.1" {
		t.Errorf("SrcIP: got %s, want 203.0.113.1", ev.SrcIP)
	}
	if ev.DstIP != "198.51.100.1" {
		t.Errorf("DstIP: got %s, want 198.51.100.1", ev.DstIP)
	}
	if ev.SrcPort != 443 {
		t.Errorf("SrcPort: got %d, want 443", ev.SrcPort)
	}
	if ev.DstPort != 54321 {
		t.Errorf("DstPort: got %d, want 54321", ev.DstPort)
	}
	if ev.Protocol != "tcp" {
		t.Errorf("Protocol: got %s, want tcp", ev.Protocol)
	}
}
