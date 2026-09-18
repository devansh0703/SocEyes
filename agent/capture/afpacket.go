package capture

import (
	"encoding/binary"
	"net"
)

// EthernetFrame represents a parsed Ethernet II frame.
type EthernetFrame struct {
	DstMAC    []byte
	SrcMAC    []byte
	EtherType uint16
	Payload   []byte
}

// IPv4Header represents a parsed IPv4 header.
type IPv4Header struct {
	Version   int
	IHL       int
	Length    int
	Protocol  int
	TTL       int
	SrcIP     net.IP
	DstIP     net.IP
	TCP       []byte // TCP header + payload
}

// TCPHeader represents a parsed TCP header.
type TCPHeader struct {
	SrcPort    int
	DstPort    int
	Seq        int
	Ack        int
	DataOffset int
	Flags      int
	Window     int
	Payload    []byte
}

// Packet represents a fully decoded network packet.
type Packet struct {
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Timestamp int64
}

// DecodeEthernetFrame parses an Ethernet II frame.
func DecodeEthernetFrame(frame []byte) (*EthernetFrame, error) {
	if len(frame) < 14 {
		return nil, nil
	}
	return &EthernetFrame{
		DstMAC:    frame[0:6],
		SrcMAC:    frame[6:12],
		EtherType: binary.BigEndian.Uint16(frame[12:14]),
		Payload:   frame[14:],
	}, nil
}

// DecodeIPv4Header parses an IPv4 header (expects at least 20 bytes).
func DecodeIPv4Header(header []byte) (*IPv4Header, error) {
	if len(header) < 20 {
		return nil, nil
	}
	return &IPv4Header{
		Version:   int(header[0] >> 4),
		IHL:       int(header[0] & 0x0F),
		Length:    int(binary.BigEndian.Uint16(header[2:4])),
		Protocol:  int(header[9]),
		TTL:       int(header[8]),
		SrcIP:     net.IP(header[12:16]),
		DstIP:     net.IP(header[16:20]),
		TCP:       nil,
	}, nil
}

// DecodeTCPHeader parses a TCP header (expects at least 20 bytes).
func DecodeTCPHeader(header []byte) (*TCPHeader, error) {
	if len(header) < 20 {
		return nil, nil
	}
	return &TCPHeader{
		SrcPort:    int(binary.BigEndian.Uint16(header[0:2])),
		DstPort:    int(binary.BigEndian.Uint16(header[2:4])),
		Seq:        int(binary.BigEndian.Uint32(header[4:8])),
		Ack:        int(binary.BigEndian.Uint32(header[8:12])),
		DataOffset: int(header[12] >> 4),
		Flags:      int(header[13]),
		Window:     int(binary.BigEndian.Uint16(header[14:16])),
		Payload:    nil,
	}, nil
}

// DecodePacket performs a full decode of an Ethernet+IPv4 packet.
func DecodePacket(packet []byte) (*Packet, error) {
	eth, err := DecodeEthernetFrame(packet)
	if err != nil {
		return nil, err
	}
	if eth.EtherType != 0x0800 {
		return nil, nil
	}
	ip, err := DecodeIPv4Header(eth.Payload)
	if err != nil {
		return nil, err
	}

	proto := "other"
	if ip.Protocol == 1 {
		proto = "icmp"
	} else if ip.Protocol == 6 {
		proto = "tcp"
	}

	ipHeaderLen := ip.IHL * 4
	if ipHeaderLen < 20 || len(eth.Payload) < ipHeaderLen {
		return nil, nil
	}

	// For TCP, decode ports; for ICMP/other, ports are zero
	if proto == "tcp" {
		tcp, err := DecodeTCPHeader(eth.Payload[ipHeaderLen:])
		if err != nil || tcp == nil {
			return &Packet{
				SrcIP:    ip.SrcIP.String(),
				DstIP:    ip.DstIP.String(),
				Protocol: proto,
			}, nil
		}
		return &Packet{
			SrcIP:    ip.SrcIP.String(),
			DstIP:    ip.DstIP.String(),
			SrcPort:  tcp.SrcPort,
			DstPort:  tcp.DstPort,
			Protocol: proto,
		}, nil
	}

	return &Packet{
		SrcIP:    ip.SrcIP.String(),
		DstIP:    ip.DstIP.String(),
		Protocol: proto,
	}, nil
}
