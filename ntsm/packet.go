package ntsm

import (
	"encoding/binary"
	"net"
)

// TCPFlags represents TCP header flags
type TCPFlags uint8

const (
	FIN TCPFlags = 1 << 0
	SYN TCPFlags = 1 << 1
	RST TCPFlags = 1 << 2
	PSH TCPFlags = 1 << 3
	ACK TCPFlags = 1 << 4
	URG TCPFlags = 1 << 5
	ECE TCPFlags = 1 << 6
	CWR TCPFlags = 1 << 7
)

// TCPHeader represents a minimal TCP header structure
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // In 4-byte words
	Flags      TCPFlags
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	Options    []byte
	Payload    []byte
}

// PacketInfo contains extracted information from a TCP packet
type PacketInfo struct {
	SrcIP   net.IP
	DstIP   net.IP
	TCP     *TCPHeader
	Payload []byte
}

// BuildTCPPacket constructs a raw TCP packet
func BuildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32,
	flags TCPFlags, window uint16, payload []byte, options []byte) []byte {

	// Calculate header length (including options)
	optionsLen := len(options)
	// Pad options to 4-byte boundary
	if optionsLen%4 != 0 {
		padding := 4 - (optionsLen % 4)
		for i := 0; i < padding; i++ {
			options = append(options, 0)
		}
		optionsLen = len(options)
	}

	headerLen := 20 + optionsLen       // Base header is 20 bytes
	dataOffset := uint8(headerLen / 4) // Data offset in 4-byte words

	// Build IP header (IPv4)
	ipHeaderLen := 20
	totalLen := ipHeaderLen + headerLen + len(payload)

	packet := make([]byte, totalLen)

	// IPv4 header
	packet[0] = 0x45 // Version (4) + IHL (5)
	packet[1] = 0x00 // Type of Service
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)      // Identification
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags + Fragment Offset (Don't Fragment)
	packet[8] = 64                                  // TTL
	packet[9] = 6                                   // Protocol (TCP)
	// Checksum will be calculated later
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[0:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// TCP header starts at offset 20
	tcpStart := 20

	// TCP header
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], srcPort)
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], dstPort)
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], seq)
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], ack)
	packet[tcpStart+12] = dataOffset << 4 // Data offset in upper 4 bits
	packet[tcpStart+13] = uint8(flags)
	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], window)
	// Checksum will be calculated later
	binary.BigEndian.PutUint16(packet[tcpStart+18:tcpStart+20], 0) // Urgent pointer

	// Copy options
	if len(options) > 0 {
		copy(packet[tcpStart+20:tcpStart+20+len(options)], options)
	}

	// Copy payload
	if len(payload) > 0 {
		copy(packet[tcpStart+headerLen:], payload)
	}

	// Calculate TCP checksum
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, packet[tcpStart:])
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], tcpChecksum)

	return packet
}

// calculateChecksum calculates the Internet checksum
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add left-over byte, if any
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

// calculateTCPChecksum calculates the TCP checksum including pseudo-header
func calculateTCPChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	// Create pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0 // Reserved
	pseudoHeader[9] = 6 // Protocol (TCP)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpData)))

	// Combine pseudo-header and TCP data
	checksumData := append(pseudoHeader, tcpData...)

	return calculateChecksum(checksumData)
}

// ParseTCPHeader parses a TCP header from raw bytes
func ParseTCPHeader(data []byte) *TCPHeader {
	if len(data) < 20 {
		return nil
	}

	header := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] >> 4) & 0x0F,
		Flags:      TCPFlags(data[13]),
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}

	headerLen := int(header.DataOffset) * 4
	if headerLen < 20 || headerLen > len(data) {
		return nil
	}

	// Extract options if present
	if headerLen > 20 {
		header.Options = make([]byte, headerLen-20)
		copy(header.Options, data[20:headerLen])
	}

	// Extract payload
	if len(data) > headerLen {
		header.Payload = make([]byte, len(data)-headerLen)
		copy(header.Payload, data[headerLen:])
	}

	return header
}

// HasFlag checks if a specific flag is set
func (h *TCPHeader) HasFlag(flag TCPFlags) bool {
	return h.Flags&flag != 0
}

// IsValidSequence checks if a sequence number is within the receive window
func IsValidSequence(seq, rcvNxt, rcvWnd uint32) bool {
	if rcvWnd == 0 {
		return seq == rcvNxt
	}
	// Check if sequence is within the receive window
	return seq >= rcvNxt && seq < rcvNxt+rcvWnd
}
