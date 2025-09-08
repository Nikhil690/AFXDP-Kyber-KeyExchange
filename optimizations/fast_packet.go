package optimizations

import (
	"encoding/binary"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FastPacketProcessor provides optimized packet processing
type FastPacketProcessor struct {
	bufferPool *BufferPool
}

func NewFastPacketProcessor(bufferPool *BufferPool) *FastPacketProcessor {
	return &FastPacketProcessor{
		bufferPool: bufferPool,
	}
}

// ParsePacketLayers extracts TCP/IP/Ethernet layers efficiently
func (fpp *FastPacketProcessor) ParsePacketLayers(packet gopacket.Packet) (*layers.Ethernet, *layers.IPv4, *layers.TCP, bool) {
	// Cache layer parsing to avoid repeated lookups
	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, nil, nil, false
	}
	ethLayer := eth.(*layers.Ethernet)

	ip := packet.Layer(layers.LayerTypeIPv4)
	if ip == nil {
		return nil, nil, nil, false
	}
	ipLayer := ip.(*layers.IPv4)

	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp == nil {
		return nil, nil, nil, false
	}
	tcpLayer := tcp.(*layers.TCP)

	return ethLayer, ipLayer, tcpLayer, true
}

// FastSerializePacket serializes packet layers efficiently using buffer pool
func (fpp *FastPacketProcessor) FastSerializePacket(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, payload []byte) ([]byte, error) {
	buf := fpp.bufferPool.GetSerializeBuffer()
	defer fpp.bufferPool.PutSerializeBuffer(buf)

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var err error
	if len(payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	}

	if err != nil {
		return nil, err
	}

	// Copy the serialized data to a new buffer to return
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	return result, nil
}

// FastParseFrameHeader parses Ethernet frame header directly from bytes
func FastParseFrameHeader(data []byte) (srcMAC, dstMAC [6]byte, etherType uint16, valid bool) {
	if len(data) < 14 {
		return [6]byte{}, [6]byte{}, 0, false
	}

	copy(dstMAC[:], data[0:6])
	copy(srcMAC[:], data[6:12])
	etherType = binary.BigEndian.Uint16(data[12:14])
	return srcMAC, dstMAC, etherType, true
}

// FastParseIPHeader parses IPv4 header directly from bytes
func FastParseIPHeader(data []byte, offset int) (srcIP, dstIP [4]byte, protocol uint8, headerLen int, valid bool) {
	if len(data) < offset+20 {
		return [4]byte{}, [4]byte{}, 0, 0, false
	}

	ipData := data[offset:]
	headerLen = int(ipData[0]&0x0F) * 4
	if len(data) < offset+headerLen {
		return [4]byte{}, [4]byte{}, 0, 0, false
	}

	protocol = ipData[9]
	copy(srcIP[:], ipData[12:16])
	copy(dstIP[:], ipData[16:20])
	return srcIP, dstIP, protocol, headerLen, true
}

// FastParseTCPHeader parses TCP header directly from bytes
func FastParseTCPHeader(data []byte, offset int) (srcPort, dstPort uint16, seq, ack uint32, flags uint8, headerLen int, valid bool) {
	if len(data) < offset+20 {
		return 0, 0, 0, 0, 0, 0, false
	}

	tcpData := data[offset:]
	srcPort = binary.BigEndian.Uint16(tcpData[0:2])
	dstPort = binary.BigEndian.Uint16(tcpData[2:4])
	seq = binary.BigEndian.Uint32(tcpData[4:8])
	ack = binary.BigEndian.Uint32(tcpData[8:12])
	headerLen = int(tcpData[12]>>4) * 4
	flags = tcpData[13]

	if len(data) < offset+headerLen {
		return 0, 0, 0, 0, 0, 0, false
	}

	return srcPort, dstPort, seq, ack, flags, headerLen, true
}

// TCPFlags constants for fast flag checking
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// HasFlag checks if a TCP flag is set
func HasFlag(flags uint8, flag uint8) bool {
	return flags&flag != 0
}

// FastPacketType determines packet type quickly
type PacketType int

const (
	PacketTypeSYN PacketType = iota
	PacketTypeSYNACK
	PacketTypeACK
	PacketTypePSHACK
	PacketTypeFIN
	PacketTypeRST
	PacketTypeOther
)

func DeterminePacketType(flags uint8) PacketType {
	switch {
	case HasFlag(flags, TCPFlagRST):
		return PacketTypeRST
	case HasFlag(flags, TCPFlagSYN) && HasFlag(flags, TCPFlagACK):
		return PacketTypeSYNACK
	case HasFlag(flags, TCPFlagSYN):
		return PacketTypeSYN
	case HasFlag(flags, TCPFlagFIN):
		return PacketTypeFIN
	case HasFlag(flags, TCPFlagPSH) && HasFlag(flags, TCPFlagACK):
		return PacketTypePSHACK
	case HasFlag(flags, TCPFlagACK):
		return PacketTypeACK
	default:
		return PacketTypeOther
	}
}

// UnsafeString converts byte slice to string without allocation
func UnsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// UnsafeBytes converts string to byte slice without allocation
func UnsafeBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}
