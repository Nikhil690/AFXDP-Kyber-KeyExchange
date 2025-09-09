package crypto

import (
	"fmt"
	"log"
	"xdp-example/optimizations"

	"github.com/cloudflare/circl/kem"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
)

// OptimizedCryptoProcessor holds optimized crypto components
type OptimizedCryptoProcessor struct {
	bufferPool      *optimizations.BufferPool
	fastProcessor   *optimizations.FastPacketProcessor
	cryptoProcessor *optimizations.CryptoMessageProcessor
}

// NewOptimizedCryptoProcessor creates a new optimized crypto processor
func NewOptimizedCryptoProcessor(bufferPool *optimizations.BufferPool, publicKey kem.PublicKey) (*OptimizedCryptoProcessor, error) {
	fastProcessor := optimizations.NewFastPacketProcessor(bufferPool)

	cryptoProcessor, err := optimizations.NewCryptoMessageProcessor(publicKey)
	if err != nil {
		return nil, err
	}

	return &OptimizedCryptoProcessor{
		bufferPool:      bufferPool,
		fastProcessor:   fastProcessor,
		cryptoProcessor: cryptoProcessor,
	}, nil
}

// StartHelloOptimized sends crypto hello message with Phase 1 optimizations
func (ocp *OptimizedCryptoProcessor) StartHelloOptimized(xsk *xdp.Socket, packet gopacket.Packet) error {
	fmt.Println("🤝 SERVER: Client connected! (Optimized)")

	// Phase 1: Use fast packet layer parsing
	eth, ip, tcp, ok := ocp.fastProcessor.ParsePacketLayers(packet)
	if !ok {
		return fmt.Errorf("invalid packet layers")
	}

	// Phase 1: Use optimized crypto message creation
	msg := ocp.cryptoProcessor.CreateKeyExchangeMessage()
	defer ocp.cryptoProcessor.ReturnMessage(msg)

	// Phase 1: Use fast message serialization
	httpPayload := ocp.cryptoProcessor.FastSerializeMessage(msg)

	// Create response packet layers efficiently
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	replyIP := &layers.IPv4{
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     0,         // Will be set by serialization
		Id:         ip.Id + 1, // Increment ID
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Protocol:   ip.Protocol,
		Checksum:   0,
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        tcp.Ack,
		Ack:        tcp.Seq,
		DataOffset: tcp.DataOffset,
		Window:     tcp.Window,
		Checksum:   0,
		Urgent:     tcp.Urgent,
		SYN:        false,
		ACK:        true,
		FIN:        false,
		RST:        false,
		PSH:        true,
		URG:        tcp.URG,
		ECE:        tcp.ECE,
		CWR:        tcp.CWR,
		NS:         tcp.NS,
	}

	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Phase 1: Use optimized packet serialization with buffer pool
	packetData, err := ocp.fastProcessor.FastSerializePacket(replyEth, replyIP, replyTCP, httpPayload)
	if err != nil {
		return fmt.Errorf("error serializing packet: %v", err)
	}

	// Send the packet
	return ocp.transmitPacket(xsk, packetData)
}

func (ocp *OptimizedCryptoProcessor) transmitPacket(xsk *xdp.Socket, data []byte) error {
	_, _, err := xsk.Poll(1)
	if err != nil {
		return err
	}

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, false)[0]
	frame := xsk.GetFrame(txDesc)
	if len(frame) < len(data) {
		return fmt.Errorf("TX frame too small, got %d bytes, need %d bytes", len(frame), len(data))
	}

	copy(frame, data)
	txDesc.Len = uint32(len(data))
	xsk.Transmit([]xdp.Desc{txDesc})

	return nil
}

// Global optimized crypto processor instance
var optimizedCrypto *OptimizedCryptoProcessor

// InitializeOptimizedCrypto initializes the optimized crypto processor
func InitializeOptimizedCrypto(bufferPool *optimizations.BufferPool, publicKey kem.PublicKey) error {
	var err error
	optimizedCrypto, err = NewOptimizedCryptoProcessor(bufferPool, publicKey)
	if err != nil {
		return err
	}
	log.Printf("✅ Optimized crypto processor initialized")
	return nil
}

// StartHelloOptimizedGlobal is a global function that uses the optimized processor
func StartHelloOptimizedGlobal(xsk *xdp.Socket, publicKey kem.PublicKey, packet gopacket.Packet) {
	if optimizedCrypto == nil {
		log.Printf("⚠️  Optimized crypto not initialized, falling back to original implementation")
		StartHelloNew(xsk, publicKey, packet)
		return
	}

	if err := optimizedCrypto.StartHelloOptimized(xsk, packet); err != nil {
		log.Printf("❌ Optimized crypto hello failed: %v", err)
		// Fallback to original implementation
		StartHelloNew(xsk, publicKey, packet)
	}
}
