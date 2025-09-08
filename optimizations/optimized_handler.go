package optimizations

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

// OptimizedPacketHandler integrates all optimizations
type OptimizedPacketHandler struct {
	bufferPool        *BufferPool
	connectionManager *FastConnectionManager
	cryptoProcessor   *CryptoMessageProcessor
	workerPool        *WorkerPool
	fastProcessor     *FastPacketProcessor
	batchProcessor    *BatchedPacketProcessor
	xsk               *sxdp.Socket
	publicKey         kem.PublicKey
	privateKey        kem.PrivateKey
	stats             *PacketStats
}

type PacketStats struct {
	TotalPackets     uint64
	ProcessedPackets uint64
	DroppedPackets   uint64
	ErrorPackets     uint64
	AvgProcessTime   time.Duration
}

// NewOptimizedPacketHandler creates a new optimized packet handler
func NewOptimizedPacketHandler(xsk *sxdp.Socket, publicKey kem.PublicKey, privateKey kem.PrivateKey) (*OptimizedPacketHandler, error) {
	// Initialize buffer pool
	bufferPool := NewBufferPool(1024, 4096)

	// Initialize connection manager with optimized settings
	connectionManager := NewFastConnectionManager(1*time.Minute, 30*time.Minute)

	// Initialize crypto processor
	cryptoProcessor, err := NewCryptoMessageProcessor(publicKey)
	if err != nil {
		return nil, err
	}

	// Initialize fast packet processor
	fastProcessor := NewFastPacketProcessor(bufferPool)

	// Initialize batched processor
	config := GetOptimizedXDPConfig()
	batchProcessor := NewBatchedPacketProcessor(xsk, config.BatchSize)

	handler := &OptimizedPacketHandler{
		bufferPool:        bufferPool,
		connectionManager: connectionManager,
		cryptoProcessor:   cryptoProcessor,
		fastProcessor:     fastProcessor,
		batchProcessor:    batchProcessor,
		xsk:               xsk,
		publicKey:         publicKey,
		privateKey:        privateKey,
		stats:             &PacketStats{},
	}

	// Initialize worker pool
	handler.workerPool = NewWorkerPool(4, 256, handler, bufferPool)

	return handler, nil
}

// ProcessPacket implements PacketProcessor interface
func (oph *OptimizedPacketHandler) ProcessPacket(item *PacketWorkItem) error {
	start := time.Now()
	defer func() {
		oph.stats.AvgProcessTime = time.Since(start)
		oph.stats.TotalPackets++
	}()

	// Fast layer parsing
	eth, ip, tcp, ok := oph.fastProcessor.ParsePacketLayers(item.Packet)
	if !ok {
		oph.stats.ErrorPackets++
		return nil // Not a TCP packet
	}

	// Create connection key
	connKey := CreateConnectionKey(ip.SrcIP, ip.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))
	conn := oph.connectionManager.GetConnection(connKey)

	// Determine packet type quickly
	packetType := DeterminePacketType(tcp.BaseLayer.Payload[13]) // TCP flags

	switch packetType {
	case PacketTypeSYN:
		return oph.handleSYN(eth, ip, tcp, conn, item)
	case PacketTypeACK:
		return oph.handleACK(eth, ip, tcp, conn, item)
	case PacketTypePSHACK:
		return oph.handlePSHACK(eth, ip, tcp, conn, item)
	case PacketTypeFIN:
		return oph.handleFIN(eth, ip, tcp, conn, item)
	default:
		return nil
	}
}

func (oph *OptimizedPacketHandler) handleSYN(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, conn *ConnectionState, item *PacketWorkItem) error {
	// Update connection state
	conn.State = 1 // SYN_RECEIVED
	conn.RecvSeq = tcp.Seq
	conn.SendAck = tcp.Seq + 1

	// Send SYN-ACK using optimized packet creation
	return oph.sendSynAck(eth, ip, tcp)
}

func (oph *OptimizedPacketHandler) handleACK(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, conn *ConnectionState, item *PacketWorkItem) error {
	if conn.State == 1 && !conn.HelloSent { // SYN_RECEIVED -> ESTABLISHED
		conn.State = 4 // ESTABLISHED

		// Send crypto hello message
		return oph.sendCryptoHello(eth, ip, tcp)
	}

	return nil
}

func (oph *OptimizedPacketHandler) handlePSHACK(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, conn *ConnectionState, item *PacketWorkItem) error {
	// Process application data
	if len(tcp.Payload) > 0 {
		return oph.processCryptoMessage(tcp.Payload, conn)
	}
	return nil
}

func (oph *OptimizedPacketHandler) handleFIN(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, conn *ConnectionState, item *PacketWorkItem) error {
	// Send FIN-ACK and cleanup connection
	oph.connectionManager.RemoveConnection(conn.Key)
	return oph.sendFinAck(eth, ip, tcp)
}

func (oph *OptimizedPacketHandler) sendSynAck(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) error {
	// Create SYN-ACK response efficiently
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	replyIP := &layers.IPv4{
		Version:  ip.Version,
		IHL:      ip.IHL,
		TOS:      ip.TOS,
		TTL:      ip.TTL,
		Protocol: ip.Protocol,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	replyTCP := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     1000, // Use a proper sequence number
		Ack:     tcp.Seq + 1,
		Window:  65535,
		SYN:     true,
		ACK:     true,
	}

	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize using optimized buffer
	packetData, err := oph.fastProcessor.FastSerializePacket(replyEth, replyIP, replyTCP, nil)
	if err != nil {
		return err
	}

	return oph.transmitPacket(packetData)
}

func (oph *OptimizedPacketHandler) sendCryptoHello(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) error {
	// Create crypto message efficiently
	msg := oph.cryptoProcessor.CreateKeyExchangeMessage()
	defer oph.cryptoProcessor.ReturnMessage(msg)

	payload := oph.cryptoProcessor.FastSerializeMessage(msg)

	// Create response packet
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	replyIP := &layers.IPv4{
		Version:  ip.Version,
		IHL:      ip.IHL,
		TOS:      ip.TOS,
		TTL:      ip.TTL,
		Protocol: ip.Protocol,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	replyTCP := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     tcp.Ack,
		Ack:     tcp.Seq,
		Window:  tcp.Window,
		ACK:     true,
		PSH:     true,
	}

	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize with payload
	packetData, err := oph.fastProcessor.FastSerializePacket(replyEth, replyIP, replyTCP, payload)
	if err != nil {
		return err
	}

	return oph.transmitPacket(packetData)
}

func (oph *OptimizedPacketHandler) sendFinAck(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) error {
	// Similar implementation for FIN-ACK
	return nil
}

func (oph *OptimizedPacketHandler) processCryptoMessage(payload []byte, conn *ConnectionState) error {
	// Fast message deserialization
	msg, err := FastDeserializeMessage(payload)
	if err != nil {
		return err
	}

	// Process based on message type
	switch msg.Type {
	// Handle different crypto message types
	}

	return nil
}

func (oph *OptimizedPacketHandler) transmitPacket(data []byte) error {
	// Get TX descriptor and transmit
	txDesc := oph.xsk.GetDescs(1, false)[0]
	frame := oph.xsk.GetFrame(txDesc)

	if len(frame) < len(data) {
		return ErrFrameTooSmall
	}

	copy(frame, data)
	txDesc.Len = uint32(len(data))
	oph.xsk.Transmit([]sxdp.Desc{txDesc})

	return nil
}

// Start begins optimized packet processing
func (oph *OptimizedPacketHandler) Start(ctx context.Context) error {
	// Start worker pool
	oph.workerPool.Start(ctx)

	// Start monitoring
	go oph.monitorPerformance(ctx)

	// Main processing loop
	return oph.processingLoop(ctx)
}

func (oph *OptimizedPacketHandler) processingLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Use batched processing
			if err := oph.batchProcessor.ProcessBatch(); err != nil {
				log.Printf("Batch processing error: %v", err)
			}
		}
	}
}

func (oph *OptimizedPacketHandler) monitorPerformance(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := oph.workerPool.GetStats()
			connStats := oph.connectionManager.GetStats()

			log.Printf("Performance Stats - Packets: %d, Dropped: %d, Connections: %d, Avg Processing: %v",
				stats.PacketsProcessed, stats.PacketsDropped, connStats.ActiveConnections, oph.stats.AvgProcessTime)
		}
	}
}

var ErrFrameTooSmall = errors.New("frame too small for packet data")
