package ntsm

import (
	"log"
	"math/rand"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
)

// PacketTransmitter is an interface for sending packets
type PacketTransmitter interface {
	SendPacket(packet []byte, xsk *xdp.Socket) error
}

// TSM represents the TCP State Machine
type TSM struct {
	connections map[ConnectionKey]*Connection
	transmitter PacketTransmitter // Optional packet transmitter
	xsk         *xdp.Socket       // AF_XDP socket
}

// NewTSM creates a new TCP State Machine instance
func NewTSM() *TSM {
	return &TSM{
		connections: make(map[ConnectionKey]*Connection),
		transmitter: nil,
		xsk:         nil,
	}
}

func (tsm *TSM) SetXsk(xsk *xdp.Socket) {
	tsm.xsk = xsk
}

// SetTransmitter sets the packet transmitter for automatic packet sending
func (tsm *TSM) SetTransmitter(transmitter PacketTransmitter) {
	tsm.transmitter = transmitter
}

// sendPackets sends packets using the configured transmitter, or returns them if no transmitter is set
func (tsm *TSM) sendPackets(packets [][]byte) [][]byte {
	for _, packet := range packets {
		err := sendPacket(packet, tsm.xsk)
		if err != nil {
			log.Printf("error: failed to send packet: descriptors returned %v", err)
		}
	}
	return nil // Return empty since packets were sent
}

// HandlePacket processes an inbound TCP packet and returns outbound packets
func (tsm *TSM) HandlePacket(pkt gopacket.Packet) [][]byte {
	// Extract IP and TCP layers
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Create packet info
	pktInfo := &PacketInfo{
		SrcIP: ip.SrcIP,
		DstIP: ip.DstIP,
		TCP: &TCPHeader{
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			SeqNum:  tcp.Seq,
			AckNum:  tcp.Ack,
			Flags:   convertGopacketFlags(tcp),
			Window:  tcp.Window,
			Payload: tcp.Payload,
		},
		Payload: tcp.Payload,
	}

	// Determine connection key (normalize to local perspective)
	connKey := NewConnectionKey(ip.DstIP, uint16(tcp.DstPort), ip.SrcIP, uint16(tcp.SrcPort))

	// Get or create connection
	conn := tsm.getOrCreateConnection(connKey, pktInfo)
	if conn == nil {
		return nil
	}

	conn.Lock()
	defer conn.Unlock()

	// Process packet based on current state
	packets := tsm.processPacket(conn, pktInfo)

	// Send packets automatically if transmitter is configured
	return tsm.sendPackets(packets)
}

// SendData segments data and returns TCP packets for transmission
func (tsm *TSM) SendData(conn *Connection, data []byte) [][]byte {
	conn.Lock()
	defer conn.Unlock()

	if !conn.State.CanSendData() {
		return nil
	}

	// Add data to send buffer
	conn.SendBuffer = append(conn.SendBuffer, data...)

	// Send as much data as possible
	packets := tsm.sendPendingData(conn)

	// Send packets automatically if transmitter is configured
	return tsm.sendPackets(packets)
}

// ReadData returns reassembled application data
func (conn *Connection) ReadData() ([]byte, error) {
	conn.Lock()
	defer conn.Unlock()

	if len(conn.ReadyData) == 0 {
		return nil, nil
	}

	data := make([]byte, len(conn.ReadyData))
	copy(data, conn.ReadyData)
	conn.ReadyData = conn.ReadyData[:0] // Clear the buffer

	return data, nil
}

// Tick processes timer events and returns packets that need retransmission
func (tsm *TSM) Tick() [][]byte {
	var packets [][]byte

	for _, conn := range tsm.connections {
		conn.Lock()

		// Check retransmission timer
		if conn.RetransTimer.IsExpired() && len(conn.UnackedData) > 0 {
			// Retransmit unacknowledged data
			retransPackets := tsm.retransmitData(conn)
			packets = append(packets, retransPackets...)
		}

		// Check TIME_WAIT expiry
		if conn.State == TIME_WAIT && time.Now().After(conn.TimeWaitExpiry) {
			conn.State = CLOSED
		}

		conn.Unlock()
	}

	// Send packets automatically if transmitter is configured
	return tsm.sendPackets(packets)
}

// getOrCreateConnection retrieves or creates a connection for the given key
func (tsm *TSM) getOrCreateConnection(key ConnectionKey, pktInfo *PacketInfo) *Connection {
	// Check if connection exists
	if conn, exists := tsm.connections[key]; exists {
		return conn
	}

	// Check for reverse connection (for incoming SYN)
	reverseKey := NewConnectionKey(
		pktInfo.DstIP, uint16(pktInfo.TCP.DstPort),
		pktInfo.SrcIP, uint16(pktInfo.TCP.SrcPort),
	)

	if conn, exists := tsm.connections[reverseKey]; exists {
		return conn
	}

	// Create new connection for incoming SYN
	if pktInfo.TCP.HasFlag(SYN) && !pktInfo.TCP.HasFlag(ACK) {
		conn := NewConnection(key, true)
		conn.State = LISTEN
		tsm.connections[key] = conn
		return conn
	}

	return nil
}

// processPacket handles packet processing based on connection state
func (tsm *TSM) processPacket(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	// Handle RST flag
	if tcp.HasFlag(RST) {
		conn.State = CLOSED
		return nil
	}

	switch conn.State {
	case CLOSED:
		return tsm.processClosed(conn, pktInfo)
	case LISTEN:
		return tsm.processListen(conn, pktInfo)
	case SYN_SENT:
		return tsm.processSynSent(conn, pktInfo)
	case SYN_RECEIVED:
		return tsm.processSynReceived(conn, pktInfo)
	case ESTABLISHED:
		return tsm.processEstablished(conn, pktInfo)
	case FIN_WAIT_1:
		return tsm.processFinWait1(conn, pktInfo)
	case FIN_WAIT_2:
		return tsm.processFinWait2(conn, pktInfo)
	case CLOSE_WAIT:
		return tsm.processCloseWait(conn, pktInfo)
	case CLOSING:
		return tsm.processClosing(conn, pktInfo)
	case LAST_ACK:
		return tsm.processLastAck(conn, pktInfo)
	case TIME_WAIT:
		return tsm.processTimeWait(conn, pktInfo)
	}

	return nil
}

// processClosed handles packets in CLOSED state
func (tsm *TSM) processClosed(conn *Connection, pktInfo *PacketInfo) [][]byte {
	// Send RST for any packet except RST
	if !pktInfo.TCP.HasFlag(RST) {
		return [][]byte{tsm.buildRSTPacket(conn, pktInfo)}
	}
	return nil
}

// processListen handles packets in LISTEN state
func (tsm *TSM) processListen(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(SYN) && !tcp.HasFlag(ACK) {
		// Incoming connection request
		conn.Seq.IRS = tcp.SeqNum
		conn.Seq.RCV_NXT = tcp.SeqNum + 1
		conn.Seq.RCV_WND = 65535

		// Generate ISN
		conn.Seq.ISS = generateISN()
		conn.Seq.SND_NXT = conn.Seq.ISS + 1
		conn.Seq.SND_UNA = conn.Seq.ISS
		conn.Seq.SND_WND = uint32(tcp.Window)

		conn.State = SYN_RECEIVED

		// Send SYN+ACK
		return [][]byte{tsm.buildSynAckPacket(conn)}
	}

	return nil
}

// processSynSent handles packets in SYN_SENT state
func (tsm *TSM) processSynSent(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(SYN) && tcp.HasFlag(ACK) {
		// Check if ACK is valid
		if tcp.AckNum != conn.Seq.SND_NXT {
			return [][]byte{tsm.buildRSTPacket(conn, pktInfo)}
		}

		conn.Seq.IRS = tcp.SeqNum
		conn.Seq.RCV_NXT = tcp.SeqNum + 1
		conn.Seq.SND_UNA = tcp.AckNum
		conn.Seq.SND_WND = uint32(tcp.Window)

		conn.State = ESTABLISHED

		// Send ACK
		return [][]byte{tsm.buildAckPacket(conn)}
	}

	return nil
}

// processSynReceived handles packets in SYN_RECEIVED state
func (tsm *TSM) processSynReceived(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(ACK) {
		// Check if ACK is valid
		if tcp.AckNum != conn.Seq.SND_NXT {
			return [][]byte{tsm.buildRSTPacket(conn, pktInfo)}
		}

		conn.Seq.SND_UNA = tcp.AckNum
		conn.Seq.SND_WND = uint32(tcp.Window)
		conn.State = ESTABLISHED

		return nil
	}

	return nil
}

// processEstablished handles packets in ESTABLISHED state
func (tsm *TSM) processEstablished(conn *Connection, pktInfo *PacketInfo) [][]byte {
	var packets [][]byte
	tcp := pktInfo.TCP

	// Process ACK
	if tcp.HasFlag(ACK) {
		packets = append(packets, tsm.processAck(conn, tcp)...)
	}

	// Process data
	if len(tcp.Payload) > 0 {
		packets = append(packets, tsm.processData(conn, tcp)...)
	}

	// Process FIN
	if tcp.HasFlag(FIN) {
		conn.Seq.RCV_NXT = tcp.SeqNum + uint32(len(tcp.Payload)) + 1
		conn.State = CLOSE_WAIT
		packets = append(packets, tsm.buildAckPacket(conn))
	}

	return packets
}

// processFinWait1 handles packets in FIN_WAIT_1 state
func (tsm *TSM) processFinWait1(conn *Connection, pktInfo *PacketInfo) [][]byte {
	var packets [][]byte
	tcp := pktInfo.TCP

	if tcp.HasFlag(ACK) {
		packets = append(packets, tsm.processAck(conn, tcp)...)
		if tcp.AckNum == conn.Seq.SND_NXT {
			conn.State = FIN_WAIT_2
		}
	}

	if tcp.HasFlag(FIN) {
		conn.Seq.RCV_NXT = tcp.SeqNum + 1
		if conn.State == FIN_WAIT_2 {
			conn.State = TIME_WAIT
			conn.TimeWaitExpiry = time.Now().Add(2 * time.Minute) // 2MSL
		} else {
			conn.State = CLOSING
		}
		packets = append(packets, tsm.buildAckPacket(conn))
	}

	return packets
}

// processFinWait2 handles packets in FIN_WAIT_2 state
func (tsm *TSM) processFinWait2(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(FIN) {
		conn.Seq.RCV_NXT = tcp.SeqNum + 1
		conn.State = TIME_WAIT
		conn.TimeWaitExpiry = time.Now().Add(2 * time.Minute) // 2MSL
		return [][]byte{tsm.buildAckPacket(conn)}
	}

	return nil
}

// processCloseWait handles packets in CLOSE_WAIT state
func (tsm *TSM) processCloseWait(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(ACK) {
		return tsm.processAck(conn, tcp)
	}

	return nil
}

// processClosing handles packets in CLOSING state
func (tsm *TSM) processClosing(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(ACK) && tcp.AckNum == conn.Seq.SND_NXT {
		conn.State = TIME_WAIT
		conn.TimeWaitExpiry = time.Now().Add(2 * time.Minute) // 2MSL
	}

	return nil
}

// processLastAck handles packets in LAST_ACK state
func (tsm *TSM) processLastAck(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(ACK) && tcp.AckNum == conn.Seq.SND_NXT {
		conn.State = CLOSED
	}

	return nil
}

// processTimeWait handles packets in TIME_WAIT state
func (tsm *TSM) processTimeWait(conn *Connection, pktInfo *PacketInfo) [][]byte {
	tcp := pktInfo.TCP

	if tcp.HasFlag(FIN) {
		// Restart TIME_WAIT timer
		conn.TimeWaitExpiry = time.Now().Add(2 * time.Minute) // 2MSL
		return [][]byte{tsm.buildAckPacket(conn)}
	}

	return nil
}

// Helper functions for packet processing

// processAck handles ACK processing
func (tsm *TSM) processAck(conn *Connection, tcp *TCPHeader) [][]byte {
	if tcp.AckNum > conn.Seq.SND_UNA && tcp.AckNum <= conn.Seq.SND_NXT {
		// Valid ACK
		ackedBytes := tcp.AckNum - conn.Seq.SND_UNA
		conn.Seq.SND_UNA = tcp.AckNum
		conn.Seq.SND_WND = uint32(tcp.Window)

		// Remove acknowledged data from unacked buffer
		if int(ackedBytes) <= len(conn.UnackedData) {
			conn.UnackedData = conn.UnackedData[ackedBytes:]
		} else {
			conn.UnackedData = nil
		}

		// Stop retransmission timer if all data is acked
		if len(conn.UnackedData) == 0 {
			conn.RetransTimer.Stop()
		}

		// Send more data if available
		return tsm.sendPendingData(conn)
	} else if tcp.AckNum == conn.Seq.SND_UNA {
		// Duplicate ACK
		conn.DupAckCount++
		if conn.DupAckCount == 3 {
			// Fast retransmit
			return tsm.retransmitData(conn)
		}
	}

	return nil
}

// processData handles data processing and reassembly
func (tsm *TSM) processData(conn *Connection, tcp *TCPHeader) [][]byte {
	if tcp.SeqNum == conn.Seq.RCV_NXT {
		// In-order data
		conn.ReadyData = append(conn.ReadyData, tcp.Payload...)
		conn.Seq.RCV_NXT += uint32(len(tcp.Payload))

		// Check for buffered out-of-order data
		tsm.processBufferedData(conn)

		return [][]byte{tsm.buildAckPacket(conn)}
	} else if tcp.SeqNum > conn.Seq.RCV_NXT {
		// Out-of-order data - buffer it
		conn.ReceiveBuffer[tcp.SeqNum] = make([]byte, len(tcp.Payload))
		copy(conn.ReceiveBuffer[tcp.SeqNum], tcp.Payload)

		// Send duplicate ACK
		return [][]byte{tsm.buildAckPacket(conn)}
	}

	// Old data - just ACK
	return [][]byte{tsm.buildAckPacket(conn)}
}

// processBufferedData processes buffered out-of-order segments
func (tsm *TSM) processBufferedData(conn *Connection) {
	for {
		if data, exists := conn.ReceiveBuffer[conn.Seq.RCV_NXT]; exists {
			conn.ReadyData = append(conn.ReadyData, data...)
			conn.Seq.RCV_NXT += uint32(len(data))
			delete(conn.ReceiveBuffer, conn.Seq.RCV_NXT-uint32(len(data)))
		} else {
			break
		}
	}
}

// sendPendingData sends data from the send buffer
func (tsm *TSM) sendPendingData(conn *Connection) [][]byte {
	var packets [][]byte

	for len(conn.SendBuffer) > 0 {
		// Determine how much data to send
		sendSize := int(conn.MSS)
		if sendSize > len(conn.SendBuffer) {
			sendSize = len(conn.SendBuffer)
		}

		// Check window
		if conn.Seq.SND_NXT-conn.Seq.SND_UNA+uint32(sendSize) > conn.Seq.SND_WND {
			break // Window is full
		}

		// Create data packet
		data := conn.SendBuffer[:sendSize]
		packet := tsm.buildDataPacket(conn, data)
		packets = append(packets, packet)

		// Update state
		conn.SendBuffer = conn.SendBuffer[sendSize:]
		conn.UnackedData = append(conn.UnackedData, data...)
		conn.Seq.SND_NXT += uint32(sendSize)

		// Start retransmission timer
		if !conn.RetransTimer.Active {
			conn.RetransTimer.Start()
		}
	}

	return packets
}

// retransmitData retransmits unacknowledged data
func (tsm *TSM) retransmitData(conn *Connection) [][]byte {
	if len(conn.UnackedData) == 0 {
		return nil
	}

	// Retransmit first segment
	sendSize := int(conn.MSS)
	if sendSize > len(conn.UnackedData) {
		sendSize = len(conn.UnackedData)
	}

	data := conn.UnackedData[:sendSize]
	packet := tsm.buildDataPacket(conn, data)

	// Restart timer
	conn.RetransTimer.Start()
	conn.DupAckCount = 0

	return [][]byte{packet}
}

// Utility functions

// convertGopacketFlags converts gopacket TCP flags to our TCPFlags type
func convertGopacketFlags(tcp *layers.TCP) TCPFlags {
	var flags TCPFlags
	if tcp.FIN {
		flags |= FIN
	}
	if tcp.SYN {
		flags |= SYN
	}
	if tcp.RST {
		flags |= RST
	}
	if tcp.PSH {
		flags |= PSH
	}
	if tcp.ACK {
		flags |= ACK
	}
	if tcp.URG {
		flags |= URG
	}
	if tcp.ECE {
		flags |= ECE
	}
	if tcp.CWR {
		flags |= CWR
	}
	return flags
}

// generateISN generates an Initial Sequence Number
func generateISN() uint32 {
	return rand.Uint32()
}
