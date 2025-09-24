package ntsm

import (
	"net"
)

// buildAckPacket creates an ACK packet for the connection
func (tsm *TSM) buildAckPacket(conn *Connection) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		conn.Seq.SND_NXT, conn.Seq.RCV_NXT,
		ACK,
		uint16(conn.Seq.RCV_WND),
		nil, // No payload
		nil, // No options
	)
}

// buildSynAckPacket creates a SYN+ACK packet for the connection
func (tsm *TSM) buildSynAckPacket(conn *Connection) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		conn.Seq.ISS, conn.Seq.RCV_NXT,
		SYN|ACK,
		uint16(conn.Seq.RCV_WND),
		nil, // No payload
		nil, // No options
	)
}

// buildSynPacket creates a SYN packet for the connection
func (tsm *TSM) buildSynPacket(conn *Connection) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		conn.Seq.ISS, 0,
		SYN,
		uint16(conn.Seq.RCV_WND),
		nil, // No payload
		nil, // No options
	)
}

// buildDataPacket creates a data packet for the connection
func (tsm *TSM) buildDataPacket(conn *Connection, data []byte) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		conn.Seq.SND_NXT, conn.Seq.RCV_NXT,
		ACK|PSH,
		uint16(conn.Seq.RCV_WND),
		data,
		nil, // No options
	)
}

// buildFinPacket creates a FIN packet for the connection
func (tsm *TSM) buildFinPacket(conn *Connection) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		conn.Seq.SND_NXT, conn.Seq.RCV_NXT,
		FIN|ACK,
		uint16(conn.Seq.RCV_WND),
		nil, // No payload
		nil, // No options
	)
}

// buildRSTPacket creates a RST packet
func (tsm *TSM) buildRSTPacket(conn *Connection, pktInfo *PacketInfo) []byte {
	localIP := net.IP(conn.Key.LocalIP[:])
	remoteIP := net.IP(conn.Key.RemoteIP[:])

	var seq, ack uint32
	var flags TCPFlags = RST

	if pktInfo.TCP.HasFlag(ACK) {
		seq = pktInfo.TCP.AckNum
	} else {
		ack = pktInfo.TCP.SeqNum + uint32(len(pktInfo.TCP.Payload))
		if pktInfo.TCP.HasFlag(SYN) || pktInfo.TCP.HasFlag(FIN) {
			ack++
		}
		flags |= ACK
	}

	return BuildTCPPacket(
		localIP, remoteIP,
		conn.Key.LocalPort, conn.Key.RemotePort,
		seq, ack,
		flags,
		0,   // Window size 0 for RST
		nil, // No payload
		nil, // No options
	)
}

// CloseConnection initiates connection closure
func (tsm *TSM) CloseConnection(conn *Connection) [][]byte {
	conn.Lock()
	defer conn.Unlock()

	var packets [][]byte

	switch conn.State {
	case ESTABLISHED, SYN_RECEIVED:
		conn.State = FIN_WAIT_1
		conn.Seq.SND_NXT++
		packets = [][]byte{tsm.buildFinPacket(conn)}

	case CLOSE_WAIT:
		conn.State = LAST_ACK
		conn.Seq.SND_NXT++
		packets = [][]byte{tsm.buildFinPacket(conn)}
	}

	// Send packets automatically if transmitter is configured
	return tsm.sendPackets(packets)
} // Connect initiates an outbound connection
func (tsm *TSM) Connect(localIP, remoteIP net.IP, localPort, remotePort uint16) (*Connection, [][]byte) {
	connKey := NewConnectionKey(localIP, localPort, remoteIP, remotePort)

	conn := NewConnection(connKey, false)
	conn.State = SYN_SENT
	conn.Seq.ISS = generateISN()
	conn.Seq.SND_NXT = conn.Seq.ISS + 1
	conn.Seq.SND_UNA = conn.Seq.ISS
	conn.Seq.RCV_WND = 65535

	tsm.connections[connKey] = conn

	synPacket := tsm.buildSynPacket(conn)
	packets := [][]byte{synPacket}

	// Send packets automatically if transmitter is configured
	return conn, tsm.sendPackets(packets)
}
