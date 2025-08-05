package tsm

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

// HandleFin processes FIN packets and sends appropriate response for connection teardown
func HandleFin(xsk *sxdp.Socket, packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		log.Printf("error: received packet without TCP layer")
		return false
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("error: received packet without IPv4 layer")
		return false
	}
	// ip := ipLayer.(*layers.IPv4)

	// Validate this is a FIN packet
	if !tcp.FIN {
		// log.Printf("Received non-FIN packet in FIN handler")
		return false
	}

	// log.Printf("📋 TCP FIN received from %s:%d -> %s:%d, Seq=%d, Ack=%d",
	// 	ip.SrcIP, tcp.SrcPort,
	// 	ip.DstIP, tcp.DstPort,
	// 	tcp.Seq, tcp.Ack)

	// Determine what type of FIN we received and respond appropriately
	if tcp.ACK && tcp.FIN {
		// Received FIN+ACK - this is the client initiating graceful shutdown
		log.Printf("🔄 Client initiated connection close (FIN+ACK)")
		SendAck(xsk, packet)    // First ACK the FIN
		SendFinAck(xsk, packet)
		return true
	} else if tcp.FIN && !tcp.ACK {
		// Received just FIN - acknowledge it and send our own FIN
		log.Printf("🔄 Client sent FIN, sending ACK then FIN")
		// SendAck(xsk, packet)    // First ACK the FIN
		SendFinAck(xsk, packet) // Then send our FIN+ACK
		return true
	}

	return false
}

// SendFinAck sends a FIN+ACK packet to close the connection
func SendFinAck(xsk *sxdp.Socket, packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		log.Printf("error: received packet without TCP layer")
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("error: received packet without IPv4 layer")
		return
	}
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Printf("error: received packet without Ethernet layer")
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Create new Ethernet layer for FIN+ACK
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC, // Server MAC (was destination)
		DstMAC:       eth.SrcMAC, // Client MAC (was source)
		EthernetType: eth.EthernetType,
	}

	// Create new IPv4 layer for FIN+ACK
	replyIP := &layers.IPv4{
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     0, // Will be set by serialization
		Id:         ip.Id + 1,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Protocol:   ip.Protocol,
		Checksum:   0,        // Will be calculated by serialization
		SrcIP:      ip.DstIP, // Server IP (was destination)
		DstIP:      ip.SrcIP, // Client IP (was source)
	}

	// Create new TCP layer for FIN+ACK
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,    // Server port (was destination)
		DstPort:    tcp.SrcPort,    // Client port (was source)
		Seq:        tcp.Ack,        // Our seq = their ack
		Ack:        tcp.Seq + 1,    // Our ack = their seq + 1 (FIN consumes 1 seq number)
		DataOffset: tcp.DataOffset, // Keep same data offset
		Window:     tcp.Window,     // Keep same window
		Checksum:   0,              // Will be calculated by serialization
		Urgent:     tcp.Urgent,
		SYN:        false,
		ACK:        true, // ACK flag set
		FIN:        true, // FIN flag set for connection close
		RST:        false,
		PSH:        false,
		URG:        tcp.URG,
		ECE:        tcp.ECE,
		CWR:        tcp.CWR,
		NS:         tcp.NS,
		// Options:    tcp.Options, // Reuse same TCP options
	}

	// Set up TCP checksum calculation
	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP); err != nil {
		log.Printf("error serializing FIN+ACK packet: %v", err)
		return
	}

	// Send FIN+ACK packet
	reply := buf.Bytes()

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))

	// Transmit the packet
	xsk.Transmit([]sxdp.Desc{txDesc})

		// log.Printf("✅ Sent TCP FIN+ACK: %s:%d -> %s:%d, Seq=%d, Ack=%d",
		// 	replyIP.SrcIP, replyTCP.SrcPort,
		// 	replyIP.DstIP, replyTCP.DstPort,
		// 	replyTCP.Seq, replyTCP.Ack)
}

// SendAck sends a simple ACK packet (for acknowledging FIN without closing)
func SendAck(xsk *sxdp.Socket, packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		log.Printf("error: received packet without TCP layer")
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("error: received packet without IPv4 layer")
		return
	}
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Printf("error: received packet without Ethernet layer")
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Create new Ethernet layer for ACK
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	// Create new IPv4 layer for ACK
	replyIP := &layers.IPv4{
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     0,
		Id:         ip.Id + 1,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Protocol:   ip.Protocol,
		Checksum:   0,
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	// Create new TCP layer for ACK
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        tcp.Ack,
		Ack:        tcp.Seq + 1, // ACK the FIN (FIN consumes 1 seq number)
		DataOffset: tcp.DataOffset,
		Window:     tcp.Window,
		Checksum:   0,
		Urgent:     tcp.Urgent,
		SYN:        false,
		ACK:        true, // Only ACK flag set
		FIN:        false,
		RST:        false,
		PSH:        false,
		URG:        tcp.URG,
		ECE:        tcp.ECE,
		CWR:        tcp.CWR,
		NS:         tcp.NS,
		// Options:    tcp.Options,
	}

	// Set up TCP checksum calculation
	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP); err != nil {
		log.Printf("error serializing ACK packet: %v", err)
		return
	}

	// Send ACK packet
	reply := buf.Bytes()

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))

	// Transmit the packet
	xsk.Transmit([]sxdp.Desc{txDesc})

	// log.Printf("✅ Sent TCP ACK: %s:%d -> %s:%d, Seq=%d, Ack=%d",
	// 	replyIP.SrcIP, replyTCP.SrcPort,
	// 	replyIP.DstIP, replyTCP.DstPort,
	// 	replyTCP.Seq, replyTCP.Ack)
}
