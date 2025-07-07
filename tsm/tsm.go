package tsm

import (
	"log"
	"xdp-example/crypto"

	"github.com/cloudflare/circl/kem"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
)

func SendSynAck(xsk *xdp.Socket, packet gopacket.Packet) {
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

	// Create new Ethernet layer for SYN-ACK
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create new IPv4 layer for SYN-ACK
	replyIP := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0, // Will be set by serialization
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0, // Will be calculated by serialization
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	// Create new TCP layer for SYN-ACK
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        tcp.Ack,     // SYN-ACK seq = received ACK
		Ack:        tcp.Seq + 1, // SYN-ACK ack = received SEQ + 1
		DataOffset: 5,
		Window:     65535,
		Checksum:   0, // Will be calculated by serialization
		Urgent:     0,
		SYN:        true,
		ACK:        true,
		FIN:        false,
		RST:        false,
		PSH:        false,
		URG:        false,
		ECE:        false,
		CWR:        false,
		NS:         false,
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
		log.Printf("error serializing SYN-ACK packet: %v", err)
		return
	}

	// Send SYN-ACK packet
	reply := buf.Bytes()

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))

	// Transmit the packet
	xsk.Transmit([]xdp.Desc{txDesc})

	log.Printf("Sent TCP SYN-ACK: %s:%d -> %s:%d, Seq=%d, Ack=%d",
		replyIP.SrcIP, replyTCP.SrcPort,
		replyIP.DstIP, replyTCP.DstPort,
		replyTCP.Seq, replyTCP.Ack)
}

func HandleAck(xsk *xdp.Socket, publicKey kem.PublicKey, packet gopacket.Packet) bool {
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
	ip := ipLayer.(*layers.IPv4)

	// Validate this is an ACK packet (ACK=true, SYN=false, other flags=false)
	if !tcp.ACK || tcp.SYN || tcp.FIN || tcp.RST {
		log.Printf("Received non-ACK packet: SYN=%v, ACK=%v, FIN=%v, RST=%v",
			tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)
		return false
	}

	log.Printf("TCP handshake completed: %s:%d -> %s:%d",
		ip.SrcIP, tcp.SrcPort,
		ip.DstIP, tcp.DstPort)

	log.Printf("Final ACK received: Seq=%d, Ack=%d",
		tcp.Seq, tcp.Ack)

	crypto.StartHello(xsk, publicKey, packet)
	return true
}
