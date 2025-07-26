package tsm

import (
	"encoding/binary"
	"log"
	"math/rand"
	"time"

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

	// Generate a random sequence number for our SYN-ACK
	rand.Seed(time.Now().UnixNano())
	serverSeq := rand.Uint32()

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
		TOS:        ip.TOS,    // Copy TOS from original packet
		Length:     0,         // Will be set by serialization
		Id:         ip.Id + 1, // Increment ID
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0, // Will be calculated by serialization
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	// Create TCP options for SYN-ACK response
	tcpOptions := createSynAckOptions(tcp)

	// Create new TCP layer for SYN-ACK
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        serverSeq,                                                   // Use random sequence number
		Ack:        tcp.Seq + 1,                                                 // SYN-ACK ack = received SEQ + 1
		DataOffset: uint8((20 + len(calculateTCPOptionsBytes(tcpOptions))) / 4), // Calculate based on options
		Window:     65535,                                                       // Our receive window
		Checksum:   0,                                                           // Will be calculated by serialization
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
		Options:    tcpOptions,
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
	xsk.Transmit([]xdp.Desc{txDesc})

	// log.Printf("Sent TCP SYN-ACK: %s:%d -> %s:%d, Seq=%d, Ack=%d, Options=%d bytes",
	// 	replyIP.SrcIP, replyTCP.SrcPort,
	// 	replyIP.DstIP, replyTCP.DstPort,
	// 	replyTCP.Seq, replyTCP.Ack, len(calculateTCPOptionsBytes(tcpOptions)))
}

// createSynAckOptions creates appropriate TCP options for SYN-ACK response
func createSynAckOptions(originalTCP *layers.TCP) []layers.TCPOption {
	var options []layers.TCPOption

	// Parse original SYN options to see what client supports
	clientSupportsMSS := false
	clientSupportsSACK := false
	clientSupportsTimestamps := false
	clientSupportsWindowScale := false
	var clientTimestamp uint32

	for _, option := range originalTCP.Options {
		switch option.OptionType {
		case layers.TCPOptionKindMSS:
			clientSupportsMSS = true
		case layers.TCPOptionKindSACKPermitted:
			clientSupportsSACK = true
		case layers.TCPOptionKindTimestamps:
			clientSupportsTimestamps = true
			if len(option.OptionData) >= 4 {
				clientTimestamp = binary.BigEndian.Uint32(option.OptionData[0:4])
			}
		case layers.TCPOptionKindWindowScale:
			clientSupportsWindowScale = true
		}
	}

	// log.Printf("Client supports: MSS=%v, SACK=%v, Timestamps=%v, WindowScale=%v",
	// 	clientSupportsMSS, clientSupportsSACK, clientSupportsTimestamps, clientSupportsWindowScale)

	// 1. Maximum Segment Size (MSS) - if client supports it
	if clientSupportsMSS {
		mssData := make([]byte, 2)
		binary.BigEndian.PutUint16(mssData, 2460) // Standard Ethernet MSS
		options = append(options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   mssData,
		})
	}

	// 2. SACK Permitted - if client supports it
	if clientSupportsSACK {
		options = append(options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
			OptionData:   nil,
		})
	}

	// 3. Timestamps - if client supports it
	if clientSupportsTimestamps {
		timestampData := make([]byte, 8)
		// Our timestamp (current time in milliseconds)
		serverTimestamp := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		binary.BigEndian.PutUint32(timestampData[0:4], serverTimestamp)
		// Echo client's timestamp
		binary.BigEndian.PutUint32(timestampData[4:8], clientTimestamp)

		options = append(options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   timestampData,
		})
	}

	// 4. Window Scale - if client supports it
	if clientSupportsWindowScale {
		// We'll use a scale factor of 7 (multiply by 128) to match common implementations
		scaleData := []byte{7} // Scale factor 7 = 128x multiplier
		options = append(options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   scaleData,
		})
	}

	// Add padding if necessary to align to 4-byte boundary
	optionsBytes := calculateTCPOptionsBytes(options)
	padding := (4 - (len(optionsBytes) % 4)) % 4
	for i := 0; i < padding; i++ {
		options = append(options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
			OptionData:   nil,
		})
	}

	return options
}

// calculateTCPOptionsBytes calculates the total bytes needed for TCP options
func calculateTCPOptionsBytes(options []layers.TCPOption) []byte {
	var optionsBytes []byte

	for _, option := range options {
		switch option.OptionType {
		case layers.TCPOptionKindNop:
			optionsBytes = append(optionsBytes, byte(option.OptionType))
		case layers.TCPOptionKindEndList:
			optionsBytes = append(optionsBytes, byte(option.OptionType))
		default:
			optionsBytes = append(optionsBytes, byte(option.OptionType))
			optionsBytes = append(optionsBytes, byte(option.OptionLength))
			if option.OptionData != nil {
				optionsBytes = append(optionsBytes, option.OptionData...)
			}
		}
	}

	return optionsBytes
}

// Alternative version with fixed common options (if you prefer simpler approach)
func SendSynAckWithFixedOptions(xsk *xdp.Socket, packet gopacket.Packet) {
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

	// Generate random sequence number
	rand.Seed(time.Now().UnixNano())
	serverSeq := rand.Uint32()

	// Create Ethernet layer
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	replyIP := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0,
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	// Create fixed TCP options for maximum compatibility
	tcpOptions := []layers.TCPOption{
		// MSS: 1460 bytes
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xB4}, // 1460 in big-endian
		},
		// SACK Permitted
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		// Timestamps
		{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   make([]byte, 8), // Will be filled with current timestamp
		},
		// NOP for padding
		{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
		},
		// Window Scale: factor 7 (128x)
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{7}, // Scale factor 7
		},
	}

	// Fill timestamp data
	currentTime := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
	binary.BigEndian.PutUint32(tcpOptions[2].OptionData[0:4], currentTime)
	// Echo timestamp from client SYN if available
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) >= 4 {
			clientTime := binary.BigEndian.Uint32(opt.OptionData[0:4])
			binary.BigEndian.PutUint32(tcpOptions[2].OptionData[4:8], clientTime)
			break
		}
	}

	// Create TCP layer with options
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        serverSeq,
		Ack:        tcp.Seq + 1,
		DataOffset: 8, // 20 bytes base + 20 bytes options = 40 bytes total / 4 = 10
		Window:     65535,
		Checksum:   0,
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
		Options:    tcpOptions,
	}

	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize and send
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP); err != nil {
		log.Printf("error serializing SYN-ACK packet: %v", err)
		return
	}

	reply := buf.Bytes()
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))
	xsk.Transmit([]xdp.Desc{txDesc})

	// log.Printf("Sent TCP SYN-ACK with options: %s:%d -> %s:%d, Seq=%d, Ack=%d",
	// 	replyIP.SrcIP, replyTCP.SrcPort,
	// 	replyIP.DstIP, replyTCP.DstPort,
	// 	replyTCP.Seq, replyTCP.Ack)
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
	// ip := ipLayer.(*layers.IPv4)

	// Validate this is an ACK packet (ACK=true, SYN=false, other flags=false)
	if !tcp.ACK || tcp.SYN || tcp.FIN || tcp.RST {
		// log.Printf("Received non-ACK packet: SYN=%v, ACK=%v, FIN=%v, RST=%v",
		// 	tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)
		return false
	}

	// log.Printf("TCP handshake completed: %s:%d -> %s:%d",
	// 	ip.SrcIP, tcp.SrcPort,
	// 	ip.DstIP, tcp.DstPort)

	// log.Printf("Final ACK received: Seq=%d, Ack=%d",
	// 	tcp.Seq, tcp.Ack)
	return true
}