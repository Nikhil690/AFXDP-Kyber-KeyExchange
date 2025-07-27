package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
	"xdp-example/crypto"
	"xdp-example/tsm"
	"xdp-example/xdp"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

// Global TCP state machine instance
var tcpStateMachine *tsm.TCPStateMachine
var ciphertextHandler *tsm.CiphertextHandler

// Initialize TCP state machine with your existing functions
func initializeTCPStateMachine(xsk *sxdp.Socket, privateKey kem.PrivateKey, scheme kem.Scheme) {
	tcpStateMachine = tsm.NewTCPStateMachine()

	// Initialize ciphertext handler
	ciphertextHandler = tsm.NewCiphertextHandler(privateKey, scheme)

	// Set up callbacks using your existing tsm functions
	tcpStateMachine.OnSendSynAck = func(conn *tsm.TCPConnection, packet gopacket.Packet) {
		// log.Printf("State machine: Sending SYN-ACK for connection %s:%d", conn.RemoteIP, conn.RemotePort)
		tsm.SendSynAck(xsk, packet) // Use your existing function

		// Update sequence numbers after sending SYN-ACK
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			conn.SendSeq = tcp.Ack
			conn.SendAck = tcp.Seq + 1
		}
	}

	tcpStateMachine.OnSendAck = func(conn *tsm.TCPConnection, packet gopacket.Packet) {
		// log.Printf("State machine: Sending ACK for connection %s:%d", conn.RemoteIP, conn.RemotePort)
		// Use your existing ACK function if you have one, or implement simple ACK
		if tsm.HandleAck != nil {
			tsm.HandleAck(xsk, nil, packet) // Call your existing HandleAck
		}
	}

	tcpStateMachine.OnSendFin = func(conn *tsm.TCPConnection, packet gopacket.Packet) {
		// log.Printf("State machine: Sending FIN for connection %s:%d", conn.RemoteIP, conn.RemotePort)
		// Use your existing FIN handling if available
		tsm.SendFinAck(xsk, packet) // Uncomment if you have this function
	}

	tcpStateMachine.OnEstablished = func(conn *tsm.TCPConnection) {
		// log.Printf("State machine: Connection ESTABLISHED: %s:%d -> %s:%d",
		// 	conn.RemoteIP, conn.RemotePort, conn.LocalIP, conn.LocalPort)

		// Store connection for later use in packet processing
		// The actual crypto.StartHello will be called in processPacketWithStateMachine
		// when we receive the ACK packet that establishes the connection
		// log.Printf("Connection established, waiting for ACK to send crypto hello")
	}

	tcpStateMachine.OnClosed = func(conn *tsm.TCPConnection) {
		// log.Printf("State machine: Connection CLOSED: %s:%d", conn.RemoteIP, conn.RemotePort)
		tcpStateMachine.CloseConnection(conn)
	}

	tcpStateMachine.OnDataReceived = func(conn *tsm.TCPConnection, data []byte) {
		// log.Printf("State machine: Data received on connection %s:%d, length: %d bytes",
		// 	conn.RemoteIP, conn.RemotePort, len(data))

		// This will be handled in the main packet processing loop
		// where we have access to the full packet
	}

	// Start cleanup routine for old connections
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			tcpStateMachine.CleanupOldConnections(30 * time.Minute)
		}
	}()

	// log.Printf("TCP State Machine and Ciphertext Handler initialized")
}

// Enhanced packet processing that integrates with your existing code
func processPacketWithStateMachine(xsk *sxdp.Socket, packet gopacket.Packet, pubkey kem.PublicKey) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp := tcpLayer.(*layers.TCP)

	// Process packet through state machine first
	conn := tcpStateMachine.ProcessPacket(packet)
	if conn == nil {
		return false
	}

	// Handle PSH+ACK packets with data (ciphertext)
	if tcp.PSH && tcp.ACK && len(tcp.Payload) > 0 {
		// log.Printf("📦 PSH+ACK received with %d bytes payload from %s:%d",
		// 	len(tcp.Payload), conn.RemoteIP, conn.RemotePort)
		return ciphertextHandler.HandlePshAckData(xsk, packet, conn)
	}

	// Handle your existing logic with state machine awareness
	if tcp.SYN && !tcp.ACK {
		// fmt.Printf("TCP syn received: %v\n", tcp.SYN)
		// State machine will handle SYN-ACK sending via callback
		return true

	} else if tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.PSH {
		// fmt.Printf("TCP ack received with seq: %d, state: %s\n", tcp.Seq, conn.GetState())

		// Check if this is the handshake completion ACK
		if conn.GetState() == tsm.ESTABLISHED && conn.ShouldSendHello() {
			// This is the initial handshake completion - send crypto hello
			log.Printf("Handshake completed, calling tsm.HandleAck and crypto.StartHello")
			if tsm.HandleAck(xsk, pubkey, packet) {
				log.Printf("tsm.HandleAck returned true, now sending crypto hello")
				crypto.StartHello(xsk, pubkey, packet)
				conn.MarkHelloSent()
				log.Printf("✅ Crypto hello sent for connection %s:%d", conn.RemoteIP, conn.RemotePort)
				return true
			} else {
				log.Printf("❌ tsm.HandleAck returned false, not sending crypto hello")
			}
		} else if conn.GetState() == tsm.ESTABLISHED && !conn.ShouldSendHello() {
			// This is a data ACK - don't send hello again
			log.Printf("Data ACK received for established connection - hello already sent: %s", conn.GetState())
			// Handle data ACK if needed
			tsm.HandleAck(xsk, pubkey, packet) // Your existing function
			return true
		} else {
			// Other ACK types (still in handshake, etc.)
			log.Printf("ACK received in state %s", conn.GetState())
			tsm.HandleAck(xsk, pubkey, packet) // Your existing function
			return true
		}

	} else if tcp.FIN {
		fmt.Printf("TCP fin received with seq: %v\n", packet)
		tsm.HandleFin(xsk, packet) // Your existing FIN handling
		return true
	}

	return false
}

func main() {
	var linkName string
	var queueID int
	var protocol int64

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link on which rebroadcast should run on.")
	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Int64Var(&protocol, "ip-proto", 0, "If greater than 0 and less than or equal to 255, limit xdp bpf_redirect_map to packets with the specified IP protocol number.")
	flag.Parse()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == linkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	var program *sxdp.Program

	// Create a new XDP eBPF program and attach it to our chosen network link.
	program, err = xdp.NewIPProtoProgram(uint32(protocol), nil)
	if err != nil {
		fmt.Printf("error: failed to create xdp program: %v\n", err)
		return
	}
	defer program.Close()
	if err := program.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer program.Detach(Ifindex)

	// Create and initialize an XDP socket attached to our chosen network
	// link.
	xsk, err := sxdp.NewSocket(Ifindex, queueID, &sxdp.SocketOptions{
		NumFrames:              128,
		FrameSize:              4096,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	})
	if err != nil {
		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
		return
	}

	// Register our XDP socket file descriptor with the eBPF program so it can be redirected packets
	if err := program.Register(queueID, xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer program.Unregister(queueID)

	// Initialize TCP state machine with crypto integration
	pubkey, privateKey := crypto.GenerateKeys() // Get both keys

	// Initialize TCP state machine with crypto parameters
	initializeTCPStateMachine(xsk, privateKey, kyber768.Scheme()) // Pass privateKey, scheme can be nil for now

	// log.Printf("Generated public key, length: %d bytes", len(pubkey))

	// Optional: Start stats monitoring in background
	// go showstats(xsk)

	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n, true))
		}

		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		// log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			rxDescs := xsk.Receive(numRx)
			for i := range rxDescs {
				desc := rxDescs[i]
				frame := xsk.GetFrame(desc)
				packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

				// Check if this is a TCP packet
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					continue // Skip non-TCP packets
				}

				// Process TCP packet with state machine integration
				if processPacketWithStateMachine(xsk, packet, pubkey) {
					// Packet was handled, continue to next packet
					continue
				}
			}
		}
	}
}

func showstats(xsk *sxdp.Socket) {
	var err error
	var stat sxdp.Stats
	for i := uint64(0); ; i++ {
		time.Sleep(time.Duration(1) * time.Second)
		stat, err = xsk.Stats()
		if err != nil {
			panic(err)
		}
		fmt.Println("---------------------------------------")
		fmt.Printf("Filled: %d\nReceived: %d\nTransmitted: %d\nCompleted: %d\nRx_dropped: %d\nRx_invalid_descs: %d\nTx_invalid_descs: %d\nRx_ring_full: %d\nRx_fill_ring_empty_descs: %d\nTx_ring_empty_descs: %d\n", stat.Filled, stat.Received, stat.Transmitted, stat.Completed, stat.KernelStats.Rx_dropped, stat.KernelStats.Rx_invalid_descs, stat.KernelStats.Tx_invalid_descs, stat.KernelStats.Rx_ring_full, stat.KernelStats.Rx_fill_ring_empty_descs, stat.KernelStats.Tx_ring_empty_descs)
		fmt.Println("---------------------------------------")
	}
}

func icmpEchoReply(numRx int, xsk *sxdp.Socket) {
	rxDescs := xsk.Receive(numRx)
	for i := range rxDescs {
		desc := rxDescs[i]
		frame := xsk.GetFrame(desc)

		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ethLayer == nil || ipLayer == nil || icmpLayer == nil {
			continue
		}

		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		icmp := icmpLayer.(*layers.ICMPv4)

		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
			continue
		}

		// Swap MAC
		eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC

		// Swap IPs
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP

		// Build ICMP Echo Reply
		icmp.TypeCode = layers.ICMPv4TypeEchoReply
		icmp.Checksum = 0 // recalculate

		// Serialize
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(buf, opts,
			eth, ip, icmp, gopacket.Payload(icmp.Payload))
		if err != nil {
			log.Printf("error serializing reply: %v", err)
			continue
		}

		reply := buf.Bytes()

		// Send reply
		txDesc := xsk.GetDescs(1, false)[0]
		copy(xsk.GetFrame(txDesc), reply)
		txDesc.Len = uint32(len(reply))

		xsk.Transmit([]sxdp.Desc{txDesc})
		log.Printf("Sent ICMP Echo Reply: %s", ip.DstIP)
	}
}
