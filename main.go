// // Copyright 2019 Asavie Technologies Ltd. All rights reserved.
// //
// // Use of this source code is governed by a BSD-style license
// // that can be found in the LICENSE file in the root of the source
// // tree.

// /*
// dumpframes demostrates how to receive frames from a network link using
// github.com/slavc/xdp package, it sets up an XDP socket attached to a
// particular network link and dumps all frames it receives to standard output.
// */
// package main

// import (
// 	"encoding/binary"
// 	"flag"
// 	"fmt"
// 	"log"
// 	"net"
// 	"time"
// 	"xdp-example/xdp"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	sxdp "github.com/slavc/xdp"
// )

// func main() {
// 	var linkName string
// 	var queueID int
// 	var protocol int64

// 	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

// 	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link on which rebroadcast should run on.")
// 	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
// 	flag.Int64Var(&protocol, "ip-proto", 0, "If greater than 0 and less than or equal to 255, limit xdp bpf_redirect_map to packets with the specified IP protocol number.")
// 	flag.Parse()

// 	interfaces, err := net.Interfaces()
// 	if err != nil {
// 		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
// 		return
// 	}

// 	Ifindex := -1
// 	for _, iface := range interfaces {
// 		if iface.Name == linkName {
// 			Ifindex = iface.Index
// 			break
// 		}
// 	}
// 	if Ifindex == -1 {
// 		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
// 		return
// 	}

// 	var program *sxdp.Program

// 	// Create a new XDP eBPF program and attach it to our chosen network link.
// 	if protocol == 0 {
// 		program, err = sxdp.NewProgram(queueID + 1)
// 	} else {
// 		program, err = xdp.NewIPProtoProgram(uint32(protocol), nil)
// 	}
// 	if err != nil {
// 		fmt.Printf("error: failed to create xdp program: %v\n", err)
// 		return
// 	}
// 	defer program.Close()
// 	if err := program.Attach(Ifindex); err != nil {
// 		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
// 		return
// 	}
// 	defer program.Detach(Ifindex)

// 	// Create and initialize an XDP socket attached to our chosen network
// 	// link.
// 	xsk, err := sxdp.NewSocket(Ifindex, queueID, nil)
// 	if err != nil {
// 		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
// 		return
// 	}

// 	// Register our XDP socket file descriptor with the eBPF program so it can be redirected packets
// 	if err := program.Register(queueID, xsk.FD()); err != nil {
// 		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
// 		return
// 	}
// 	defer program.Unregister(queueID)

// 	for {
// 		// If there are any free slots on the Fill queue...
// 		if n := xsk.NumFreeFillSlots(); n > 0 {
// 			// ...then fetch up to that number of not-in-use
// 			// descriptors and push them onto the Fill ring queue
// 			// for the kernel to fill them with the received
// 			// frames.
// 			xsk.Fill(xsk.GetDescs(n, true))
// 		}

// 		// Wait for receive - meaning the kernel has
// 		// produced one or more descriptors filled with a received
// 		// frame onto the Rx ring queue.
// 		// log.Printf("waiting for frame(s) to be received...")
// 		numRx, _, err := xsk.Poll(-1)
// 		if err != nil {
// 			fmt.Printf("error: %v\n", err)
// 			return
// 		}

// 		if numRx > 0 {
// 			// Consume the descriptors filled with received frames
// 			// from the Rx ring queue.
// 			icmpEchoReply(numRx, xsk)
// 		}
// 	}
// }

// func icmpEchoReply(numRx int, xsk *sxdp.Socket) {
// 	rxDescs := xsk.Receive(numRx)
// 	for i := range rxDescs {
// 		desc := rxDescs[i]
// 		frame := xsk.GetFrame(desc)

// 		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
// 		ethLayer := packet.Layer(layers.LayerTypeEthernet)
// 		ipLayer := packet.Layer(layers.LayerTypeIPv4)
// 		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

// 		if ethLayer == nil || ipLayer == nil || icmpLayer == nil {
// 			continue
// 		}

// 		eth := ethLayer.(*layers.Ethernet)
// 		ip := ipLayer.(*layers.IPv4)
// 		icmp := icmpLayer.(*layers.ICMPv4)

// 		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
// 			continue
// 		}

// 		// Swap MAC
// 		eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC

// 		// Swap IPs
// 		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP

// 		// Build ICMP Echo Reply
// 		icmp.TypeCode = layers.ICMPv4TypeEchoReply
// 		icmp.Checksum = 0 // recalculate

// 		// Serialize
// 		buf := gopacket.NewSerializeBuffer()
// 		opts := gopacket.SerializeOptions{
// 			FixLengths:       true,
// 			ComputeChecksums: true,
// 		}
// 		err := gopacket.SerializeLayers(buf, opts,
// 			eth, ip, icmp, gopacket.Payload(icmp.Payload))
// 		if err != nil {
// 			log.Printf("error serializing reply: %v", err)
// 			continue
// 		}

// 		reply := buf.Bytes()

// 		// Send reply
// 		txDesc := xsk.GetDescs(1, false)[0]
// 		copy(xsk.GetFrame(txDesc), reply)
// 		txDesc.Len = uint32(len(reply))

// 		xsk.Transmit([]sxdp.Desc{txDesc})
// 		// log.Printf("Sent ICMP Echo Reply: %s", ip.DstIP)
// 	}
// }

// // BuildICMPEchoPacket creates a complete Ethernet + IPv4 + ICMPv4 Echo Request packet.
// func BuildICMPEchoPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16, payload []byte) ([]byte, error) {
// 	eth := &layers.Ethernet{
// 		SrcMAC:       srcMAC,
// 		DstMAC:       dstMAC,
// 		EthernetType: layers.EthernetTypeIPv4,
// 	}

// 	ip := &layers.IPv4{
// 		Version:  4,
// 		IHL:      5,
// 		TOS:      0,
// 		Length:   0, // Will be calculated by Serialize
// 		Id:       0xabcd,
// 		Flags:    layers.IPv4DontFragment,
// 		TTL:      64,
// 		Protocol: layers.IPProtocolICMPv4,
// 		SrcIP:    srcIP,
// 		DstIP:    dstIP,
// 	}

// 	icmp := &layers.ICMPv4{
// 		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
// 		Id:       id,
// 		Seq:      seq,
// 	}

// 	// Add timestamp or any custom payload
// 	if payload == nil {
// 		payload = make([]byte, 32)
// 		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
// 	}

// 	buffer := gopacket.NewSerializeBuffer()
// 	opts := gopacket.SerializeOptions{
// 		FixLengths:       true,
// 		ComputeChecksums: true,
// 	}

// 	err := gopacket.SerializeLayers(buffer, opts,
// 		eth,
// 		ip,
// 		icmp,
// 		gopacket.Payload(payload),
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return buffer.Bytes(), nil
// }

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

func main() {
	var linkName, mode, dstIPStr string
	var queueID int
	var protocol int64

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link.")
	flag.StringVar(&mode, "mode", "response", "Mode: 'request' or 'response'")
	flag.StringVar(&dstIPStr, "dstip", "", "Destination IP (only for request mode)")
	flag.IntVar(&queueID, "queueid", 0, "Rx queue ID")
	flag.Int64Var(&protocol, "ip-proto", 0, "Optional IP protocol filter")
	flag.Parse()

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get interfaces: %v", err)
	}

	var iface net.Interface
	found := false
	for _, i := range ifaces {
		if i.Name == linkName {
			iface = i
			found = true
			break
		}
	}
	if !found {
		log.Fatalf("interface %s not found", linkName)
	}

	ifindex := iface.Index
	program, err := sxdp.NewProgram(queueID + 1)
	if err != nil {
		log.Fatalf("failed to create XDP program: %v", err)
	}
	defer program.Close()

	if err := program.Attach(ifindex); err != nil {
		log.Fatalf("failed to attach program: %v", err)
	}
	defer program.Detach(ifindex)

	xsk, err := sxdp.NewSocket(ifindex, queueID, nil)
	if err != nil {
		log.Fatalf("failed to create XDP socket: %v", err)
	}

	if err := program.Register(queueID, xsk.FD()); err != nil {
		log.Fatalf("failed to register socket in map: %v", err)
	}
	defer program.Unregister(queueID)

	if mode == "request" {
		sendICMPEchoRequest(xsk, iface.HardwareAddr, dstIPStr)
		return
	}

	for {
		if n := xsk.NumFreeFillSlots(); n > 0 {
			xsk.Fill(xsk.GetDescs(n, true))
		}
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			log.Fatalf("poll error: %v", err)
		}
		if numRx > 0 {
			icmpEchoReply(numRx, xsk)
		}
	}
}

func sendICMPEchoRequest(xsk *sxdp.Socket, srcMAC net.HardwareAddr, dstIPStr string) {
	dstIP := net.ParseIP(dstIPStr).To4()
	if dstIP == nil {
		log.Fatalf("invalid destination IP: %s", dstIPStr)
	}

	// Dummy ARP lookup or hardcoded test MAC for now
	dstMAC, _ := net.ParseMAC("ea:f5:44:31:b4:c2") //NOTE: Replace with dynamic MAC of the destination

	srcIP := net.IPv4(10, 11, 1, 1) //NOTE: Replace with IP of the interface manually or lookup
	id := uint16(1234)
	seq := uint16(1)

	packet, err := BuildICMPEchoPacket(srcMAC, dstMAC, srcIP, dstIP, id, seq, nil)
	if err != nil {
		log.Fatalf("failed to build ICMP request: %v", err)
	}

	desc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(desc), packet)
	desc.Len = uint32(len(packet))
	if err := xsk.Transmit([]sxdp.Desc{desc}); err == 0 {
		log.Printf("transmit error: %v", err)
	}
	printpacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	log.Printf("Sent ICMP Echo Request to %s with SrcIP %s \n %v", dstIPStr, srcIP, printpacket)
	start := time.Now()
	timeout := 3 * time.Second

	for {
		if time.Since(start) > timeout {
			log.Println("Timed out waiting for ICMP Echo Reply.")
			return
		}

		if n := xsk.NumFreeFillSlots(); n > 0 {
			xsk.Fill(xsk.GetDescs(n, false))
		}

		numRx, _, err := xsk.Poll(1) // 1us timeout
		if err != nil {
			log.Printf("poll error: %v", err)
			continue
		}

		if numRx == 0 {
			continue
		}

		rxDescs := xsk.Receive(numRx)
		for _, desc := range rxDescs {
			frame := xsk.GetFrame(desc)
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if ipLayer == nil || icmpLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			icmp := icmpLayer.(*layers.ICMPv4)

			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
				ip.SrcIP.Equal(dstIP) && icmp.Id == id && icmp.Seq == seq {
				rtt := time.Since(start)
				log.Printf("Received ICMP Echo Reply from %s in %v", ip.SrcIP, rtt)
				return
			}
		}
	}
}

func icmpEchoReply(numRx int, xsk *sxdp.Socket) {
	rxDescs := xsk.Receive(numRx)
	for i := range rxDescs {
		desc := rxDescs[i]
		frame := xsk.GetFrame(desc)

		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Println(packet)
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

		eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
		icmp.TypeCode = layers.ICMPv4TypeEchoReply
		icmp.Checksum = 0

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(icmp.Payload))
		if err != nil {
			log.Printf("serialization error: %v", err)
			continue
		}

		reply := buf.Bytes()
		txDesc := xsk.GetDescs(1, false)[0]
		copy(xsk.GetFrame(txDesc), reply)
		txDesc.Len = uint32(len(reply))
		xsk.Transmit([]sxdp.Desc{txDesc})

		log.Printf("Send ICMP Echo Reponse to %s", ip.DstIP)
	}
}

func BuildICMPEchoPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4,
		SrcIP: srcIP, DstIP: dstIP, Flags: layers.IPv4DontFragment,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       id, Seq: seq,
	}
	if payload == nil {
		payload = make([]byte, 32)
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload))
	return buf.Bytes(), err
}
