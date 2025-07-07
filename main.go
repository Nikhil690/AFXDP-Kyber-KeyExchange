// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
dumpframes demostrates how to receive frames from a network link using
github.com/slavc/xdp package, it sets up an XDP socket attached to a
particular network link and dumps all frames it receives to standard output.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"xdp-example/xdp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

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
	if protocol == 0 {
		program, err = sxdp.NewProgram(queueID + 1)
	} else {
		program, err = xdp.NewIPProtoProgram(uint32(protocol), nil)
	}
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
	xsk, err := sxdp.NewSocket(Ifindex, queueID, nil)
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
		log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)
			for i := 0; i < len(rxDescs); i++ {
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
	}
}
