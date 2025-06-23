package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
    // "unsafe"

    "github.com/slavc/xdp"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    // "golang.org/x/sys/unix"
)

const (
    STAT_RX_PACKETS = 0
    STAT_TX_PACKETS = 1
    STAT_UDP_PACKETS = 2
    STAT_TCP_PACKETS = 3
    
    FRAME_SIZE = 2048
    NUM_FRAMES = 4096
)

type PacketProcessor struct {
    xdpObjs    *xdpObjects
    xdpLink    link.Link
    xdpSocket  *xdp.Socket
    interfaceName string
}

func NewPacketProcessor(interfaceName string) (*PacketProcessor, error) {
    // Remove memory limit for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("removing memlock: %v", err)
    }

    // Load eBPF program
    spec, err := loadXdp()
    if err != nil {
        return nil, fmt.Errorf("loading eBPF spec: %v", err)
    }

    objs := xdpObjects{}
    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        return nil, fmt.Errorf("loading eBPF objects: %v", err)
    }

    return &PacketProcessor{
        xdpObjs:       &objs,
        interfaceName: interfaceName,
    }, nil
}

func (p *PacketProcessor) Start() error {
    // Get network interface
    iface, err := net.InterfaceByName(p.interfaceName)
    if err != nil {
        return fmt.Errorf("getting interface %s: %v", p.interfaceName, err)
    }

    // Create AF_XDP socket
    p.xdpSocket, err = xdp.NewSocket(iface.Index, 0, &xdp.SocketOptions{
        NumFrames:              NUM_FRAMES,
        FrameSize:             FRAME_SIZE,
        FillRingNumDescs:      2048,
        CompletionRingNumDescs: 2048,
        RxRingNumDescs:        2048,
        TxRingNumDescs:        2048,
    })
    if err != nil {
        return fmt.Errorf("creating XDP socket: %v", err)
    }

    // Update XSK map with socket FD
    key := uint32(0)
    value := uint32(p.xdpSocket.FD())
	println("Updating xsks_map with key:", key, "value:", value)
    if err := p.xdpObjs.XsksMap.Update(key, value, ebpf.UpdateAny); err != nil {
        return fmt.Errorf("updating xsks_map: %v", err)
    }

    // Attach XDP program to interface
    p.xdpLink, err = link.AttachXDP(link.XDPOptions{
        Program:   p.xdpObjs.XdpSockProg,
        Interface: iface.Index,
    })
    if err != nil {
        return fmt.Errorf("attaching XDP program: %v", err)
    }

    fmt.Printf("XDP program attached to interface %s\n", p.interfaceName)
    return nil
}

func (p *PacketProcessor) ProcessPackets(ctx context.Context) {
    fmt.Println("Starting packet processing...")
    
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            p.printStats()
        default:
            // Process incoming packets
            if p.xdpSocket != nil {
                p.receivePackets()
            } else {
                log.Println("XDP socket is nil, cannot receive packets")
            }
        }
    }
}
func (p *PacketProcessor) receivePackets() {
    // Get received packets
    rxDescs := p.xdpSocket.Receive(100)  // Receive up to 100 packets

    if len(rxDescs) > 0 {
        log.Printf("Received %d packets", len(rxDescs))
    }

    for i := 0; i < len(rxDescs); i++ {
        // Get packet data
        pktData := p.xdpSocket.GetFrame(rxDescs[i])

        // Process packet (simple example - just print packet size)
        if len(pktData) > 0 {
            log.Printf("Processing packet %d: size=%d", i, len(pktData))
            p.processPacket(pktData)
        } else {
            log.Printf("Received empty packet at index %d", i)
        }
    }

    // Return frames to fill ring for reuse
    if len(rxDescs) > 0 {
        log.Printf("Returning %d frames to fill ring", len(rxDescs))
        p.xdpSocket.Fill(rxDescs)
    }
}

func (p *PacketProcessor) processPacket(data []byte) {
    // Simple packet processing - you can add your custom logic here
    if len(data) >= 14 { // At least Ethernet header
        // Extract Ethernet header
        ethType := uint16(data[12])<<8 | uint16(data[13])
        
        if ethType == 0x0800 && len(data) >= 34 { // IPv4
            // Extract IP header info
            protocol := data[23]
            srcIP := net.IPv4(data[26], data[27], data[28], data[29])
            dstIP := net.IPv4(data[30], data[31], data[32], data[33])
            
            fmt.Printf("Packet: %s -> %s, Protocol: %d, Size: %d\n", 
                srcIP, dstIP, protocol, len(data))
        }
    }
}

func (p *PacketProcessor) printStats() {
    stats := []string{"RX", "TX", "UDP", "TCP"}
    
    fmt.Print("Stats: ")
    for i, name := range stats {
        key := uint32(i)
        var count uint64
        if err := p.xdpObjs.StatsMap.Lookup(key, &count); err == nil {
            fmt.Printf("%s: %d ", name, count)
        }
    }
    fmt.Println()
}

func (p *PacketProcessor) Close() {
    if p.xdpSocket != nil {
        p.xdpSocket.Close()
    }
    if p.xdpLink != nil {
        p.xdpLink.Close()
    }
    if p.xdpObjs != nil {
        p.xdpObjs.Close()
    }
}

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintf(os.Stderr, "Usage: %s <interface>\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "Example: sudo %s eth0\n", os.Args[0])
        os.Exit(1)
    }

    interfaceName := os.Args[1]

    // Check if running as root
    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root")
    }

    // Create packet processor
    processor, err := NewPacketProcessor(interfaceName)
    if err != nil {
        log.Fatalf("Creating packet processor: %v", err)
    }
    defer processor.Close()

    // Start packet processing
    if err := processor.Start(); err != nil {
        log.Fatalf("Starting packet processor: %v", err)
    }

    // Handle graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        fmt.Println("\nShutting down...")
        cancel()
    }()

    // Process packets
    processor.ProcessPackets(ctx)
    fmt.Println("Program terminated")
}