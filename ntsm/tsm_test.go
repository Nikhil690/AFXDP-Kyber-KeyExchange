package ntsm

import (
	"net"
	"testing"
	"time"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
)

func TestXsk(t *testing.T) {
	linkName := "afxdp"
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

	xsk, err := xdp.NewSocket(Ifindex, 0, &xdp.SocketOptions{
		NumFrames:              128,
		FrameSize:              4096,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	})
	if err != nil {
		t.Fatalf("Failed to create AF_XDP socket: %v", err)
	}
	tsm := NewTSM()
	tsm.xsk = xsk
	time.Sleep(2 * time.Second)
}

func TestTSMCreation(t *testing.T) {
	tsm := NewTSM()
	if tsm == nil {
		t.Fatal("TSM creation failed")
	}
	if tsm.connections == nil {
		t.Fatal("TSM connections map not initialized")
	}
}

func TestConnectionCreation(t *testing.T) {
	localIP := net.ParseIP("192.168.1.100")
	remoteIP := net.ParseIP("192.168.1.200")
	key := NewConnectionKey(localIP, 12345, remoteIP, 80)

	conn := NewConnection(key, false)
	if conn == nil {
		t.Fatal("Connection creation failed")
	}
	if conn.State != CLOSED {
		t.Errorf("Expected CLOSED state, got %s", conn.State.String())
	}
	if conn.MSS != 1460 {
		t.Errorf("Expected MSS 1460, got %d", conn.MSS)
	}
}

func TestConnect(t *testing.T) {
	tsm := NewTSM()
	localIP := net.ParseIP("192.168.1.100")
	remoteIP := net.ParseIP("192.168.1.200")

	conn, packets := tsm.Connect(localIP, remoteIP, 12345, 80)

	if conn == nil {
		t.Fatal("Connect returned nil connection")
	}
	if conn.State != SYN_SENT {
		t.Errorf("Expected SYN_SENT state, got %s", conn.State.String())
	}
	if len(packets) != 1 {
		t.Errorf("Expected 1 SYN packet, got %d", len(packets))
	}
}

func TestStateTransitions(t *testing.T) {
	tests := []struct {
		name     string
		state    TCPState
		canSend  bool
		canRecv  bool
		isClosed bool
	}{
		{"CLOSED", CLOSED, false, false, true},
		{"LISTEN", LISTEN, false, false, false},
		{"SYN_SENT", SYN_SENT, false, false, false},
		{"SYN_RECEIVED", SYN_RECEIVED, false, false, false},
		{"ESTABLISHED", ESTABLISHED, true, true, false},
		{"FIN_WAIT_1", FIN_WAIT_1, false, true, false},
		{"FIN_WAIT_2", FIN_WAIT_2, false, true, false},
		{"CLOSE_WAIT", CLOSE_WAIT, true, false, false},
		{"CLOSING", CLOSING, false, false, false},
		{"LAST_ACK", LAST_ACK, false, false, false},
		{"TIME_WAIT", TIME_WAIT, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.state.CanSendData() != tt.canSend {
				t.Errorf("State %s: expected CanSendData=%v, got %v",
					tt.state.String(), tt.canSend, tt.state.CanSendData())
			}
			if tt.state.CanReceiveData() != tt.canRecv {
				t.Errorf("State %s: expected CanReceiveData=%v, got %v",
					tt.state.String(), tt.canRecv, tt.state.CanReceiveData())
			}
			if tt.state.IsClosedState() != tt.isClosed {
				t.Errorf("State %s: expected IsClosedState=%v, got %v",
					tt.state.String(), tt.isClosed, tt.state.IsClosedState())
			}
		})
	}
}

func TestPacketBuilding(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.200")

	packet := BuildTCPPacket(srcIP, dstIP, 12345, 80, 1000, 2000, SYN|ACK, 65535, nil, nil)

	if len(packet) < 40 { // Minimum IP + TCP header size
		t.Errorf("Packet too small: %d bytes", len(packet))
	}

	// Parse and verify the packet
	goPacket := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := goPacket.Layer(layers.LayerTypeIPv4)
	tcpLayer := goPacket.Layer(layers.LayerTypeTCP)

	if ipLayer == nil {
		t.Fatal("IP layer not found in built packet")
	}
	if tcpLayer == nil {
		t.Fatal("TCP layer not found in built packet")
	}

	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)

	if !ip.SrcIP.Equal(srcIP) {
		t.Errorf("Expected src IP %s, got %s", srcIP, ip.SrcIP)
	}
	if !ip.DstIP.Equal(dstIP) {
		t.Errorf("Expected dst IP %s, got %s", dstIP, ip.DstIP)
	}
	if tcp.SrcPort != 12345 {
		t.Errorf("Expected src port 12345, got %d", tcp.SrcPort)
	}
	if tcp.DstPort != 80 {
		t.Errorf("Expected dst port 80, got %d", tcp.DstPort)
	}
}

func TestRetransmissionTimer(t *testing.T) {
	timer := NewRetransmissionTimer()

	if timer.Active {
		t.Error("Timer should not be active initially")
	}
	if timer.IsExpired() {
		t.Error("Timer should not be expired initially")
	}

	timer.Start()
	if !timer.Active {
		t.Error("Timer should be active after Start()")
	}

	// Test RTT update
	timer.UpdateRTT(100 * time.Millisecond)
	if timer.SRTT == 0 {
		t.Error("SRTT should be set after UpdateRTT")
	}
	if timer.RTO < time.Millisecond*200 {
		t.Error("RTO should be at least 200ms")
	}

	timer.Stop()
	if timer.Active {
		t.Error("Timer should not be active after Stop()")
	}
}

func TestDataSegmentation(t *testing.T) {
	tsm := NewTSM()
	localIP := net.ParseIP("192.168.1.100")
	remoteIP := net.ParseIP("192.168.1.200")
	key := NewConnectionKey(localIP, 12345, remoteIP, 80)

	conn := NewConnection(key, false)
	conn.State = ESTABLISHED
	conn.Seq.SND_NXT = 1000
	conn.Seq.SND_UNA = 1000
	conn.Seq.SND_WND = 65535
	conn.MSS = 100 // Small MSS for testing

	// Send data larger than MSS
	data := make([]byte, 250) // 2.5 segments
	for i := range data {
		data[i] = byte(i % 256)
	}

	packets := tsm.SendData(conn, data)

	// Should generate 3 packets (100 + 100 + 50 bytes)
	if len(packets) != 3 {
		t.Errorf("Expected 3 packets, got %d", len(packets))
	}

	// Verify sequence numbers advanced
	expectedSeq := uint32(1000 + len(data))
	if conn.Seq.SND_NXT != expectedSeq {
		t.Errorf("Expected SND_NXT %d, got %d", expectedSeq, conn.Seq.SND_NXT)
	}
}

func TestSequenceValidation(t *testing.T) {
	tests := []struct {
		seq    uint32
		rcvNxt uint32
		rcvWnd uint32
		valid  bool
	}{
		{1000, 1000, 1000, true},  // At start of window
		{1500, 1000, 1000, true},  // Middle of window
		{1999, 1000, 1000, true},  // End of window
		{2000, 1000, 1000, false}, // Past window
		{999, 1000, 1000, false},  // Before window
		{1000, 1000, 0, true},     // Zero window, exact match
		{1001, 1000, 0, false},    // Zero window, no match
	}

	for _, tt := range tests {
		result := IsValidSequence(tt.seq, tt.rcvNxt, tt.rcvWnd)
		if result != tt.valid {
			t.Errorf("IsValidSequence(%d, %d, %d) = %v, want %v",
				tt.seq, tt.rcvNxt, tt.rcvWnd, result, tt.valid)
		}
	}
}

func TestConnectionKey(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.200")

	key1 := NewConnectionKey(ip1, 12345, ip2, 80)
	key2 := NewConnectionKey(ip1, 12345, ip2, 80)
	key3 := NewConnectionKey(ip1, 12346, ip2, 80) // Different port

	// Test map usage (keys should be comparable)
	m := make(map[ConnectionKey]int)
	m[key1] = 1
	m[key2] = 2 // Should overwrite key1
	m[key3] = 3

	if len(m) != 2 {
		t.Errorf("Expected 2 unique keys, got %d", len(m))
	}
	if m[key1] != 2 {
		t.Errorf("key1 should have value 2, got %d", m[key1])
	}
	if m[key3] != 3 {
		t.Errorf("key3 should have value 3, got %d", m[key3])
	}
}

// Benchmark tests
func BenchmarkPacketBuilding(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.200")
	data := make([]byte, 1460)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildTCPPacket(srcIP, dstIP, 12345, 80, 1000, 2000, ACK, 65535, data, nil)
	}
}

func BenchmarkTSMHandlePacket(b *testing.B) {
	tsm := NewTSM()

	// Create a test packet
	packet := createTestPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tsm.HandlePacket(packet)
	}
}

func createTestPacket() gopacket.Packet {
	// Create a simple ACK packet for benchmarking
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.200"),
		DstIP:    net.ParseIP("192.168.1.100"),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: 80,
		DstPort: 12345,
		Seq:     1000,
		Ack:     2000,
		ACK:     true,
		Window:  65535,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
