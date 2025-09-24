# TCP State Machine (TSM) Library

A Go library that provides a complete **TCP State Machine** for managing TCP connections at the **packet level**. This library handles TCP protocol logic, state transitions, segmentation, reassembly, and acknowledgments without relying on the kernel's TCP stack.

## 🚀 Features

- **Complete TCP State Machine**: Implements all TCP states (CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN states, TIME-WAIT, etc.)
- **Packet-level Processing**: Consumes decoded TCP packets and produces raw outbound packets
- **Segmentation & Reassembly**: Handles data segmentation into MSS-sized chunks and reassembles out-of-order segments
- **Reliable Transmission**: Implements acknowledgments, retransmissions, and duplicate ACK detection
- **Timer Management**: Provides retransmission timers and TIME-WAIT handling
- **Thread-safe**: All connection operations are properly synchronized
- **AF_XDP Ready**: Designed to work with AF_XDP socket implementations

## 📦 Installation

```bash
go get github.com/pivot/tsm
```

## 🎯 Core API

### Main Functions

```go
// Process inbound packet, update state machine, return outbound packets
func (tsm *TSM) HandlePacket(pkt gopacket.Packet) [][]byte

// Segment payload into TCP packets, update sequence numbers
func (tsm *TSM) SendData(conn *Connection, data []byte) [][]byte

// Deliver reassembled application data from buffered segments
func (conn *Connection) ReadData() ([]byte, error)

// Process timer events and return retransmission packets
func (tsm *TSM) Tick() [][]byte

// Initiate outbound connection
func (tsm *TSM) Connect(localIP, remoteIP net.IP, localPort, remotePort uint16) (*Connection, [][]byte)

// Close connection gracefully
func (tsm *TSM) CloseConnection(conn *Connection) [][]byte
```

## 🏗️ Architecture

### Core Components

1. **TSM (TCP State Machine)**: Main controller managing multiple connections
2. **Connection**: Per-connection control block with state, buffers, and timers
3. **Packet Processing**: Raw packet parsing and construction
4. **State Management**: TCP state transitions and protocol handling
5. **Timer System**: Retransmission and connection lifecycle timers

### Connection States

The library implements the full TCP state machine:

```
CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
       ↘ SYN_SENT → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED
```

## 🔧 Usage Examples

### Basic Usage

```go
package main

import (
    "github.com/pivot/tsm"
    "github.com/google/gopacket"
)

func main() {
    // Create TCP State Machine
    tcpSM := tsm.NewTSM()
    
    // Create outbound connection
    localIP := net.ParseIP("192.168.1.100")
    remoteIP := net.ParseIP("192.168.1.200")
    conn, synPackets := tcpSM.Connect(localIP, remoteIP, 12345, 80)
    
    // Send SYN packet via your transmission method
    for _, packet := range synPackets {
        sendPacket(packet) // Your TX implementation
    }
    
    // Process incoming packets
    for {
        packet := receivePacket() // Your RX implementation
        goPacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
        
        responses := tcpSM.HandlePacket(goPacket)
        for _, response := range responses {
            sendPacket(response)
        }
        
        // Process timers periodically
        timerPackets := tcpSM.Tick()
        for _, packet := range timerPackets {
            sendPacket(packet)
        }
    }
}
```

### Sending Data

```go
// Send application data
data := []byte("Hello, TCP!")
dataPackets := tcpSM.SendData(conn, data)

for _, packet := range dataPackets {
    sendPacket(packet)
}
```

### Receiving Data

```go
// Read reassembled data from connection
data, err := conn.ReadData()
if err == nil && len(data) > 0 {
    processApplicationData(data)
}
```

### AF_XDP Integration Example

```go
func runAFXDPLoop(tcpSM *tsm.TSM) {
    for {
        // Receive from AF_XDP RX ring
        rawPacket := receiveFromAFXDP()
        
        // Parse packet
        packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
        
        // Process with TSM
        outboundPackets := tcpSM.HandlePacket(packet)
        
        // Send responses via AF_XDP TX ring
        for _, pkt := range outboundPackets {
            sendViaAFXDP(pkt)
        }
        
        // Process timers
        timerPackets := tcpSM.Tick()
        for _, pkt := range timerPackets {
            sendViaAFXDP(pkt)
        }
    }
}
```

## 📊 Connection State Management

### Connection Control Block

Each connection maintains:

- **Sequence Space**: ISS, SND_UNA, SND_NXT, SND_WND, IRS, RCV_NXT, RCV_WND
- **State**: Current TCP state
- **Buffers**: Send buffer, receive buffer, reassembled data
- **Timers**: Retransmission timer with RTT estimation
- **Congestion Control**: Basic congestion window management
- **Window Management**: Flow control implementation

### State Transitions

The library correctly handles all TCP state transitions:

- **Connection Establishment**: 3-way handshake (SYN → SYN+ACK → ACK)
- **Data Transfer**: Reliable data transmission with acknowledgments
- **Connection Termination**: 4-way handshake (FIN → ACK → FIN → ACK)
- **Error Handling**: RST processing and timeout handling

## ⚙️ Configuration

### Maximum Segment Size (MSS)

```go
conn.MSS = 1460 // Set custom MSS
```

### Retransmission Timeout (RTO)

```go
conn.RetransTimer.RTO = time.Second * 2 // Custom RTO
```

### Receive Window

```go
conn.Seq.RCV_WND = 32768 // Custom receive window
```

## 🔄 Timer Management

The library provides timer hooks that you must call periodically:

```go
// Call this periodically (e.g., every 100ms)
timerPackets := tcpSM.Tick()
for _, packet := range timerPackets {
    sendPacket(packet)
}
```

Timers handle:
- **Retransmission**: Unacknowledged data retransmission
- **TIME_WAIT**: 2MSL timer for connection cleanup
- **RTT Estimation**: Round-trip time measurement and RTO calculation

## 🧪 Testing

Run the example:

```bash
cd example
go run main.go
```

## 🏗️ Integration Notes

### With AF_XDP

1. Your AF_XDP receiver extracts TCP packets using `gopacket`
2. Pass packets to `tsm.HandlePacket()`
3. TSM returns outbound packets as raw `[]byte`
4. Copy returned packets to AF_XDP TX ring and transmit

### Packet Flow

```
AF_XDP RX → gopacket.Parse → TSM.HandlePacket → TSM.SendData → AF_XDP TX
     ↑                                                              ↓
     └─────────────── TSM.Tick (timers) ──────────────────────────┘
```

## 🔧 Extensibility

The library is designed to be modular and extensible:

- **Custom Congestion Control**: Modify `CwndSize` and `SSThresh` management
- **Custom Timers**: Extend timer functionality
- **Custom Options**: Add TCP option parsing and generation
- **Performance Tuning**: Adjust buffer sizes and thresholds

## 📋 Requirements

- Go 1.21+
- `github.com/google/gopacket` for packet parsing
- User-provided AF_XDP socket setup and ring management

## ⚠️ Constraints

- Does NOT handle AF_XDP socket setup, RX/TX rings, or polling
- Does NOT use `net.TCPConn` or kernel TCP stack  
- All TCP logic is implemented in userland
- Thread-safe for concurrent access to different connections
- Single-threaded access recommended per connection for optimal performance

## 📝 License

This library is provided as-is for educational and development purposes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and enhancement requests.

---

**Note**: This library provides the TCP protocol logic only. You are responsible for:
- AF_XDP socket setup and management
- Packet reception and transmission
- Integration with your network stack
- Performance optimization for your specific use case
