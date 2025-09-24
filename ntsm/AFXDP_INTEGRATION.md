# AF_XDP Integration Guide

## 🚀 Overview

The TSM library now supports **automatic packet transmission** via a configurable transmitter interface. This allows you to plug in your AF_XDP transmission code directly into the TSM, eliminating the need to manually handle outbound packets.

## 🔧 How It Works

### 1. PacketTransmitter Interface

```go
type PacketTransmitter interface {
    SendPacket(packet []byte) error
}
```

### 2. TSM with Transmitter

```go
type TSM struct {
    connections map[ConnectionKey]*Connection
    transmitter PacketTransmitter // Optional packet transmitter
}
```

### 3. Automatic vs Manual Mode

- **Without Transmitter**: Functions return `[][]byte` for manual sending
- **With Transmitter**: Functions automatically send packets and return `nil` or fewer packets

## 📦 Integration Steps

### Step 1: Implement PacketTransmitter

```go
type YourAFXDPTransmitter struct {
    xsk *your_afxdp_type // Your AF_XDP socket
}

func (tx *YourAFXDPTransmitter) SendPacket(packet []byte) error {
    // Your existing AF_XDP transmission sequence:
    reply := packet // packet is already complete frame []byte

    // Get TX descriptor and copy packet data
    txDesc := tx.xsk.GetDescs(1, false)[0]
    copy(tx.xsk.GetFrame(txDesc), reply)
    txDesc.Len = uint32(len(reply))

    // Transmit the packet
    err := tx.xsk.Transmit([]sxdp.Desc{txDesc})
    if err != nil {
        return fmt.Errorf("AF_XDP transmission failed: %v", err)
    }
    
    return nil
}
```

### Step 2: Configure TSM

```go
// Create TSM with automatic transmission
tcpSM := tsm.NewTSM()
afxdpTx := &YourAFXDPTransmitter{xsk: yourSocket}
tcpSM.SetTransmitter(afxdpTx)
```

### Step 3: Use TSM Normally

```go
// All these functions now send packets automatically:
tcpSM.HandlePacket(packet)    // Responses sent via AF_XDP
tcpSM.SendData(conn, data)    // Data packets sent via AF_XDP  
tcpSM.Tick()                  // Retransmissions sent via AF_XDP
tcpSM.Connect(...)            // SYN sent via AF_XDP
tcpSM.CloseConnection(conn)   // FIN sent via AF_XDP
```

## 🔄 Complete AF_XDP Loop

```go
func main() {
    // Setup
    tcpSM := tsm.NewTSM()
    afxdpTx := &YourAFXDPTransmitter{xsk: yourSocket}
    tcpSM.SetTransmitter(afxdpTx)

    for {
        // Receive from AF_XDP RX ring
        rawPacket := receiveFromAFXDP()
        
        // Parse packet
        packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
        
        // Process with TSM - ALL responses automatically sent via AF_XDP!
        tcpSM.HandlePacket(packet)
        
        // Timer processing - retransmissions automatically sent via AF_XDP!
        tcpSM.Tick()
        
        // That's it! No manual packet transmission needed.
    }
}
```

## ⚡ Benefits

1. **Simplified Code**: No manual packet transmission loops
2. **Automatic Sending**: All TCP responses sent immediately
3. **Backward Compatible**: Works with or without transmitter
4. **Performance**: Direct integration eliminates packet copying
5. **Clean Architecture**: Separation of concerns

## 🔀 Mode Comparison

### Without Transmitter (Manual Mode)
```go
tcpSM := tsm.NewTSM()
packets := tcpSM.HandlePacket(packet)
for _, pkt := range packets {
    sendViaAFXDP(pkt) // Manual transmission
}
```

### With Transmitter (Automatic Mode)
```go
tcpSM := tsm.NewTSM()
tcpSM.SetTransmitter(afxdpTx)
tcpSM.HandlePacket(packet) // Automatic transmission!
```

## 🎯 Your Integration

Replace the placeholder in `afxdp_transmitter.go` with your actual code:

```go
func (tx *AFXDPTransmitter) SendPacket(packet []byte) error {
    // Replace this with your existing transmission sequence:
    reply := packet

    // Get TX descriptor and copy packet data  
    txDesc := tx.xsk.GetDescs(1, false)[0]
    copy(tx.xsk.GetFrame(txDesc), reply)
    txDesc.Len = uint32(len(reply))

    // Transmit the packet
    return tx.xsk.Transmit([]sxdp.Desc{txDesc})
}
```

## 📊 Function Behavior Changes

| Function | Without Transmitter | With Transmitter |
|----------|-------------------|------------------|
| `HandlePacket()` | Returns `[][]byte` packets | Returns `nil`, sends automatically |
| `SendData()` | Returns `[][]byte` packets | Returns `nil`, sends automatically |
| `Tick()` | Returns `[][]byte` packets | Returns `nil`, sends automatically |
| `Connect()` | Returns `(*Connection, [][]byte)` | Returns `(*Connection, nil)`, sends automatically |
| `CloseConnection()` | Returns `[][]byte` packets | Returns `nil`, sends automatically |

Your AF_XDP transmission code is now fully integrated into the TSM! 🎉
