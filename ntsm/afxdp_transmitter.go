package ntsm

import (
	"fmt"

	"github.com/slavc/xdp"
)

// // SendPacket implements PacketTransmitter interface for AF_XDP
func sendPacket(packet []byte, xsk *xdp.Socket) error {
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), packet)
	txDesc.Len = uint32(len(packet))
	nsum := xsk.Transmit([]xdp.Desc{txDesc})
	if nsum == 0 {
		return fmt.Errorf("AF_XDP transmission failed: transmitted %d packets", nsum)
	}
	return nil
}

// // Example integration with your AF_XDP code:
// /*
// func (tx *AFXDPTransmitter) SendPacket(packet []byte) error {
// 	// Your existing AF_XDP transmission sequence:
// 	reply := packet  // packet is already []byte

// 	// Get TX descriptor and copy packet data
// 	txDesc := tx.xsk.GetDescs(1, false)[0]
// 	copy(tx.xsk.GetFrame(txDesc), reply)
// 	txDesc.Len = uint32(len(reply))

// 	// Transmit the packet
// 	err := tx.xsk.Transmit([]sxdp.Desc{txDesc})
// 	if err != nil {
// 		return fmt.Errorf("AF_XDP transmission failed: %v", err)
// 	}

// 	return nil
// }
// */

// // Usage example:
// /*
// func main() {
// 	// Create TSM with AF_XDP transmitter
// 	tsm := NewTSM()
// 	afxdpTx := NewAFXDPTransmitter()
// 	tsm.SetTransmitter(afxdpTx)

// 	// Now all packet transmission is automatic
// 	for {
// 		// Receive packet from AF_XDP RX ring
// 		rawPacket := receiveFromAFXDP()

// 		// Parse and process with TSM
// 		packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
// 		tsm.HandlePacket(packet) // Automatically sends responses via AF_XDP

// 		// Timer processing also sends automatically
// 		tsm.Tick()
// 	}
// }
// */
