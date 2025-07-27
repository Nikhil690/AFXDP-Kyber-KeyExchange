package tsm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)
// processCiphertext extracts and processes ciphertext from the payload
func (ch *CiphertextHandler) processCiphertext(conn *TCPConnection, payload string) bool {
	// Find the ciphertext in the payload
	ciphertextStart := strings.Index(payload, MSG_CIPHERTEXT+":")
	if ciphertextStart == -1 {
		log.Printf("❌ CIPHERTEXT marker not found in payload")
		return false
	}

	// Extract everything after "CIPHERTEXT:"
	ciphertextPart := payload[ciphertextStart+len(MSG_CIPHERTEXT)+1:]

	// Clean up the ciphertext (remove HTTP headers, newlines, etc.)
	lines := strings.Split(ciphertextPart, "\n")
	var ciphertextHex string
	for _, line := range lines {
		cleaned := strings.TrimSpace(line)
		if len(cleaned) > 0 && isHexString(cleaned) {
			ciphertextHex += cleaned
		}
	}

	if len(ciphertextHex) == 0 {
		log.Printf("❌ No valid hex ciphertext found")
		return false
	}

	// log.Printf("🔍 Extracted ciphertext hex (%d chars)", len(ciphertextHex))

	// Parse the ciphertext
	if len(ciphertextHex) < 10 { // Minimum reasonable length
		log.Printf("❌ Invalid ciphertext format - too short (%d chars)", len(ciphertextHex))
		return false
	}

	// Decode hex string to bytes
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		log.Printf("❌ Failed to decode ciphertext hex: %v", err)
		return false
	}

	// log.Printf("✅ Successfully decoded ciphertext: %d bytes", len(ciphertext))

	// Process the ciphertext using your crypto scheme
	return ch.decapsulateSharedSecret(conn, ciphertext)
}

// decapsulateSharedSecret performs the decapsulation using your crypto scheme
func (ch *CiphertextHandler) decapsulateSharedSecret(conn *TCPConnection, ciphertext []byte) bool {
	// log.Printf("🔓 SERVER: Decapsulating shared secret for connection %s:%d...", conn.RemoteIP, conn.RemotePort)
	// Step 4: Decapsulate to get shared secret using your crypto scheme
	// Replace this interface{} cast with your actual scheme type
	if ch.scheme == nil {
		log.Printf("❌ Crypto scheme not initialized")
		return false
	}

	// TODO: Uncomment and modify this section to use your actual crypto library
	// Example integration with your crypto library:
	sharedSecret, err := ch.scheme.Decapsulate(ch.privateKey, ciphertext)
	if err != nil {
		log.Printf("❌ Failed to decapsulate: %v", err)
		return false
	}

	// TEMPORARY: For testing purposes - replace with actual decapsulation
	// This simulates successful decapsulation
	// sharedSecret := make([]byte, 32)
	// copy(sharedSecret, ciphertext[:min(32, len(ciphertext))])

	// Hash the shared secret to get a symmetric key (your exact logic)
	hash := sha256.Sum256(sharedSecret)
	symmetricKey := hash[:]

	// Store the cipher connection state
	connKey := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
	ch.connections[connKey] = &CipherConnection{
		SharedSecret:   sharedSecret,
		SymmetricKey:   symmetricKey,
		CipherReceived: true,
	}

	// fmt.Printf("🔑 SERVER: Shared secret established! (32 bytes)\n")
	// fmt.Printf("🔑 SERVER: Symmetric key: %s...\n", hex.EncodeToString(symmetricKey)[:16])

	return true
}

// sendAckResponse sends an ACK response to acknowledge data receipt
func (ch *CiphertextHandler) sendAckResponse(xsk *sxdp.Socket, packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Create ACK response
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: eth.EthernetType,
	}

	replyIP := &layers.IPv4{
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     0,
		Id:         ip.Id + 1,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Protocol:   ip.Protocol,
		Checksum:   0,
		SrcIP:      ip.DstIP,
		DstIP:      ip.SrcIP,
	}

	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        tcp.Ack,                            // Our seq = their ack
		Ack:        tcp.Seq + uint32(len(tcp.Payload)), // Our ack = their seq + payload length
		DataOffset: 5,
		Window:     tcp.Window,
		Checksum:   0,
		Urgent:     0,
		SYN:        false,
		ACK:        true, // Only ACK flag
		FIN:        false,
		RST:        false,
		PSH:        false,
		URG:        false,
		ECE:        false,
		CWR:        false,
		NS:         false,
	}

	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize and send
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP); err != nil {
		log.Printf("❌ Error serializing ACK response: %v", err)
		return
	}

	reply := buf.Bytes()
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))
	xsk.Transmit([]sxdp.Desc{txDesc})

	// log.Printf("✅ Sent ACK response: %s:%d -> %s:%d, Seq=%d, Ack=%d",
	// 	replyIP.SrcIP, replyTCP.SrcPort,
	// 	replyIP.DstIP, replyTCP.DstPort,
	// 	replyTCP.Seq, replyTCP.Ack)
}

// GetSymmetricKey retrieves the symmetric key for a connection
func (ch *CiphertextHandler) GetSymmetricKey(conn *TCPConnection) []byte {
	connKey := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
	if cipherConn, exists := ch.connections[connKey]; exists && cipherConn.CipherReceived {
		return cipherConn.SymmetricKey
	}
	return nil
}

// Helper functions
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
