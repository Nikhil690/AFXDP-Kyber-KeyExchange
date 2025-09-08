package tsm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"xdp-example/crypto"
	"xdp-example/message"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
	sxdp "github.com/slavc/xdp"
)

type KeyResponseMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Salt       []byte `json:"salt"`
}

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

func (ch *CiphertextHandler) processCiphertextsalt(conn *TCPConnection, msg *message.Message) bool {
	if msg.Type != message.MsgTypeKeyResponse {
		log.Printf("❌ Unexpected message type: %d", msg.Type)
		return false
	}

	var keyResponse KeyResponseMessage
	if err := json.Unmarshal(msg.Payload, &keyResponse); err != nil {
		log.Printf("❌ Failed to unmarshal key response: %v", err)
		return false
	}
	privateKeyBytes, err := ch.privateKey.MarshalBinary()
	if err != nil {
		log.Printf("❌ Failed to marshal private key: %v", err)
		return false
	}
	sharedSecret, err := crypto.DecapsulateSecret(privateKeyBytes, keyResponse.Ciphertext)
	if err != nil {
		log.Printf("❌ Failed to decapsulate: %v", err)
		return false
	}
	key, err := crypto.DeriveKeyWithSalt(sharedSecret, keyResponse.Salt, []byte("kyber-benchmark"))
	if err != nil {
		log.Printf("❌ Failed to derive key: %v", err)
		return false
	}
	encCtx, err := crypto.NewEncryptionContext(key)
	if err != nil {
		log.Printf("❌ Failed to create encryption context: %v", err)
		return false
	}
	ch.encryption = encCtx
	return true
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

func (ch *CiphertextHandler) handleBenchmarkPacket(xsk *sxdp.Socket, packet gopacket.Packet, conn *TCPConnection, msg *message.Message) bool {
	var payload []byte = msg.Payload
	decrypted, err := ch.encryption.Decrypt(msg.Payload)
	if err != nil {
		log.Printf("❌ Failed to decrypt benchmark payload: %v", err)
		return false
	}
	// log.Printf("📦 Decrypted benchmark payload (%d bytes)", len(decrypted))
	payload = decrypted
	responsePayload := payload

	encrypted, err := ch.encryption.Encrypt(responsePayload)
	if err != nil {
		log.Printf("❌ Failed to encrypt benchmark response: %v", err)
		return false
	}
	responsePayload = encrypted
	response := &message.Message{
		Type:    message.MsgTypeResponse,
		Length:  uint32(len(responsePayload)),
		Payload: responsePayload,
	}
	
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
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Printf("error: received packet without Ethernet layer")
		return false
	}
	eth := ethLayer.(*layers.Ethernet)

	// Serialize the message to binary format using the struct method
	httpPayload := response.Serialize()

	// Reuse Ethernet layer, just swap MAC addresses
	replyEth := &layers.Ethernet{
		SrcMAC:       eth.DstMAC,       // Server MAC (was destination)
		DstMAC:       eth.SrcMAC,       // Client MAC (was source)
		EthernetType: eth.EthernetType, // Keep same EthernetType
	}

	// Reuse IP layer, just swap IPs and update necessary fields
	replyIP := &layers.IPv4{
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     0,         // Will be set by serialization
		Id:         ip.Id + 1, // Increment ID
		Flags:      ip.Flags,  // Keep same flags
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,      // Keep same TTL
		Protocol:   ip.Protocol, // Keep TCP protocol
		Checksum:   0,           // Will be calculated by serialization
		SrcIP:      ip.DstIP,    // Server IP (was destination)
		DstIP:      ip.SrcIP,    // Client IP (was source)
	}

	// Reuse TCP layer structure, modify only necessary fields
	replyTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,    // Server port (was destination)
		DstPort:    tcp.SrcPort,    // Client port (was source)
		Seq:        tcp.Ack,        // Our seq = their ack
		Ack:        tcp.Seq,        // Our ack = their seq (no payload in ACK)
		DataOffset: tcp.DataOffset, // Keep same data offset if has options
		Window:     tcp.Window,     // Keep same window size
		Checksum:   0,              // Will be calculated by serialization
		Urgent:     tcp.Urgent,     // Keep same urgent pointer
		SYN:        false,
		ACK:        true, // Keep ACK flag
		FIN:        false,
		RST:        false,
		PSH:        true,    // Set PSH for data transmission
		URG:        tcp.URG, // Keep URG flag
		ECE:        tcp.ECE, // Keep ECE flag
		CWR:        tcp.CWR, // Keep CWR flag
		NS:         tcp.NS,  // Keep NS flag
		// Options:    tcp.Options, // Reuse same TCP options
	}

	// Set up TCP checksum calculation
	replyTCP.SetNetworkLayerForChecksum(replyIP)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP, gopacket.Payload(httpPayload)); err != nil {
		log.Printf("error serializing public key request packet: %v", err)
		return false
	}

	// outgoingpacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	// fmt.Printf("Outgoing packet: %s\n", outgoingpacket)

	_, _, err = xsk.Poll(1)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("num received: %d, num completed: %d\n", numRec, numCom)
	// Send the request packet
	reply := buf.Bytes()

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, false)[0]
	frame := xsk.GetFrame(txDesc)
	if len(frame) < len(reply) {
		log.Printf("error: TX frame too small, got %d bytes, need %d bytes", len(frame), len(reply))
		return false
	}
	// fmt.Printf("TX frame size: %d bytes, reply size: %d bytes\n", len(frame), len(reply))
	copy(frame, reply)
	txDesc.Len = uint32(len(reply))
	xsk.Transmit([]xdp.Desc{txDesc})
	return true
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
