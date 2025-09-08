package tsm

import (
	"log"
	"xdp-example/crypto"
	"xdp-example/message"

	"github.com/cloudflare/circl/kem"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

const (
	MSG_CIPHERTEXT = "CIPHERTEXT"
	ENCRYPTED_DATA = "ENCRYPTED_DATA"
)

// CiphertextHandler processes PSH+ACK packets containing ciphertext data
type CiphertextHandler struct {
	privateKey  kem.PrivateKey
	scheme      kem.Scheme // Your crypto scheme interface
	connections map[string]*CipherConnection
	encryption  *crypto.EncryptionContext
}

// CipherConnection tracks cipher-related state per connection
type CipherConnection struct {
	SharedSecret   []byte
	SymmetricKey   []byte
	CipherReceived bool
}

// NewCiphertextHandler creates a new ciphertext handler
func NewCiphertextHandler(privateKey kem.PrivateKey, scheme kem.Scheme) *CiphertextHandler {
	return &CiphertextHandler{
		privateKey:  privateKey,
		scheme:      scheme,
		connections: make(map[string]*CipherConnection),
	}
}

// HandlePshAckData processes PSH+ACK packets with payload data
func (ch *CiphertextHandler) HandlePshAckData(xsk *sxdp.Socket, packet gopacket.Packet, conn *TCPConnection) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp := tcpLayer.(*layers.TCP)

	// Check if this is a PSH+ACK packet with data
	if !tcp.PSH || !tcp.ACK || len(tcp.Payload) == 0 {
		return false
	}

	// log.Printf("📦 Received PSH+ACK packet with %d bytes of data from %s:%d",
	// 	len(tcp.Payload), conn.RemoteIP, conn.RemotePort)

	// Extract and process the payload

	msg, err := message.Deserialize(tcp.Payload)
	if err != nil {
		log.Printf("Failed to deserialize message: %v", err)
		return false
	}
	// log.Printf("Deserialized Message Type: %d, Length: %d", msg.Type, msg.Length)

	// Check if this contains ciphertext
	switch msg.Type {
	case message.MsgTypeKeyResponse:
		log.Printf("📥 SERVER: Received ciphertext from client %s:%d", conn.RemoteIP, conn.RemotePort)

		// Process the ciphertext
		if ch.processCiphertextsalt(conn, msg) {
			// Send ACK to acknowledge receipt
			ch.sendAckResponse(xsk, packet)
			return true
		}
	case message.MsgTypeBenchmark:
		if ch.handleBenchmarkPacket(xsk, packet, conn, msg) {
			return true
		}
	case message.MsgTypeShutdown:
		return false // Connection will be closed by the main loop
	default:
		return false
	}

	return false
}
