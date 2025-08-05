package tsm

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	sxdp "github.com/slavc/xdp"
)

// Add this to your existing tsm package

const (
	MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
)

// processEncryptedDataFromHTTPBody handles encrypted data messages
func (ch *CiphertextHandler) processEncryptedDataFromHTTPBody(xsk *sxdp.Socket, packet gopacket.Packet, conn *TCPConnection, bodyStr string) bool {
	// Get the symmetric key for this connection
	connKey := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
	cipherConn, exists := ch.connections[connKey]
	if !exists || !cipherConn.CipherReceived {
		log.Printf("❌ No symmetric key found for connection %s:%d", conn.RemoteIP, conn.RemotePort)
		return false
	}

	symmetricKey := cipherConn.SymmetricKey

	// fmt.Println("📥 SERVER: Received encrypted message from client")

	// Parse encrypted data
	encryptedDataStart := strings.Index(bodyStr, MSG_ENCRYPTED_DATA+":")
	if encryptedDataStart == -1 {
		log.Printf("❌ ENCRYPTED_DATA marker not found in HTTP body")
		return false
	}

	// Extract everything after "ENCRYPTED_DATA:"
	encryptedPart := bodyStr[encryptedDataStart+len(MSG_ENCRYPTED_DATA)+1:]

	// Clean up the encrypted data - extract only hex characters
	var encryptedHex strings.Builder
	for _, r := range encryptedPart {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			encryptedHex.WriteRune(r)
		}
	}

	encryptedHexStr := encryptedHex.String()
	if len(encryptedHexStr) < len(MSG_ENCRYPTED_DATA)+1 {
		log.Printf("❌ Invalid encrypted message format")
		return false
	}

	// Decode hex string to bytes
	// encryptedData, err := hex.DecodeString(encryptedHexStr)
	// if err != nil {
	// 	log.Printf("❌ Failed to decode encrypted data: %v", err)
	// 	return false
	// }

	// Decrypt the message
	// decryptedData := xorEncrypt(encryptedData, symmetricKey)
	// fmt.Printf("🔓 SERVER: Decrypted message: '%s'\n", string(decryptedData))

	// Send encrypted response back
	responseMsg := "Hello from server! Kyber key exchange successful!"
	encryptedResponse := xorEncrypt([]byte(responseMsg), symmetricKey)

	// Create HTTP response with encrypted data
	httpResponse := fmt.Sprintf("%s:%s", MSG_ENCRYPTED_DATA, hex.EncodeToString(encryptedResponse))

	// Send the HTTP response
	if ch.sendHTTPResponsePacket(xsk, packet, conn, []byte(httpResponse)) {
		// fmt.Println("✅ SERVER: Sent encrypted response to client")
		// fmt.Println("🎉 SERVER: Key exchange and secure communication complete!")
		return true
	}

	return false
}

// sendHTTPResponsePacket sends an HTTP response packet
func (ch *CiphertextHandler) sendHTTPResponsePacket(xsk *sxdp.Socket, packet gopacket.Packet, conn *TCPConnection, httpResponse []byte) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return false
	}
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false
	}
	eth := ethLayer.(*layers.Ethernet)

	// Create response packet
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
		Seq:        tcp.Ack,
		Ack:        tcp.Seq + uint32(len(tcp.Payload)),
		DataOffset: 5,
		Window:     tcp.Window,
		Checksum:   0,
		Urgent:     0,
		SYN:        false,
		ACK:        true,
		FIN:        false,
		RST:        false,
		PSH:        true,
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

	if err := gopacket.SerializeLayers(buf, opts, replyEth, replyIP, replyTCP, gopacket.Payload(httpResponse)); err != nil {
		log.Printf("❌ Error serializing HTTP response: %v", err)
		return false
	}

	reply := buf.Bytes()
	txDesc := xsk.GetDescs(1, false)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))
	xsk.Transmit([]sxdp.Desc{txDesc})

	// log.Printf("✅ Sent HTTP response: %s:%d -> %s:%d, PayloadLen=%d",
	// 	replyIP.SrcIP, replyTCP.SrcPort,
	// 	replyIP.DstIP, replyTCP.DstPort, len(httpResponse))

	return true
}

// xorEncrypt performs XOR encryption/decryption
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}
