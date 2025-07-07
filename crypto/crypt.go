package crypto

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"
)

const (
	MSG_PUBLIC_KEY     = "PUBLIC_KEY"
	MSG_CIPHERTEXT     = "CIPHERTEXT"
	MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
)

func GenerateKeys() (publicKey kem.PublicKey, privateKey kem.PrivateKey) {
	scheme := kyber768.Scheme()

	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}

	fmt.Printf("✅ SERVER: Generated keys - Public key size: %d bytes, Private key size: %d bytes\n",
		len(publicKeyBytes), scheme.PrivateKeySize())

	return publicKey, privateKey
}

func StartHello(xsk *xdp.Socket, publicKey kem.PublicKey, packet gopacket.Packet) {
	fmt.Println("🤝 SERVER: Client connected!")

	// Step 2: Send public key to client
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}
	fmt.Println("📤 SERVER: Sending public key to client...")

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		log.Printf("error: received packet without TCP layer")
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("error: received packet without IPv4 layer")
		return
	}
	ip := ipLayer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Printf("error: received packet without Ethernet layer")
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Convert public key buffer to hex string
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Create HTTP request body with public key
	httpBody := fmt.Sprintf("PUBLIC_KEY:%s", publicKeyHex)

	// Create HTTP request headers
	httpRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s:%d\r\n"+
		"Content-Type: text/plain\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n%s", ip.SrcIP.String(), tcp.SrcPort, len(httpBody), httpBody)

	httpPayload := []byte(httpRequest)

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
		PSH:        true,        // Set PSH for data transmission
		URG:        tcp.URG,     // Keep URG flag
		ECE:        tcp.ECE,     // Keep ECE flag
		CWR:        tcp.CWR,     // Keep CWR flag
		NS:         tcp.NS,      // Keep NS flag
		Options:    tcp.Options, // Reuse same TCP options
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
		return
	}

	// Send the request packet
	reply := buf.Bytes()

	// Get TX descriptor and copy packet data
	txDesc := xsk.GetDescs(1, true)[0]
	copy(xsk.GetFrame(txDesc), reply)
	txDesc.Len = uint32(len(reply))

	// Transmit the packet
	xsk.Transmit([]xdp.Desc{txDesc})

	log.Printf("Sent HTTP request with PUBLIC_KEY: %s:%d -> %s:%d, Seq=%d, Ack=%d, PayloadLen=%d",
		replyIP.SrcIP, replyTCP.SrcPort,
		replyIP.DstIP, replyTCP.DstPort,
		replyTCP.Seq, replyTCP.Ack, len(httpPayload))
	// conn.Write([]byte(message + "\n"))

	// // Step 3: Receive ciphertext from client
	// buffer := make([]byte, 4096)
	// n, err := conn.Read(buffer)
	// if err != nil {
	// 	log.Fatal("Failed to read from client:", err)
	// }

	// response := strings.TrimSpace(string(buffer[:n]))
	// fmt.Println("📥 SERVER: Received ciphertext from client")

	// // Parse the ciphertext
	// if len(response) < len(MSG_CIPHERTEXT)+1 {
	// 	log.Fatal("Invalid message format")
	// }

	// ciphertextHex := response[len(MSG_CIPHERTEXT)+1:]
	// ciphertext, err := hex.DecodeString(ciphertextHex)
	// if err != nil {
	// 	log.Fatal("Failed to decode ciphertext:", err)
	// }

	// // Step 4: Decapsulate to get shared secret
	// fmt.Println("🔓 SERVER: Decapsulating shared secret...")
	// sharedSecret, err := scheme.Decapsulate(privateKey, ciphertext)
	// if err != nil {
	// 	log.Fatal("Failed to decapsulate:", err)
	// }

	// // Hash the shared secret to get a symmetric key
	// hash := sha256.Sum256(sharedSecret)
	// symmetricKey := hash[:]

	// fmt.Printf("🔑 SERVER: Shared secret established! (32 bytes)\n")
	// fmt.Printf("🔑 SERVER: Symmetric key: %s...\n", hex.EncodeToString(symmetricKey)[:16])

	// // Step 5: Wait for encrypted data from client
	// n, err = conn.Read(buffer)
	// if err != nil {
	// 	log.Fatal("Failed to read encrypted data:", err)
	// }

	// encryptedResponse := strings.TrimSpace(string(buffer[:n]))
	// fmt.Println("📥 SERVER: Received encrypted message from client")

	// // Parse encrypted data
	// if len(encryptedResponse) < len(MSG_ENCRYPTED_DATA)+1 {
	// 	log.Fatal("Invalid encrypted message format")
	// }

	// encryptedHex := encryptedResponse[len(MSG_ENCRYPTED_DATA)+1:]
	// encryptedData, err := hex.DecodeString(encryptedHex)
	// if err != nil {
	// 	log.Fatal("Failed to decode encrypted data:", err)
	// }

	// // Decrypt the message
	// decryptedData := xorEncrypt(encryptedData, symmetricKey)
	// fmt.Printf("🔓 SERVER: Decrypted message: '%s'\n", string(decryptedData))

	// // Send encrypted response back
	// responseMsg := "Hello from server! Kyber key exchange successful!"
	// encryptedResponse2 := xorEncrypt([]byte(responseMsg), symmetricKey)
	// conn.Write([]byte(fmt.Sprintf("%s:%s\n", MSG_ENCRYPTED_DATA, hex.EncodeToString(encryptedResponse2))))

	// fmt.Println("✅ SERVER: Sent encrypted response to client")
	// fmt.Println("🎉 SERVER: Key exchange and secure communication complete!")
}
