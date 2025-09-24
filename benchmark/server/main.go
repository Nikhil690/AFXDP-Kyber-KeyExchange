package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"kyber-benchmark/crypto"
	"kyber-benchmark/metrics"
	"kyber-benchmark/network"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	Port         int
	Address      string
	EnableCrypto bool
	MaxClients   int
	Verbose      bool
}

// Server represents the benchmark server
type Server struct {
	config     *ServerConfig
	keyPair    *crypto.KyberKeyPair
	encryption *crypto.EncryptionContext
	metrics    *metrics.BenchmarkMetrics
	server     *network.Server

	// Client management
	clients   map[string]*ClientSession
	clientMux sync.RWMutex

	// Shutdown handling
	shutdown chan bool
	done     chan bool
}

// ClientSession represents an active client session
type ClientSession struct {
	conn       *network.Connection
	encryption *crypto.EncryptionContext
	id         string
}

// KeyExchangeMessage represents the key exchange payload
type KeyExchangeMessage struct {
	PublicKey []byte `json:"public_key"`
}

// KeyResponseMessage represents the key response payload
type KeyResponseMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Salt       []byte `json:"salt"`
}

func main() {
	config := parseFlags()

	server, err := NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func parseFlags() *ServerConfig {
	config := &ServerConfig{}

	flag.IntVar(&config.Port, "port", 8080, "Server port")
	flag.StringVar(&config.Address, "address", "localhost", "Server address")
	flag.BoolVar(&config.EnableCrypto, "crypto", true, "Enable encryption")
	flag.IntVar(&config.MaxClients, "max-clients", 100, "Maximum concurrent clients")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	return config
}

// NewServer creates a new benchmark server
func NewServer(config *ServerConfig) (*Server, error) {
	fmt.Println("================================================================================")
	fmt.Println("🖥️  KYBER BENCHMARK SERVER INITIALIZING")
	fmt.Println("================================================================================")

	// Generate Kyber key pair if crypto is enabled
	var keyPair *crypto.KyberKeyPair
	if config.EnableCrypto {
		fmt.Println("🔐 GENERATING KYBER-768 KEY PAIR...")
		var err error
		keyPair, err = crypto.GenerateKyberKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		fmt.Printf("✅ Kyber key pair generated successfully\n")
		fmt.Printf("🔑 Public key size: %d bytes\n", len(keyPair.PublicKey))
		fmt.Printf("🔒 Private key size: %d bytes\n", len(keyPair.PrivateKey))
	} else {
		fmt.Println("🔓 ENCRYPTION DISABLED - PLAINTEXT MODE")
	}

	fmt.Println("📊 INITIALIZING METRICS COLLECTION...")
	time.Sleep(200 * time.Millisecond)
	fmt.Println("✅ Server initialization complete")
	fmt.Println()

	return &Server{
		config:   config,
		keyPair:  keyPair,
		metrics:  metrics.NewBenchmarkMetrics(),
		clients:  make(map[string]*ClientSession),
		shutdown: make(chan bool),
		done:     make(chan bool),
	}, nil
}

// Start starts the server
func (s *Server) Start() error {
	fmt.Println("🚀 STARTING TCP SERVER...")

	// Create TCP server
	addr := fmt.Sprintf("%s:%d",s.config.Address, s.config.Port)
	server, err := network.NewServer(addr)
	if err != nil {
		return fmt.Errorf("failed to create TCP server: %w", err)
	}
	s.server = server

	fmt.Println("================================================================================")
	fmt.Println("🌐 SERVER CONFIGURATION")
	fmt.Println("================================================================================")
	fmt.Printf("📍 Address: %s\n", server.GetAddr())
	fmt.Printf("🔐 Encryption: %t\n", s.config.EnableCrypto)
	fmt.Printf("👥 Max Clients: %d\n", s.config.MaxClients)
	fmt.Printf("📝 Verbose Mode: %t\n", s.config.Verbose)
	if s.config.EnableCrypto {
		fmt.Printf("🔑 Kyber Algorithm: Kyber-768 (NIST Level 3)\n")
		fmt.Printf("🔒 Symmetric Cipher: AES-256-GCM\n")
	}
	fmt.Println("================================================================================")
	fmt.Println()

	fmt.Println("📈 STARTING METRICS COLLECTION...")
	// Start metrics collection
	s.metrics.Start()
	fmt.Println("✅ Metrics collection started")
	time.Sleep(300 * time.Millisecond)

	fmt.Println("🔄 SETTING UP GRACEFUL SHUTDOWN HANDLER...")
	// Handle graceful shutdown
	go s.handleShutdown()
	fmt.Println("✅ Shutdown handler ready")
	time.Sleep(200 * time.Millisecond)

	fmt.Println("👂 STARTING CONNECTION ACCEPTOR...")
	// Accept connections
	go s.acceptConnections()
	fmt.Println("✅ Now accepting client connections")
	time.Sleep(200 * time.Millisecond)

	fmt.Println()
	fmt.Println("🎯 SERVER IS READY AND WAITING FOR CLIENTS...")
	fmt.Println("   Press Ctrl+C to stop the server gracefully")
	fmt.Println()

	// Wait for shutdown
	<-s.done

	return nil
}

// acceptConnections accepts and handles incoming connections
func (s *Server) acceptConnections() {
	for {
		select {
		case <-s.shutdown:
			return
		default:
			conn, err := s.server.Accept()
			if err != nil {
				if s.config.Verbose {
					log.Printf("Failed to accept connection: %v", err)
				}
				continue
			}

			// Check client limit
			s.clientMux.RLock()
			clientCount := len(s.clients)
			s.clientMux.RUnlock()

			if clientCount >= s.config.MaxClients {
				if s.config.Verbose {
					log.Printf("Max clients reached, rejecting connection from %s",
						conn.GetRemoteAddr())
				}
				conn.Close()
				continue
			}

			// Handle client in goroutine
			go s.handleClient(conn)
		}
	}
}

// handleClient handles a client connection
func (s *Server) handleClient(conn *network.Connection) {
	clientID := conn.GetRemoteAddr().String()

	fmt.Printf("🔗 NEW CLIENT CONNECTED: %s\n", clientID)

	// Get current client count
	s.clientMux.RLock()
	clientCount := len(s.clients)
	s.clientMux.RUnlock()

	fmt.Printf("👥 Active clients: %d/%d\n", clientCount+1, s.config.MaxClients)

	session := &ClientSession{
		conn: conn,
		id:   clientID,
	}

	// Register client
	s.clientMux.Lock()
	s.clients[clientID] = session
	s.clientMux.Unlock()

	if s.config.Verbose {
		fmt.Printf("📋 Client %s registered in session table\n", clientID)
	}

	defer func() {
		// Unregister client
		s.clientMux.Lock()
		delete(s.clients, clientID)
		finalCount := len(s.clients)
		s.clientMux.Unlock()

		conn.Close()
		fmt.Printf("👋 CLIENT DISCONNECTED: %s\n", clientID)
		fmt.Printf("👥 Remaining clients: %d\n", finalCount)
	}()

	// Handle key exchange if crypto is enabled
	if s.config.EnableCrypto {
		fmt.Printf("🔐 STARTING KEY EXCHANGE WITH %s...\n", clientID)
		if err := s.handleKeyExchange(session); err != nil {
			fmt.Printf("❌ KEY EXCHANGE FAILED FOR %s: %v\n", clientID, err)
			return
		}
		fmt.Printf("✅ KEY EXCHANGE COMPLETED FOR %s\n", clientID)
	} else {
		fmt.Printf("🔓 PLAINTEXT MODE - SKIPPING KEY EXCHANGE FOR %s\n", clientID)
	}

	// Handle benchmark messages
	fmt.Printf("📊 STARTING BENCHMARK SESSION FOR %s\n", clientID)
	s.handleBenchmarkMessages(session)
	fmt.Printf("🏁 BENCHMARK SESSION ENDED FOR %s\n", clientID)
}

// handleKeyExchange performs the Kyber key exchange
func (s *Server) handleKeyExchange(session *ClientSession) error {
	if s.config.Verbose {
		fmt.Printf("📤 Sending Kyber public key to %s (%d bytes)...\n", session.id, len(s.keyPair.PublicKey))
	}

	// Send public key to client
	keyMsg := KeyExchangeMessage{
		PublicKey: s.keyPair.PublicKey,
	}

	keyMsgBytes, err := json.Marshal(keyMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal key message: %w", err)
	}

	msg := &network.Message{
		Type:    network.MsgTypeKeyExchange,
		Payload: keyMsgBytes,
	}

	if err := session.conn.SendMessage(msg); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	if s.config.Verbose {
		fmt.Printf("✅ Public key sent to %s\n", session.id)
		fmt.Printf("⏳ Waiting for client ciphertext and salt...\n")
	}

	// Receive ciphertext from client
	response, err := session.conn.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive key response: %w", err)
	}

	if response.Type != network.MsgTypeKeyResponse {
		return fmt.Errorf("unexpected message type: %d", response.Type)
	}

	if s.config.Verbose {
		fmt.Printf("📬 Received key response from %s (%d bytes)\n", session.id, len(response.Payload))
	}

	var keyResponse KeyResponseMessage
	if err := json.Unmarshal(response.Payload, &keyResponse); err != nil {
		return fmt.Errorf("failed to unmarshal key response: %w", err)
	}

	if s.config.Verbose {
		fmt.Printf("🔓 Parsed ciphertext (%d bytes) and salt (%d bytes)\n",
			len(keyResponse.Ciphertext), len(keyResponse.Salt))
		fmt.Printf("⚙️  Starting Kyber decapsulation...\n")
	}

	// Decapsulate shared secret
	sharedSecret, err := crypto.DecapsulateSecret(s.keyPair.PrivateKey, keyResponse.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decapsulate secret: %w", err)
	}

	if s.config.Verbose {
		fmt.Printf("✅ Decapsulation successful (%d bytes shared secret)\n", len(sharedSecret))
		fmt.Printf("🔑 Deriving AES-256 key using HKDF...\n")
	}

	// Derive symmetric key
	key, err := crypto.DeriveKeyWithSalt(sharedSecret, keyResponse.Salt, []byte("kyber-benchmark"))
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if s.config.Verbose {
		fmt.Printf("✅ AES-256 key derived (%d bytes)\n", len(key))
		fmt.Printf("🔒 Creating encryption context...\n")
	}

	// Create encryption context
	encCtx, err := crypto.NewEncryptionContext(key)
	if err != nil {
		return fmt.Errorf("failed to create encryption context: %w", err)
	}

	session.encryption = encCtx

	if s.config.Verbose {
		fmt.Printf("✅ Encryption context ready for %s\n", session.id)
	}

	return nil
}

// handleBenchmarkMessages handles benchmark data messages
func (s *Server) handleBenchmarkMessages(session *ClientSession) {
	for {
		msg, err := session.conn.ReceiveMessage()
		if err != nil {
			if s.config.Verbose {
				log.Printf("Failed to receive message from %s: %v", session.id, err)
			}
			return
		}

		switch msg.Type {
		case network.MsgTypeBenchmark:
			s.handleBenchmarkPacket(session, msg)
		case network.MsgTypeShutdown:
			if s.config.Verbose {
				log.Printf("Client %s requested shutdown", session.id)
			}
			return
		default:
			if s.config.Verbose {
				log.Printf("Unknown message type %d from %s", msg.Type, session.id)
			}
		}
	}
}

// handleBenchmarkPacket processes a benchmark packet and sends response
func (s *Server) handleBenchmarkPacket(session *ClientSession, msg *network.Message) {
	var payload []byte = msg.Payload

	// Decrypt if encryption is enabled
	if s.config.EnableCrypto && session.encryption != nil {
		decrypted, err := session.encryption.Decrypt(msg.Payload)
		if err != nil {
			if s.config.Verbose {
				log.Printf("Failed to decrypt message from %s: %v", session.id, err)
			}
			return
		}
		payload = decrypted
	}

	// Record metrics
	s.metrics.RecordPacketReceived(uint64(len(payload)), 0) // Server doesn't measure latency

	// Prepare response (echo the data)
	responsePayload := payload

	// Encrypt response if encryption is enabled
	if s.config.EnableCrypto && session.encryption != nil {
		encrypted, err := session.encryption.Encrypt(responsePayload)
		if err != nil {
			if s.config.Verbose {
				log.Printf("Failed to encrypt response for %s: %v", session.id, err)
			}
			return
		}
		responsePayload = encrypted
	}

	// Send response
	response := &network.Message{
		Type:    network.MsgTypeResponse,
		Payload: responsePayload,
	}

	if err := session.conn.SendMessage(response); err != nil {
		if s.config.Verbose {
			log.Printf("Failed to send response to %s: %v", session.id, err)
		}
		return
	}

	s.metrics.RecordPacketSent(uint64(len(responsePayload)))
}

// handleShutdown handles graceful shutdown
func (s *Server) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println("\nShutting down server...")

	// Stop accepting new connections
	close(s.shutdown)

	// Close all client connections
	s.clientMux.RLock()
	for _, session := range s.clients {
		session.conn.Close()
	}
	s.clientMux.RUnlock()

	// Close server
	if s.server != nil {
		s.server.Close()
	}

	// Stop metrics and print report
	s.metrics.Stop()
	s.metrics.PrintReport()

	close(s.done)
}
