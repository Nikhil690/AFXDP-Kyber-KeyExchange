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

	"kyber-benchmark/crypto"
	"kyber-benchmark/metrics"
	"kyber-benchmark/network"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	Port         int
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
	flag.BoolVar(&config.EnableCrypto, "crypto", true, "Enable encryption")
	flag.IntVar(&config.MaxClients, "max-clients", 100, "Maximum concurrent clients")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	return config
}

// NewServer creates a new benchmark server
func NewServer(config *ServerConfig) (*Server, error) {
	// Generate Kyber key pair if crypto is enabled
	var keyPair *crypto.KyberKeyPair
	if config.EnableCrypto {
		var err error
		keyPair, err = crypto.GenerateKyberKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
	}

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
	// Create TCP server
	addr := fmt.Sprintf(":%d", s.config.Port)
	server, err := network.NewServer(addr)
	if err != nil {
		return fmt.Errorf("failed to create TCP server: %w", err)
	}
	s.server = server

	fmt.Printf("Server starting on %s\n", server.GetAddr())
	fmt.Printf("Encryption: %t\n", s.config.EnableCrypto)
	fmt.Printf("Max clients: %d\n", s.config.MaxClients)

	// Start metrics collection
	s.metrics.Start()

	// Handle graceful shutdown
	go s.handleShutdown()

	// Accept connections
	go s.acceptConnections()

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

	if s.config.Verbose {
		log.Printf("Client connected: %s", clientID)
	}

	session := &ClientSession{
		conn: conn,
		id:   clientID,
	}

	// Register client
	s.clientMux.Lock()
	s.clients[clientID] = session
	s.clientMux.Unlock()

	defer func() {
		// Unregister client
		s.clientMux.Lock()
		delete(s.clients, clientID)
		s.clientMux.Unlock()

		conn.Close()
		if s.config.Verbose {
			log.Printf("Client disconnected: %s", clientID)
		}
	}()

	// Handle key exchange if crypto is enabled
	if s.config.EnableCrypto {
		if err := s.handleKeyExchange(session); err != nil {
			if s.config.Verbose {
				log.Printf("Key exchange failed for %s: %v", clientID, err)
			}
			return
		}
	}

	// Handle benchmark messages
	s.handleBenchmarkMessages(session)
}

// handleKeyExchange performs the Kyber key exchange
func (s *Server) handleKeyExchange(session *ClientSession) error {
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

	// Receive ciphertext from client
	response, err := session.conn.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive key response: %w", err)
	}

	if response.Type != network.MsgTypeKeyResponse {
		return fmt.Errorf("unexpected message type: %d", response.Type)
	}

	var keyResponse KeyResponseMessage
	if err := json.Unmarshal(response.Payload, &keyResponse); err != nil {
		return fmt.Errorf("failed to unmarshal key response: %w", err)
	}

	// Decapsulate shared secret
	sharedSecret, err := crypto.DecapsulateSecret(s.keyPair.PrivateKey, keyResponse.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decapsulate secret: %w", err)
	}

	// Derive symmetric key
	key, err := crypto.DeriveKeyWithSalt(sharedSecret, keyResponse.Salt, []byte("kyber-benchmark"))
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create encryption context
	encCtx, err := crypto.NewEncryptionContext(key)
	if err != nil {
		return fmt.Errorf("failed to create encryption context: %w", err)
	}

	session.encryption = encCtx

	if s.config.Verbose {
		log.Printf("Key exchange completed for %s", session.id)
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
