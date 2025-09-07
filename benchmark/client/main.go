package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"kyber-benchmark/crypto"
	"kyber-benchmark/metrics"
	"kyber-benchmark/network"
)

// ClientConfig holds client configuration
type ClientConfig struct {
	ServerAddr   string
	PacketSize   int
	PacketCount  int
	Workers      int
	EnableCrypto bool
	Verbose      bool
	ConnTimeout  time.Duration
	TestDuration time.Duration
}

// Client represents the benchmark client
type Client struct {
	config     *ClientConfig
	encryption *crypto.EncryptionContext
	metrics    *metrics.BenchmarkMetrics

	// Synchronization
	wg   sync.WaitGroup
	done chan bool
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

	client := NewClient(config)

	if err := client.Run(); err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}
}

func parseFlags() *ClientConfig {
	config := &ClientConfig{}

	flag.StringVar(&config.ServerAddr, "server", "localhost:8080", "Server address")
	flag.IntVar(&config.PacketSize, "size", 1024, "Packet size in bytes")
	flag.IntVar(&config.PacketCount, "count", 10000, "Number of packets to send (0 for time-based)")
	flag.IntVar(&config.Workers, "workers", 1, "Number of concurrent workers")
	flag.BoolVar(&config.EnableCrypto, "crypto", true, "Enable encryption")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.DurationVar(&config.ConnTimeout, "timeout", 10*time.Second, "Connection timeout")
	flag.DurationVar(&config.TestDuration, "duration", 0, "Test duration (0 for packet count based)")
	flag.Parse()

	return config
}

// NewClient creates a new benchmark client
func NewClient(config *ClientConfig) *Client {
	return &Client{
		config:  config,
		metrics: metrics.NewBenchmarkMetrics(),
		done:    make(chan bool),
	}
}

// Run executes the benchmark
func (c *Client) Run() error {
	fmt.Printf("Starting benchmark client\n")
	fmt.Printf("Server: %s\n", c.config.ServerAddr)
	fmt.Printf("Packet size: %d bytes\n", c.config.PacketSize)
	fmt.Printf("Workers: %d\n", c.config.Workers)
	fmt.Printf("Encryption: %t\n", c.config.EnableCrypto)

	if c.config.TestDuration > 0 {
		fmt.Printf("Duration: %v\n", c.config.TestDuration)
	} else {
		fmt.Printf("Packet count: %d\n", c.config.PacketCount)
	}

	// Start metrics collection
	c.metrics.Start()

	// Start workers
	packetsPerWorker := c.config.PacketCount / c.config.Workers
	if c.config.TestDuration > 0 {
		packetsPerWorker = 0 // Unlimited for time-based tests
	}

	for i := 0; i < c.config.Workers; i++ {
		c.wg.Add(1)
		go c.worker(i, packetsPerWorker)
	}

	// Handle time-based test
	if c.config.TestDuration > 0 {
		go func() {
			time.Sleep(c.config.TestDuration)
			close(c.done)
		}()
	}

	// Wait for all workers to complete
	c.wg.Wait()

	// Stop metrics and print report
	c.metrics.Stop()
	c.metrics.PrintReport()

	return nil
}

// worker runs the benchmark for a single worker
func (c *Client) worker(workerID, packetCount int) {
	defer c.wg.Done()

	if c.config.Verbose {
		log.Printf("Worker %d starting", workerID)
	}

	// Connect to server
	conn, err := network.ConnectWithTimeout(c.config.ServerAddr, c.config.ConnTimeout)
	if err != nil {
		log.Printf("Worker %d: Failed to connect to server: %v", workerID, err)
		return
	}
	defer conn.Close()

	if c.config.Verbose {
		log.Printf("Worker %d connected to server", workerID)
	}

	// Perform key exchange if crypto is enabled
	if c.config.EnableCrypto {
		encryption, err := c.performKeyExchange(conn, workerID)
		if err != nil {
			log.Printf("Worker %d: Key exchange failed: %v", workerID, err)
			return
		}
		c.encryption = encryption

		if c.config.Verbose {
			log.Printf("Worker %d: Key exchange completed", workerID)
		}
	}

	// Generate test data
	testData, err := c.generateTestData()
	if err != nil {
		log.Printf("Worker %d: Failed to generate test data: %v", workerID, err)
		return
	}

	// Run benchmark loop
	c.runBenchmarkLoop(conn, workerID, testData, packetCount)

	// Send shutdown message
	shutdownMsg := &network.Message{
		Type:    network.MsgTypeShutdown,
		Payload: []byte{},
	}
	conn.SendMessage(shutdownMsg)

	if c.config.Verbose {
		log.Printf("Worker %d completed", workerID)
	}
}

// performKeyExchange handles the Kyber key exchange with the server
func (c *Client) performKeyExchange(conn *network.Connection, workerID int) (*crypto.EncryptionContext, error) {
	// Receive server's public key
	msg, err := conn.ReceiveMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive server public key: %w", err)
	}

	if msg.Type != network.MsgTypeKeyExchange {
		return nil, fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var keyMsg KeyExchangeMessage
	if err := json.Unmarshal(msg.Payload, &keyMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key message: %w", err)
	}

	// Perform encapsulation
	ciphertext, sharedSecret, err := crypto.EncapsulateSecret(keyMsg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate secret: %w", err)
	}

	// Generate salt for key derivation
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive symmetric key
	key, err := crypto.DeriveKeyWithSalt(sharedSecret, salt, []byte("kyber-benchmark"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Send ciphertext and salt to server
	keyResponse := KeyResponseMessage{
		Ciphertext: ciphertext,
		Salt:       salt,
	}

	responseBytes, err := json.Marshal(keyResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key response: %w", err)
	}

	responseMsg := &network.Message{
		Type:    network.MsgTypeKeyResponse,
		Payload: responseBytes,
	}

	if err := conn.SendMessage(responseMsg); err != nil {
		return nil, fmt.Errorf("failed to send key response: %w", err)
	}

	// Create encryption context
	encCtx, err := crypto.NewEncryptionContext(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption context: %w", err)
	}

	return encCtx, nil
}

// generateTestData creates test data for benchmarking
func (c *Client) generateTestData() ([]byte, error) {
	data := make([]byte, c.config.PacketSize)

	// Fill with pattern for verification (optional)
	for i := range data {
		data[i] = byte(i % 256)
	}

	return data, nil
}

// runBenchmarkLoop runs the main benchmark loop
func (c *Client) runBenchmarkLoop(conn *network.Connection, workerID int, testData []byte, packetCount int) {
	sent := 0

	for {
		// Check for time-based termination
		select {
		case <-c.done:
			return
		default:
		}

		// Check for count-based termination
		if packetCount > 0 && sent >= packetCount {
			return
		}

		// Send benchmark packet
		if err := c.sendBenchmarkPacket(conn, testData); err != nil {
			if c.config.Verbose {
				log.Printf("Worker %d: Failed to send packet: %v", workerID, err)
			}
			c.metrics.RecordError()
			continue
		}

		// Receive response and measure latency
		startTime := time.Now()
		if err := c.receiveBenchmarkResponse(conn); err != nil {
			if c.config.Verbose {
				log.Printf("Worker %d: Failed to receive response: %v", workerID, err)
			}
			c.metrics.RecordError()
			continue
		}
		latency := time.Since(startTime)

		// Record metrics
		c.metrics.RecordPacketReceived(uint64(len(testData)), latency)

		sent++

		// Optional: add small delay to control rate
		// time.Sleep(time.Microsecond * 10)
	}
}

// sendBenchmarkPacket sends a benchmark data packet
func (c *Client) sendBenchmarkPacket(conn *network.Connection, data []byte) error {
	var payload []byte = data

	// Encrypt if encryption is enabled
	if c.config.EnableCrypto && c.encryption != nil {
		encrypted, err := c.encryption.Encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		payload = encrypted
	}

	msg := &network.Message{
		Type:    network.MsgTypeBenchmark,
		Payload: payload,
	}

	if err := conn.SendMessage(msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	c.metrics.RecordPacketSent(uint64(len(payload)))
	return nil
}

// receiveBenchmarkResponse receives and processes a benchmark response
func (c *Client) receiveBenchmarkResponse(conn *network.Connection) error {
	msg, err := conn.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive message: %w", err)
	}

	if msg.Type != network.MsgTypeResponse {
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var payload []byte = msg.Payload

	// Decrypt if encryption is enabled
	if c.config.EnableCrypto && c.encryption != nil {
		decrypted, err := c.encryption.Decrypt(msg.Payload)
		if err != nil {
			return fmt.Errorf("failed to decrypt response: %w", err)
		}
		payload = decrypted
	}

	// Optional: verify response data
	// This could include checking that the echoed data matches what was sent
	_ = payload // Suppress unused variable warning

	return nil
}
