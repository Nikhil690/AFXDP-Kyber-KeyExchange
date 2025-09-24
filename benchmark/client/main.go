package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
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
	TotalData    string // New field for total data amount (e.g., "1GB", "500MB")
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
	flag.IntVar(&config.PacketCount, "count", 10000, "Number of packets to send (0 for time-based or data-based)")
	flag.StringVar(&config.TotalData, "data", "", "Total data to send (e.g., '1GB', '500MB', '10KB') - overrides count")
	flag.IntVar(&config.Workers, "workers", 1, "Number of concurrent workers")
	flag.BoolVar(&config.EnableCrypto, "crypto", true, "Enable encryption")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.DurationVar(&config.ConnTimeout, "timeout", 10*time.Second, "Connection timeout")
	flag.DurationVar(&config.TestDuration, "duration", 0, "Test duration (0 for packet count based)")
	flag.Parse()

	// Process data size if provided
	if config.TotalData != "" {
		totalBytes, err := parseDataSize(config.TotalData)
		if err != nil {
			log.Fatalf("Invalid data size '%s': %v", config.TotalData, err)
		}
		// Calculate packet count based on total data and packet size
		config.PacketCount = int(totalBytes / uint64(config.PacketSize))
		if totalBytes%uint64(config.PacketSize) != 0 {
			config.PacketCount++ // Round up for partial packets
		}
	}

	return config
}

// parseDataSize parses data size strings like "1GB", "500MB", "10KB" into bytes
func parseDataSize(sizeStr string) (uint64, error) {
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))

	var multiplier uint64 = 1
	var numStr string

	if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "GB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "B") {
		multiplier = 1
		numStr = strings.TrimSuffix(sizeStr, "B")
	} else {
		// Assume bytes if no suffix
		numStr = sizeStr
	}

	// Parse the numeric part (support decimals)
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", numStr)
	}

	if num < 0 {
		return 0, fmt.Errorf("size cannot be negative")
	}

	return uint64(num * float64(multiplier)), nil
}

// formatBytes formats bytes into human-readable format
func formatBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	} else if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	} else if n < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
	} else {
		return fmt.Sprintf("%.1f GB", float64(n)/1024/1024/1024)
	}
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
	fmt.Println("================================================================================")
	fmt.Println("🚀 KYBER BENCHMARK CLIENT STARTING")
	fmt.Println("================================================================================")
	fmt.Printf("🌐 Server Address: %s\n", c.config.ServerAddr)
	fmt.Printf("📦 Packet Size: %d bytes (%.2f KB)\n", c.config.PacketSize, float64(c.config.PacketSize)/1024)
	fmt.Printf("🔢 Workers: %d\n", c.config.Workers)
	fmt.Printf("🔐 Encryption: %t\n", c.config.EnableCrypto)
	fmt.Printf("📝 Verbose Mode: %t\n", c.config.Verbose)
	fmt.Printf("⏱️  Connection Timeout: %v\n", c.config.ConnTimeout)

	if c.config.TestDuration > 0 {
		fmt.Printf("⏰ Test Duration: %v\n", c.config.TestDuration)
		fmt.Printf("📊 Mode: Time-based testing\n")
	} else if c.config.TotalData != "" {
		totalBytes := uint64(c.config.PacketCount) * uint64(c.config.PacketSize)
		fmt.Printf("� Total Data Target: %s (%s)\n", c.config.TotalData, formatBytes(totalBytes))
		fmt.Printf("�📊 Calculated Packet Count: %d\n", c.config.PacketCount)
		fmt.Printf("📊 Packets per Worker: %d\n", c.config.PacketCount/c.config.Workers)
		fmt.Printf("📊 Mode: Data-based testing\n")
	} else {
		fmt.Printf("📊 Packet Count: %d\n", c.config.PacketCount)
		fmt.Printf("📊 Packets per Worker: %d\n", c.config.PacketCount/c.config.Workers)
		totalBytes := uint64(c.config.PacketCount) * uint64(c.config.PacketSize)
		fmt.Printf("💾 Total Data: %s\n", formatBytes(totalBytes))
		fmt.Printf("📊 Mode: Count-based testing\n")
	}

	fmt.Println("================================================================================")
	fmt.Println()

	// Start metrics collection
	fmt.Println("📈 INITIALIZING METRICS COLLECTION...")
	c.metrics.Start()
	fmt.Println("✅ Metrics collection started")
	time.Sleep(500 * time.Millisecond)
	fmt.Println()

	// Calculate packets per worker
	packetsPerWorker := c.config.PacketCount / c.config.Workers
	if c.config.TestDuration > 0 {
		packetsPerWorker = 0 // Unlimited for time-based tests
		fmt.Println("🔄 CONFIGURING TIME-BASED TEST...")
	} else if c.config.TotalData != "" {
		fmt.Println("🔄 CONFIGURING DATA-BASED TEST...")
		fmt.Printf("📊 Target: %s total data\n", c.config.TotalData)
	} else {
		fmt.Println("🔄 CONFIGURING COUNT-BASED TEST...")
	}
	fmt.Printf("⚙️  Packets per worker: %d\n", packetsPerWorker)
	time.Sleep(300 * time.Millisecond)
	fmt.Println()

	// Start workers
	fmt.Printf("🚀 LAUNCHING %d WORKER(S)...\n", c.config.Workers)
	for i := 0; i < c.config.Workers; i++ {
		fmt.Printf("   🔧 Starting worker %d...\n", i+1)
		c.wg.Add(1)
		go c.worker(i, packetsPerWorker)
		time.Sleep(100 * time.Millisecond) // Stagger worker startup
	}
	fmt.Println("✅ All workers launched successfully")
	time.Sleep(500 * time.Millisecond)
	fmt.Println()

	// Handle time-based test
	if c.config.TestDuration > 0 {
		fmt.Printf("⏰ STARTING TIMER FOR %v...\n", c.config.TestDuration)
		go func() {
			time.Sleep(c.config.TestDuration)
			fmt.Println("⏰ Timer expired, signaling workers to stop...")
			close(c.done)
		}()
		fmt.Println("✅ Timer started")
		fmt.Println()
	}

	fmt.Println("🔥 BENCHMARK IN PROGRESS...")
	fmt.Println("   (Workers are running, please wait for completion)")
	fmt.Println()

	// Wait for all workers to complete
	c.wg.Wait()

	fmt.Println("🏁 ALL WORKERS COMPLETED")
	fmt.Println("📊 GENERATING FINAL REPORT...")
	time.Sleep(300 * time.Millisecond)

	// Stop metrics and print report
	c.metrics.Stop()
	c.metrics.PrintReport()

	return nil
} // worker runs the benchmark for a single worker
func (c *Client) worker(workerID, packetCount int) {
	defer c.wg.Done()

	fmt.Printf("👷 WORKER %d: INITIALIZING...\n", workerID+1)
	time.Sleep(200 * time.Millisecond)

	if c.config.Verbose {
		fmt.Printf("👷 Worker %d: Detailed logging enabled\n", workerID+1)
	}

	// Connect to server
	fmt.Printf("🔌 WORKER %d: CONNECTING TO SERVER %s...\n", workerID+1, c.config.ServerAddr)
	conn, err := network.ConnectWithTimeout(c.config.ServerAddr, c.config.ConnTimeout)
	if err != nil {
		fmt.Printf("❌ WORKER %d: CONNECTION FAILED: %v\n", workerID+1, err)
		return
	}
	defer conn.Close()

	fmt.Printf("✅ WORKER %d: CONNECTED TO %s\n", workerID+1, conn.GetRemoteAddr())
	time.Sleep(300 * time.Millisecond)

	// Perform key exchange if crypto is enabled
	if c.config.EnableCrypto {
		fmt.Printf("🔐 WORKER %d: STARTING KYBER KEY EXCHANGE...\n", workerID+1)
		encryption, err := c.performKeyExchange(conn, workerID)
		if err != nil {
			fmt.Printf("❌ WORKER %d: KEY EXCHANGE FAILED: %v\n", workerID+1, err)
			return
		}
		c.encryption = encryption

		fmt.Printf("✅ WORKER %d: KEY EXCHANGE COMPLETED SUCCESSFULLY\n", workerID+1)
		if c.config.Verbose {
			fmt.Printf("🔑 Worker %d: Symmetric encryption key derived and ready\n", workerID+1)
		}
		time.Sleep(200 * time.Millisecond)
	} else {
		fmt.Printf("🔓 WORKER %d: ENCRYPTION DISABLED - PLAINTEXT MODE\n", workerID+1)
		time.Sleep(100 * time.Millisecond)
	}

	// Generate test data
	fmt.Printf("📝 WORKER %d: GENERATING TEST DATA (%d bytes)...\n", workerID+1, c.config.PacketSize)
	testData, err := c.generateTestData()
	if err != nil {
		fmt.Printf("❌ WORKER %d: TEST DATA GENERATION FAILED: %v\n", workerID+1, err)
		return
	}
	fmt.Printf("✅ WORKER %d: TEST DATA READY\n", workerID+1)
	time.Sleep(200 * time.Millisecond)

	// Run benchmark loop
	fmt.Printf("🏃 WORKER %d: STARTING BENCHMARK LOOP...\n", workerID+1)
	if packetCount > 0 {
		fmt.Printf("📊 WORKER %d: TARGET: %d packets\n", workerID+1, packetCount)
	} else {
		fmt.Printf("📊 WORKER %d: TARGET: Time-based (until timer expires)\n", workerID+1)
	}
	time.Sleep(300 * time.Millisecond)

	c.runBenchmarkLoop(conn, workerID, testData, packetCount)

	// Send shutdown message
	fmt.Printf("🛑 WORKER %d: SENDING SHUTDOWN SIGNAL...\n", workerID+1)
	shutdownMsg := &network.Message{
		Type:    network.MsgTypeShutdown,
		Payload: []byte{},
	}
	conn.SendMessage(shutdownMsg)

	fmt.Printf("✅ WORKER %d: COMPLETED SUCCESSFULLY\n", workerID+1)
	time.Sleep(100 * time.Millisecond)
}

// performKeyExchange handles the Kyber key exchange with the server
func (c *Client) performKeyExchange(conn *network.Connection, workerID int) (*crypto.EncryptionContext, error) {
	if c.config.Verbose {
		fmt.Printf("🔄 Worker %d: Waiting for server's Kyber public key...\n", workerID+1)
	}

	// Receive server's public key
	msg, err := conn.ReceiveMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive server public key: %w", err)
	}

	if msg.Type != network.MsgTypeKeyExchange {
		return nil, fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	if c.config.Verbose {
		fmt.Printf("📬 Worker %d: Received server public key (%d bytes)\n", workerID+1, len(msg.Payload))
	}

	var keyMsg KeyExchangeMessage
	if err := json.Unmarshal(msg.Payload, &keyMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key message: %w", err)
	}

	if c.config.Verbose {
		fmt.Printf("🔐 Worker %d: Parsed public key (%d bytes)\n", workerID+1, len(keyMsg.PublicKey))
		fmt.Printf("⚙️  Worker %d: Starting Kyber encapsulation...\n", workerID+1)
	}

	// Perform encapsulation
	ciphertext, sharedSecret, err := crypto.EncapsulateSecret(keyMsg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate secret: %w", err)
	}

	if c.config.Verbose {
		fmt.Printf("✅ Worker %d: Encapsulation complete (ciphertext: %d bytes, secret: %d bytes)\n",
			workerID+1, len(ciphertext), len(sharedSecret))
		fmt.Printf("🧂 Worker %d: Generating random salt for HKDF...\n", workerID+1)
	}

	// Generate salt for key derivation
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	if c.config.Verbose {
		fmt.Printf("🔑 Worker %d: Deriving AES-256 key using HKDF...\n", workerID+1)
	}

	// Derive symmetric key
	key, err := crypto.DeriveKeyWithSalt(sharedSecret, salt, []byte("kyber-benchmark"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	if c.config.Verbose {
		fmt.Printf("✅ Worker %d: AES-256 key derived (%d bytes)\n", workerID+1, len(key))
		fmt.Printf("📤 Worker %d: Sending ciphertext and salt to server...\n", workerID+1)
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
	lastProgress := 0
	progressInterval := 1000 // Report progress every 1000 packets

	if packetCount > 0 && packetCount < progressInterval {
		progressInterval = packetCount / 10 // Adjust for smaller packet counts
		if progressInterval < 1 {
			progressInterval = 1
		}
	}

	if c.config.Verbose {
		fmt.Printf("📈 Worker %d: Progress reporting every %d packets\n", workerID+1, progressInterval)
	}

	for {
		// Check for time-based termination
		select {
		case <-c.done:
			fmt.Printf("⏰ Worker %d: Time-based test completed (%d packets sent)\n", workerID+1, sent)
			return
		default:
		}

		// Check for count-based termination
		if packetCount > 0 && sent >= packetCount {
			fmt.Printf("✅ Worker %d: Count-based test completed (%d/%d packets)\n", workerID+1, sent, packetCount)
			return
		}

		// Send benchmark packet
		if err := c.sendBenchmarkPacket(conn, testData); err != nil {
			if c.config.Verbose {
				fmt.Printf("❌ Worker %d: Failed to send packet %d: %v\n", workerID+1, sent+1, err)
			}
			c.metrics.RecordError()
			continue
		}

		// Receive response and measure latency
		startTime := time.Now()
		if err := c.receiveBenchmarkResponse(conn); err != nil {
			if c.config.Verbose {
				fmt.Printf("❌ Worker %d: Failed to receive response for packet %d: %v\n", workerID+1, sent+1, err)
			}
			c.metrics.RecordError()
			continue
		}
		latency := time.Since(startTime)

		// Record metrics
		c.metrics.RecordPacketReceived(uint64(len(testData)), latency)

		sent++

		// Progress reporting
		if sent-lastProgress >= progressInterval {
			if packetCount > 0 {
				progress := float64(sent) / float64(packetCount) * 100
				fmt.Printf("📊 Worker %d: Progress %d/%d (%.1f%%) - Avg latency: %.2fμs\n",
					workerID+1, sent, packetCount, progress, float64(latency.Nanoseconds())/1000)
			} else {
				fmt.Printf("📊 Worker %d: Sent %d packets - Last latency: %.2fμs\n",
					workerID+1, sent, float64(latency.Nanoseconds())/1000)
			}
			lastProgress = sent
		}

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
