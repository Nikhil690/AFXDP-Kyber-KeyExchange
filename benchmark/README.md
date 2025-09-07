# Kyber-Benchmark: High-Performance Post-Quantum Cryptography Benchmarking

A Go-based client-server benchmarking application for high-performance networking with post-quantum cryptography (Kyber KEM) integration.

## Features

- **Post-Quantum Cryptography**: Uses Kyber-768 KEM for key exchange
- **Symmetric Encryption**: AES-256-GCM for payload encryption
- **High-Performance Networking**: TCP-based client-server architecture
- **Comprehensive Metrics**: Throughput, latency, CPU/memory usage tracking
- **Configurable Parameters**: Packet size, count, encryption toggle, worker threads
- **Graceful Shutdown**: Proper cleanup and metrics reporting

## Architecture

```
crypto/         → Kyber KEM + AES-GCM/HKDF utilities
network/        → TCP networking logic
metrics/        → Throughput, latency, CPU usage collection
server/         → Server main entrypoint
client/         → Client main entrypoint
```

## Protocol Flow

1. **Server Setup**: Server generates Kyber keypair and listens for connections
2. **Client Connection**: Client connects to server
3. **Key Exchange**: 
   - Server sends Kyber public key to client
   - Client performs encapsulation, sends ciphertext + salt
   - Both derive the same symmetric key using HKDF
4. **Benchmarking**: Client sends N packets, server echoes responses
5. **Metrics Collection**: Both sides collect performance metrics
6. **Report Generation**: Comprehensive performance report

## Building

```bash
# Download dependencies
go mod tidy

# Build server
go build -o server ./server

# Build client  
go build -o client ./client
```

## Usage

### Server

```bash
# Basic server (default port 8080, encryption enabled)
./server

# Custom configuration
./server -port 9090 -crypto=false -max-clients 50 -verbose
```

**Server Options:**
- `-port`: Server port (default: 8080)
- `-crypto`: Enable encryption (default: true)
- `-max-clients`: Maximum concurrent clients (default: 100)
- `-verbose`: Enable verbose logging (default: false)

### Client

```bash
# Basic client (1KB packets, 10k count)
./client -server localhost:8080

# High throughput test
./client -server localhost:8080 -size 64000 -count 100000 -workers 10

# Time-based test
./client -server localhost:8080 -duration 30s -workers 5

# Unencrypted test
./client -server localhost:8080 -crypto=false -size 1024 -count 50000
```

**Client Options:**
- `-server`: Server address (default: localhost:8080)
- `-size`: Packet size in bytes (default: 1024)
- `-count`: Number of packets to send (default: 10000, 0 for time-based)
- `-workers`: Number of concurrent workers (default: 1)
- `-crypto`: Enable encryption (default: true)
- `-verbose`: Enable verbose logging (default: false)
- `-timeout`: Connection timeout (default: 10s)
- `-duration`: Test duration for time-based tests (default: 0, disabled)

## Example Runs

### High Throughput Test
```bash
# Terminal 1 (Server)
./server -verbose

# Terminal 2 (Client)
./client -size 64000 -count 50000 -workers 8 -verbose
```

### Latency Test
```bash
# Terminal 1 (Server)
./server

# Terminal 2 (Client) 
./client -size 64 -count 100000 -workers 1
```

### Unencrypted Baseline
```bash
# Terminal 1 (Server)
./server -crypto=false

# Terminal 2 (Client)
./client -crypto=false -size 1024 -count 50000 -workers 4
```

## Sample Output

```
================================================================================
BENCHMARK REPORT
================================================================================
Duration: 15.234s
Packets Sent: 50000
Packets Received: 50000  
Bytes Sent: 53248000 (50.80 MB)
Bytes Received: 53248000 (50.80 MB)
Error Rate: 0.00%

----------------------------------------
THROUGHPUT
----------------------------------------
Packets/sec: 3281.45
MB/sec: 3.33
Gbps: 0.027

----------------------------------------
LATENCY
----------------------------------------
Min: 156.2µs
Max: 2.134ms
Mean: 294.7µs
Median: 267.3µs
95th percentile: 445.6µs
99th percentile: 623.1µs

----------------------------------------
SYSTEM RESOURCES
----------------------------------------
Avg CPU%: 12.45
Max CPU%: 18.23
Avg Memory: 15.67 MB
Max Memory: 18.90 MB
Goroutines: 12
================================================================================
```

## Performance Considerations

### Network Optimization
- Use large packet sizes (32KB+) for maximum throughput
- Multiple workers can improve concurrent performance
- Consider network buffer tuning for high-speed networks

### Crypto Performance
- Kyber-768 provides excellent performance vs. security tradeoff
- AES-256-GCM leverages hardware acceleration when available
- Key derivation is performed once per connection

### Memory Usage
- Pre-allocated buffers minimize GC pressure
- Metrics collection uses bounded memory
- Connection pooling reduces allocation overhead

## Dependencies

- **github.com/cloudflare/circl**: Cloudflare's post-quantum crypto library
- **golang.org/x/crypto**: Extended Go cryptography package

## Testing Different Scenarios

### Encryption Impact Analysis
```bash
# Test with encryption
./client -crypto=true -size 1024 -count 10000

# Test without encryption  
./client -crypto=false -size 1024 -count 10000
```

### Scalability Testing
```bash
# Single worker
./client -workers 1 -count 10000

# Multiple workers
./client -workers 8 -count 10000
```

### Large Transfer Testing
```bash
# Large packets
./client -size 65536 -count 1000 -workers 4
```

## Security Notes

- Uses Kyber-768 (NIST Level 3 security)
- HKDF provides proper key derivation
- AES-256-GCM ensures authenticated encryption
- Random nonces prevent replay attacks
- Separate keys per client session

## Troubleshooting

### Connection Issues
- Check firewall settings
- Verify server is listening on correct port
- Ensure network connectivity

### Performance Issues
- Monitor system resources (CPU, memory, network)
- Try different packet sizes and worker counts
- Check for network bottlenecks

### Crypto Errors
- Ensure both client and server have same crypto settings
- Check for version compatibility
- Verify proper key exchange completion

## Future Enhancements

- [ ] UDP transport option
- [ ] Additional KEM algorithms (NTRU, SABER)
- [ ] ChaCha20-Poly1305 cipher option
- [ ] Prometheus metrics export
- [ ] TLS wrapper support
- [ ] Batch processing optimization
