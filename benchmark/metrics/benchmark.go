package metrics

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// BenchmarkMetrics holds all benchmark measurements
type BenchmarkMetrics struct {
	mutex           sync.RWMutex
	startTime       time.Time
	endTime         time.Time
	packetsSent     uint64
	packetsReceived uint64
	bytesSent       uint64
	bytesReceived   uint64
	latencies       []time.Duration
	errors          uint64

	// CPU and memory tracking
	cpuSamples    []float64
	memorySamples []uint64
	samplingStop  chan bool
	samplingDone  chan bool
}

// LatencyStats holds latency statistics
type LatencyStats struct {
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
	P95    time.Duration
	P99    time.Duration
}

// ThroughputStats holds throughput statistics
type ThroughputStats struct {
	PacketsPerSecond float64
	BytesPerSecond   float64
	Duration         time.Duration
}

// SystemStats holds system resource statistics
type SystemStats struct {
	AvgCPUPercent float64
	MaxCPUPercent float64
	AvgMemoryMB   float64
	MaxMemoryMB   float64
	Goroutines    int
}

// NewBenchmarkMetrics creates a new metrics collector
func NewBenchmarkMetrics() *BenchmarkMetrics {
	return &BenchmarkMetrics{
		latencies:    make([]time.Duration, 0, 10000), // Pre-allocate for performance
		samplingStop: make(chan bool),
		samplingDone: make(chan bool),
	}
}

// Start begins the benchmark measurement
func (bm *BenchmarkMetrics) Start() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.startTime = time.Now()
	bm.packetsSent = 0
	bm.packetsReceived = 0
	bm.bytesSent = 0
	bm.bytesReceived = 0
	bm.errors = 0
	bm.latencies = bm.latencies[:0] // Reset slice but keep capacity
	bm.cpuSamples = bm.cpuSamples[:0]
	bm.memorySamples = bm.memorySamples[:0]

	// Start system resource monitoring
	go bm.sampleSystemResources()
}

// Stop ends the benchmark measurement
func (bm *BenchmarkMetrics) Stop() {
	bm.mutex.Lock()
	bm.endTime = time.Now()
	bm.mutex.Unlock()

	// Stop system resource monitoring
	close(bm.samplingStop)
	<-bm.samplingDone
}

// RecordPacketSent records a sent packet
func (bm *BenchmarkMetrics) RecordPacketSent(bytes uint64) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	bm.packetsSent++
	bm.bytesSent += bytes
}

// RecordPacketReceived records a received packet with latency
func (bm *BenchmarkMetrics) RecordPacketReceived(bytes uint64, latency time.Duration) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	bm.packetsReceived++
	bm.bytesReceived += bytes
	bm.latencies = append(bm.latencies, latency)
}

// RecordError records an error
func (bm *BenchmarkMetrics) RecordError() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	bm.errors++
}

// GetLatencyStats calculates latency statistics
func (bm *BenchmarkMetrics) GetLatencyStats() LatencyStats {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	if len(bm.latencies) == 0 {
		return LatencyStats{}
	}

	// Sort latencies for percentile calculations
	sorted := make([]time.Duration, len(bm.latencies))
	copy(sorted, bm.latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// Calculate statistics
	var total time.Duration
	for _, latency := range sorted {
		total += latency
	}

	count := len(sorted)
	mean := total / time.Duration(count)

	return LatencyStats{
		Min:    sorted[0],
		Max:    sorted[count-1],
		Mean:   mean,
		Median: sorted[count/2],
		P95:    sorted[int(float64(count)*0.95)],
		P99:    sorted[int(float64(count)*0.99)],
	}
}

// GetThroughputStats calculates throughput statistics
func (bm *BenchmarkMetrics) GetThroughputStats() ThroughputStats {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	duration := bm.endTime.Sub(bm.startTime)
	if duration == 0 {
		return ThroughputStats{}
	}

	seconds := duration.Seconds()

	return ThroughputStats{
		PacketsPerSecond: float64(bm.packetsReceived) / seconds,
		BytesPerSecond:   float64(bm.bytesReceived) / seconds,
		Duration:         duration,
	}
}

// GetSystemStats calculates system resource statistics
func (bm *BenchmarkMetrics) GetSystemStats() SystemStats {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	var avgCPU, maxCPU float64
	var avgMem, maxMem float64

	if len(bm.cpuSamples) > 0 {
		var totalCPU float64
		for _, cpu := range bm.cpuSamples {
			totalCPU += cpu
			if cpu > maxCPU {
				maxCPU = cpu
			}
		}
		avgCPU = totalCPU / float64(len(bm.cpuSamples))
	}

	if len(bm.memorySamples) > 0 {
		var totalMem uint64
		for _, mem := range bm.memorySamples {
			totalMem += mem
			if float64(mem) > maxMem {
				maxMem = float64(mem)
			}
		}
		avgMem = float64(totalMem) / float64(len(bm.memorySamples))
	}

	return SystemStats{
		AvgCPUPercent: avgCPU,
		MaxCPUPercent: maxCPU,
		AvgMemoryMB:   avgMem / 1024 / 1024, // Convert to MB
		MaxMemoryMB:   maxMem / 1024 / 1024, // Convert to MB
		Goroutines:    runtime.NumGoroutine(),
	}
}

// GetErrorRate returns the error rate as a percentage
func (bm *BenchmarkMetrics) GetErrorRate() float64 {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	total := bm.packetsSent
	if total == 0 {
		return 0.0
	}

	return (float64(bm.errors) / float64(total)) * 100.0
}

// sampleSystemResources periodically samples CPU and memory usage
func (bm *BenchmarkMetrics) sampleSystemResources() {
	defer close(bm.samplingDone)

	ticker := time.NewTicker(100 * time.Millisecond) // Sample every 100ms
	defer ticker.Stop()

	var prevStats runtime.MemStats
	runtime.ReadMemStats(&prevStats)

	for {
		select {
		case <-bm.samplingStop:
			return
		case <-ticker.C:
			// Sample memory
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			bm.mutex.Lock()
			bm.memorySamples = append(bm.memorySamples, memStats.Alloc)
			// For CPU, we'll use a simple approximation based on runtime stats
			// In a production system, you might want to use OS-specific APIs
			bm.cpuSamples = append(bm.cpuSamples, float64(runtime.NumGoroutine())*0.1) // Placeholder
			bm.mutex.Unlock()
		}
	}
}

// PrintReport prints a comprehensive benchmark report
func (bm *BenchmarkMetrics) PrintReport() {
	latencyStats := bm.GetLatencyStats()
	throughputStats := bm.GetThroughputStats()
	systemStats := bm.GetSystemStats()
	errorRate := bm.GetErrorRate()

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("BENCHMARK REPORT")
	fmt.Println(strings.Repeat("=", 80))

	// Basic stats
	fmt.Printf("Duration: %v\n", throughputStats.Duration)
	fmt.Printf("Packets Sent: %d\n", bm.packetsSent)
	fmt.Printf("Packets Received: %d\n", bm.packetsReceived)
	fmt.Printf("Bytes Sent: %d (%.2f MB)\n", bm.bytesSent, float64(bm.bytesSent)/1024/1024)
	fmt.Printf("Bytes Received: %d (%.2f MB)\n", bm.bytesReceived, float64(bm.bytesReceived)/1024/1024)
	fmt.Printf("Error Rate: %.2f%%\n", errorRate)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("THROUGHPUT")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Packets/sec: %.2f\n", throughputStats.PacketsPerSecond)
	fmt.Printf("MB/sec: %.2f\n", throughputStats.BytesPerSecond/1024/1024)
	fmt.Printf("Gbps: %.2f\n", (throughputStats.BytesPerSecond*8)/1000000000)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("LATENCY")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Min: %v\n", latencyStats.Min)
	fmt.Printf("Max: %v\n", latencyStats.Max)
	fmt.Printf("Mean: %v\n", latencyStats.Mean)
	fmt.Printf("Median: %v\n", latencyStats.Median)
	fmt.Printf("95th percentile: %v\n", latencyStats.P95)
	fmt.Printf("99th percentile: %v\n", latencyStats.P99)

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("SYSTEM RESOURCES")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Avg CPU%%: %.2f\n", systemStats.AvgCPUPercent)
	fmt.Printf("Max CPU%%: %.2f\n", systemStats.MaxCPUPercent)
	fmt.Printf("Avg Memory: %.2f MB\n", systemStats.AvgMemoryMB)
	fmt.Printf("Max Memory: %.2f MB\n", systemStats.MaxMemoryMB)
	fmt.Printf("Goroutines: %d\n", systemStats.Goroutines)

	fmt.Println(strings.Repeat("=", 80))
}
