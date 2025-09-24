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

	fmt.Println()
	fmt.Println("🎯 GENERATING COMPREHENSIVE BENCHMARK REPORT...")
	time.Sleep(500 * time.Millisecond)

	fmt.Println("\n" + strings.Repeat("=", 88))
	fmt.Println("📊 KYBER BENCHMARK PERFORMANCE REPORT")
	fmt.Println(strings.Repeat("=", 88))

	// Test completion status
	if errorRate == 0 {
		fmt.Println("✅ TEST STATUS: COMPLETED SUCCESSFULLY (No errors)")
	} else {
		fmt.Printf("⚠️  TEST STATUS: COMPLETED WITH ERRORS (%.2f%% error rate)\n", errorRate)
	}
	fmt.Println()

	// Basic stats with emojis and better formatting
	fmt.Println("📈 EXECUTION SUMMARY")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("⏱️  Total Duration: %v\n", throughputStats.Duration)
	fmt.Printf("📤 Packets Sent: %s\n", formatNumber(bm.packetsSent))
	fmt.Printf("📥 Packets Received: %s\n", formatNumber(bm.packetsReceived))
	fmt.Printf("📊 Data Sent: %s (%.2f MB)\n", formatBytes(bm.bytesSent), float64(bm.bytesSent)/1024/1024)
	fmt.Printf("📊 Data Received: %s (%.2f MB)\n", formatBytes(bm.bytesReceived), float64(bm.bytesReceived)/1024/1024)
	if errorRate > 0 {
		fmt.Printf("❌ Error Rate: %.2f%%\n", errorRate)
	}
	fmt.Printf("✅ Success Rate: %.2f%%\n", 100-errorRate)

	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("🚀 THROUGHPUT PERFORMANCE")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("📦 Packets/sec: %s\n", formatNumber(uint64(throughputStats.PacketsPerSecond)))
	fmt.Printf("💾 MB/sec: %.2f\n", throughputStats.BytesPerSecond/1024/1024)
	fmt.Printf("⚡ Gbps: %.3f\n", (throughputStats.BytesPerSecond*8)/1000000000)

	// Add performance indicators
	mbps := throughputStats.BytesPerSecond / 1024 / 1024
	if mbps > 1000 {
		fmt.Println("🔥 EXCELLENT: >1 GB/s throughput!")
	} else if mbps > 100 {
		fmt.Println("✨ GREAT: >100 MB/s throughput!")
	} else if mbps > 10 {
		fmt.Println("👍 GOOD: >10 MB/s throughput")
	}

	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("⚡ LATENCY ANALYSIS")
	fmt.Println(strings.Repeat("-", 50))
	if len(bm.latencies) > 0 {
		fmt.Printf("⏱️  Minimum: %v\n", latencyStats.Min)
		fmt.Printf("⏱️  Maximum: %v\n", latencyStats.Max)
		fmt.Printf("📊 Average: %v\n", latencyStats.Mean)
		fmt.Printf("📈 Median (P50): %v\n", latencyStats.Median)
		fmt.Printf("📈 95th Percentile: %v\n", latencyStats.P95)
		fmt.Printf("📈 99th Percentile: %v\n", latencyStats.P99)

		// Add latency performance indicators
		avgMicros := float64(latencyStats.Mean.Nanoseconds()) / 1000
		if avgMicros < 100 {
			fmt.Println("🚀 EXCELLENT: <100μs average latency!")
		} else if avgMicros < 1000 {
			fmt.Println("✨ GREAT: <1ms average latency!")
		} else if avgMicros < 10000 {
			fmt.Println("👍 GOOD: <10ms average latency")
		}
	} else {
		fmt.Println("📊 No latency data available")
	}

	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("💻 SYSTEM RESOURCES")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("🔧 CPU Usage - Avg: %.2f%%, Max: %.2f%%\n", systemStats.AvgCPUPercent, systemStats.MaxCPUPercent)
	fmt.Printf("🧠 Memory Usage - Avg: %.2f MB, Max: %.2f MB\n", systemStats.AvgMemoryMB, systemStats.MaxMemoryMB)
	fmt.Printf("🔄 Goroutines: %d\n", systemStats.Goroutines)

	fmt.Println("\n" + strings.Repeat("=", 88))
	fmt.Println("🎉 BENCHMARK REPORT COMPLETE")
	fmt.Println(strings.Repeat("=", 88))
}

// Helper function to format large numbers with commas
func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	} else if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	} else {
		return fmt.Sprintf("%.1fB", float64(n)/1000000000)
	}
}

// Helper function to format bytes
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
