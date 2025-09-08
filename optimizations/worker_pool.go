package optimizations

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	sxdp "github.com/slavc/xdp"
)

// PacketWorkItem represents a packet to be processed
type PacketWorkItem struct {
	Packet   gopacket.Packet
	Frame    []byte
	Desc     sxdp.Desc
	RecvTime time.Time
}

// PacketProcessor defines the interface for processing packets
type PacketProcessor interface {
	ProcessPacket(item *PacketWorkItem) error
}

// WorkerPool manages a pool of workers for packet processing
type WorkerPool struct {
	workers    int
	workQueue  chan *PacketWorkItem
	quit       chan struct{}
	wg         sync.WaitGroup
	processor  PacketProcessor
	bufferPool *BufferPool
	stats      WorkerStats
	statsMutex sync.RWMutex
}

type WorkerStats struct {
	PacketsProcessed uint64
	PacketsDropped   uint64
	ProcessingTime   time.Duration
	QueueDepth       int
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount, queueSize int, processor PacketProcessor, bufferPool *BufferPool) *WorkerPool {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	wp := &WorkerPool{
		workers:    workerCount,
		workQueue:  make(chan *PacketWorkItem, queueSize),
		quit:       make(chan struct{}),
		processor:  processor,
		bufferPool: bufferPool,
	}

	return wp
}

// Start starts the worker pool
func (wp *WorkerPool) Start(ctx context.Context) {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}

	// Start stats collector
	go wp.statsCollector(ctx)
}

// Stop gracefully stops the worker pool
func (wp *WorkerPool) Stop() {
	close(wp.quit)
	wp.wg.Wait()
}

// SubmitPacket submits a packet for processing
func (wp *WorkerPool) SubmitPacket(packet gopacket.Packet, frame []byte, desc sxdp.Desc) bool {
	item := &PacketWorkItem{
		Packet:   packet,
		Frame:    frame,
		Desc:     desc,
		RecvTime: time.Now(),
	}

	select {
	case wp.workQueue <- item:
		return true
	default:
		wp.incrementDropped()
		return false // Queue is full, drop packet
	}
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.quit:
			return
		case item := <-wp.workQueue:
			start := time.Now()

			if err := wp.processor.ProcessPacket(item); err != nil {
				// Log error or handle as needed
			}

			processingTime := time.Since(start)
			wp.updateStats(processingTime)
		}
	}
}

func (wp *WorkerPool) incrementDropped() {
	wp.statsMutex.Lock()
	wp.stats.PacketsDropped++
	wp.statsMutex.Unlock()
}

func (wp *WorkerPool) updateStats(processingTime time.Duration) {
	wp.statsMutex.Lock()
	wp.stats.PacketsProcessed++
	wp.stats.ProcessingTime += processingTime
	wp.statsMutex.Unlock()
}

func (wp *WorkerPool) statsCollector(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.quit:
			return
		case <-ticker.C:
			wp.statsMutex.Lock()
			wp.stats.QueueDepth = len(wp.workQueue)
			wp.statsMutex.Unlock()
		}
	}
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerStats {
	wp.statsMutex.RLock()
	defer wp.statsMutex.RUnlock()
	return wp.stats
}

// AdaptiveWorkerPool automatically adjusts worker count based on load
type AdaptiveWorkerPool struct {
	*WorkerPool
	minWorkers    int
	maxWorkers    int
	scaleUpThresh float64
	scaleDownTh   float64
	lastScale     time.Time
	scaleCooldown time.Duration
}

func NewAdaptiveWorkerPool(minWorkers, maxWorkers, initialQueueSize int, processor PacketProcessor, bufferPool *BufferPool) *AdaptiveWorkerPool {
	return &AdaptiveWorkerPool{
		WorkerPool:    NewWorkerPool(minWorkers, initialQueueSize, processor, bufferPool),
		minWorkers:    minWorkers,
		maxWorkers:    maxWorkers,
		scaleUpThresh: 0.8, // Scale up when queue is 80% full
		scaleDownTh:   0.2, // Scale down when queue is 20% full
		scaleCooldown: 5 * time.Second,
	}
}

// MonitorAndScale monitors queue depth and adjusts workers
func (awp *AdaptiveWorkerPool) MonitorAndScale(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-awp.quit:
			return
		case <-ticker.C:
			awp.checkAndScale()
		}
	}
}

func (awp *AdaptiveWorkerPool) checkAndScale() {
	if time.Since(awp.lastScale) < awp.scaleCooldown {
		return
	}

	stats := awp.GetStats()
	queueUtilization := float64(stats.QueueDepth) / float64(cap(awp.workQueue))

	if queueUtilization > awp.scaleUpThresh && awp.workers < awp.maxWorkers {
		awp.scaleUp()
	} else if queueUtilization < awp.scaleDownTh && awp.workers > awp.minWorkers {
		awp.scaleDown()
	}
}

func (awp *AdaptiveWorkerPool) scaleUp() {
	// Implementation depends on how you want to handle dynamic scaling
	// This is a simplified version
	awp.workers++
	awp.lastScale = time.Now()
	// Start new worker goroutine here
}

func (awp *AdaptiveWorkerPool) scaleDown() {
	if awp.workers > awp.minWorkers {
		awp.workers--
		awp.lastScale = time.Now()
		// Signal one worker to stop (implementation specific)
	}
}
