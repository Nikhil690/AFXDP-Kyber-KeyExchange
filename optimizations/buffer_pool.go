package optimizations

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BufferPool manages reusable buffers for packet processing
type BufferPool struct {
	buffers     chan []byte
	serBuffers  chan gopacket.SerializeBuffer
	maxSize     int
	defaultSize int
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(poolSize, defaultBufferSize int) *BufferPool {
	bp := &BufferPool{
		buffers:     make(chan []byte, poolSize),
		serBuffers:  make(chan gopacket.SerializeBuffer, poolSize),
		maxSize:     poolSize,
		defaultSize: defaultBufferSize,
	}

	// Pre-populate the pool
	for i := 0; i < poolSize; i++ {
		bp.buffers <- make([]byte, defaultBufferSize)
		bp.serBuffers <- gopacket.NewSerializeBuffer()
	}

	return bp
}

// GetBuffer returns a buffer from the pool
func (bp *BufferPool) GetBuffer() []byte {
	select {
	case buf := <-bp.buffers:
		return buf[:0] // Reset length but keep capacity
	default:
		return make([]byte, 0, bp.defaultSize) // Create new if pool empty
	}
}

// PutBuffer returns a buffer to the pool
func (bp *BufferPool) PutBuffer(buf []byte) {
	if cap(buf) >= bp.defaultSize {
		select {
		case bp.buffers <- buf:
		default:
			// Pool is full, discard buffer
		}
	}
}

// GetSerializeBuffer returns a serialize buffer from the pool
func (bp *BufferPool) GetSerializeBuffer() gopacket.SerializeBuffer {
	select {
	case buf := <-bp.serBuffers:
		buf.Clear()
		return buf
	default:
		return gopacket.NewSerializeBuffer()
	}
}

// PutSerializeBuffer returns a serialize buffer to the pool
func (bp *BufferPool) PutSerializeBuffer(buf gopacket.SerializeBuffer) {
	select {
	case bp.serBuffers <- buf:
	default:
		// Pool is full, discard buffer
	}
}

// PacketDataPool manages pre-allocated packet data structures
type PacketDataPool struct {
	pool sync.Pool
}

func NewPacketDataPool() *PacketDataPool {
	return &PacketDataPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &PacketData{}
			},
		},
	}
}

type PacketData struct {
	TCP *layers.TCP
	IP  *layers.IPv4
	ETH *layers.Ethernet
}

func (pdp *PacketDataPool) Get() *PacketData {
	return pdp.pool.Get().(*PacketData)
}

func (pdp *PacketDataPool) Put(pd *PacketData) {
	// Reset the data
	pd.TCP = nil
	pd.IP = nil
	pd.ETH = nil
	pdp.pool.Put(pd)
}
