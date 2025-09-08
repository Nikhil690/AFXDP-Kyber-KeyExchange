package optimizations

import (
	"net"
	"sync"
	"time"
)

// ConnectionKey represents a unique connection identifier
type ConnectionKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// FastConnectionManager provides optimized connection management
type FastConnectionManager struct {
	connections map[ConnectionKey]*ConnectionState
	mutex       sync.RWMutex
	pool        sync.Pool
	cleanupTick time.Duration
	maxIdle     time.Duration
}

type ConnectionState struct {
	Key         ConnectionKey
	State       int
	LastSeen    time.Time
	SendSeq     uint32
	SendAck     uint32
	RecvSeq     uint32
	RecvAck     uint32
	HelloSent   bool
	CryptoState interface{} // For storing crypto-related state
}

func NewFastConnectionManager(cleanupInterval, maxIdleTime time.Duration) *FastConnectionManager {
	fcm := &FastConnectionManager{
		connections: make(map[ConnectionKey]*ConnectionState),
		pool: sync.Pool{
			New: func() interface{} {
				return &ConnectionState{}
			},
		},
		cleanupTick: cleanupInterval,
		maxIdle:     maxIdleTime,
	}

	// Start cleanup goroutine
	go fcm.cleanupRoutine()

	return fcm
}

// IPToUint32 converts net.IP to uint32 for faster comparison
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// CreateConnectionKey creates a connection key efficiently
func CreateConnectionKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) ConnectionKey {
	return ConnectionKey{
		SrcIP:   IPToUint32(srcIP),
		DstIP:   IPToUint32(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// GetConnection retrieves or creates a connection state
func (fcm *FastConnectionManager) GetConnection(key ConnectionKey) *ConnectionState {
	fcm.mutex.RLock()
	conn, exists := fcm.connections[key]
	fcm.mutex.RUnlock()

	if exists {
		conn.LastSeen = time.Now()
		return conn
	}

	// Create new connection
	fcm.mutex.Lock()
	defer fcm.mutex.Unlock()

	// Double-check after acquiring write lock
	if conn, exists := fcm.connections[key]; exists {
		conn.LastSeen = time.Now()
		return conn
	}

	// Get connection state from pool
	conn = fcm.pool.Get().(*ConnectionState)
	conn.Key = key
	conn.State = 0 // CLOSED
	conn.LastSeen = time.Now()
	conn.SendSeq = 0
	conn.SendAck = 0
	conn.RecvSeq = 0
	conn.RecvAck = 0
	conn.HelloSent = false
	conn.CryptoState = nil

	fcm.connections[key] = conn
	return conn
}

// RemoveConnection removes a connection and returns it to the pool
func (fcm *FastConnectionManager) RemoveConnection(key ConnectionKey) {
	fcm.mutex.Lock()
	defer fcm.mutex.Unlock()

	if conn, exists := fcm.connections[key]; exists {
		delete(fcm.connections, key)
		fcm.pool.Put(conn)
	}
}

// GetConnectionCount returns the number of active connections
func (fcm *FastConnectionManager) GetConnectionCount() int {
	fcm.mutex.RLock()
	defer fcm.mutex.RUnlock()
	return len(fcm.connections)
}

// cleanupRoutine periodically removes idle connections
func (fcm *FastConnectionManager) cleanupRoutine() {
	ticker := time.NewTicker(fcm.cleanupTick)
	defer ticker.Stop()

	for range ticker.C {
		fcm.cleanupIdleConnections()
	}
}

func (fcm *FastConnectionManager) cleanupIdleConnections() {
	now := time.Now()
	var toRemove []ConnectionKey

	fcm.mutex.RLock()
	for key, conn := range fcm.connections {
		if now.Sub(conn.LastSeen) > fcm.maxIdle {
			toRemove = append(toRemove, key)
		}
	}
	fcm.mutex.RUnlock()

	if len(toRemove) > 0 {
		fcm.mutex.Lock()
		for _, key := range toRemove {
			if conn, exists := fcm.connections[key]; exists {
				delete(fcm.connections, key)
				fcm.pool.Put(conn)
			}
		}
		fcm.mutex.Unlock()
	}
}

// ConnectionStats provides connection statistics
type ConnectionStats struct {
	ActiveConnections int
	TotalConnections  int64
	CleanedUp         int64
}

func (fcm *FastConnectionManager) GetStats() ConnectionStats {
	fcm.mutex.RLock()
	defer fcm.mutex.RUnlock()

	return ConnectionStats{
		ActiveConnections: len(fcm.connections),
		// Add counters for total and cleaned up if needed
	}
}
