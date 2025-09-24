package ntsm

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnectionKey uniquely identifies a TCP connection
type ConnectionKey struct {
	LocalIP    [4]byte // Use fixed-size array instead of net.IP slice
	LocalPort  uint16
	RemoteIP   [4]byte // Use fixed-size array instead of net.IP slice
	RemotePort uint16
}

// NewConnectionKey creates a new connection key from net.IP addresses
func NewConnectionKey(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) ConnectionKey {
	var localIPBytes, remoteIPBytes [4]byte
	copy(localIPBytes[:], localIP.To4())
	copy(remoteIPBytes[:], remoteIP.To4())

	return ConnectionKey{
		LocalIP:    localIPBytes,
		LocalPort:  localPort,
		RemoteIP:   remoteIPBytes,
		RemotePort: remotePort,
	}
}

// String returns a string representation of the connection key
func (k ConnectionKey) String() string {
	localIP := net.IP(k.LocalIP[:])
	remoteIP := net.IP(k.RemoteIP[:])
	return fmt.Sprintf("%s:%d -> %s:%d", localIP, k.LocalPort, remoteIP, k.RemotePort)
}

// SequenceSpace tracks TCP sequence numbers
type SequenceSpace struct {
	ISS     uint32 // Initial Send Sequence
	SND_UNA uint32 // Send Unacknowledged
	SND_NXT uint32 // Send Next
	SND_WND uint32 // Send Window

	IRS     uint32 // Initial Receive Sequence
	RCV_NXT uint32 // Receive Next
	RCV_WND uint32 // Receive Window
}

// RetransmissionTimer manages retransmission timing
type RetransmissionTimer struct {
	RTO      time.Duration // Retransmission Timeout
	SRTT     time.Duration // Smoothed Round Trip Time
	RTTVAR   time.Duration // Round Trip Time Variation
	LastSent time.Time     // Last transmission time
	Active   bool          // Timer is active
}

// NewRetransmissionTimer creates a new retransmission timer
func NewRetransmissionTimer() *RetransmissionTimer {
	return &RetransmissionTimer{
		RTO:    time.Second, // Initial RTO of 1 second
		SRTT:   0,
		RTTVAR: 0,
		Active: false,
	}
}

// Start activates the retransmission timer
func (rt *RetransmissionTimer) Start() {
	rt.LastSent = time.Now()
	rt.Active = true
}

// Stop deactivates the retransmission timer
func (rt *RetransmissionTimer) Stop() {
	rt.Active = false
}

// IsExpired checks if the timer has expired
func (rt *RetransmissionTimer) IsExpired() bool {
	if !rt.Active {
		return false
	}
	return time.Since(rt.LastSent) >= rt.RTO
}

// UpdateRTT updates the RTT estimates
func (rt *RetransmissionTimer) UpdateRTT(rtt time.Duration) {
	if rt.SRTT == 0 {
		rt.SRTT = rtt
		rt.RTTVAR = rtt / 2
	} else {
		rt.RTTVAR = (3*rt.RTTVAR + absDuration(rt.SRTT-rtt)) / 4
		rt.SRTT = (7*rt.SRTT + rtt) / 8
	}
	rt.RTO = rt.SRTT + max(time.Millisecond*100, 4*rt.RTTVAR)

	// Clamp RTO to reasonable bounds
	if rt.RTO < time.Millisecond*200 {
		rt.RTO = time.Millisecond * 200
	}
	if rt.RTO > time.Second*60 {
		rt.RTO = time.Second * 60
	}
}

// Connection represents a TCP connection's control block
type Connection struct {
	mu sync.RWMutex

	// Connection identification
	Key ConnectionKey

	// State machine
	State TCPState

	// Sequence space
	Seq SequenceSpace

	// MSS (Maximum Segment Size)
	MSS uint16

	// Send buffer - data waiting to be sent
	SendBuffer []byte

	// Receive buffer - out-of-order segments
	ReceiveBuffer map[uint32][]byte

	// Reassembled data ready for application
	ReadyData []byte

	// Retransmission management
	RetransTimer *RetransmissionTimer
	UnackedData  []byte // Data that has been sent but not acknowledged

	// Window management
	WindowScale uint8

	// Congestion control
	CwndSize    uint32 // Congestion window size
	SSThresh    uint32 // Slow start threshold
	DupAckCount int    // Duplicate ACK counter

	// Timers
	TimeWaitExpiry time.Time

	// Flags
	IsPassive bool // True if this is a passive (listening) connection
}

// NewConnection creates a new TCP connection
func NewConnection(key ConnectionKey, isPassive bool) *Connection {
	return &Connection{
		Key:           key,
		State:         CLOSED,
		Seq:           SequenceSpace{},
		MSS:           1460, // Default MSS for Ethernet
		SendBuffer:    make([]byte, 0),
		ReceiveBuffer: make(map[uint32][]byte),
		ReadyData:     make([]byte, 0),
		RetransTimer:  NewRetransmissionTimer(),
		UnackedData:   make([]byte, 0),
		WindowScale:   0,
		CwndSize:      1460, // Start with 1 MSS
		SSThresh:      65535,
		DupAckCount:   0,
		IsPassive:     isPassive,
	}
}

// Lock acquires the connection lock
func (c *Connection) Lock() {
	c.mu.Lock()
}

// Unlock releases the connection lock
func (c *Connection) Unlock() {
	c.mu.Unlock()
}

// RLock acquires the connection read lock
func (c *Connection) RLock() {
	c.mu.RLock()
}

// RUnlock releases the connection read lock
func (c *Connection) RUnlock() {
	c.mu.RUnlock()
}

// Utility functions
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
