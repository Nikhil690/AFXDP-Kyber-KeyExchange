package ntsm

// TCPState represents the various states in the TCP state machine
type TCPState int

const (
	CLOSED TCPState = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSE_WAIT
	CLOSING
	LAST_ACK
	TIME_WAIT
)

// String returns the string representation of the TCP state
func (s TCPState) String() string {
	states := []string{
		"CLOSED",
		"LISTEN",
		"SYN_SENT",
		"SYN_RECEIVED",
		"ESTABLISHED",
		"FIN_WAIT_1",
		"FIN_WAIT_2",
		"CLOSE_WAIT",
		"CLOSING",
		"LAST_ACK",
		"TIME_WAIT",
	}
	if int(s) < len(states) {
		return states[s]
	}
	return "UNKNOWN"
}

// IsClosedState returns true if the connection is in a closed state
func (s TCPState) IsClosedState() bool {
	return s == CLOSED || s == TIME_WAIT
}

// CanSendData returns true if the connection can send data
func (s TCPState) CanSendData() bool {
	return s == ESTABLISHED || s == CLOSE_WAIT
}

// CanReceiveData returns true if the connection can receive data
func (s TCPState) CanReceiveData() bool {
	return s == ESTABLISHED || s == FIN_WAIT_1 || s == FIN_WAIT_2
}
