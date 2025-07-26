package tsm

import (
    "fmt"
    "net"
    "sync"
    "time"
    
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

// TCPState represents RFC 793 TCP connection states
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

func (s TCPState) String() string {
    states := []string{
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED",
        "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
    }
    if int(s) < len(states) {
        return states[s]
    }
    return "UNKNOWN"
}

// TCPEvent represents events that can trigger state transitions
type TCPEvent int

const (
    EVENT_OPEN TCPEvent = iota
    EVENT_SEND_SYN
    EVENT_RECV_SYN
    EVENT_RECV_SYN_ACK
    EVENT_RECV_ACK
    EVENT_SEND_DATA
    EVENT_RECV_DATA
    EVENT_CLOSE
    EVENT_SEND_FIN
    EVENT_RECV_FIN
    EVENT_RECV_RST
    EVENT_TIMEOUT
)

func (e TCPEvent) String() string {
    events := []string{
        "OPEN", "SEND_SYN", "RECV_SYN", "RECV_SYN_ACK", "RECV_ACK",
        "SEND_DATA", "RECV_DATA", "CLOSE", "SEND_FIN", "RECV_FIN", "RECV_RST", "TIMEOUT",
    }
    if int(e) < len(events) {
        return events[e]
    }
    return "UNKNOWN"
}

// TCPAction represents actions to take during state transitions
type TCPAction int

const (
    ACTION_NONE TCPAction = iota
    ACTION_SEND_SYN
    ACTION_SEND_SYN_ACK
    ACTION_SEND_ACK
    ACTION_SEND_FIN
    ACTION_SEND_RST
    ACTION_SEND_DATA
    ACTION_DELIVER_DATA
    ACTION_NOTIFY_APP
    ACTION_START_TIMER
    ACTION_CANCEL_TIMER
)

func (a TCPAction) String() string {
    actions := []string{
        "NONE", "SEND_SYN", "SEND_SYN_ACK", "SEND_ACK", "SEND_FIN",
        "SEND_RST", "SEND_DATA", "DELIVER_DATA", "NOTIFY_APP", "START_TIMER", "CANCEL_TIMER",
    }
    if int(a) < len(actions) {
        return actions[a]
    }
    return "UNKNOWN"
}

// StateTransition defines a state machine transition
type StateTransition struct {
    FromState TCPState
    Event     TCPEvent
    ToState   TCPState
    Actions   []TCPAction
}

// TCPConnection represents a single TCP connection
type TCPConnection struct {
    // Connection identifiers
    LocalIP    net.IP
    LocalPort  layers.TCPPort
    RemoteIP   net.IP
    RemotePort layers.TCPPort
    
    // TCP state machine
    State         TCPState
    PreviousState TCPState
    
    // Sequence number tracking
    SendSeq       uint32    // Next sequence number to send
    SendAck       uint32    // Next acknowledgment number to send
    RecvSeq       uint32    // Next sequence number expected to receive
    RecvAck       uint32    // Last acknowledgment number received
    
    // Connection metadata
    CreatedAt     time.Time
    LastActivity  time.Time
    MSS           uint16    // Maximum Segment Size
    WindowSize    uint16    // Receive window size
    
    // Application-specific flags
    HelloSent     bool      // Custom flag for crypto hello
    DataSent      bool      // Custom flag for data transmission
    
    // Timers (simplified)
    RetransmitTimer *time.Timer
    TimeWaitTimer   *time.Timer
    
    // Mutex for thread safety
    mutex sync.RWMutex
}

// TCPStateMachine manages multiple TCP connections
type TCPStateMachine struct {
    connections map[string]*TCPConnection
    transitions []StateTransition
    mutex       sync.RWMutex
    
    // Callbacks for actions
    OnSendSynAck   func(*TCPConnection, gopacket.Packet)
    OnSendAck      func(*TCPConnection, gopacket.Packet)
    OnSendFin      func(*TCPConnection, gopacket.Packet)
    OnSendRst      func(*TCPConnection, gopacket.Packet)
    OnEstablished  func(*TCPConnection)
    OnClosed       func(*TCPConnection)
    OnDataReceived func(*TCPConnection, []byte)
}

// NewTCPStateMachine creates a new TCP state machine
func NewTCPStateMachine() *TCPStateMachine {
    tsm := &TCPStateMachine{
        connections: make(map[string]*TCPConnection),
        transitions: createTransitionTable(),
    }
    return tsm
}

// createTransitionTable defines the RFC 793 state transition table
func createTransitionTable() []StateTransition {
    return []StateTransition{
        // CLOSED state transitions
        {CLOSED, EVENT_RECV_SYN, SYN_RECEIVED, []TCPAction{ACTION_SEND_SYN_ACK}},
        
        // SYN_RECEIVED state transitions
        {SYN_RECEIVED, EVENT_RECV_ACK, ESTABLISHED, []TCPAction{ACTION_NOTIFY_APP}},
        {SYN_RECEIVED, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {SYN_RECEIVED, EVENT_RECV_FIN, CLOSE_WAIT, []TCPAction{ACTION_SEND_ACK}},
        
        // ESTABLISHED state transitions
        {ESTABLISHED, EVENT_RECV_FIN, CLOSE_WAIT, []TCPAction{ACTION_SEND_ACK, ACTION_NOTIFY_APP}},
        {ESTABLISHED, EVENT_SEND_FIN, FIN_WAIT_1, []TCPAction{ACTION_SEND_FIN}},
        {ESTABLISHED, EVENT_RECV_DATA, ESTABLISHED, []TCPAction{ACTION_SEND_ACK, ACTION_DELIVER_DATA}},
        {ESTABLISHED, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        
        // FIN_WAIT_1 state transitions
        {FIN_WAIT_1, EVENT_RECV_ACK, FIN_WAIT_2, []TCPAction{ACTION_NONE}},
        {FIN_WAIT_1, EVENT_RECV_FIN, CLOSING, []TCPAction{ACTION_SEND_ACK}},
        
        // FIN_WAIT_2 state transitions
        {FIN_WAIT_2, EVENT_RECV_FIN, TIME_WAIT, []TCPAction{ACTION_SEND_ACK, ACTION_START_TIMER}},
        
        // CLOSE_WAIT state transitions
        {CLOSE_WAIT, EVENT_SEND_FIN, LAST_ACK, []TCPAction{ACTION_SEND_FIN}},
        
        // CLOSING state transitions
        {CLOSING, EVENT_RECV_ACK, TIME_WAIT, []TCPAction{ACTION_START_TIMER}},
        
        // LAST_ACK state transitions
        {LAST_ACK, EVENT_RECV_ACK, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        
        // TIME_WAIT state transitions
        {TIME_WAIT, EVENT_TIMEOUT, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        
        // RST can close connection from any state
        {SYN_RECEIVED, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {ESTABLISHED, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {FIN_WAIT_1, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {FIN_WAIT_2, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {CLOSE_WAIT, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {CLOSING, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {LAST_ACK, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
        {TIME_WAIT, EVENT_RECV_RST, CLOSED, []TCPAction{ACTION_NOTIFY_APP}},
    }
}

// generateConnectionKey creates a unique key for the connection
func (tsm *TCPStateMachine) generateConnectionKey(remoteIP net.IP, remotePort layers.TCPPort, localIP net.IP, localPort layers.TCPPort) string {
    return fmt.Sprintf("%s:%d-%s:%d", remoteIP.String(), remotePort, localIP.String(), localPort)
}

// GetConnection retrieves an existing connection or creates a new one
func (tsm *TCPStateMachine) GetConnection(remoteIP net.IP, remotePort layers.TCPPort, localIP net.IP, localPort layers.TCPPort) *TCPConnection {
    key := tsm.generateConnectionKey(remoteIP, remotePort, localIP, localPort)
    
    tsm.mutex.Lock()
    defer tsm.mutex.Unlock()
    
    if conn, exists := tsm.connections[key]; exists {
        conn.LastActivity = time.Now()
        return conn
    }
    
    // Create new connection in CLOSED state
    conn := &TCPConnection{
        LocalIP:      localIP,
        LocalPort:    localPort,
        RemoteIP:     remoteIP,
        RemotePort:   remotePort,
        State:        CLOSED,
        CreatedAt:    time.Now(),
        LastActivity: time.Now(),
        MSS:          1460,
        WindowSize:   65535,
    }
    
    tsm.connections[key] = conn
    return conn
}

// ProcessEvent processes a TCP event and triggers state transitions
func (tsm *TCPStateMachine) ProcessEvent(conn *TCPConnection, event TCPEvent, packet gopacket.Packet) bool {
    conn.mutex.Lock()
    defer conn.mutex.Unlock()
    
    // oldState := conn.State
    
    // Find matching transition
    var transition *StateTransition
    for _, t := range tsm.transitions {
        if t.FromState == conn.State && t.Event == event {
            transition = &t
            break
        }
    }
    
    if transition == nil {
        // No valid transition - this might be normal (e.g., duplicate ACK)
        // fmt.Printf("No transition for state %s with event %s\n", conn.State, event)
        return false
    }
    
    // Update state
    conn.PreviousState = conn.State
    conn.State = transition.ToState
    conn.LastActivity = time.Now()
    
    // fmt.Printf("TCP State Transition: %s -> %s (Event: %s)\n", 
    //     oldState, conn.State, event)
    
    // Execute actions
    for _, action := range transition.Actions {
        tsm.executeAction(conn, action, packet)
    }
    
    return true
}

// executeAction performs the specified action
func (tsm *TCPStateMachine) executeAction(conn *TCPConnection, action TCPAction, packet gopacket.Packet) {
    switch action {
    case ACTION_SEND_SYN_ACK:
        if tsm.OnSendSynAck != nil {
            tsm.OnSendSynAck(conn, packet)
        }
        
    case ACTION_SEND_ACK:
        if tsm.OnSendAck != nil {
            tsm.OnSendAck(conn, packet)
        }
        
    case ACTION_SEND_FIN:
        if tsm.OnSendFin != nil {
            tsm.OnSendFin(conn, packet)
        }
        
    case ACTION_SEND_RST:
        if tsm.OnSendRst != nil {
            tsm.OnSendRst(conn, packet)
        }
        
    case ACTION_NOTIFY_APP:
        if conn.State == ESTABLISHED && tsm.OnEstablished != nil {
            tsm.OnEstablished(conn)
        } else if conn.State == CLOSED && tsm.OnClosed != nil {
            tsm.OnClosed(conn)
        }
        
    case ACTION_DELIVER_DATA:
        if tsm.OnDataReceived != nil && packet != nil {
            tcpLayer := packet.Layer(layers.LayerTypeTCP)
            if tcpLayer != nil {
                tcp := tcpLayer.(*layers.TCP)
                if len(tcp.Payload) > 0 {
                    tsm.OnDataReceived(conn, tcp.Payload)
                }
            }
        }
        
    case ACTION_START_TIMER:
        // Start TIME_WAIT timer (2 * MSL = 4 minutes)
        if conn.TimeWaitTimer != nil {
            conn.TimeWaitTimer.Stop()
        }
        conn.TimeWaitTimer = time.AfterFunc(4*time.Minute, func() {
            tsm.ProcessEvent(conn, EVENT_TIMEOUT, nil)
        })
        
    default:
        // Other actions can be implemented as needed
    }
}

// ProcessPacket processes an incoming TCP packet
func (tsm *TCPStateMachine) ProcessPacket(packet gopacket.Packet) *TCPConnection {
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer == nil {
        return nil
    }
    tcp := tcpLayer.(*layers.TCP)
    
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return nil
    }
    ip := ipLayer.(*layers.IPv4)
    
    // Get connection (client IP/port first, then server IP/port)
    conn := tsm.GetConnection(ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
    
    // Update sequence numbers
    conn.RecvSeq = tcp.Seq
    if tcp.ACK {
        conn.RecvAck = tcp.Ack
    }
    
    // Determine event based on TCP flags
    var event TCPEvent
    
    if tcp.RST {
        event = EVENT_RECV_RST
    } else if tcp.SYN && !tcp.ACK {
        event = EVENT_RECV_SYN
    } else if tcp.SYN && tcp.ACK {
        event = EVENT_RECV_SYN_ACK
    } else if tcp.FIN {
        event = EVENT_RECV_FIN
    } else if tcp.ACK && len(tcp.Payload) > 0 {
        event = EVENT_RECV_DATA
    } else if tcp.ACK {
        event = EVENT_RECV_ACK
    } else {
        return conn // Unknown packet type
    }
    
    // Process the event
    tsm.ProcessEvent(conn, event, packet)
    
    return conn
}

// IsEstablished checks if connection is in ESTABLISHED state
func (conn *TCPConnection) IsEstablished() bool {
    conn.mutex.RLock()
    defer conn.mutex.RUnlock()
    return conn.State == ESTABLISHED
}

// ShouldSendHello determines if crypto hello should be sent
func (conn *TCPConnection) ShouldSendHello() bool {
    conn.mutex.RLock()
    defer conn.mutex.RUnlock()
    return conn.State == ESTABLISHED && !conn.HelloSent
}

// MarkHelloSent marks that crypto hello has been sent
func (conn *TCPConnection) MarkHelloSent() {
    conn.mutex.Lock()
    defer conn.mutex.Unlock()
    conn.HelloSent = true
}

// GetState returns the current connection state
func (conn *TCPConnection) GetState() TCPState {
    conn.mutex.RLock()
    defer conn.mutex.RUnlock()
    return conn.State
}

// CloseConnection removes connection from state machine
func (tsm *TCPStateMachine) CloseConnection(conn *TCPConnection) {
    key := tsm.generateConnectionKey(conn.RemoteIP, conn.RemotePort, conn.LocalIP, conn.LocalPort)
    
    tsm.mutex.Lock()
    defer tsm.mutex.Unlock()
    
    // Cancel timers
    if conn.RetransmitTimer != nil {
        conn.RetransmitTimer.Stop()
    }
    if conn.TimeWaitTimer != nil {
        conn.TimeWaitTimer.Stop()
    }
    
    delete(tsm.connections, key)
    // fmt.Printf("Connection removed from state machine: %s\n", key)
}

// GetConnectionCount returns the number of active connections
func (tsm *TCPStateMachine) GetConnectionCount() int {
    tsm.mutex.RLock()
    defer tsm.mutex.RUnlock()
    return len(tsm.connections)
}

// CleanupOldConnections removes connections that have been inactive for too long
func (tsm *TCPStateMachine) CleanupOldConnections(maxAge time.Duration) {
    tsm.mutex.Lock()
    defer tsm.mutex.Unlock()
    
    now := time.Now()
    var toDelete []string
    
    for key, conn := range tsm.connections {
        if now.Sub(conn.LastActivity) > maxAge {
            toDelete = append(toDelete, key)
        }
    }
    
    for _, key := range toDelete {
        conn := tsm.connections[key]
        if conn.RetransmitTimer != nil {
            conn.RetransmitTimer.Stop()
        }
        if conn.TimeWaitTimer != nil {
            conn.TimeWaitTimer.Stop()
        }
        delete(tsm.connections, key)
        fmt.Printf("Cleaned up old connection: %s\n", key)
    }
    
    if len(toDelete) > 0 {
        fmt.Printf("Cleaned up %d old connections\n", len(toDelete))
    }
}