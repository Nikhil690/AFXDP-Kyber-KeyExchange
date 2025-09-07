package network

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Message represents a network message
type Message struct {
	Type    uint8
	Length  uint32
	Payload []byte
}

// Message types
const (
	MsgTypeKeyExchange = iota
	MsgTypeKeyResponse
	MsgTypeBenchmark
	MsgTypeResponse
	MsgTypeShutdown
)

// Connection wraps a network connection with message handling
type Connection struct {
	conn   net.Conn
	reader *bufio.Reader
}

// NewConnection creates a new connection wrapper
func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// SendMessage sends a message over the connection
func (c *Connection) SendMessage(msg *Message) error {
	// Calculate total message size
	totalSize := 1 + 4 + len(msg.Payload) // type + length + payload

	// Create buffer
	buf := make([]byte, totalSize)

	// Write message type
	buf[0] = msg.Type

	// Write payload length
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(msg.Payload)))

	// Write payload
	copy(buf[5:], msg.Payload)

	// Send the message
	_, err := c.conn.Write(buf)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// ReceiveMessage receives a message from the connection
func (c *Connection) ReceiveMessage() (*Message, error) {
	// Read message type
	msgType, err := c.reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}

	// Read payload length
	lengthBytes := make([]byte, 4)
	_, err = io.ReadFull(c.reader, lengthBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	payloadLength := binary.BigEndian.Uint32(lengthBytes)

	// Read payload
	payload := make([]byte, payloadLength)
	if payloadLength > 0 {
		_, err = io.ReadFull(c.reader, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to read message payload: %w", err)
		}
	}

	return &Message{
		Type:    msgType,
		Length:  payloadLength,
		Payload: payload,
	}, nil
}

// Close closes the connection
func (c *Connection) Close() error {
	return c.conn.Close()
}

// SetDeadline sets read/write deadline
func (c *Connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// GetRemoteAddr returns the remote address
func (c *Connection) GetRemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// GetLocalAddr returns the local address
func (c *Connection) GetLocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Server represents a TCP server
type Server struct {
	listener net.Listener
	addr     string
}

// NewServer creates a new TCP server
func NewServer(addr string) (*Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return &Server{
		listener: listener,
		addr:     listener.Addr().String(),
	}, nil
}

// Accept accepts a new connection
func (s *Server) Accept() (*Connection, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	return NewConnection(conn), nil
}

// Close closes the server
func (s *Server) Close() error {
	return s.listener.Close()
}

// GetAddr returns the server address
func (s *Server) GetAddr() string {
	return s.addr
}

// ConnectToServer connects to a TCP server
func ConnectToServer(addr string) (*Connection, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	return NewConnection(conn), nil
}

// ConnectWithTimeout connects to a TCP server with timeout
func ConnectWithTimeout(addr string, timeout time.Duration) (*Connection, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	return NewConnection(conn), nil
}
