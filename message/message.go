package message

import (
	"encoding/binary"
	"fmt"
)

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

// Serialize converts the Message struct to binary format
// Format: [1 byte type][4 bytes length][payload bytes]
func (m *Message) Serialize() []byte {
	totalSize := 1 + 4 + len(m.Payload)
	buf := make([]byte, totalSize)

	// Set message type
	buf[0] = m.Type

	// Set payload length (4 bytes, big endian)
	binary.BigEndian.PutUint32(buf[1:5], m.Length)

	// Copy payload data
	copy(buf[5:], m.Payload)

	return buf
}

// Deserialize parses binary data into a Message struct
func Deserialize(data []byte) (*Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("insufficient data for message header")
	}

	msg := &Message{
		Type:   data[0],
		Length: binary.BigEndian.Uint32(data[1:5]),
	}

	if len(data) < int(5+msg.Length) {
		return nil, fmt.Errorf("insufficient data for payload")
	}

	msg.Payload = make([]byte, msg.Length)
	copy(msg.Payload, data[5:5+msg.Length])

	return msg, nil
}
