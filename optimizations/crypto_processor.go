package optimizations

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"xdp-example/message"

	"github.com/cloudflare/circl/kem"
)

var (
	ErrInsufficientData = errors.New("insufficient data for message")
)

// CryptoMessageProcessor provides optimized crypto message processing
type CryptoMessageProcessor struct {
	keyMsgPool     sync.Pool
	messagePool    sync.Pool
	publicKeyBytes []byte // Pre-marshaled public key
	publicKeyMsg   []byte // Pre-marshaled JSON message
}

type KeyExchangeMessage struct {
	PublicKey []byte `json:"public_key"`
}

func NewCryptoMessageProcessor(publicKey kem.PublicKey) (*CryptoMessageProcessor, error) {
	// Pre-marshal the public key to avoid repeated marshaling
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	keyMsg := KeyExchangeMessage{
		PublicKey: publicKeyBytes,
	}
	publicKeyMsgBytes, err := json.Marshal(keyMsg)
	if err != nil {
		return nil, err
	}

	cmp := &CryptoMessageProcessor{
		publicKeyBytes: publicKeyBytes,
		publicKeyMsg:   publicKeyMsgBytes,
		keyMsgPool: sync.Pool{
			New: func() interface{} {
				return &KeyExchangeMessage{}
			},
		},
		messagePool: sync.Pool{
			New: func() interface{} {
				return &message.Message{}
			},
		},
	}

	return cmp, nil
}

// CreateKeyExchangeMessage creates a key exchange message efficiently
func (cmp *CryptoMessageProcessor) CreateKeyExchangeMessage() *message.Message {
	msg := cmp.messagePool.Get().(*message.Message)
	msg.Type = message.MsgTypeKeyExchange
	msg.Length = uint32(len(cmp.publicKeyMsg))
	msg.Payload = cmp.publicKeyMsg // Use pre-marshaled message
	return msg
}

// ReturnMessage returns a message to the pool
func (cmp *CryptoMessageProcessor) ReturnMessage(msg *message.Message) {
	msg.Type = 0
	msg.Length = 0
	msg.Payload = nil
	cmp.messagePool.Put(msg)
}

// FastSerializeMessage serializes a message without additional allocations
func (cmp *CryptoMessageProcessor) FastSerializeMessage(msg *message.Message) []byte {
	totalSize := 1 + 4 + len(msg.Payload)
	buf := make([]byte, totalSize)

	// Set message type
	buf[0] = msg.Type

	// Set payload length (4 bytes, big endian)
	binary.BigEndian.PutUint32(buf[1:5], msg.Length)

	// Copy payload data
	copy(buf[5:], msg.Payload)

	return buf
}

// FastDeserializeMessage deserializes a message efficiently
func FastDeserializeMessage(data []byte) (*message.Message, error) {
	if len(data) < 5 {
		return nil, ErrInsufficientData
	}

	msg := &message.Message{
		Type:   data[0],
		Length: binary.BigEndian.Uint32(data[1:5]),
	}

	if len(data) < int(5+msg.Length) {
		return nil, ErrInsufficientData
	}

	// Avoid copy by using slice reference
	msg.Payload = data[5 : 5+msg.Length]

	return msg, nil
}

// PrecomputedCryptoContext stores precomputed cryptographic values
type PrecomputedCryptoContext struct {
	Scheme        kem.Scheme
	PrivateKey    kem.PrivateKey
	PublicKey     kem.PublicKey
	PublicKeyData []byte
	KeyMsgData    []byte
}

func NewPrecomputedCryptoContext(scheme kem.Scheme) (*PrecomputedCryptoContext, error) {
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	publicKeyData, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	keyMsg := KeyExchangeMessage{
		PublicKey: publicKeyData,
	}
	keyMsgData, err := json.Marshal(keyMsg)
	if err != nil {
		return nil, err
	}

	return &PrecomputedCryptoContext{
		Scheme:        scheme,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		PublicKeyData: publicKeyData,
		KeyMsgData:    keyMsgData,
	}, nil
}

// BatchMessageProcessor processes multiple messages efficiently
type BatchMessageProcessor struct {
	messages chan *message.Message
	results  chan []byte
	workers  int
	cmp      *CryptoMessageProcessor
}

func NewBatchMessageProcessor(workers int, cmp *CryptoMessageProcessor) *BatchMessageProcessor {
	bmp := &BatchMessageProcessor{
		messages: make(chan *message.Message, workers*2),
		results:  make(chan []byte, workers*2),
		workers:  workers,
		cmp:      cmp,
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go bmp.worker()
	}

	return bmp
}

func (bmp *BatchMessageProcessor) worker() {
	for msg := range bmp.messages {
		result := bmp.cmp.FastSerializeMessage(msg)
		bmp.results <- result
		bmp.cmp.ReturnMessage(msg)
	}
}

func (bmp *BatchMessageProcessor) ProcessMessage(msg *message.Message) <-chan []byte {
	bmp.messages <- msg
	return bmp.results
}
