package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
)

// KyberKeyPair represents a Kyber key pair
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// EncryptionContext holds the encryption state
type EncryptionContext struct {
	Key    []byte
	Cipher cipher.AEAD
}

const (
	// KeySize for AES-256
	KeySize = 32
	// NonceSize for AES-GCM
	NonceSize = 12
)

// GenerateKyberKeyPair generates a new Kyber-768 key pair
func GenerateKyberKeyPair() (*KyberKeyPair, error) {
	scheme := kyber768.Scheme()

	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	privKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &KyberKeyPair{
		PublicKey:  pubKeyBytes,
		PrivateKey: privKeyBytes,
	}, nil
}

// EncapsulateSecret performs Kyber encapsulation to generate a shared secret
func EncapsulateSecret(publicKeyBytes []byte) ([]byte, []byte, error) {
	scheme := kyber768.Scheme()

	publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	return ciphertext, sharedSecret, nil
}

// DecapsulateSecret performs Kyber decapsulation to recover the shared secret
func DecapsulateSecret(privateKeyBytes, ciphertext []byte) ([]byte, error) {
	scheme := kyber768.Scheme()

	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	sharedSecret, err := scheme.Decapsulate(privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	return sharedSecret, nil
}

// DeriveKey derives a symmetric key from the shared secret using HKDF
func DeriveKey(sharedSecret []byte, info []byte) ([]byte, error) {
	salt := make([]byte, 32) // 32-byte salt for stronger security
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hkdf := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// DeriveKeyWithSalt derives a symmetric key with a provided salt (for consistency between client/server)
func DeriveKeyWithSalt(sharedSecret, salt, info []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// NewEncryptionContext creates a new encryption context with AES-256-GCM
func NewEncryptionContext(key []byte) (*EncryptionContext, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptionContext{
		Key:    key,
		Cipher: gcm,
	}, nil
}

// Encrypt encrypts data using AES-256-GCM
func (ec *EncryptionContext) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := ec.Cipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
func (ec *EncryptionContext) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	plaintext, err := ec.Cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateRandomData generates random data of specified size
func GenerateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}
	return data, nil
}
