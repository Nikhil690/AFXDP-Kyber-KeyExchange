package crypto

import (
	"bytes"
	"testing"
)

func TestKyberKeyGeneration(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if len(keyPair.PublicKey) == 0 {
		t.Error("Public key is empty")
	}

	if len(keyPair.PrivateKey) == 0 {
		t.Error("Private key is empty")
	}
}

func TestKyberEncapsulationDecapsulation(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encapsulate
	ciphertext, sharedSecret1, err := EncapsulateSecret(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	// Decapsulate
	sharedSecret2, err := DecapsulateSecret(keyPair.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets do not match")
	}
}

func TestKeyDerivation(t *testing.T) {
	sharedSecret := []byte("test-shared-secret-32-bytes-long!!")
	salt := []byte("test-salt-32-bytes-long-for-hkdf!")
	info := []byte("test-info")

	key1, err := DeriveKeyWithSalt(sharedSecret, salt, info)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	key2, err := DeriveKeyWithSalt(sharedSecret, salt, info)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Keys should be deterministic
	if !bytes.Equal(key1, key2) {
		t.Error("Derived keys do not match")
	}

	if len(key1) != KeySize {
		t.Errorf("Key size incorrect: expected %d, got %d", KeySize, len(key1))
	}
}

func TestEncryptionDecryption(t *testing.T) {
	// Generate a key
	key, err := GenerateRandomData(KeySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create encryption context
	ctx, err := NewEncryptionContext(key)
	if err != nil {
		t.Fatalf("Failed to create encryption context: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, World! This is a test message for encryption.")

	// Encrypt
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original")
	}
}

func TestFullCryptoFlow(t *testing.T) {
	// Server generates key pair
	serverKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	// Client encapsulates
	ciphertext, clientSecret, err := EncapsulateSecret(serverKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	// Server decapsulates
	serverSecret, err := DecapsulateSecret(serverKeyPair.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate: %v", err)
	}

	// Verify secrets match
	if !bytes.Equal(clientSecret, serverSecret) {
		t.Error("Client and server secrets do not match")
	}

	// Derive keys
	salt := []byte("test-salt-32-bytes-long-for-hkdf!")
	info := []byte("kyber-benchmark")

	clientKey, err := DeriveKeyWithSalt(clientSecret, salt, info)
	if err != nil {
		t.Fatalf("Failed to derive client key: %v", err)
	}

	serverKey, err := DeriveKeyWithSalt(serverSecret, salt, info)
	if err != nil {
		t.Fatalf("Failed to derive server key: %v", err)
	}

	// Verify keys match
	if !bytes.Equal(clientKey, serverKey) {
		t.Error("Client and server keys do not match")
	}

	// Test encryption/decryption
	clientCtx, err := NewEncryptionContext(clientKey)
	if err != nil {
		t.Fatalf("Failed to create client encryption context: %v", err)
	}

	serverCtx, err := NewEncryptionContext(serverKey)
	if err != nil {
		t.Fatalf("Failed to create server encryption context: %v", err)
	}

	// Client encrypts
	plaintext := []byte("Test message from client to server")
	ciphertext, err = clientCtx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Server decrypts
	decrypted, err := serverCtx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted message does not match original")
	}
}

func BenchmarkKyberKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKyberKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberEncapsulation(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := EncapsulateSecret(keyPair.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESEncryption(b *testing.B) {
	key, err := GenerateRandomData(KeySize)
	if err != nil {
		b.Fatal(err)
	}

	ctx, err := NewEncryptionContext(key)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ctx.Encrypt(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}
