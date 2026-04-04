// Package crypto provides AES-256-GCM encryption for sensitive configuration data.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce prepended to the output.
// The key must be exactly 32 bytes (AES-256). Returns [12-byte nonce][ciphertext+tag].
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt.
// Expects format: [12-byte nonce][ciphertext+tag]. Key must be exactly 32 bytes.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	nonce, ciphertextBody := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// DeriveKey derives a 32-byte AES-256 key from a passphrase using PBKDF2-SHA256.
// Uses a fixed application-specific salt and 100,000 iterations for resistance
// to brute-force attacks on weak passphrases.
func DeriveKey(passphrase string) []byte {
	// Fixed salt is acceptable here because:
	// 1. Each certctl instance has its own passphrase
	// 2. The salt prevents generic rainbow table attacks
	// 3. Per-user salts are unnecessary (single server key, not user passwords)
	salt := []byte("certctl-config-encryption-v1")
	return pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)
}

// EncryptIfKeySet encrypts plaintext if a key is provided, otherwise returns plaintext unchanged.
// This supports the development/demo fallback where encryption isn't configured.
func EncryptIfKeySet(plaintext []byte, key []byte) ([]byte, bool, error) {
	if len(key) == 0 {
		return plaintext, false, nil
	}
	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, false, err
	}
	return encrypted, true, nil
}

// DecryptIfKeySet decrypts ciphertext if a key is provided, otherwise returns ciphertext unchanged.
func DecryptIfKeySet(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return ciphertext, nil
	}
	return Decrypt(ciphertext, key)
}
