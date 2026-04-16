// Package crypto provides AES-256-GCM encryption for sensitive configuration data.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// ErrEncryptionKeyRequired is returned by EncryptIfKeySet and DecryptIfKeySet when
// the caller provides an empty key but the data on the wire requires protection.
//
// Historically these helpers silently returned plaintext when no key was configured,
// which produced a data-at-rest confidentiality bypass (CWE-311): sensitive fields
// in dynamically-configured issuer and target records (source='database') were
// persisted to PostgreSQL without any encryption whenever the operator forgot to
// set CERTCTL_CONFIG_ENCRYPTION_KEY. Callers could not distinguish the encrypted
// and plaintext branches at runtime, so the only visible signal was a warning
// line emitted once at startup.
//
// The fix is to fail closed: EncryptIfKeySet/DecryptIfKeySet now require a key
// whenever they are invoked on sensitive material, and the server refuses to
// start if any source='database' rows already exist without a configured key.
var ErrEncryptionKeyRequired = errors.New("crypto: CERTCTL_CONFIG_ENCRYPTION_KEY is required to encrypt or decrypt sensitive config")

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

// EncryptIfKeySet encrypts plaintext with the supplied 32-byte AES-256 key.
//
// The second return value is always true when err == nil — the "wasEncrypted"
// flag is retained for source-compatibility with callers that previously used it
// to log provenance. Callers MUST handle err: passing an empty key now returns
// ErrEncryptionKeyRequired rather than silently emitting plaintext. See the
// package-level ErrEncryptionKeyRequired documentation for the history behind
// this behavior change.
func EncryptIfKeySet(plaintext []byte, key []byte) ([]byte, bool, error) {
	if len(key) == 0 {
		return nil, false, ErrEncryptionKeyRequired
	}
	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, false, err
	}
	return encrypted, true, nil
}

// DecryptIfKeySet decrypts ciphertext with the supplied 32-byte AES-256 key.
//
// Passing an empty key now returns ErrEncryptionKeyRequired. Callers that
// legitimately store plaintext (e.g. env-seeded source='env' rows that keep
// the raw JSON in the unencrypted `config` column) must branch on the presence
// of the ciphertext themselves rather than relying on this helper to silently
// pass bytes through. See the package-level ErrEncryptionKeyRequired
// documentation for the history behind this behavior change.
func DecryptIfKeySet(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	return Decrypt(ciphertext, key)
}
