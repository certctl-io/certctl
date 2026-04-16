package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey("test-passphrase")
	plaintext := []byte(`{"api_key":"secret123","org_id":"456"}`)

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := DeriveKey("key-one")
	key2 := DeriveKey("key-two")
	plaintext := []byte("sensitive config data")

	encrypted, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(encrypted, key2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := DeriveKey("test-key")
	plaintext := []byte("important data")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with the ciphertext (flip a byte after the nonce)
	if len(encrypted) > 13 {
		encrypted[13] ^= 0xFF
	}

	_, err = Decrypt(encrypted, key)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	key := DeriveKey("test-key")
	plaintext := []byte{}

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt empty plaintext failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt empty plaintext failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("empty plaintext round-trip failed: got %q", decrypted)
	}
}

func TestEncryptInvalidKeyLength(t *testing.T) {
	_, err := Encrypt([]byte("data"), []byte("short-key"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestDecryptInvalidKeyLength(t *testing.T) {
	_, err := Decrypt([]byte("some-ciphertext-data"), []byte("short-key"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestDecryptTooShortCiphertext(t *testing.T) {
	key := DeriveKey("test-key")
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	key1 := DeriveKey("same-passphrase")
	key2 := DeriveKey("same-passphrase")
	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveKey should be deterministic")
	}
	if len(key1) != 32 {
		t.Fatalf("DeriveKey should return 32 bytes, got %d", len(key1))
	}
}

func TestDeriveKeyDifferentPassphrases(t *testing.T) {
	key1 := DeriveKey("passphrase-one")
	key2 := DeriveKey("passphrase-two")
	if bytes.Equal(key1, key2) {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestEncryptIfKeySet_WithKey(t *testing.T) {
	key := DeriveKey("test-key")
	plaintext := []byte("config data")

	result, wasEncrypted, err := EncryptIfKeySet(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	if !wasEncrypted {
		t.Fatal("expected wasEncrypted=true when key provided")
	}
	if bytes.Equal(result, plaintext) {
		t.Fatal("result should be encrypted")
	}

	decrypted, err := DecryptIfKeySet(result, key)
	if err != nil {
		t.Fatalf("DecryptIfKeySet failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip failed: got %q", decrypted)
	}
}

// TestEncryptIfKeySet_EmptyKeyFailsClosed asserts the C-2 regression guard:
// EncryptIfKeySet must refuse to silently emit plaintext when no key is configured.
// The pre-fix behavior was to return plaintext with wasEncrypted=false, which
// produced a data-at-rest confidentiality bypass (CWE-311) for GUI-created
// issuer and target configs.
func TestEncryptIfKeySet_EmptyKeyFailsClosed(t *testing.T) {
	plaintext := []byte("config data")

	cases := []struct {
		name string
		key  []byte
	}{
		{"nil_key", nil},
		{"empty_key", []byte{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, wasEncrypted, err := EncryptIfKeySet(plaintext, tc.key)
			if err == nil {
				t.Fatal("expected ErrEncryptionKeyRequired, got nil")
			}
			if !errors.Is(err, ErrEncryptionKeyRequired) {
				t.Fatalf("expected ErrEncryptionKeyRequired, got %v", err)
			}
			if wasEncrypted {
				t.Fatal("wasEncrypted must be false on error")
			}
			if result != nil {
				t.Fatalf("expected nil result on error, got %q", result)
			}
		})
	}
}

// TestDecryptIfKeySet_EmptyKeyFailsClosed asserts the matching C-2 regression
// guard on the read path: DecryptIfKeySet must refuse to pass ciphertext
// through as plaintext when no key is configured.
func TestDecryptIfKeySet_EmptyKeyFailsClosed(t *testing.T) {
	data := []byte("plaintext config data")

	cases := []struct {
		name string
		key  []byte
	}{
		{"nil_key", nil},
		{"empty_key", []byte{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := DecryptIfKeySet(data, tc.key)
			if err == nil {
				t.Fatal("expected ErrEncryptionKeyRequired, got nil")
			}
			if !errors.Is(err, ErrEncryptionKeyRequired) {
				t.Fatalf("expected ErrEncryptionKeyRequired, got %v", err)
			}
			if result != nil {
				t.Fatalf("expected nil result on error, got %q", result)
			}
		})
	}
}

// TestEncryptDecryptIfKeySet_RoundTripProducesDifferentCiphertext proves the
// "if set" helpers produce real AES-GCM output (not plaintext) and that a full
// round-trip through both helpers recovers the original bytes.
func TestEncryptDecryptIfKeySet_RoundTripProducesDifferentCiphertext(t *testing.T) {
	key := DeriveKey("round-trip-key")
	plaintext := []byte(`{"api_key":"s3cr3t","token":"abc"}`)

	encrypted, wasEncrypted, err := EncryptIfKeySet(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	if !wasEncrypted {
		t.Fatal("wasEncrypted must be true when key is present")
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("EncryptIfKeySet returned plaintext — would regress C-2")
	}

	decrypted, err := DecryptIfKeySet(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptIfKeySet failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestDecryptIfKeySet_RejectsTamperedCiphertext confirms the AEAD auth tag
// still rejects modified ciphertext when routed through the helper.
func TestDecryptIfKeySet_RejectsTamperedCiphertext(t *testing.T) {
	key := DeriveKey("tamper-test-key")
	plaintext := []byte("authenticated data")

	encrypted, _, err := EncryptIfKeySet(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	// Flip a byte inside the GCM body (past the 12-byte nonce) to invalidate the tag.
	if len(encrypted) <= 13 {
		t.Fatalf("ciphertext too short to tamper: %d bytes", len(encrypted))
	}
	encrypted[13] ^= 0xFF

	if _, err := DecryptIfKeySet(encrypted, key); err == nil {
		t.Fatal("DecryptIfKeySet accepted tampered ciphertext — AEAD tag check bypassed")
	}
}

// TestEncryptIfKeySet_PreservesErrEncryptionKeyRequiredSentinel guards the
// stability of the public sentinel error so audit-log detectors and callers
// outside this package can rely on errors.Is(err, ErrEncryptionKeyRequired).
func TestEncryptIfKeySet_PreservesErrEncryptionKeyRequiredSentinel(t *testing.T) {
	if ErrEncryptionKeyRequired == nil {
		t.Fatal("ErrEncryptionKeyRequired sentinel must be non-nil")
	}
	if ErrEncryptionKeyRequired.Error() == "" {
		t.Fatal("ErrEncryptionKeyRequired must carry a non-empty message")
	}
	// Wrap it and confirm errors.Is unwraps correctly — real callers wrap with %w.
	wrapped := wrapSentinel(ErrEncryptionKeyRequired)
	if !errors.Is(wrapped, ErrEncryptionKeyRequired) {
		t.Fatal("errors.Is must unwrap ErrEncryptionKeyRequired through %w-wrapped callers")
	}
}

// wrapSentinel is a tiny helper that mimics how production callers propagate
// the sentinel (e.g. fmt.Errorf("failed to encrypt config: %w", err)).
func wrapSentinel(err error) error {
	return errors.Join(errors.New("failed to encrypt config"), err)
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := DeriveKey("test-key")
	plaintext := []byte("same data")

	enc1, _ := Encrypt(plaintext, key)
	enc2, _ := Encrypt(plaintext, key)

	if bytes.Equal(enc1, enc2) {
		t.Fatal("encrypting same plaintext twice should produce different ciphertexts (random nonce)")
	}
}
