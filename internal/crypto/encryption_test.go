package crypto

import (
	"bytes"
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

func TestEncryptIfKeySet_NilKey(t *testing.T) {
	plaintext := []byte("config data")

	result, wasEncrypted, err := EncryptIfKeySet(plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptIfKeySet with nil key failed: %v", err)
	}
	if wasEncrypted {
		t.Fatal("expected wasEncrypted=false when key is nil")
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatal("result should be unchanged plaintext when key is nil")
	}
}

func TestDecryptIfKeySet_NilKey(t *testing.T) {
	data := []byte("plaintext config data")

	result, err := DecryptIfKeySet(data, nil)
	if err != nil {
		t.Fatalf("DecryptIfKeySet with nil key failed: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Fatal("result should be unchanged when key is nil")
	}
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
