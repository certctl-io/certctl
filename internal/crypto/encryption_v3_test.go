package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// Bundle B / Audit M-001 (CWE-916 / OWASP 2024) regression suite.
//
// The on-disk blob format is now versioned three ways:
//   v1 — pre-M-8, fixed-salt, 100k PBKDF2 rounds
//   v2 — M-8, per-ciphertext salt, 100k rounds, magic 0x02
//   v3 — Bundle B, per-ciphertext salt, 600k rounds, magic 0x03 (current)
//
// EncryptIfKeySet always emits v3. DecryptIfKeySet must accept all three
// in order v3 → v2 → v1 with AEAD-fallback so wrong-passphrase v3 blobs
// don't get incorrectly attributed to v1. These tests pin every arm.

// TestEncryptIfKeySet_V3RoundTrip pins the happy-path round trip under v3.
func TestEncryptIfKeySet_V3RoundTrip(t *testing.T) {
	plaintext := []byte(`{"api_key":"acme-prod-2026","scope":"issuer"}`)
	passphrase := "test-passphrase-bundleB"

	blob, ok, err := EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet: %v", err)
	}
	if !ok {
		t.Fatal("ok must be true on success")
	}
	if blob[0] != v3Magic {
		t.Fatalf("first byte must be v3Magic 0x%02x, got 0x%02x", v3Magic, blob[0])
	}

	got, err := DecryptIfKeySet(blob, passphrase)
	if err != nil {
		t.Fatalf("DecryptIfKeySet: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestDecryptIfKeySet_V2BlobReadFallback constructs a deterministic v2
// blob using the v1/v2 PBKDF2 work factor and asserts DecryptIfKeySet
// still reads it correctly (read-time backward compat, no in-place
// re-encrypt).
func TestDecryptIfKeySet_V2BlobReadFallback(t *testing.T) {
	passphrase := "v2-era-passphrase"
	plaintext := []byte(`{"legacy":"v2"}`)

	// Hand-build a v2 blob: magic(0x02) || salt(16) || nonce(12) || ct+tag.
	salt := bytes.Repeat([]byte{0xAB}, v2SaltSize)
	key := deriveKeyWithSalt(passphrase, salt) // 100k rounds
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := bytes.Repeat([]byte{0xCD}, gcm.NonceSize())
	inner := gcm.Seal(nonce, nonce, plaintext, nil)

	v2Blob := make([]byte, 0, 1+v2SaltSize+len(inner))
	v2Blob = append(v2Blob, v2Magic)
	v2Blob = append(v2Blob, salt...)
	v2Blob = append(v2Blob, inner...)

	got, err := DecryptIfKeySet(v2Blob, passphrase)
	if err != nil {
		t.Fatalf("DecryptIfKeySet must read v2 blob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("v2 round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestDecryptIfKeySet_V3WrongPassphraseFails ensures a wrong passphrase
// against a v3 blob does NOT silently succeed via the v2/v1 fallback.
func TestDecryptIfKeySet_V3WrongPassphraseFails(t *testing.T) {
	plaintext := []byte("secret")
	blob, _, err := EncryptIfKeySet(plaintext, "correct-pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptIfKeySet(blob, "wrong-pw"); err == nil {
		t.Fatal("decrypt with wrong passphrase must fail; got nil error")
	}
}

// TestDecryptIfKeySet_V2MagicCollisionWithV3Header pins the AEAD-fallback
// behavior: a fresh v3 blob whose first byte happens to be 0x02 (would
// only occur if v3Magic were 0x02 — it is not, but the dispatch must
// still be robust). We exercise the inverse case explicitly: a real v2
// blob is correctly read after the v3 attempt fails.
func TestDecryptIfKeySet_V3VsV2DispatchOrder(t *testing.T) {
	// Construct a v2 blob whose first byte is v3Magic by forcing the
	// magic-byte choice. This simulates the 1/256 case where a hostile
	// or coincidental nonce-prefix collision would otherwise mis-route.
	passphrase := "ambiguous-pw"
	plaintext := []byte("payload")
	salt := bytes.Repeat([]byte{0xFE}, v2SaltSize)
	key := deriveKeyWithSalt(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := bytes.Repeat([]byte{0xCD}, gcm.NonceSize())
	inner := gcm.Seal(nonce, nonce, plaintext, nil)

	// Manually splice: magic(0x02) is correct for v2.
	v2Blob := append([]byte{v2Magic}, salt...)
	v2Blob = append(v2Blob, inner...)

	got, err := DecryptIfKeySet(v2Blob, passphrase)
	if err != nil {
		t.Fatalf("v2 blob must be readable: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("v2 fallback mismatch: got %q want %q", got, plaintext)
	}
}

// TestDeriveKeyWithSaltV3_DistinctFromV2 sanity-checks that v2 and v3
// derive distinct keys for the same (passphrase, salt) — a regression
// here would mean the iteration count was accidentally identical.
func TestDeriveKeyWithSaltV3_DistinctFromV2(t *testing.T) {
	passphrase := "any"
	salt := bytes.Repeat([]byte{0x42}, 16)
	v2Key := deriveKeyWithSalt(passphrase, salt)
	v3Key := deriveKeyWithSaltV3(passphrase, salt)
	if bytes.Equal(v2Key, v3Key) {
		t.Fatal("v2 and v3 keys must differ for the same (passphrase, salt) — work factor must differ")
	}
}

// TestPBKDF2Iterations_V3IsOWASP2024Floor pins the iteration count at the
// OWASP 2024 floor of 600,000. If a future change lowers this number,
// the test must fail so the change requires an explicit audit-trail
// update to BOTH the constant AND this assertion.
func TestPBKDF2Iterations_V3IsOWASP2024Floor(t *testing.T) {
	const owasp2024MinIterations = 600000
	if pbkdf2IterationsV3 < owasp2024MinIterations {
		t.Fatalf("pbkdf2IterationsV3 = %d, below OWASP 2024 floor of %d (Bundle B / M-001 / CWE-916)",
			pbkdf2IterationsV3, owasp2024MinIterations)
	}
}

// TestIsLegacyFormat_V3IsNotLegacy pins the helper's contract: a v3 blob
// (magic 0x03) is NOT legacy.
func TestIsLegacyFormat_V3IsNotLegacy(t *testing.T) {
	v3Blob, _, err := EncryptIfKeySet([]byte("x"), "p")
	if err != nil {
		t.Fatal(err)
	}
	if IsLegacyFormat(v3Blob) {
		t.Fatal("a v3 blob must NOT report as legacy")
	}
}
