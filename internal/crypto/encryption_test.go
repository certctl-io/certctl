package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	plaintext := []byte("config data")

	result, wasEncrypted, err := EncryptIfKeySet(plaintext, "test-passphrase")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	if !wasEncrypted {
		t.Fatal("expected wasEncrypted=true when passphrase provided")
	}
	if bytes.Equal(result, plaintext) {
		t.Fatal("result should be encrypted")
	}

	decrypted, err := DecryptIfKeySet(result, "test-passphrase")
	if err != nil {
		t.Fatalf("DecryptIfKeySet failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip failed: got %q", decrypted)
	}
}

// TestEncryptIfKeySet_EmptyKeyFailsClosed asserts the C-2 regression guard:
// EncryptIfKeySet must refuse to silently emit plaintext when no passphrase is
// configured. The pre-fix behavior was to return plaintext with
// wasEncrypted=false, which produced a data-at-rest confidentiality bypass
// (CWE-311) for GUI-created issuer and target configs.
func TestEncryptIfKeySet_EmptyKeyFailsClosed(t *testing.T) {
	plaintext := []byte("config data")

	result, wasEncrypted, err := EncryptIfKeySet(plaintext, "")
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
}

// TestDecryptIfKeySet_EmptyKeyFailsClosed asserts the matching C-2 regression
// guard on the read path: DecryptIfKeySet must refuse to pass ciphertext
// through as plaintext when no passphrase is configured.
func TestDecryptIfKeySet_EmptyKeyFailsClosed(t *testing.T) {
	data := []byte("plaintext config data")

	result, err := DecryptIfKeySet(data, "")
	if err == nil {
		t.Fatal("expected ErrEncryptionKeyRequired, got nil")
	}
	if !errors.Is(err, ErrEncryptionKeyRequired) {
		t.Fatalf("expected ErrEncryptionKeyRequired, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result on error, got %q", result)
	}
}

// TestEncryptDecryptIfKeySet_RoundTripProducesDifferentCiphertext proves the
// "if set" helpers produce real AES-GCM output (not plaintext) and that a full
// round-trip through both helpers recovers the original bytes.
func TestEncryptDecryptIfKeySet_RoundTripProducesDifferentCiphertext(t *testing.T) {
	plaintext := []byte(`{"api_key":"s3cr3t","token":"abc"}`)

	encrypted, wasEncrypted, err := EncryptIfKeySet(plaintext, "round-trip-key")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	if !wasEncrypted {
		t.Fatal("wasEncrypted must be true when passphrase is present")
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("EncryptIfKeySet returned plaintext — would regress C-2")
	}

	decrypted, err := DecryptIfKeySet(encrypted, "round-trip-key")
	if err != nil {
		t.Fatalf("DecryptIfKeySet failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestDecryptIfKeySet_RejectsTamperedCiphertext confirms the AEAD auth tag
// still rejects modified ciphertext when routed through the helper. The v2
// wire format is magic(1) || salt(16) || nonce(12) || ciphertext+tag, so
// flipping a byte anywhere past offset 29 lands squarely inside the AEAD body.
func TestDecryptIfKeySet_RejectsTamperedCiphertext(t *testing.T) {
	plaintext := []byte("authenticated data")

	encrypted, _, err := EncryptIfKeySet(plaintext, "tamper-test-key")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	// Flip a byte past the v2 header (1 + 16 + 12 = 29) to invalidate the tag.
	const minV2HeaderLen = 1 + v2SaltSize + 12
	if len(encrypted) <= minV2HeaderLen {
		t.Fatalf("ciphertext too short to tamper: %d bytes", len(encrypted))
	}
	encrypted[minV2HeaderLen] ^= 0xFF

	if _, err := DecryptIfKeySet(encrypted, "tamper-test-key"); err == nil {
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

// ---------------------------------------------------------------------------
// M-8 additions: per-ciphertext salt + v2 wire format + v1 backward compat.
// ---------------------------------------------------------------------------

// TestDeriveKey_DifferentSaltsProduceDifferentKeys asserts that
// deriveKeyWithSalt fans out distinct 32-byte keys for the same passphrase
// across different salts. This is the core M-8 defense-in-depth property: even
// if an attacker obtains two v2 ciphertexts encrypted with the same master
// passphrase, the derived AES keys differ, and a brute-force attempt on one
// blob cannot be amortized across the other.
func TestDeriveKey_DifferentSaltsProduceDifferentKeys(t *testing.T) {
	passphrase := "master-passphrase"
	saltA := bytes.Repeat([]byte{0xAA}, v2SaltSize)
	saltB := bytes.Repeat([]byte{0xBB}, v2SaltSize)

	keyA := deriveKeyWithSalt(passphrase, saltA)
	keyB := deriveKeyWithSalt(passphrase, saltB)

	if len(keyA) != aes256KeySize || len(keyB) != aes256KeySize {
		t.Fatalf("derived key length wrong: %d / %d", len(keyA), len(keyB))
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("deriveKeyWithSalt must produce different keys for different salts")
	}

	// Sanity-check that deterministic behaviour is preserved under a fixed salt.
	keyA2 := deriveKeyWithSalt(passphrase, saltA)
	if !bytes.Equal(keyA, keyA2) {
		t.Fatal("deriveKeyWithSalt must be deterministic for a fixed (passphrase, salt)")
	}
}

// TestEncryptIfKeySet_ProducesV2Format asserts the exact v2 wire-format bytes:
// magic(0x02) || salt(16) || nonce(12) || ciphertext+tag.
func TestEncryptIfKeySet_ProducesV2Format(t *testing.T) {
	blob, _, err := EncryptIfKeySet([]byte("hello"), "any-passphrase")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}

	const minLen = 1 + v2SaltSize + 12 + 16 // magic + salt + nonce + GCM tag (16)
	if len(blob) < minLen {
		t.Fatalf("v2 blob too short: got %d, want >= %d", len(blob), minLen)
	}
	if blob[0] != v2Magic {
		t.Fatalf("v2 blob must start with magic byte 0x%02x, got 0x%02x", v2Magic, blob[0])
	}
	if IsLegacyFormat(blob) {
		t.Fatal("IsLegacyFormat must return false for a freshly produced v2 blob")
	}
}

// TestEncryptIfKeySet_SaltIsRandom asserts that two calls with the same
// passphrase and plaintext produce distinct embedded salts.
func TestEncryptIfKeySet_SaltIsRandom(t *testing.T) {
	plaintext := []byte("same plaintext")
	passphrase := "same-passphrase"

	blob1, _, err := EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet #1 failed: %v", err)
	}
	blob2, _, err := EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet #2 failed: %v", err)
	}

	salt1 := blob1[1 : 1+v2SaltSize]
	salt2 := blob2[1 : 1+v2SaltSize]
	if bytes.Equal(salt1, salt2) {
		t.Fatal("two EncryptIfKeySet invocations must produce distinct per-ciphertext salts")
	}
	if bytes.Equal(blob1, blob2) {
		t.Fatal("two v2 blobs with same (passphrase, plaintext) must differ end-to-end")
	}
}

// TestDecryptIfKeySet_V1BackwardCompat builds a deterministic v1-format
// ciphertext using the pre-M-8 recipe (DeriveKey with the fixed salt, then
// Encrypt with an all-zero nonce for reproducibility) and asserts that
// DecryptIfKeySet still decrypts it correctly. This is the migration guarantee:
// v1 blobs persisted before M-8 must remain decryptable.
func TestDecryptIfKeySet_V1BackwardCompat(t *testing.T) {
	passphrase := "legacy-passphrase"
	plaintext := []byte(`{"api_key":"legacy","org_id":"789"}`)

	// Build a deterministic v1 blob directly: nonce(12 zero bytes) || ct+tag.
	// This matches the exact wire shape that Encrypt produces, minus the random
	// nonce, so the test is stable rather than 1/256 flaky.
	key := DeriveKey(passphrase) // fixed-salt derivation (pre-M-8 behavior)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize()) // all zeros → first byte != v2Magic
	v1Blob := gcm.Seal(nonce, nonce, plaintext, nil)
	if v1Blob[0] == v2Magic {
		t.Fatalf("fixture nonce collided with v2 magic byte — test design error")
	}

	decrypted, err := DecryptIfKeySet(v1Blob, passphrase)
	if err != nil {
		t.Fatalf("DecryptIfKeySet(v1) failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("v1 decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Cross-check: IsLegacyFormat should flag this as legacy.
	if !IsLegacyFormat(v1Blob) {
		t.Fatal("IsLegacyFormat must return true for a v1 blob whose first byte != v2Magic")
	}
}

// TestDecryptIfKeySet_V1MagicByteCollisionFallsThrough covers the 1/256 edge
// case where a v1 ciphertext's random 12-byte nonce happens to begin with
// 0x02. The dispatch must attempt v2, see AEAD failure, and fall through to
// v1 — never return a decrypt error when the passphrase is correct.
func TestDecryptIfKeySet_V1MagicByteCollisionFallsThrough(t *testing.T) {
	passphrase := "collision-passphrase"
	plaintext := []byte("colliding v1 blob")

	// Craft a v1 blob whose first byte equals v2Magic by choosing a nonce
	// starting with 0x02 and sealing manually.
	key := DeriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	nonce[0] = v2Magic // force collision
	v1Blob := gcm.Seal(nonce, nonce, plaintext, nil)
	if v1Blob[0] != v2Magic {
		t.Fatal("fixture construction bug: first byte must equal v2Magic")
	}

	decrypted, err := DecryptIfKeySet(v1Blob, passphrase)
	if err != nil {
		t.Fatalf("DecryptIfKeySet must fall through to v1 on AEAD failure, got err: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("v1-via-fallback decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestDecryptIfKeySet_V2WithWrongPassphraseFails asserts that a v2 blob
// sealed under passphrase A cannot be decrypted under passphrase B. Both the
// v2 AEAD verify (with salt from the blob + passphrase B) and the v1 fallback
// (with fixed salt + passphrase B) must fail, and an error must be returned
// rather than silently-corrupt plaintext.
func TestDecryptIfKeySet_V2WithWrongPassphraseFails(t *testing.T) {
	blob, _, err := EncryptIfKeySet([]byte("secret"), "passphrase-A")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}

	got, err := DecryptIfKeySet(blob, "passphrase-B")
	if err == nil {
		t.Fatalf("DecryptIfKeySet must return error for wrong passphrase, got plaintext %q", got)
	}
	if got != nil {
		t.Fatalf("result must be nil on decrypt error, got %q", got)
	}
}

// TestDecryptIfKeySet_TruncatedV2Blob asserts that a blob starting with the v2
// magic byte but too short to contain a full v2 header does not trip an
// out-of-bounds slice and does not succeed. It either returns an error (v1
// fallback on the short bytes fails with "ciphertext too short") or at minimum
// never returns plaintext.
func TestDecryptIfKeySet_TruncatedV2Blob(t *testing.T) {
	truncated := []byte{v2Magic, 0x00, 0x01, 0x02, 0x03} // 5 bytes — well below the 29-byte v2 minimum
	got, err := DecryptIfKeySet(truncated, "any-passphrase")
	if err == nil {
		t.Fatalf("DecryptIfKeySet must reject a truncated v2 blob, got plaintext %q", got)
	}
	if got != nil {
		t.Fatalf("result must be nil on decrypt error, got %q", got)
	}
}

// TestIsLegacyFormat covers the three branches of the public magic-byte
// heuristic: v2 blob → false, v1 blob → true, empty blob → false.
func TestIsLegacyFormat(t *testing.T) {
	v2Blob, _, err := EncryptIfKeySet([]byte("data"), "p")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}
	if IsLegacyFormat(v2Blob) {
		t.Fatal("v2 blob must not be flagged as legacy")
	}

	// Any blob whose first byte isn't v2Magic should be reported as legacy.
	v1Shape := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF}
	if !IsLegacyFormat(v1Shape) {
		t.Fatal("non-v2-magic blob must be flagged as legacy")
	}

	if IsLegacyFormat(nil) {
		t.Fatal("nil blob must not be flagged as legacy (undefined)")
	}
	if IsLegacyFormat([]byte{}) {
		t.Fatal("empty blob must not be flagged as legacy (undefined)")
	}
}
