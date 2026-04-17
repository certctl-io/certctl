// Package crypto provides AES-256-GCM encryption for sensitive configuration data.
//
// The on-disk format for blobs produced by [EncryptIfKeySet] is versioned. Two
// versions coexist and both can be read by [DecryptIfKeySet]:
//
//	v2 (current, M-8)
//	    magic(0x02) || salt(16) || nonce(12) || ciphertext+tag
//	    — 32-byte AES-256 key derived via PBKDF2-SHA256 from the operator
//	      passphrase and the per-ciphertext random salt.
//
//	v1 (legacy, pre-M-8)
//	    nonce(12) || ciphertext+tag
//	    — 32-byte AES-256 key derived via PBKDF2-SHA256 from the operator
//	      passphrase and the package-level fixed salt
//	      "certctl-config-encryption-v1".
//
// v1 blobs are accepted by the read path for backward compatibility with rows
// persisted before the M-8 remediation. They are never produced by the write
// path. Any row that is updated after M-8 is re-sealed as v2 in-place via the
// normal UPDATE flow.
//
// Rationale for the per-ciphertext salt (see M-8 / CWE-916 / CWE-329): the
// pre-M-8 design reused a single 28-byte fixed salt for every ciphertext, which
// (a) removes one defense-in-depth layer against passphrase-space brute force
// and (b) makes every encrypted column across every row share the exact same
// derived key. v2 replaces the fixed salt with 16 fresh random bytes per write
// and stores the salt alongside the ciphertext. Derived keys now differ per
// row and per re-encryption.
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
// the caller provides an empty passphrase but the data on the wire requires
// protection.
//
// Historically these helpers silently returned plaintext when no key was configured,
// which produced a data-at-rest confidentiality bypass (CWE-311): sensitive fields
// in dynamically-configured issuer and target records (source='database') were
// persisted to PostgreSQL without any encryption whenever the operator forgot to
// set CERTCTL_CONFIG_ENCRYPTION_KEY. Callers could not distinguish the encrypted
// and plaintext branches at runtime, so the only visible signal was a warning
// line emitted once at startup.
//
// The fix (C-2, commit fb4ce1a) is to fail closed: EncryptIfKeySet/DecryptIfKeySet
// now require a passphrase whenever they are invoked on sensitive material, and
// the server refuses to start if any source='database' rows already exist without
// a configured passphrase.
var ErrEncryptionKeyRequired = errors.New("crypto: CERTCTL_CONFIG_ENCRYPTION_KEY is required to encrypt or decrypt sensitive config")

// v2Magic is the first byte of every v2-format ciphertext blob. It distinguishes
// v2 blobs (per-ciphertext random salt, embedded in the blob) from v1 legacy
// blobs (no magic byte, fixed package-level salt).
//
// The choice of 0x02 is deliberate: v1 blobs begin with a random 12-byte AES-GCM
// nonce. A v1 nonce can coincidentally start with 0x02 with probability 1/256,
// which makes a pure magic-byte dispatch ambiguous. [DecryptIfKeySet] resolves
// the ambiguity by falling back to the v1 path when v2 AEAD verification fails.
const v2Magic byte = 0x02

// v2SaltSize is the length in bytes of the per-ciphertext salt embedded in a
// v2 blob. 16 bytes (128 bits) matches the lower bound recommended in NIST
// SP 800-132 §5.1 for PBKDF2 salts and is sufficient given the one-shot-per-row
// nature of the derivation.
const v2SaltSize = 16

// pbkdf2Iterations is the PBKDF2-SHA256 work factor applied uniformly to both
// v1 and v2 key derivations. The value is preserved from the pre-M-8 design so
// that v1 fallback reads stay bit-identical.
const pbkdf2Iterations = 100000

// aes256KeySize is the output length in bytes of both [DeriveKey] and
// [deriveKeyWithSalt]. It is also the only AES key length accepted by [Encrypt]
// and [Decrypt].
const aes256KeySize = 32

// legacyV1Salt is the fixed salt used by pre-M-8 config encryption. It is
// retained exclusively to preserve the v1 read path — any v1 blob that pre-dates
// M-8 remediation must be decryptable with a key derived from (passphrase,
// legacyV1Salt). The write path never uses this salt.
//
// Exposed as a package-level var rather than a local so that tests can reason
// about v1 fixture bytes symbolically.
var legacyV1Salt = []byte("certctl-config-encryption-v1")

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce prepended to the output.
// The key must be exactly 32 bytes (AES-256). Returns [12-byte nonce][ciphertext+tag].
//
// Encrypt is a low-level primitive. It is intentionally kept byte-identical to
// the pre-M-8 implementation so that existing v1 blobs on disk remain
// decryptable via [Decrypt] when paired with a [DeriveKey]-derived key. New
// callers should prefer [EncryptIfKeySet], which handles key derivation and
// emits the v2 wire format.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("encryption key must be exactly %d bytes, got %d", aes256KeySize, len(key))
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
//
// Decrypt is a low-level primitive. It is intentionally kept byte-identical to
// the pre-M-8 implementation so that [DecryptIfKeySet] can delegate to it for
// both the v2 inner blob (after stripping the magic byte + embedded salt) and
// the v1 legacy blob (unmodified).
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("encryption key must be exactly %d bytes, got %d", aes256KeySize, len(key))
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

// DeriveKey derives a 32-byte AES-256 key from a passphrase using PBKDF2-SHA256
// with the legacy v1 fixed salt.
//
// This helper is preserved byte-identical to the pre-M-8 implementation so that
// v1 ciphertexts persisted before the M-8 remediation remain decryptable
// unchanged. New code paths should prefer [EncryptIfKeySet] and
// [DecryptIfKeySet], which use a per-ciphertext random salt.
func DeriveKey(passphrase string) []byte {
	return deriveKeyWithSalt(passphrase, legacyV1Salt)
}

// deriveKeyWithSalt derives a 32-byte AES-256 key from a passphrase and an
// explicit salt using PBKDF2-SHA256 with [pbkdf2Iterations] rounds.
//
// The per-ciphertext random salt path (v2) calls this directly with a fresh
// 16-byte random salt embedded in the ciphertext blob. The legacy path
// ([DeriveKey]) calls it with the package-level fixed salt [legacyV1Salt].
func deriveKeyWithSalt(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, aes256KeySize, sha256.New)
}

// IsLegacyFormat reports whether blob is in the v1 legacy wire format (no magic
// byte, fixed-salt derivation) as opposed to the v2 wire format
// (magic(0x02) || salt(16) || nonce(12) || ciphertext+tag).
//
// A return value of false is a necessary but not sufficient condition for a
// blob to be a valid v2 ciphertext: the shortest possible v2 blob is
// 1 + v2SaltSize + 12 = 29 bytes, and even a 29+ byte blob that starts with
// 0x02 may turn out to be a v1 ciphertext whose random nonce happens to begin
// with 0x02 (probability 1/256). [DecryptIfKeySet] resolves this ambiguity at
// decrypt time by falling back to v1 when v2 AEAD verification fails; callers
// of IsLegacyFormat should use it only as a heuristic (e.g. migration
// tooling, log annotation).
func IsLegacyFormat(blob []byte) bool {
	if len(blob) == 0 {
		return false
	}
	return blob[0] != v2Magic
}

// EncryptIfKeySet encrypts plaintext with the supplied passphrase and emits a
// v2 wire-format blob: magic(0x02) || salt(16) || nonce(12) || ciphertext+tag.
//
// Key derivation is performed internally per invocation with a fresh 16-byte
// random salt, producing a distinct AES-256 key for every ciphertext. The
// operator-supplied passphrase is the only cross-ciphertext shared secret.
//
// The second return value is always true when err == nil — the "wasEncrypted"
// flag is retained for source-compatibility with callers that previously used
// it to log provenance. Callers MUST handle err: passing an empty passphrase
// returns [ErrEncryptionKeyRequired] rather than silently emitting plaintext.
// See the package-level [ErrEncryptionKeyRequired] documentation for the
// history behind this behavior change (C-2).
//
// The write path never produces a v1 blob. v1 blobs are read-only legacy
// state — see [DecryptIfKeySet] for the compatibility fallback.
func EncryptIfKeySet(plaintext []byte, passphrase string) ([]byte, bool, error) {
	if passphrase == "" {
		return nil, false, ErrEncryptionKeyRequired
	}

	salt := make([]byte, v2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, false, fmt.Errorf("failed to generate v2 salt: %w", err)
	}

	key := deriveKeyWithSalt(passphrase, salt)
	inner, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, false, err
	}

	// v2 blob layout: magic(1) || salt(v2SaltSize) || inner
	blob := make([]byte, 0, 1+v2SaltSize+len(inner))
	blob = append(blob, v2Magic)
	blob = append(blob, salt...)
	blob = append(blob, inner...)
	return blob, true, nil
}

// DecryptIfKeySet decrypts blob with the supplied passphrase, supporting both
// v2 (M-8 and later) and v1 (legacy) on-disk formats.
//
// Dispatch is first-byte magic + AEAD fallback. If blob starts with
// [v2Magic] and is long enough to contain a v2 header plus an AEAD-authenticated
// inner ciphertext, a v2 decrypt is attempted using a key derived from the
// embedded salt. If that succeeds, its plaintext is returned. If v2 AEAD
// verification fails — which covers both the "wrong passphrase" case and the
// 1/256 case where a v1 blob's first byte happens to be 0x02 — the function
// falls through to the v1 path and attempts decryption using a key derived
// from the package-level fixed salt [legacyV1Salt].
//
// Passing an empty passphrase returns [ErrEncryptionKeyRequired]. Callers that
// legitimately store plaintext (e.g. env-seeded source='env' rows that keep the
// raw JSON in the unencrypted `config` column) must branch on the presence of
// the ciphertext themselves rather than relying on this helper to silently
// pass bytes through. See the package-level [ErrEncryptionKeyRequired]
// documentation for the history behind this behavior change (C-2).
//
// The function never re-encrypts in place. A v1 blob that is successfully
// decrypted is returned to the caller as plaintext; re-sealing as v2 happens
// naturally on the next UPDATE via [EncryptIfKeySet].
func DecryptIfKeySet(blob []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrEncryptionKeyRequired
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	// v2 path: magic || salt(16) || nonce(12) || ciphertext+tag (min 29 bytes
	// ignoring the GCM tag; the AEAD verify inside Decrypt enforces the tag).
	if blob[0] == v2Magic && len(blob) >= 1+v2SaltSize+12 {
		salt := blob[1 : 1+v2SaltSize]
		sealed := blob[1+v2SaltSize:]
		key := deriveKeyWithSalt(passphrase, salt)
		if plaintext, err := Decrypt(sealed, key); err == nil {
			return plaintext, nil
		}
		// v2 AEAD verification failed. Fall through to v1 so that a v1 blob
		// whose first byte happens to be 0x02 (1/256 probability) is still
		// decryptable. If this is truly a v2 blob with the wrong passphrase,
		// the v1 attempt below will also fail and the v1 error is returned.
	}

	// v1 legacy path: blob is the full ciphertext with no header and was
	// sealed with a key derived from (passphrase, legacyV1Salt).
	key := DeriveKey(passphrase)
	return Decrypt(blob, key)
}
