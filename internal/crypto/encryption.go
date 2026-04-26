// Package crypto provides AES-256-GCM encryption for sensitive configuration data.
//
// The on-disk format for blobs produced by [EncryptIfKeySet] is versioned.
// Three versions coexist; the write path always emits v3, the read path
// (DecryptIfKeySet) accepts all three:
//
//	v3 (current, Bundle B / M-001)
//	    magic(0x03) || salt(16) || nonce(12) || ciphertext+tag
//	    — 32-byte AES-256 key derived via PBKDF2-SHA256 (600,000 rounds)
//	      from the operator passphrase and the per-ciphertext random salt.
//	      OWASP 2024 recommends 600,000 rounds for SHA-256 PBKDF2; this is
//	      a 6× increase over v2.
//
//	v2 (legacy, M-8)
//	    magic(0x02) || salt(16) || nonce(12) || ciphertext+tag
//	    — 32-byte AES-256 key derived via PBKDF2-SHA256 (100,000 rounds)
//	      from the operator passphrase and the per-ciphertext random salt.
//
//	v1 (legacy, pre-M-8)
//	    nonce(12) || ciphertext+tag
//	    — 32-byte AES-256 key derived via PBKDF2-SHA256 (100,000 rounds)
//	      from the operator passphrase and the package-level fixed salt
//	      "certctl-config-encryption-v1".
//
// v1 and v2 blobs are accepted by the read path for backward compatibility
// with rows persisted before each remediation. They are never produced by the
// write path. Any row that is updated after Bundle B is re-sealed as v3
// in-place via the normal UPDATE flow.
//
// Rationale for the iteration bump (see Bundle B / Audit M-001 / CWE-916):
// PBKDF2 work factor is the only knob that bounds an attacker's ability to
// brute-force a leaked passphrase + ciphertext pair. OWASP's December-2023
// Password Storage Cheat Sheet raises the SHA-256 PBKDF2 floor to 600,000;
// 100k was the 2018-era floor. v3 brings certctl onto the current floor at
// the cost of ~6× more boot-time CPU on the encryption code path (a
// configuration-load operation, so amortized across the entire process
// lifetime).
//
// Rationale for the per-ciphertext salt (M-8 / CWE-916 / CWE-329): the
// pre-M-8 design reused a single 28-byte fixed salt for every ciphertext,
// which (a) removes one defense-in-depth layer against passphrase-space
// brute force and (b) makes every encrypted column across every row share
// the exact same derived key. v2/v3 replace the fixed salt with 16 fresh
// random bytes per write and store the salt alongside the ciphertext.
// Derived keys differ per row and per re-encryption.
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

// v2Magic / v3Magic are the first byte of every v2/v3-format ciphertext blob.
// Magic bytes distinguish each version from v1 legacy blobs (no magic byte,
// fixed package-level salt) and from each other (different PBKDF2 work
// factors).
//
// The choice of 0x02 / 0x03 is deliberate: v1 blobs begin with a random
// 12-byte AES-GCM nonce. A v1 nonce can coincidentally start with 0x02 or
// 0x03 with probability 1/256 each, which makes a pure magic-byte dispatch
// ambiguous. [DecryptIfKeySet] resolves the ambiguity by falling back
// through the version chain on AEAD verification failure
// (v3 → v2 → v1).
const (
	v2Magic byte = 0x02
	v3Magic byte = 0x03
)

// v2SaltSize / v3SaltSize is the length in bytes of the per-ciphertext salt
// embedded in v2/v3 blobs. 16 bytes (128 bits) matches the lower bound
// recommended in NIST SP 800-132 §5.1 for PBKDF2 salts and is sufficient
// given the one-shot-per-row nature of the derivation. The two versions use
// the same salt size — only the iteration count changes.
const (
	v2SaltSize = 16
	v3SaltSize = 16
)

// pbkdf2IterationsV1V2 is the PBKDF2-SHA256 work factor for v1 and v2 blobs
// (100,000 rounds, the 2018-era OWASP recommendation). Preserved byte-for-byte
// so legacy fallback reads stay deterministic.
//
// pbkdf2IterationsV3 is the work factor for newly-written v3 blobs (600,000
// rounds, the OWASP 2024 recommendation per the Password Storage Cheat Sheet).
// Bundle B / Audit M-001 / CWE-916.
const (
	pbkdf2IterationsV1V2 = 100000
	pbkdf2IterationsV3   = 600000
)

// pbkdf2Iterations is preserved as an alias for v1V2 so existing internal
// references and downstream tests that compute v1 bytes manually keep working.
// New code should reference pbkdf2IterationsV3 explicitly.
const pbkdf2Iterations = pbkdf2IterationsV1V2

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
// explicit salt using PBKDF2-SHA256 with [pbkdf2Iterations] rounds (= the
// v1/v2 work factor). v3 blobs use [deriveKeyWithSaltV3] instead.
//
// The per-ciphertext random salt path (v2) calls this directly with a fresh
// 16-byte random salt embedded in the ciphertext blob. The legacy path
// ([DeriveKey]) calls it with the package-level fixed salt [legacyV1Salt].
func deriveKeyWithSalt(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, aes256KeySize, sha256.New)
}

// deriveKeyWithSaltV3 derives a 32-byte AES-256 key from a passphrase and
// an explicit salt using PBKDF2-SHA256 with [pbkdf2IterationsV3] rounds
// (the OWASP 2024 floor of 600,000). Bundle B / Audit M-001 / CWE-916.
func deriveKeyWithSaltV3(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2IterationsV3, aes256KeySize, sha256.New)
}

// IsLegacyFormat reports whether blob is in the v1 legacy wire format (no
// magic byte, fixed-salt derivation) as opposed to a v2 or v3 wire format
// (magic byte || salt(16) || nonce(12) || ciphertext+tag).
//
// A return value of false is a necessary but not sufficient condition for
// a blob to be a valid v2/v3 ciphertext: the shortest possible v2/v3 blob
// is 1 + saltSize + 12 = 29 bytes, and even a 29+ byte blob that starts
// with 0x02/0x03 may turn out to be a v1 ciphertext whose random nonce
// happens to begin with that byte (probability 1/256 each).
// [DecryptIfKeySet] resolves this ambiguity at decrypt time by falling
// back through the version chain when AEAD verification fails; callers of
// IsLegacyFormat should use it only as a heuristic (e.g. migration
// tooling, log annotation).
func IsLegacyFormat(blob []byte) bool {
	if len(blob) == 0 {
		return false
	}
	first := blob[0]
	return first != v2Magic && first != v3Magic
}

// EncryptIfKeySet encrypts plaintext with the supplied passphrase and emits
// a v3 wire-format blob: magic(0x03) || salt(16) || nonce(12) || ciphertext+tag.
//
// Key derivation is performed internally per invocation with a fresh 16-byte
// random salt, producing a distinct AES-256 key for every ciphertext. The
// operator-supplied passphrase is the only cross-ciphertext shared secret.
// The work factor is [pbkdf2IterationsV3] (600,000) — Bundle B / Audit M-001
// / CWE-916 / OWASP 2024.
//
// The second return value is always true when err == nil — the "wasEncrypted"
// flag is retained for source-compatibility with callers that previously
// used it to log provenance. Callers MUST handle err: passing an empty
// passphrase returns [ErrEncryptionKeyRequired] rather than silently
// emitting plaintext. See the package-level [ErrEncryptionKeyRequired]
// documentation for the history behind this behavior change (C-2).
//
// The write path never produces v1 or v2 blobs. They are read-only legacy
// state — see [DecryptIfKeySet] for the compatibility fallback.
func EncryptIfKeySet(plaintext []byte, passphrase string) ([]byte, bool, error) {
	if passphrase == "" {
		return nil, false, ErrEncryptionKeyRequired
	}

	salt := make([]byte, v3SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, false, fmt.Errorf("failed to generate v3 salt: %w", err)
	}

	key := deriveKeyWithSaltV3(passphrase, salt)
	inner, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, false, err
	}

	// v3 blob layout: magic(1) || salt(v3SaltSize) || inner
	blob := make([]byte, 0, 1+v3SaltSize+len(inner))
	blob = append(blob, v3Magic)
	blob = append(blob, salt...)
	blob = append(blob, inner...)
	return blob, true, nil
}

// DecryptIfKeySet decrypts blob with the supplied passphrase, supporting v3
// (Bundle B and later), v2 (M-8 era), and v1 (pre-M-8 legacy) on-disk
// formats.
//
// Dispatch is first-byte magic + AEAD fallback. If blob starts with
// [v3Magic] / [v2Magic] and is long enough to contain a header plus an
// AEAD-authenticated inner ciphertext, the matching version is attempted
// using a key derived from the embedded salt at the version's PBKDF2 work
// factor. If AEAD verification fails — which covers both the "wrong
// passphrase" case and the 1/256 case where a different-version blob
// happens to start with that magic byte — the function falls through to
// the next version. The order is v3 → v2 → v1.
//
// A v1 blob that is successfully decrypted is returned as plaintext;
// re-sealing as v3 happens naturally on the next UPDATE via
// [EncryptIfKeySet]. The function never re-encrypts in place.
//
// Passing an empty passphrase returns [ErrEncryptionKeyRequired]. Callers
// that legitimately store plaintext (e.g. env-seeded source='env' rows
// that keep the raw JSON in the unencrypted `config` column) must branch
// on the presence of the ciphertext themselves rather than relying on
// this helper to silently pass bytes through. See the package-level
// [ErrEncryptionKeyRequired] documentation for the history behind this
// behavior change (C-2).
func DecryptIfKeySet(blob []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrEncryptionKeyRequired
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	// v3 path: Bundle B / M-001 — magic(0x03) || salt(16) || nonce(12) || ct+tag.
	// 600,000 PBKDF2 rounds.
	if blob[0] == v3Magic && len(blob) >= 1+v3SaltSize+12 {
		salt := blob[1 : 1+v3SaltSize]
		sealed := blob[1+v3SaltSize:]
		key := deriveKeyWithSaltV3(passphrase, salt)
		if plaintext, err := Decrypt(sealed, key); err == nil {
			return plaintext, nil
		}
		// v3 AEAD failed. Fall through — could be a v2 blob whose first
		// byte happens to be 0x03 (1/256), or a v1 nonce-prefix collision,
		// or a wrong-passphrase v3.
	}

	// v2 path: M-8 — magic(0x02) || salt(16) || nonce(12) || ct+tag.
	// 100,000 PBKDF2 rounds.
	if blob[0] == v2Magic && len(blob) >= 1+v2SaltSize+12 {
		salt := blob[1 : 1+v2SaltSize]
		sealed := blob[1+v2SaltSize:]
		key := deriveKeyWithSalt(passphrase, salt)
		if plaintext, err := Decrypt(sealed, key); err == nil {
			return plaintext, nil
		}
		// v2 AEAD failed. Fall through to v1.
	}

	// v1 legacy path: blob is the full ciphertext with no header and was
	// sealed with a key derived from (passphrase, legacyV1Salt) at 100k
	// rounds. If both v2/v3 attempts above failed and this also fails, the
	// returned error is the v1 attempt's error — which is the most likely
	// "wrong passphrase" surface for an operator on a recent install (no
	// pre-M-8 v1 rows, so the first two paths are the actual write format
	// and only v1 has a chance to surface a meaningful error).
	key := DeriveKey(passphrase)
	return Decrypt(blob, key)
}
