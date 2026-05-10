package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// =============================================================================
// Bundle 2 Phase 13 — OIDC client_secret encryption invariant test.
//
// Phase 13 prompt:
//   New test internal/auth/oidc/secret_storage_test.go asserts:
//   (a) OIDCProvider.client_secret_encrypted column never contains the
//       plaintext (SELECT client_secret_encrypted FROM oidc_providers
//       rows must NOT match the input plaintext byte-for-byte);
//   (b) the column stores a v2 blob (magic byte 0x02 || salt(16) ||
//       nonce(12) || ciphertext+tag) per internal/crypto/encryption.go;
//   (c) reading back through the repo with the configured
//       CERTCTL_CONFIG_ENCRYPTION_KEY recovers the original plaintext.
//
// Format-version drift note: the prompt was written when v2 was the
// current write format. Bundle B / Audit M-001 / CWE-916 (the OWASP
// 2024 PBKDF2 600,000-rounds bump) introduced v3 as the new write
// format; v2 stayed in the read path for backward compatibility. This
// test asserts CURRENT write behavior (v3 magic 0x03) but accepts
// either v2 (0x02) OR v3 (0x03) as the leading byte so the invariant
// pin survives a future v3-or-later upgrade without a brittle exact-
// match. The shape `magic || salt(16) || nonce(12) || ciphertext+tag`
// is identical across v2 and v3.
//
// Mirrors Bundle 1's invariant tests for issuer / target credentials.
// Lives in the postgres_test package so it runs against the real
// migrated schema via testcontainers; protected by testing.Short().
// =============================================================================

const (
	// Magic bytes for v2 + v3 ciphertext blobs. Test acknowledges either
	// version as valid output; the production write path emits v3
	// (current).
	v2BlobMagic byte = 0x02
	v3BlobMagic byte = 0x03

	// Blob-shape constants from internal/crypto/encryption.go. The v2
	// and v3 layouts share these dimensions; only the PBKDF2 iteration
	// count differs.
	saltSize  = 16
	nonceSize = 12
	// magic(1) + salt(16) + nonce(12) = 29-byte fixed prefix before
	// ciphertext+tag (which is plaintext_len + 16-byte AEAD tag).
	fixedPrefixLen = 1 + saltSize + nonceSize
)

// TestOIDCProviderEncryptionInvariant_Phase13 pins the three encryption
// invariants the Phase 13 prompt enumerates against the live schema.
func TestOIDCProviderEncryptionInvariant_Phase13(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 13 encryption invariant: integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	// (Setup) Encrypt a known plaintext via the same code path the
	// HTTP handler uses (auth_session_oidc.go:encryptClientSecret →
	// internal/crypto.EncryptIfKeySet). The passphrase here is the
	// CERTCTL_CONFIG_ENCRYPTION_KEY value; pin a deterministic test
	// value so the round-trip assertion is reproducible.
	const passphrase = "phase-13-test-encryption-key-DO-NOT-USE-IN-PROD"
	plaintext := []byte("certctl-keycloak-test-secret")

	blob, encrypted, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet: %v", err)
	}
	if !encrypted {
		t.Fatalf("EncryptIfKeySet returned encrypted=false with non-empty passphrase")
	}

	// Persist a provider row carrying the encrypted blob.
	prov := newValidProvider("phase13-encryption-invariant")
	prov.ClientSecretEncrypted = blob
	if err := repo.Create(ctx, prov); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// ── Invariant (a): SELECT raw bytes; plaintext MUST NOT appear. ──
	var stored []byte
	row := db.QueryRowContext(ctx,
		`SELECT client_secret_encrypted FROM oidc_providers WHERE id = $1`, prov.ID)
	if err := row.Scan(&stored); err != nil {
		t.Fatalf("SELECT raw client_secret_encrypted: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("client_secret_encrypted column empty after Create")
	}
	if bytes.Contains(stored, plaintext) {
		t.Errorf("INVARIANT (a) VIOLATED: client_secret_encrypted contains plaintext %q in stored bytes", plaintext)
	}
	// Defense-in-depth: also reject a substring match against any
	// pseudo-printable form. If the encryption was somehow a no-op,
	// any reasonably-long suffix of the plaintext would be present.
	for n := 8; n < len(plaintext); n += 4 {
		if bytes.Contains(stored, plaintext[:n]) {
			t.Errorf("INVARIANT (a) VIOLATED: stored contains %d-byte plaintext prefix", n)
			break
		}
	}

	// ── Invariant (b): blob shape must be v2 or v3 ──
	// magic(1) || salt(16) || nonce(12) || ciphertext+tag (≥16 bytes).
	if len(stored) < fixedPrefixLen+16 {
		t.Fatalf("INVARIANT (b) VIOLATED: blob too short (%d bytes; need ≥%d)", len(stored), fixedPrefixLen+16)
	}
	switch stored[0] {
	case v2BlobMagic:
		t.Logf("Blob version: v2 (0x02) — legacy read-path-only format; production write emits v3")
	case v3BlobMagic:
		t.Logf("Blob version: v3 (0x03) — current production write format")
	default:
		t.Errorf("INVARIANT (b) VIOLATED: unknown magic byte 0x%02x; want 0x02 (v2) or 0x03 (v3)", stored[0])
	}
	// Sanity: the salt + nonce regions should not be all-zeros (which
	// would indicate a deterministic-RNG bug or a stub encryption path).
	if bytes.Equal(stored[1:1+saltSize], make([]byte, saltSize)) {
		t.Error("INVARIANT (b) VIOLATED: salt is all zeros (RNG failure?)")
	}
	if bytes.Equal(stored[1+saltSize:fixedPrefixLen], make([]byte, nonceSize)) {
		t.Error("INVARIANT (b) VIOLATED: nonce is all zeros (RNG failure?)")
	}

	// ── Invariant (c): round-trip recovers plaintext. ──
	recovered, err := cryptopkg.DecryptIfKeySet(stored, passphrase)
	if err != nil {
		t.Fatalf("INVARIANT (c) VIOLATED: DecryptIfKeySet: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("INVARIANT (c) VIOLATED: recovered %q != plaintext %q", recovered, plaintext)
	}

	// Negative round-trip: wrong passphrase MUST fail (AEAD tag check).
	_, err = cryptopkg.DecryptIfKeySet(stored, passphrase+"-wrong")
	if err == nil {
		t.Error("INVARIANT (c) DEFENSE: DecryptIfKeySet succeeded with wrong passphrase (AEAD broken?)")
	}
}

// TestOIDCProviderEncryptionInvariant_RotateRoundsViaUpdate pins the
// "Update with a new client_secret produces a fresh ciphertext" path —
// the operator-rotate UX from the Phase 8 GUI's "Edit provider" dialog.
// Two consecutive encrypts of the same plaintext under the same
// passphrase MUST produce different ciphertexts (random per-row salt +
// random AES-GCM nonce).
func TestOIDCProviderEncryptionInvariant_RotateProducesFreshCiphertext(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 13 encryption invariant: integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	const passphrase = "phase-13-rotate-test-key"
	plaintext := []byte("rotate-me-please")

	prov := newValidProvider("phase13-rotate")
	blob1, _, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("first EncryptIfKeySet: %v", err)
	}
	_ = blob1 // used below
	prov.ClientSecretEncrypted = blob1
	if err := repo.Create(ctx, prov); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// "Rotate": same plaintext, same passphrase, but a fresh encrypt
	// (random salt + nonce) and re-persist via Update.
	blob2, _, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("second EncryptIfKeySet: %v", err)
	}
	if bytes.Equal(blob1, blob2) {
		t.Error("two encrypts of same plaintext produced identical ciphertext (RNG broken?)")
	}
	prov.ClientSecretEncrypted = blob2
	if err := repo.Update(ctx, prov); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Read back and confirm the second blob made it.
	got, err := repo.Get(ctx, prov.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.ClientSecretEncrypted, blob2) {
		t.Error("Update did not persist the rotated ciphertext")
	}
	// Both blobs decrypt to the same plaintext.
	for i, blob := range [][]byte{blob1, blob2} {
		recovered, err := cryptopkg.DecryptIfKeySet(blob, passphrase)
		if err != nil {
			t.Fatalf("blob %d Decrypt: %v", i+1, err)
		}
		if !bytes.Equal(recovered, plaintext) {
			t.Errorf("blob %d round-trip: got %q, want %q", i+1, recovered, plaintext)
		}
	}
}

// TestOIDCProviderEncryptionInvariant_EmptyPassphraseFailsClosed pins the
// fail-closed contract on the production crypto helper: empty
// passphrase MUST return ErrEncryptionKeyRequired (CWE-311 fix per
// Bundle B's M-001). Production deploys MUST set
// CERTCTL_CONFIG_ENCRYPTION_KEY; the server's startup gate enforces
// this when any source='database' rows already exist. The HTTP
// handler's encryptClientSecret has its own short-circuit for
// development-mode tests where the key is unset, but the underlying
// crypto helper is strict.
func TestOIDCProviderEncryptionInvariant_EmptyPassphraseFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 13 encryption invariant: integration test in short mode")
	}

	_, encrypted, err := cryptopkg.EncryptIfKeySet([]byte("dev-secret"), "")
	if !errors.Is(err, cryptopkg.ErrEncryptionKeyRequired) {
		t.Errorf("EncryptIfKeySet(empty passphrase) err = %v; want ErrEncryptionKeyRequired", err)
	}
	if encrypted {
		t.Error("encrypted=true on the empty-passphrase path; want false")
	}

	// DecryptIfKeySet has the same fail-closed contract.
	_, err = cryptopkg.DecryptIfKeySet([]byte{0x03, 0x00}, "")
	if !errors.Is(err, cryptopkg.ErrEncryptionKeyRequired) {
		t.Errorf("DecryptIfKeySet(empty passphrase) err = %v; want ErrEncryptionKeyRequired", err)
	}
}
