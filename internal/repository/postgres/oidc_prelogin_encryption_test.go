package postgres_test

import (
	"bytes"
	"context"
	"testing"

	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// Audit 2026-05-10 HIGH-5 closure — pin the at-rest invariant for
// the OIDC pre-login table. Pre-fix, state / nonce / pkce_verifier
// rode plaintext columns; an operator restoring an unredacted backup
// to a debug environment leaked every in-flight handshake. Post-fix,
// the new write path encrypts via crypto.EncryptIfKeySet (v3 magic
// 0x03 || salt(16) || nonce(12) || ciphertext+tag). The legacy
// plaintext columns remain on the schema (nullable) for in-flight
// rolling-deploy compat; the new write path NEVER populates them.
//
// Mirror of the Phase 13 oidc_providers encryption-invariant pattern.
// Lives in the postgres_test package so it runs against the real
// migrated schema via testcontainers; protected by testing.Short().

const (
	preLoginEncTestPassphrase = "high-5-prelogin-test-encryption-key-DO-NOT-USE-IN-PROD"
)

// TestPreLoginRepository_EncryptionInvariant_HIGH5 pins three legs:
//
//	(a) the {state,nonce,pkce_verifier}_enc columns contain v3
//	    AES-GCM blobs (NOT the plaintext) immediately after Create;
//	(b) the legacy plaintext columns are NULL after the new write
//	    path runs (defense against a regressing patch that re-adds
//	    plaintext writes);
//	(c) LookupAndConsume round-trips the original plaintext via the
//	    encrypted columns, returning state / nonce / pkce_verifier
//	    byte-for-byte equal to the values written.
func TestPreLoginRepository_EncryptionInvariant_HIGH5(t *testing.T) {
	if testing.Short() {
		t.Skip("HIGH-5 encryption invariant: integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()

	// Seed a session_signing_keys row + an oidc_providers row so the
	// pre-login row's FK constraints are satisfied. The signing-key
	// material can be any non-empty byte slice (the pre-login repo
	// doesn't decrypt it).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO session_signing_keys (id, tenant_id, key_material_encrypted)
		VALUES ('sk-high5', 't-default', $1)`,
		[]byte{0x03, 0x00, 0x01, 0x02}); err != nil {
		t.Fatalf("seed session_signing_keys: %v", err)
	}
	provRepo := postgres.NewOIDCProviderRepository(db)
	if err := provRepo.Create(ctx, newValidProvider("high5")); err != nil {
		t.Fatalf("seed oidc_provider: %v", err)
	}

	repo := postgres.NewPreLoginRepository(db, preLoginEncTestPassphrase)

	statePlain := "very-secret-oidc-state-do-not-leak"
	noncePlain := "very-secret-oidc-nonce-do-not-leak"
	verifierPlain := "very-secret-pkce-verifier-bytes-do-not-leak"

	row := &repository.PreLoginSession{
		ID:             "pl-high5-1",
		TenantID:       "t-default",
		SigningKeyID:   "sk-high5",
		OIDCProviderID: "op-high5",
		State:          statePlain,
		Nonce:          noncePlain,
		PKCEVerifier:   verifierPlain,
	}
	if err := repo.Create(ctx, row); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// ── Invariant (a): encrypted columns contain v3 blobs, NOT plaintext. ──
	var stateEnc, nonceEnc, verifierEnc []byte
	if err := db.QueryRowContext(ctx, `
		SELECT state_enc, nonce_enc, pkce_verifier_enc
		FROM oidc_pre_login_sessions WHERE id = $1`, row.ID).
		Scan(&stateEnc, &nonceEnc, &verifierEnc); err != nil {
		t.Fatalf("SELECT raw enc columns: %v", err)
	}
	for label, blob := range map[string][]byte{
		"state":         stateEnc,
		"nonce":         nonceEnc,
		"pkce_verifier": verifierEnc,
	} {
		if len(blob) == 0 {
			t.Errorf("INVARIANT (a) VIOLATED: %s_enc is empty post-Create", label)
			continue
		}
		// v3 magic + salt(16) + nonce(12) + at least 16 bytes for the AEAD tag.
		if len(blob) < 1+16+12+16 {
			t.Errorf("INVARIANT (a) VIOLATED: %s_enc blob too short (%d bytes)", label, len(blob))
		}
		if blob[0] != 0x03 {
			t.Errorf("INVARIANT (a) VIOLATED: %s_enc magic = 0x%02x; want 0x03 (v3)", label, blob[0])
		}
	}
	if bytes.Contains(stateEnc, []byte(statePlain)) {
		t.Errorf("INVARIANT (a) VIOLATED: state_enc contains plaintext substring %q", statePlain)
	}
	if bytes.Contains(nonceEnc, []byte(noncePlain)) {
		t.Errorf("INVARIANT (a) VIOLATED: nonce_enc contains plaintext substring %q", noncePlain)
	}
	if bytes.Contains(verifierEnc, []byte(verifierPlain)) {
		t.Errorf("INVARIANT (a) VIOLATED: pkce_verifier_enc contains plaintext substring %q", verifierPlain)
	}

	// ── Invariant (b): legacy plaintext columns are NULL post-Create. ──
	var statePlainCol, noncePlainCol, verifierPlainCol *string
	if err := db.QueryRowContext(ctx, `
		SELECT state, nonce, pkce_verifier
		FROM oidc_pre_login_sessions WHERE id = $1`, row.ID).
		Scan(&statePlainCol, &noncePlainCol, &verifierPlainCol); err != nil {
		t.Fatalf("SELECT plaintext columns: %v", err)
	}
	if statePlainCol != nil {
		t.Errorf("INVARIANT (b) VIOLATED: legacy state column = %q; want NULL", *statePlainCol)
	}
	if noncePlainCol != nil {
		t.Errorf("INVARIANT (b) VIOLATED: legacy nonce column = %q; want NULL", *noncePlainCol)
	}
	if verifierPlainCol != nil {
		t.Errorf("INVARIANT (b) VIOLATED: legacy pkce_verifier column = %q; want NULL", *verifierPlainCol)
	}

	// ── Invariant (c): LookupAndConsume round-trips the plaintext. ──
	got, err := repo.LookupAndConsume(ctx, row.ID)
	if err != nil {
		t.Fatalf("LookupAndConsume: %v", err)
	}
	if got.State != statePlain {
		t.Errorf("INVARIANT (c) VIOLATED: round-trip state = %q; want %q", got.State, statePlain)
	}
	if got.Nonce != noncePlain {
		t.Errorf("INVARIANT (c) VIOLATED: round-trip nonce = %q; want %q", got.Nonce, noncePlain)
	}
	if got.PKCEVerifier != verifierPlain {
		t.Errorf("INVARIANT (c) VIOLATED: round-trip pkce_verifier = %q; want %q", got.PKCEVerifier, verifierPlain)
	}

	// Sanity: a wrong passphrase MUST fail the AEAD check.
	if _, err := cryptopkg.DecryptIfKeySet(stateEnc, preLoginEncTestPassphrase+"-wrong"); err == nil {
		t.Error("AEAD broken: DecryptIfKeySet succeeded with wrong passphrase")
	}
}

// TestPreLoginRepository_EncryptionInvariant_LegacyPlaintextStillReadable
// pins the rolling-deploy fallback. Pre-deploy code paths that already
// wrote a row using the legacy schema (plaintext columns populated,
// _enc columns NULL) must continue to consume cleanly. After 000042
// drops the plaintext columns, this test should be deleted along with
// the materialize() fallback in the repo.
func TestPreLoginRepository_EncryptionInvariant_LegacyPlaintextStillReadable(t *testing.T) {
	if testing.Short() {
		t.Skip("HIGH-5 legacy fallback: integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO session_signing_keys (id, tenant_id, key_material_encrypted)
		VALUES ('sk-legacy', 't-default', $1)`,
		[]byte{0x03, 0x00, 0x01, 0x02}); err != nil {
		t.Fatalf("seed session_signing_keys: %v", err)
	}
	provRepo := postgres.NewOIDCProviderRepository(db)
	if err := provRepo.Create(ctx, newValidProvider("legacy")); err != nil {
		t.Fatalf("seed oidc_provider: %v", err)
	}

	// Simulate a legacy-write row (plaintext populated, _enc NULL) by
	// inserting directly via SQL — this is the byte shape the pre-fix
	// code path produced.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO oidc_pre_login_sessions (
			id, tenant_id, signing_key_id, oidc_provider_id,
			state, nonce, pkce_verifier
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"pl-legacy-1", "t-default", "sk-legacy", "op-legacy",
		"legacy-state", "legacy-nonce", "legacy-verifier"); err != nil {
		t.Fatalf("legacy direct INSERT: %v", err)
	}

	repo := postgres.NewPreLoginRepository(db, preLoginEncTestPassphrase)
	got, err := repo.LookupAndConsume(ctx, "pl-legacy-1")
	if err != nil {
		t.Fatalf("LookupAndConsume legacy row: %v", err)
	}
	if got.State != "legacy-state" {
		t.Errorf("legacy round-trip state = %q; want legacy-state", got.State)
	}
	if got.Nonce != "legacy-nonce" {
		t.Errorf("legacy round-trip nonce = %q; want legacy-nonce", got.Nonce)
	}
	if got.PKCEVerifier != "legacy-verifier" {
		t.Errorf("legacy round-trip pkce_verifier = %q; want legacy-verifier", got.PKCEVerifier)
	}
}
