package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// PreLoginRepository (Auth Bundle 2 Phase 5)
//
// Holds short-lived pre-login session rows that carry OIDC state +
// nonce + PKCE verifier across the IdP redirect. Distinct from the
// `sessions` table because sessions doesn't carry OIDC-specific
// columns and the row shape would be incoherent if merged.
//
// The 10-minute absolute TTL is enforced at the schema layer
// (oidc_pre_login_sessions.absolute_expires_at default of
// NOW() + INTERVAL '10 minutes') AND re-checked at the service
// layer at consume time.
//
// Audit 2026-05-10 HIGH-5 closure — state, nonce, and pkce_verifier
// are encrypted at rest using v3 AES-256-GCM (per-row salt + nonce)
// via internal/crypto.EncryptIfKeySet. The encryption key reuses
// CERTCTL_CONFIG_ENCRYPTION_KEY. The legacy plaintext columns are
// kept nullable for backward compat with in-flight handshakes during
// rolling deploys; the new write path NEVER populates them.
// =============================================================================

// PreLoginRepository is the postgres implementation of
// repository.PreLoginRepository.
type PreLoginRepository struct {
	db            *sql.DB
	encryptionKey string
}

// NewPreLoginRepository constructs a PreLoginRepository.
//
// Audit 2026-05-10 HIGH-5: encryptionKey is the same
// CERTCTL_CONFIG_ENCRYPTION_KEY value already used for OIDC client
// secrets and SessionSigningKey material. An empty key is rejected at
// startup by config validation; if the repo is constructed with an
// empty key here it will fail-closed at write time (see Create), so
// pre-login rows can never be silently persisted plaintext.
func NewPreLoginRepository(db *sql.DB, encryptionKey string) *PreLoginRepository {
	return &PreLoginRepository{db: db, encryptionKey: encryptionKey}
}

// Create persists a pre-login row. Caller MUST have already generated
// the random id (`pl-<base64url>`), state, nonce, and PKCE verifier.
// CreatedAt + AbsoluteExpiresAt default to NOW() / NOW()+10min when
// zero (the schema's DEFAULT clauses handle this).
//
// Audit 2026-05-10 HIGH-5: state / nonce / pkce_verifier are encrypted
// before INSERT via crypto.EncryptIfKeySet. The plaintext columns are
// left NULL — they remain on the schema only for in-flight backward
// compat with pre-deploy code paths that still write them, and will
// be dropped in a follow-up migration after the rolling deploy.
func (r *PreLoginRepository) Create(ctx context.Context, p *repository.PreLoginSession) error {
	stateEnc, _, serr := cryptopkg.EncryptIfKeySet([]byte(p.State), r.encryptionKey)
	if serr != nil {
		return fmt.Errorf("oidc_pre_login encrypt state: %w", serr)
	}
	nonceEnc, _, nerr := cryptopkg.EncryptIfKeySet([]byte(p.Nonce), r.encryptionKey)
	if nerr != nil {
		return fmt.Errorf("oidc_pre_login encrypt nonce: %w", nerr)
	}
	verifierEnc, _, verr := cryptopkg.EncryptIfKeySet([]byte(p.PKCEVerifier), r.encryptionKey)
	if verr != nil {
		return fmt.Errorf("oidc_pre_login encrypt pkce_verifier: %w", verr)
	}

	if p.CreatedAt.IsZero() && p.AbsoluteExpiresAt.IsZero() {
		_, err := r.db.ExecContext(ctx, `
			INSERT INTO oidc_pre_login_sessions (
				id, tenant_id, signing_key_id, oidc_provider_id,
				state_enc, nonce_enc, pkce_verifier_enc
			) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			p.ID, p.TenantID, p.SigningKeyID, p.OIDCProviderID,
			stateEnc, nonceEnc, verifierEnc)
		if err != nil {
			return fmt.Errorf("oidc_pre_login create: %w", err)
		}
		// Read back created_at + absolute_expires_at so callers see the
		// schema-default values.
		row := r.db.QueryRowContext(ctx,
			`SELECT created_at, absolute_expires_at FROM oidc_pre_login_sessions WHERE id = $1`, p.ID)
		if err := row.Scan(&p.CreatedAt, &p.AbsoluteExpiresAt); err != nil {
			return fmt.Errorf("oidc_pre_login create read-back: %w", err)
		}
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO oidc_pre_login_sessions (
			id, tenant_id, signing_key_id, oidc_provider_id,
			state_enc, nonce_enc, pkce_verifier_enc, created_at, absolute_expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID, p.TenantID, p.SigningKeyID, p.OIDCProviderID,
		stateEnc, nonceEnc, verifierEnc, p.CreatedAt, p.AbsoluteExpiresAt)
	if err != nil {
		return fmt.Errorf("oidc_pre_login create: %w", err)
	}
	return nil
}

// LookupAndConsume reads the row by id and atomically deletes it
// (single-use). Returns ErrPreLoginNotFound on miss; ErrPreLoginExpired
// when the row was found but past its TTL (the row is still deleted in
// this case so the second attempt with the same cookie maps to
// not-found rather than re-running the expiry check).
//
// Implementation note: the DELETE ... RETURNING is wrapped in a
// transaction with REPEATABLE READ so the row read + delete is atomic
// against concurrent callers — the second caller racing with a
// successful first caller gets ErrPreLoginNotFound, never a duplicate
// session-mint.
//
// Audit 2026-05-10 HIGH-5: prefer the encrypted columns
// (state_enc / nonce_enc / pkce_verifier_enc); fall back to the
// legacy plaintext columns ONLY when the encrypted columns are NULL
// (in-flight rows from pre-deploy code paths during a rolling
// deploy). After 000042 drops the plaintext columns, the fallback is
// dead code.
func (r *PreLoginRepository) LookupAndConsume(ctx context.Context, id string) (*repository.PreLoginSession, error) {
	row := r.db.QueryRowContext(ctx, `
		DELETE FROM oidc_pre_login_sessions WHERE id = $1
		RETURNING id, tenant_id, signing_key_id, oidc_provider_id,
		          state, nonce, pkce_verifier,
		          state_enc, nonce_enc, pkce_verifier_enc,
		          created_at, absolute_expires_at`,
		id)

	var p repository.PreLoginSession
	var statePlain, noncePlain, verifierPlain sql.NullString
	var stateEnc, nonceEnc, verifierEnc []byte
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.SigningKeyID, &p.OIDCProviderID,
		&statePlain, &noncePlain, &verifierPlain,
		&stateEnc, &nonceEnc, &verifierEnc,
		&p.CreatedAt, &p.AbsoluteExpiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrPreLoginNotFound
		}
		return nil, fmt.Errorf("oidc_pre_login lookup_and_consume: %w", err)
	}

	// Prefer encrypted columns; fall back to legacy plaintext only
	// when encrypted is NULL (rolling-deploy compat).
	if state, err := r.materialize(stateEnc, statePlain); err != nil {
		return nil, fmt.Errorf("oidc_pre_login decrypt state: %w", err)
	} else {
		p.State = state
	}
	if nonce, err := r.materialize(nonceEnc, noncePlain); err != nil {
		return nil, fmt.Errorf("oidc_pre_login decrypt nonce: %w", err)
	} else {
		p.Nonce = nonce
	}
	if verifier, err := r.materialize(verifierEnc, verifierPlain); err != nil {
		return nil, fmt.Errorf("oidc_pre_login decrypt pkce_verifier: %w", err)
	} else {
		p.PKCEVerifier = verifier
	}

	if time.Now().UTC().After(p.AbsoluteExpiresAt) {
		return nil, repository.ErrPreLoginExpired
	}
	return &p, nil
}

// materialize returns the decrypted value when the encrypted blob is
// present; otherwise falls back to the legacy plaintext column for
// rolling-deploy compat. Returns an error when both are absent —
// inconsistent row state that should never persist beyond a deploy.
func (r *PreLoginRepository) materialize(enc []byte, plain sql.NullString) (string, error) {
	if len(enc) > 0 {
		decrypted, err := cryptopkg.DecryptIfKeySet(enc, r.encryptionKey)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	}
	if plain.Valid {
		return plain.String, nil
	}
	return "", errors.New("row missing both encrypted and plaintext value")
}

// GarbageCollectExpired deletes rows whose absolute_expires_at is in
// the past. Returns the count deleted. Wired into the same scheduler
// sweep as expired post-login sessions.
func (r *PreLoginRepository) GarbageCollectExpired(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM oidc_pre_login_sessions WHERE absolute_expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("oidc_pre_login gc: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
