package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
// =============================================================================

// PreLoginRepository is the postgres implementation of
// repository.PreLoginRepository.
type PreLoginRepository struct {
	db *sql.DB
}

// NewPreLoginRepository constructs a PreLoginRepository.
func NewPreLoginRepository(db *sql.DB) *PreLoginRepository {
	return &PreLoginRepository{db: db}
}

const preLoginColumns = `id, tenant_id, signing_key_id, oidc_provider_id,
		state, nonce, pkce_verifier, created_at, absolute_expires_at`

func scanPreLogin(row interface{ Scan(...interface{}) error }) (*repository.PreLoginSession, error) {
	var p repository.PreLoginSession
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.SigningKeyID, &p.OIDCProviderID,
		&p.State, &p.Nonce, &p.PKCEVerifier, &p.CreatedAt, &p.AbsoluteExpiresAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// Create persists a pre-login row. Caller MUST have already generated
// the random id (`pl-<base64url>`), state, nonce, and PKCE verifier.
// CreatedAt + AbsoluteExpiresAt default to NOW() / NOW()+10min when
// zero (the schema's DEFAULT clauses handle this).
func (r *PreLoginRepository) Create(ctx context.Context, p *repository.PreLoginSession) error {
	if p.CreatedAt.IsZero() && p.AbsoluteExpiresAt.IsZero() {
		_, err := r.db.ExecContext(ctx, `
			INSERT INTO oidc_pre_login_sessions (
				id, tenant_id, signing_key_id, oidc_provider_id,
				state, nonce, pkce_verifier
			) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			p.ID, p.TenantID, p.SigningKeyID, p.OIDCProviderID,
			p.State, p.Nonce, p.PKCEVerifier)
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
			state, nonce, pkce_verifier, created_at, absolute_expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID, p.TenantID, p.SigningKeyID, p.OIDCProviderID,
		p.State, p.Nonce, p.PKCEVerifier, p.CreatedAt, p.AbsoluteExpiresAt)
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
func (r *PreLoginRepository) LookupAndConsume(ctx context.Context, id string) (*repository.PreLoginSession, error) {
	row := r.db.QueryRowContext(ctx, `
		DELETE FROM oidc_pre_login_sessions WHERE id = $1
		RETURNING `+preLoginColumns,
		id)
	p, err := scanPreLogin(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrPreLoginNotFound
		}
		return nil, fmt.Errorf("oidc_pre_login lookup_and_consume: %w", err)
	}
	if time.Now().UTC().After(p.AbsoluteExpiresAt) {
		return nil, repository.ErrPreLoginExpired
	}
	return p, nil
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
