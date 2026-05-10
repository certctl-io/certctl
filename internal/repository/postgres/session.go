package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// SessionRepository (Auth Bundle 2 Phase 2)
// =============================================================================

// SessionRepository is the postgres implementation of
// repository.SessionRepository.
type SessionRepository struct {
	db *sql.DB
}

// NewSessionRepository constructs a SessionRepository.
func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

const sessionColumns = `id, tenant_id, actor_id, actor_type,
		signing_key_id, is_pre_login, csrf_token_hash,
		idle_expires_at, absolute_expires_at, created_at, last_seen_at,
		ip_address, user_agent, revoked_at`

func scanSession(row interface{ Scan(...interface{}) error }) (*sessiondomain.Session, error) {
	var s sessiondomain.Session
	var revokedAt sql.NullTime
	if err := row.Scan(
		&s.ID, &s.TenantID, &s.ActorID, &s.ActorType,
		&s.SigningKeyID, &s.IsPreLogin, &s.CSRFTokenHash,
		&s.IdleExpiresAt, &s.AbsoluteExpiresAt, &s.CreatedAt, &s.LastSeenAt,
		&s.IPAddress, &s.UserAgent, &revokedAt,
	); err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		s.RevokedAt = &revokedAt.Time
	}
	return &s, nil
}

// Create persists a session row. Caller MUST have called s.Validate().
func (r *SessionRepository) Create(ctx context.Context, s *sessiondomain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (
			id, tenant_id, actor_id, actor_type, signing_key_id,
			is_pre_login, csrf_token_hash, idle_expires_at,
			absolute_expires_at, created_at, last_seen_at,
			ip_address, user_agent
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.ID, s.TenantID, s.ActorID, s.ActorType, s.SigningKeyID,
		s.IsPreLogin, s.CSRFTokenHash, s.IdleExpiresAt,
		s.AbsoluteExpiresAt, s.CreatedAt, s.LastSeenAt,
		s.IPAddress, s.UserAgent)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrAuthDuplicateName
		}
		return fmt.Errorf("sessions create: %w", err)
	}
	return nil
}

// Get returns a session by id. Returns the row even if revoked /
// expired; the service layer handles the disposition.
func (r *SessionRepository) Get(ctx context.Context, id string) (*sessiondomain.Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id)
	s, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrSessionNotFound
		}
		return nil, fmt.Errorf("sessions get: %w", err)
	}
	return s, nil
}

// ListByActor returns active (non-revoked, non-expired, non-pre-login)
// sessions for an actor.
func (r *SessionRepository) ListByActor(ctx context.Context, actorID, actorType, tenantID string) ([]*sessiondomain.Session, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sessionColumns+`
		FROM sessions
		WHERE actor_id = $1
		  AND actor_type = $2
		  AND tenant_id = $3
		  AND revoked_at IS NULL
		  AND is_pre_login = FALSE
		  AND absolute_expires_at > NOW()
		ORDER BY created_at DESC`,
		actorID, actorType, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sessions list_by_actor: %w", err)
	}
	defer rows.Close()

	var out []*sessiondomain.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("sessions scan: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateLastSeen sets last_seen_at = NOW() for the named session.
func (r *SessionRepository) UpdateLastSeen(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("sessions update_last_seen: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrSessionNotFound
	}
	return nil
}

// UpdateCSRFTokenHash replaces csrf_token_hash on the named session.
// Phase 4's RotateCSRFToken consumes this on login completion, logout,
// and any actor-role mutation against this actor.
func (r *SessionRepository) UpdateCSRFTokenHash(ctx context.Context, id, csrfTokenHash string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE sessions SET csrf_token_hash = $2 WHERE id = $1`, id, csrfTokenHash)
	if err != nil {
		return fmt.Errorf("sessions update_csrf_token_hash: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrSessionNotFound
	}
	return nil
}

// Revoke sets revoked_at = NOW() for the named session. Idempotent:
// re-revoking an already-revoked session is a no-op (returns nil).
func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("sessions revoke: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Distinguish "not found" from "already revoked" by re-querying.
		row := r.db.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE id = $1`, id)
		var x int
		if err := row.Scan(&x); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return repository.ErrSessionNotFound
			}
			return fmt.Errorf("sessions revoke probe: %w", err)
		}
		// Row exists but already revoked: idempotent success.
	}
	return nil
}

// RevokeAllForActor sets revoked_at = NOW() on every active session
// for an actor. Returns nil on zero matches (idempotent).
func (r *SessionRepository) RevokeAllForActor(ctx context.Context, actorID, actorType, tenantID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = NOW()
		WHERE actor_id = $1 AND actor_type = $2 AND tenant_id = $3 AND revoked_at IS NULL`,
		actorID, actorType, tenantID)
	if err != nil {
		return fmt.Errorf("sessions revoke_all_for_actor: %w", err)
	}
	return nil
}

// RevokeAllExceptForActor sets revoked_at = NOW() on every active
// session for an actor EXCEPT the named exceptSessionID. Returns the
// count of rows revoked. Audit 2026-05-10 MED-3 closure — backs the
// "Sign out all other sessions" flow on SessionsPage. exceptSessionID
// is the caller's current session ID (read from context); passing
// empty exceptID falls through to RevokeAllForActor semantics
// (revoke literally all).
func (r *SessionRepository) RevokeAllExceptForActor(ctx context.Context, actorID, actorType, tenantID, exceptSessionID string) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = NOW()
		WHERE actor_id = $1 AND actor_type = $2 AND tenant_id = $3
		  AND revoked_at IS NULL
		  AND id != $4`,
		actorID, actorType, tenantID, exceptSessionID)
	if err != nil {
		return 0, fmt.Errorf("sessions revoke_all_except_for_actor: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GarbageCollectExpired deletes:
//   - Sessions whose absolute_expires_at < NOW() (post-login expired).
//   - Pre-login sessions older than 10 minutes.
//
// Returns the number of rows deleted across both classes.
func (r *SessionRepository) GarbageCollectExpired(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE absolute_expires_at < NOW()
		   OR (is_pre_login = TRUE AND created_at < NOW() - INTERVAL '10 minutes')`)
	if err != nil {
		return 0, fmt.Errorf("sessions garbage_collect: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Delete unconditionally removes a session row.
func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("sessions delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrSessionNotFound
	}
	return nil
}

// =============================================================================
// SessionSigningKeyRepository (Auth Bundle 2 Phase 2)
// =============================================================================

// SessionSigningKeyRepository is the postgres implementation of
// repository.SessionSigningKeyRepository.
type SessionSigningKeyRepository struct {
	db *sql.DB
}

// NewSessionSigningKeyRepository constructs a SessionSigningKeyRepository.
func NewSessionSigningKeyRepository(db *sql.DB) *SessionSigningKeyRepository {
	return &SessionSigningKeyRepository{db: db}
}

const sessionSigningKeyColumns = `id, tenant_id, key_material_encrypted, created_at, retired_at`

func scanSessionSigningKey(row interface{ Scan(...interface{}) error }) (*sessiondomain.SessionSigningKey, error) {
	var k sessiondomain.SessionSigningKey
	var retiredAt sql.NullTime
	if err := row.Scan(&k.ID, &k.TenantID, &k.KeyMaterialEncrypted, &k.CreatedAt, &retiredAt); err != nil {
		return nil, err
	}
	if retiredAt.Valid {
		k.RetiredAt = &retiredAt.Time
	}
	return &k, nil
}

// List returns every signing key in the tenant, including retired ones.
func (r *SessionSigningKeyRepository) List(ctx context.Context, tenantID string) ([]*sessiondomain.SessionSigningKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+sessionSigningKeyColumns+` FROM session_signing_keys WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("session_signing_keys list: %w", err)
	}
	defer rows.Close()

	var out []*sessiondomain.SessionSigningKey
	for rows.Next() {
		k, err := scanSessionSigningKey(rows)
		if err != nil {
			return nil, fmt.Errorf("session_signing_keys scan: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetActive returns the most-recently-created non-retired key. Returns
// ErrSessionSigningKeyNotFound when no non-retired key exists.
func (r *SessionSigningKeyRepository) GetActive(ctx context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+sessionSigningKeyColumns+`
		FROM session_signing_keys
		WHERE tenant_id = $1 AND retired_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`, tenantID)
	k, err := scanSessionSigningKey(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrSessionSigningKeyNotFound
		}
		return nil, fmt.Errorf("session_signing_keys get_active: %w", err)
	}
	return k, nil
}

// Get returns a key by id (including retired keys; Phase 4's Validate
// consults this for cookies signed under retired-but-in-retention keys).
func (r *SessionSigningKeyRepository) Get(ctx context.Context, id string) (*sessiondomain.SessionSigningKey, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+sessionSigningKeyColumns+` FROM session_signing_keys WHERE id = $1`, id)
	k, err := scanSessionSigningKey(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrSessionSigningKeyNotFound
		}
		return nil, fmt.Errorf("session_signing_keys get: %w", err)
	}
	return k, nil
}

// Add persists a new signing key. Caller MUST have called k.Validate().
func (r *SessionSigningKeyRepository) Add(ctx context.Context, k *sessiondomain.SessionSigningKey) error {
	if k.CreatedAt.IsZero() {
		_, err := r.db.ExecContext(ctx, `
			INSERT INTO session_signing_keys (id, tenant_id, key_material_encrypted)
			VALUES ($1, $2, $3)`,
			k.ID, k.TenantID, k.KeyMaterialEncrypted)
		if err != nil {
			return fmt.Errorf("session_signing_keys add: %w", err)
		}
		// Read the row back to populate CreatedAt.
		row := r.db.QueryRowContext(ctx, `SELECT created_at FROM session_signing_keys WHERE id = $1`, k.ID)
		if err := row.Scan(&k.CreatedAt); err != nil {
			return fmt.Errorf("session_signing_keys add (read created_at): %w", err)
		}
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO session_signing_keys (id, tenant_id, key_material_encrypted, created_at)
		VALUES ($1, $2, $3, $4)`,
		k.ID, k.TenantID, k.KeyMaterialEncrypted, k.CreatedAt)
	if err != nil {
		return fmt.Errorf("session_signing_keys add: %w", err)
	}
	return nil
}

// Retire marks an active key as retired (sets retired_at = NOW()).
// Idempotent: re-retiring an already-retired key is a no-op.
func (r *SessionSigningKeyRepository) Retire(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE session_signing_keys SET retired_at = NOW() WHERE id = $1 AND retired_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("session_signing_keys retire: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Distinguish not-found vs already-retired.
		row := r.db.QueryRowContext(ctx, `SELECT 1 FROM session_signing_keys WHERE id = $1`, id)
		var x int
		if err := row.Scan(&x); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return repository.ErrSessionSigningKeyNotFound
			}
			return fmt.Errorf("session_signing_keys retire probe: %w", err)
		}
		// Row exists but already retired: idempotent success.
	}
	return nil
}

// Delete unconditionally removes a signing key. Returns
// ErrSessionSigningKeyInUse on SQLSTATE 23503 (FK ON DELETE RESTRICT
// from sessions.signing_key_id).
func (r *SessionSigningKeyRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM session_signing_keys WHERE id = $1`, id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return repository.ErrSessionSigningKeyInUse
		}
		return fmt.Errorf("session_signing_keys delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrSessionSigningKeyNotFound
	}
	return nil
}
