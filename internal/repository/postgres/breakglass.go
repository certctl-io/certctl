// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// BreakglassCredentialRepository is the postgres implementation of
// repository.BreakglassCredentialRepository. Auth Bundle 2 Phase 7.5.
type BreakglassCredentialRepository struct {
	db *sql.DB
}

// NewBreakglassCredentialRepository constructs a
// BreakglassCredentialRepository.
func NewBreakglassCredentialRepository(db *sql.DB) *BreakglassCredentialRepository {
	return &BreakglassCredentialRepository{db: db}
}

const breakglassColumns = `id, tenant_id, actor_id, password_hash,
		created_at, last_password_change_at, failure_count, locked_until,
		last_failure_at`

func scanBreakglass(row interface{ Scan(...interface{}) error }) (*bgdomain.BreakglassCredential, error) {
	var c bgdomain.BreakglassCredential
	var lockedUntil, lastFailureAt sql.NullTime
	if err := row.Scan(
		&c.ID, &c.TenantID, &c.ActorID, &c.PasswordHash,
		&c.CreatedAt, &c.LastPasswordChangeAt, &c.FailureCount,
		&lockedUntil, &lastFailureAt,
	); err != nil {
		return nil, err
	}
	if lockedUntil.Valid {
		c.LockedUntil = &lockedUntil.Time
	}
	if lastFailureAt.Valid {
		c.LastFailureAt = &lastFailureAt.Time
	}
	return &c, nil
}

// Create persists a new credential row.
func (r *BreakglassCredentialRepository) Create(ctx context.Context, c *bgdomain.BreakglassCredential) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO breakglass_credentials (
			id, tenant_id, actor_id, password_hash
		) VALUES ($1,$2,$3,$4)`,
		c.ID, c.TenantID, c.ActorID, c.PasswordHash)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrBreakglassDuplicate
		}
		return fmt.Errorf("breakglass create: %w", err)
	}
	return nil
}

// GetByActor returns the credential for the named actor.
func (r *BreakglassCredentialRepository) GetByActor(ctx context.Context, actorID, tenantID string) (*bgdomain.BreakglassCredential, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+breakglassColumns+` FROM breakglass_credentials WHERE actor_id = $1 AND tenant_id = $2`,
		actorID, tenantID)
	c, err := scanBreakglass(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrBreakglassNotFound
		}
		return nil, fmt.Errorf("breakglass get_by_actor: %w", err)
	}
	return c, nil
}

// UpdatePasswordHash rotates the password hash. Idempotent reset of
// failure_count + locked_until (a fresh password starts unlocked).
func (r *BreakglassCredentialRepository) UpdatePasswordHash(ctx context.Context, actorID, tenantID, newHash string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE breakglass_credentials
		SET password_hash = $3,
		    last_password_change_at = NOW(),
		    failure_count = 0,
		    locked_until = NULL,
		    last_failure_at = NULL
		WHERE actor_id = $1 AND tenant_id = $2`,
		actorID, tenantID, newHash)
	if err != nil {
		return fmt.Errorf("breakglass update_password_hash: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrBreakglassNotFound
	}
	return nil
}

// IncrementFailure atomically bumps failure_count + sets last_failure_at;
// when the new count >= threshold, sets locked_until = NOW() + duration.
// The whole transition is one UPDATE so concurrent racing wrong-password
// attempts can't observe an intermediate state.
//
// Returns the post-update row so the service can decide whether to
// surface ErrBreakglassLocked without a re-read.
func (r *BreakglassCredentialRepository) IncrementFailure(ctx context.Context, actorID, tenantID string, threshold int, lockoutDurationSec int) (*bgdomain.BreakglassCredential, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE breakglass_credentials
		SET failure_count = failure_count + 1,
		    last_failure_at = NOW(),
		    locked_until = CASE
		        WHEN failure_count + 1 >= $3 THEN NOW() + ($4 || ' seconds')::interval
		        ELSE locked_until
		    END
		WHERE actor_id = $1 AND tenant_id = $2
		RETURNING `+breakglassColumns,
		actorID, tenantID, threshold, lockoutDurationSec)
	c, err := scanBreakglass(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrBreakglassNotFound
		}
		return nil, fmt.Errorf("breakglass increment_failure: %w", err)
	}
	return c, nil
}

// ResetFailureCount clears failure_count + locked_until. Used on
// successful Authenticate AND on admin-initiated Unlock. Idempotent.
func (r *BreakglassCredentialRepository) ResetFailureCount(ctx context.Context, actorID, tenantID string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE breakglass_credentials
		SET failure_count = 0,
		    locked_until = NULL,
		    last_failure_at = NULL
		WHERE actor_id = $1 AND tenant_id = $2`,
		actorID, tenantID)
	if err != nil {
		return fmt.Errorf("breakglass reset_failure_count: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrBreakglassNotFound
	}
	return nil
}

// Delete removes a credential row.
func (r *BreakglassCredentialRepository) Delete(ctx context.Context, actorID, tenantID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM breakglass_credentials WHERE actor_id = $1 AND tenant_id = $2`,
		actorID, tenantID)
	if err != nil {
		return fmt.Errorf("breakglass delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrBreakglassNotFound
	}
	return nil
}

// List returns every break-glass credential in the tenant. Audit
// 2026-05-10 CRIT-4 closure — backs the GUI admin page that lists
// credentialed actors. The password hash is read into the returned
// row (it's an internal type passed to the handler which strips it
// before serializing the JSON response).
func (r *BreakglassCredentialRepository) List(ctx context.Context, tenantID string) ([]*bgdomain.BreakglassCredential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+breakglassColumns+`
		   FROM breakglass_credentials
		  WHERE tenant_id = $1
		  ORDER BY created_at ASC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("breakglass list: %w", err)
	}
	defer rows.Close()
	var out []*bgdomain.BreakglassCredential
	for rows.Next() {
		c, err := scanBreakglass(rows)
		if err != nil {
			return nil, fmt.Errorf("breakglass list scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("breakglass list iter: %w", err)
	}
	return out, nil
}
