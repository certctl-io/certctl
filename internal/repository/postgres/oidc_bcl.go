// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/certctl-io/certctl/internal/repository"
)

// BCLReplayRepository is the postgres implementation of
// repository.BCLReplayRepository. Audit 2026-05-10 HIGH-3.
type BCLReplayRepository struct {
	db *sql.DB
}

func NewBCLReplayRepository(db *sql.DB) *BCLReplayRepository {
	return &BCLReplayRepository{db: db}
}

// ConsumeJTI atomically records that a (jti, issuer_url) pair has been
// consumed. INSERT...ON CONFLICT DO NOTHING RETURNING gives us
// single-use semantics in one round-trip: if zero rows return, the
// jti was already there.
func (r *BCLReplayRepository) ConsumeJTI(ctx context.Context, jti, issuerURL string, ttl time.Duration) error {
	expiresAt := time.Now().UTC().Add(ttl)
	var inserted bool
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO oidc_bcl_consumed_jtis (jti, issuer_url, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti, issuer_url) DO NOTHING
		RETURNING true`,
		jti, issuerURL, expiresAt,
	).Scan(&inserted)
	if err != nil {
		if err == sql.ErrNoRows {
			// ON CONFLICT DO NOTHING returns zero rows = already consumed.
			return repository.ErrBCLJTIAlreadyConsumed
		}
		return fmt.Errorf("bcl consume_jti: %w", err)
	}
	return nil
}

// SweepExpired removes rows whose expires_at is in the past.
func (r *BCLReplayRepository) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM oidc_bcl_consumed_jtis WHERE expires_at < $1`,
		now)
	if err != nil {
		return 0, fmt.Errorf("bcl sweep_expired: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
