// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Phase 13 Sprint 13.3 closure (2026-05-14, architecture diligence audit
// ARCH-M1): the scheduler-invoked janitor for the postgres-backed
// rate-limit bucket table. Sweeps rows whose updated_at is older than
// the longest configured window any caller uses — these rows can
// never be at-cap (every timestamp inside has aged past the window),
// so dropping them entirely is safe.
//
// The in-memory backend's prune-on-Allow path keeps buckets short-
// lived without a separate sweep; this file is postgres-only.

// PostgresGC drives the rate_limit_buckets sweep. Constructed from the
// same *sql.DB the limiters use; the scheduler holds it as a value
// satisfying the ratelimit.GarbageCollector interface (mirrors the
// shape of acme.GarbageCollector + sessions.GarbageCollector).
type PostgresGC struct {
	db        *sql.DB
	maxWindow time.Duration
}

// NewPostgresGC returns a janitor that sweeps rows whose updated_at
// is older than `maxWindow` ago. Pass the longest window any caller
// in the deployment configures (the EST per-principal limiter uses
// 24h today; bump if a new caller introduces a longer window).
//
// maxWindow <= 0 disables the sweep — GarbageCollect becomes a
// no-op. Operator opt-out for sketchpad / single-replica deploys
// that still want the postgres backend (rare; the memory backend is
// the better fit).
func NewPostgresGC(db *sql.DB, maxWindow time.Duration) *PostgresGC {
	return &PostgresGC{db: db, maxWindow: maxWindow}
}

// GarbageCollect deletes every rate_limit_buckets row whose
// updated_at is older than now-maxWindow. Returns the number of
// rows deleted + any error from the DELETE.
//
// Single statement, single round-trip — operates on the
// rate_limit_buckets_updated_at_idx index introduced in migration
// 000046. Idempotent: repeated calls find 0 rows.
func (g *PostgresGC) GarbageCollect(ctx context.Context) (int64, error) {
	if g.maxWindow <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-g.maxWindow)
	res, err := g.db.ExecContext(ctx, `
		DELETE FROM rate_limit_buckets
		WHERE updated_at < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("ratelimit-gc: delete stale buckets: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Driver doesn't expose RowsAffected; rare. Don't fail the
		// sweep — the delete already ran.
		return 0, nil
	}
	return n, nil
}
