// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// Phase 13 Sprint 13.2 closure (2026-05-14, architecture diligence audit
// ARCH-M1): the cross-replica-consistent rate-limit backend. Same
// algorithm as SlidingWindowLimiter (prune-on-Allow sliding-window log)
// but the state lives in postgres so N replicas see the same per-key
// bucket. Replaces the per-process in-memory limit when the operator
// sets CERTCTL_RATELIMIT_BACKEND=postgres (wired in Sprint 13.3).
//
// Algorithm
// =========
// Each Allow call runs a single BEGIN/COMMIT transaction:
//
//  1. INSERT ... ON CONFLICT (bucket_key) DO NOTHING — ensure the
//     row exists so the SELECT FOR UPDATE below has something to lock.
//  2. SELECT timestamps FROM rate_limit_buckets WHERE bucket_key=$1
//     FOR UPDATE — acquire the per-key row lock for the rest of the
//     transaction.
//  3. Prune timestamps older than (now - window) in Go (reusing the
//     unexported pruneOlderThan helper shared with SlidingWindowLimiter
//     — single source of truth for the prune semantics).
//  4. If cardinality(pruned) >= maxN: persist the pruned state without
//     appending, COMMIT, return ErrRateLimited.
//  5. Else: append `now`, persist, COMMIT, return nil.
//
// SELECT FOR UPDATE serializes Allow calls for the same key across
// replicas: replicas A and B firing simultaneous Allow("k") never
// race because Postgres' row-lock arbitrates. This is the entire
// reason for the close — the memory backend's sync.Mutex only
// arbitrates within a process; pg's row lock arbitrates the cluster.
//
// Why a transaction (not a single CTE)
// ====================================
// A "compute everything in one SQL statement" approach using
// INSERT ... ON CONFLICT DO UPDATE SET timestamps = CASE WHEN ... is
// possible but the conditional logic to gate the append on the
// pruned-cardinality requires nested CTEs whose check-then-act
// semantics are hard to read + harder to convince yourself are
// race-free across all isolation levels. The explicit transaction
// version above is correct under READ COMMITTED (Postgres' default),
// matches the memory backend's read-decide-write shape line-for-line,
// and shares the same prune helper. Two extra round-trips per Allow
// vs one is acceptable for the rate-limit hot path — the operation
// is gated anyway.
//
// Sprint 13.3 will wire the scheduler janitor loop that GCs rows
// whose updated_at is older than the longest configured window; the
// migration ships the supporting btree index on updated_at.

// PostgresSlidingWindowLimiter implements Limiter against the
// rate_limit_buckets table introduced in migration 000046.
//
// Constructed via NewPostgresSlidingWindowLimiter. The zero value is
// NOT usable — the db handle is required.
//
// Concurrency: safe for concurrent Allow calls across goroutines AND
// across N replicas (the underlying SELECT FOR UPDATE serializes
// per-key access across the cluster).
type PostgresSlidingWindowLimiter struct {
	db       *sql.DB
	maxN     int
	window   time.Duration
	disabled bool // maxN <= 0 → all Allow calls return nil
}

// NewPostgresSlidingWindowLimiter returns a limiter with the given
// per-key cap + window. maxN <= 0 disables the limiter (all Allow
// calls return nil); matches the memory backend's opt-out semantics
// for test harnesses + sketchpad deploys.
//
// Window defaults to 24h when zero, mirroring SlidingWindowLimiter.
//
// The db argument is required + must outlive the limiter. Construction
// itself does NOT touch the database — DDL is owned by migration
// 000046_rate_limit_buckets.up.sql which runs at boot via
// cmd/server's RunMigrations path.
func NewPostgresSlidingWindowLimiter(db *sql.DB, maxN int, window time.Duration) *PostgresSlidingWindowLimiter {
	if window <= 0 {
		window = 24 * time.Hour
	}
	disabled := maxN <= 0
	return &PostgresSlidingWindowLimiter{
		db:       db,
		maxN:     maxN,
		window:   window,
		disabled: disabled,
	}
}

// Allow records a request at the given (key, now) and returns
// ErrRateLimited if the configured cap is exceeded inside the
// configured window. Matches SlidingWindowLimiter.Allow byte-for-byte
// in caller-visible semantics so Sprint 13.3's backend-selector swap
// is signature-clean.
//
// The `now` argument is the timestamp the call is "happening at".
// Used as the prune cutoff (entries older than now-window are dropped)
// and as the new appended entry. Tests pass synthetic `now` values
// to exercise window-expiry deterministically; production call sites
// pass time.Now() (matching how SlidingWindowLimiter is invoked
// today — see internal/api/handler/{est,export,certificates,
// auth_breakglass}.go).
//
// Empty `key` short-circuits to nil (matches the memory backend's
// chokepoint-avoidance contract).
func (l *PostgresSlidingWindowLimiter) Allow(key string, now time.Time) error {
	if l.disabled {
		return nil
	}
	if key == "" {
		return nil
	}

	ctx := context.Background()
	tx, err := l.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("ratelimit: begin tx: %w", err)
	}
	defer func() {
		// Rollback is a no-op once the tx is committed; safe to defer
		// unconditionally for the error paths.
		_ = tx.Rollback()
	}()

	// Step 1: ensure the row exists so SELECT FOR UPDATE has something
	// to lock. ON CONFLICT DO NOTHING is a no-op when the row already
	// exists.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO rate_limit_buckets (bucket_key, timestamps, updated_at)
		VALUES ($1, '{}', $2)
		ON CONFLICT (bucket_key) DO NOTHING
	`, key, now); err != nil {
		return fmt.Errorf("ratelimit: ensure row: %w", err)
	}

	// Step 2: lock the row + read current state.
	var existing pq.GenericArray
	var ts []time.Time
	existing.A = &ts
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(timestamps, '{}'::timestamptz[])
		FROM rate_limit_buckets
		WHERE bucket_key = $1
		FOR UPDATE
	`, key).Scan(&existing); err != nil {
		// Shouldn't happen — step 1 ensured the row exists. Treat
		// the sql.ErrNoRows path as a no-op (be conservative; never
		// over-limit on transient DB weirdness).
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("ratelimit: select-for-update: %w", err)
	}

	// Step 3: prune in Go via the shared helper. Same prune semantics
	// as SlidingWindowLimiter — single source of truth.
	cutoff := now.Add(-l.window)
	pruned := pruneOlderThan(ts, cutoff)

	// Step 4: decide.
	rateLimited := len(pruned) >= l.maxN
	if !rateLimited {
		pruned = append(pruned, now)
	}

	// Step 5: persist.
	if _, err := tx.ExecContext(ctx, `
		UPDATE rate_limit_buckets
		SET timestamps = $2, updated_at = $3
		WHERE bucket_key = $1
	`, key, pq.Array(pruned), now); err != nil {
		return fmt.Errorf("ratelimit: update: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ratelimit: commit: %w", err)
	}

	if rateLimited {
		return ErrRateLimited
	}
	return nil
}

// Disabled reports whether the limiter is in opt-out mode (maxN <= 0).
// Mirrors SlidingWindowLimiter.Disabled() so handler-side gating +
// admin-endpoint observability can ask the same question of either
// backend.
func (l *PostgresSlidingWindowLimiter) Disabled() bool {
	return l.disabled
}
