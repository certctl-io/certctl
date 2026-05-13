// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lib/pq"
)

// pgErrInvalidPassword is the SQLSTATE for class 28 / code 28P01 —
// invalid_password — emitted by PostgreSQL when the client presents
// credentials that don't match pg_authid. Defined locally because the
// lib/pq package does not export named constants for SQLSTATE codes (it
// only exposes the typed string alias pq.ErrorCode and a name-lookup map
// at runtime). Pinned as a string constant rather than a pq.ErrorCode
// literal so the contract is grep-able from operator-facing log lines.
//
// Reference: https://www.postgresql.org/docs/16/errcodes-appendix.html
const pgErrInvalidPassword = "28P01"

// NewDB opens a PostgreSQL database connection and sets up connection pooling.
//
// The pool size is hard-coded here for backward compatibility with call
// sites that don't pass an explicit limit. The Bundle 3 closure (D12)
// added NewDBWithMaxConns so the operator-facing CERTCTL_DATABASE_MAX_CONNS
// env var actually flows through to db.SetMaxOpenConns; cmd/server/main.go
// uses NewDBWithMaxConns now. Idle conns are kept at MaxOpenConns/5
// (rounded up to at least 1) so the ratio behavior pre-Bundle-3 (5 idle
// out of 25 max) generalizes to any operator-supplied limit.
func NewDB(connStr string) (*sql.DB, error) {
	return NewDBWithMaxConns(connStr, 25)
}

// NewDBWithMaxConns opens a PostgreSQL database connection and sets the
// connection-pool max-open + max-idle limits.
//
// Bundle 3 closure (D12): pre-Bundle-3 the pool was hard-coded to
// SetMaxOpenConns(25) regardless of the operator's
// CERTCTL_DATABASE_MAX_CONNS setting. The config field was loaded by
// internal/config/config.go (validated to be >= 1), wired into values.yaml's
// `CERTCTL_DATABASE_MAX_CONNS: "25"` example comment, AND surfaced in
// docs/reference/configuration.md as if it took effect — but the
// underlying pool ignored it. Operators tuning for higher load found
// no behavioral change.
//
// Post-Bundle-3 the operator-facing knob actually flows here. The
// idle-pool size scales with maxOpen so the historical 1:5 ratio
// (5 idle of 25 max) carries forward to any operator-supplied size.
// Floors: maxOpen guaranteed >= 1 by config.Validate; maxIdle floored
// to 1 to avoid the 0-idle pathological case where every query opens
// a fresh connection.
func NewDBWithMaxConns(connStr string, maxOpen int) (*sql.DB, error) {
	if maxOpen < 1 {
		maxOpen = 1
	}
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool.
	db.SetMaxOpenConns(maxOpen)
	maxIdle := maxOpen / 5
	if maxIdle < 1 {
		maxIdle = 1
	}
	db.SetMaxIdleConns(maxIdle)

	// Ping to verify connection.
	if err := db.Ping(); err != nil {
		return nil, wrapPingError(err)
	}

	return db, nil
}

// wrapPingError converts a db.Ping() failure into an operator-friendly
// diagnostic. The default wrap is the original opaque
// `"failed to ping database: <inner>"` shape. The exception is SQLSTATE 28P01
// (invalid_password): when postgres rejects the server's credentials we emit
// extended guidance that names the most common operator misstep — editing
// POSTGRES_PASSWORD in `.env` after the postgres named volume has already
// been initialized — and lists both the destructive (`docker compose down -v`)
// and non-destructive (`ALTER ROLE`) remediations.
//
// U-1 (P1, GitHub #10): closes the audit-flagged
// cat-u-quickstart_postgres_password_volume_trap finding. The postgres
// docker-entrypoint runs initdb only when /var/lib/postgresql/data is empty;
// on subsequent boots the password baked into pg_authid on first boot wins
// over whatever the env var carries, so the env-vs-pg_authid divergence is
// intrinsic to how the postgres image bootstraps and cannot be fixed by us
// upstream of pg_authid. The ergonomic answer is to surface a clear
// diagnostic at the failure site so operators don't waste an hour on
// "is my password right" before discovering the volume needs to be torn
// down (or the role's password rotated in-place).
//
// The wrap chain is preserved via fmt.Errorf("%w", err) so callers using
// errors.As(err, &*pq.Error) on the returned value continue to work; this
// matches the audit's "no substring matching on err.Error()" requirement
// from the M-1 sentinel-error migration.
//
// Returns nil when err is nil so callers can defensively pipe through this
// helper without an extra branch.
func wrapPingError(err error) error {
	if err == nil {
		return nil
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) && string(pqErr.Code) == pgErrInvalidPassword {
		return fmt.Errorf(
			"failed to ping database: postgres rejected the configured credentials "+
				"(SQLSTATE %s — invalid_password). If you recently rotated POSTGRES_PASSWORD "+
				"on a docker-compose deploy, the postgres container's data volume still "+
				"holds the previous password: initdb seeds POSTGRES_PASSWORD into pg_authid "+
				"only on first boot of a fresh data dir, so editing the env var after that "+
				"point updates only the certctl-server container. Reset destructively with "+
				"`docker compose -f deploy/docker-compose.yml down -v && "+
				"docker compose -f deploy/docker-compose.yml up -d --build` (this DESTROYS "+
				"all data in the postgres volume), or non-destructively with "+
				"`docker compose -f deploy/docker-compose.yml exec postgres "+
				"psql -U certctl -c \"ALTER ROLE certctl PASSWORD '<new-password>';\"` "+
				"and then redeploy with the matching POSTGRES_PASSWORD. Underlying error: %w",
			pgErrInvalidPassword, err)
	}

	return fmt.Errorf("failed to ping database: %w", err)
}

// migrationAdvisoryLockID is the Postgres pg_advisory_lock key that
// gates concurrent migration execution. Computed as a stable hash of
// the literal string "certctl-migrations" so the same constant resolves
// across deployments without colliding with operator-supplied advisory
// locks for other workloads on the same database.
//
// Bundle 4 closure (HIGH-1 + D4 + finding 4, 2026-05-13): pre-Bundle-4
// `RunMigrations` re-executed every `.up.sql` file on every server
// boot with no concurrency control. The "idempotency via IF NOT EXISTS
// / ON CONFLICT" contract in the CLAUDE.md operating rules held for
// every individual migration, but offered no protection when two
// server replicas executed RunMigrations against the same database
// simultaneously (the Helm chart's `server.replicas > 1` HA path):
// duplicate DDL races could still produce SQLSTATE 42P07 (relation
// already exists) under specific schema-modification interleavings,
// and any future migration that drifted from the IF-NOT-EXISTS
// pattern would race-corrupt without warning.
//
// Post-Bundle-4 RunMigrations acquires this advisory lock on a
// dedicated connection before scanning the directory; runner-up
// replicas block at pg_advisory_lock() until the migrator finishes,
// then observe the populated schema_migrations table and skip every
// already-applied file. Single-replica deploys see no behavior change
// beyond the schema_migrations audit trail and the lock acquire/
// release log lines.
const migrationAdvisoryLockID int64 = 7283164759461502341

// migrationsTableDDL creates the audit-trail table that records which
// migration files have already been applied. Idempotent: subsequent
// boots see the table, scan its contents, and skip any .up.sql whose
// version (the filename, e.g. "000001_initial_schema.up.sql") is
// already present.
//
// The version column intentionally stores the FULL filename rather
// than a parsed version-number prefix. Migrations have always been
// filename-keyed; storing the raw name keeps the lookup mechanical
// and survives any future renames (a hash-based fingerprint would
// re-run every migration on rename, an explicit numeric version
// breaks if a migration is ever renamed without renumbering).
const migrationsTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    TEXT PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

// RunMigrations reads and executes SQL migration files from a directory.
//
// Bundle 4 closure: now wraps every migration execution in:
//
//  1. A `pg_advisory_lock(migrationAdvisoryLockID)` so only one
//     server replica applies migrations at a time. Other replicas
//     block at acquire and proceed once migrations finish.
//  2. A `schema_migrations` audit table so each subsequent boot
//     skips already-applied files instead of re-executing them.
//     This converts the implicit "idempotency via IF NOT EXISTS"
//     contract into an explicit applied-versions ledger an operator
//     or acquirer can audit with `SELECT * FROM schema_migrations
//     ORDER BY applied_at`.
//
// Single-replica deploys see zero behavior change beyond the new
// audit-table population. Multi-replica deploys (Helm
// `server.replicas > 1`) get HA-safe schema bootstrap.
//
// The advisory lock and audit table are managed through a dedicated
// *sql.Conn so the lock survives even if the underlying pool rotates
// connections; the deferred unlock is `LOCAL` to that connection.
// Failure modes:
//
//   - Migrations directory missing: returned unchanged from the
//     pre-Bundle-4 error path so existing callers ergonomics hold.
//   - Lock acquire fails (network / shutdown): wrapped with context
//     so the operator-visible error names the wrapping operation.
//   - Individual migration fails: aborts with the same %s wrap as
//     pre-Bundle-4, leaving schema_migrations untouched for that
//     migration so a retry rerun reattempts only the failing file.
func RunMigrations(db *sql.DB, migrationsPath string) error {
	// Check if migrations directory exists.
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory not found: %s", migrationsPath)
	}

	// Read all SQL files from the migrations directory.
	files, err := os.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort and filter to only .up.sql migration files (skip .down.sql
	// rollbacks and seed files). os.ReadDir returns entries in lexical
	// order which matches the migration file naming convention
	// (000001_, 000002_, ..., 000045_).
	var sqlFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".up.sql") {
			sqlFiles = append(sqlFiles, file.Name())
		}
	}

	// Pin to a single connection for the lock-table-migrations
	// lifecycle. pg_advisory_lock is connection-scoped: releasing it
	// requires the SAME connection that acquired it. Using a pooled
	// db.Exec for the unlock could land on a different connection and
	// silently fail to release.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire migration connection: %w", err)
	}
	defer conn.Close()

	// Bundle 4: acquire the cross-replica advisory lock. Blocks until
	// acquired; postgres queues the second replica behind the first.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("failed to acquire migration advisory lock: %w", err)
	}
	defer func() {
		// Best-effort release on the same connection. The connection
		// will close anyway via the defer above, which also releases
		// the lock at the postgres backend.
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockID)
	}()

	// Bundle 4: ensure the audit table exists before consulting it.
	// IF NOT EXISTS keeps this idempotent on every boot.
	if _, err := conn.ExecContext(ctx, migrationsTableDDL); err != nil {
		return fmt.Errorf("failed to ensure schema_migrations table: %w", err)
	}

	// Read the set of already-applied versions. We hold the advisory
	// lock through the entire SELECT → apply → INSERT cycle, so no
	// other replica can race-INSERT a duplicate row between this read
	// and our subsequent writes.
	applied := make(map[string]struct{})
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("failed to read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan schema_migrations row: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("schema_migrations scan error: %w", err)
	}
	rows.Close()

	// Execute each migration file in order, skipping already-applied
	// versions.
	for _, filename := range sqlFiles {
		if _, ok := applied[filename]; ok {
			// Already applied on a prior boot; skip.
			continue
		}
		filePath := filepath.Join(migrationsPath, filename)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		// Execute the SQL content on the locked connection so any
		// session-scoped state set by the migration (e.g. SET ROLE)
		// stays within the migration's session.
		if _, err := conn.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
		}

		// Record the applied version. ON CONFLICT (version) DO NOTHING
		// is defense-in-depth: even though we hold the advisory lock
		// (so no concurrent migrator should be writing here), a stale
		// `schema_migrations` row from a half-rolled-back deploy
		// shouldn't crash the boot.
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
			filename,
		); err != nil {
			return fmt.Errorf("failed to record applied migration %s in schema_migrations: %w", filename, err)
		}
	}

	return nil
}

// RunSeed reads and executes the baseline seed SQL file from the migrations
// directory. Designed to run AFTER RunMigrations so every column referenced by
// the seed is already in place.
//
// U-3 (P1, cat-u-seed_initdb_schema_drift): pre-U-3 the deploy compose stack
// mounted both a hand-curated subset of `migrations/*.up.sql` and `seed.sql`
// into postgres `/docker-entrypoint-initdb.d/`. Postgres applied them at
// initdb time. When `seed.sql` was updated to reference columns added by
// migrations *after* the mounted cutoff (e.g., `policy_rules.severity` from
// `000013_policy_rule_severity.up.sql`), initdb crashed during the seed step
// and the container was reported `unhealthy` indefinitely — bare
// `docker compose -f deploy/docker-compose.yml up -d --build` from a fresh
// clone of v2.0.50 hit this on the first try (GitHub #10 reopened by
// mikeakasully). Helm and the example compose files were already runtime-
// only (Path B) and worked through the same window.
//
// Post-U-3 the compose stack drops all initdb mounts; postgres comes up with
// an empty schema; the server applies all migrations via RunMigrations and
// then this function applies the seed. Single source of truth, removes the
// drift hazard architecturally.
//
// The seed file is expected at `<migrationsPath>/seed.sql`. Missing-file is
// treated as a no-op (returns nil) so deployments that explicitly remove the
// seed (custom packaging, cert-manager managed schemas) don't break.
//
// Idempotency: every INSERT in the shipped seed.sql uses
// `ON CONFLICT (id) DO NOTHING`, so re-running on a populated DB is safe.
// This function is invoked on every server start, so the contract MUST hold.
//
// Demo seed: `seed_demo.sql` is applied separately by RunDemoSeed below
// when CERTCTL_DEMO_SEED=true (see internal/config/config.go::DemoSeed).
// Splitting demo from baseline keeps a default deploy from accidentally
// landing 90-days-of-fake-history into a real customer database, while
// still giving the demo overlay a single source of truth (no more initdb
// mounts). The demo seed itself uses ON CONFLICT (id) DO NOTHING so it's
// idempotent; missing-file is also tolerated (custom packaging may strip
// seed_demo.sql to shrink the image).
func RunSeed(db *sql.DB, migrationsPath string) error {
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory not found: %s", migrationsPath)
	}

	seedPath := filepath.Join(migrationsPath, "seed.sql")
	content, err := os.ReadFile(seedPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing seed.sql is acceptable — operators may have removed it
			// for custom-packaging reasons. Return nil rather than fail-loud.
			return nil
		}
		return fmt.Errorf("failed to read seed file %s: %w", seedPath, err)
	}

	if _, err := db.Exec(string(content)); err != nil {
		return fmt.Errorf("failed to execute seed file %s: %w", seedPath, err)
	}

	return nil
}

// RunDemoSeed applies the demo overlay seed file
// (`<migrationsPath>/seed_demo.sql`) on top of the baseline seed.
//
// U-3 follow-on: pre-U-3 the demo overlay mounted `seed_demo.sql` into
// postgres `/docker-entrypoint-initdb.d/` and relied on initdb to apply it
// alongside the schema. Once U-3 dropped the initdb migration mounts, that
// path stopped working — postgres comes up empty, and the demo seed
// references tables (issuers, certificates, etc.) that wouldn't exist yet
// at initdb time. RunDemoSeed restores the demo capability through the
// same runtime path RunSeed uses, gated by CERTCTL_DEMO_SEED so production
// deploys never accidentally land the fake-history rows.
//
// Order contract: must run AFTER RunSeed so foreign-key references from
// demo rows to baseline rows (e.g., demo certificates referencing
// `rp-default` from baseline) resolve cleanly. The caller in
// cmd/server/main.go enforces this order.
//
// Missing-file is acceptable (returns nil) — operators packaging a
// production-only image often strip seed_demo.sql to shrink the artifact,
// and that should not break boot when CERTCTL_DEMO_SEED happens to be set.
//
// Idempotency: every INSERT in seed_demo.sql uses
// `ON CONFLICT (id) DO NOTHING`, so re-running on a populated DB is safe.
// Server restarts in demo mode therefore re-apply the file harmlessly.
func RunDemoSeed(db *sql.DB, migrationsPath string) error {
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory not found: %s", migrationsPath)
	}

	seedPath := filepath.Join(migrationsPath, "seed_demo.sql")
	content, err := os.ReadFile(seedPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Custom production packaging frequently strips this file.
			// Fail-soft to preserve the U-3 contract: a missing seed file
			// must not gate server boot.
			return nil
		}
		return fmt.Errorf("failed to read demo seed file %s: %w", seedPath, err)
	}

	if _, err := db.Exec(string(content)); err != nil {
		return fmt.Errorf("failed to execute demo seed file %s: %w", seedPath, err)
	}

	return nil
}
