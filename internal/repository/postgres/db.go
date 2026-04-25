package postgres

import (
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
func NewDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	// Ping to verify connection
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

// RunMigrations reads and executes SQL migration files from a directory.
func RunMigrations(db *sql.DB, migrationsPath string) error {
	// Check if migrations directory exists
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory not found: %s", migrationsPath)
	}

	// Read all SQL files from the migrations directory
	files, err := os.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort and filter to only .up.sql migration files (skip .down.sql rollbacks and seed files)
	var sqlFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".up.sql") {
			sqlFiles = append(sqlFiles, file.Name())
		}
	}

	// Execute each migration file in order
	for _, filename := range sqlFiles {
		filePath := filepath.Join(migrationsPath, filename)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		// Execute the SQL content
		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
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
