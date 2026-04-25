// Integration tests for the U-3 schema-vs-seed coupling fix.
//
// Pre-U-3 the deploy compose stack mounted both a hand-curated subset of
// `migrations/*.up.sql` and `seed.sql` into postgres
// `/docker-entrypoint-initdb.d/`. Postgres applied them at initdb time.
// When `seed.sql` was updated to reference columns added by migrations
// *after* the mounted cutoff (e.g., `policy_rules.severity` from
// `000013_policy_rule_severity.up.sql`), initdb crashed during the seed
// step and the container was reported `unhealthy` indefinitely.
//
// Post-U-3 the schema is built EXCLUSIVELY by the server at startup via
// internal/repository/postgres.RunMigrations + RunSeed. These tests pin
// that contract: RunSeed must complete without error against a freshly
// migrated database, and re-application must be idempotent so server
// restarts don't double-insert.
//
// Skipped under -short to keep CI fast lanes green; the integration lane
// runs them via the testcontainers harness.
package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/shankar0123/certctl/internal/repository/postgres"
)

// TestRunSeed_AppliesIdempotently verifies the U-3 contract that RunSeed
// can be called repeatedly against a populated database without error and
// without producing duplicate rows. The server invokes RunSeed on EVERY
// boot (it has no migration-state table to skip from), so any non-
// idempotent INSERT in seed.sql would crash the container loop on the
// second start.
//
// The assertion uses renewal_policies.id='rp-default' as a witness — that
// row is the most-referenced FK target in the seed (it's the default
// renewal policy attached to every certificate that doesn't override).
// If the seed double-inserted, we'd see SQLSTATE 23505 from the second
// RunSeed call. If the seed silently ON CONFLICT-DO-NOTHING'd as
// designed, the row count stays at exactly 1.
func TestRunSeed_AppliesIdempotently(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	migrationsPath := findMigrationsDir()

	// Apply the seed twice — second call simulates a server restart on a
	// populated database. Both must succeed; pre-U-3 the second call
	// would fail with 23505 if any INSERT lacked ON CONFLICT.
	if err := postgres.RunSeed(db, migrationsPath); err != nil {
		t.Fatalf("RunSeed (first call) returned error: %v", err)
	}
	if err := postgres.RunSeed(db, migrationsPath); err != nil {
		t.Fatalf("RunSeed (second call — idempotency check) returned error: %v\n"+
			"This means the seed produced a duplicate row; every INSERT in seed.sql "+
			"must use ON CONFLICT (id) DO NOTHING because the server applies the "+
			"seed on EVERY start.", err)
	}

	// Witness check: rp-default is the renewal policy every cert defaults
	// to. Exactly one row must exist after two seed applications.
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM renewal_policies WHERE id = 'rp-default'`,
	).Scan(&count)
	if err != nil {
		t.Fatalf("witness query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("renewal_policies WHERE id='rp-default' returned %d rows after two RunSeed calls; want exactly 1 (ON CONFLICT idempotency contract)", count)
	}
}

// TestRunSeed_MissingFileIsNoOp verifies the fail-soft contract documented
// on RunSeed: an operator who deletes seed.sql for custom packaging (CI
// pipelines that bake their own seeds, cert-manager managed deployments)
// must still get a healthy server boot. RunSeed returning nil for a
// missing file is the only way to hold this contract — returning an error
// would force every minimal-image deployment to ship the seed file just
// to satisfy a no-op load.
//
// We point at a directory that exists (empty temp dir) but contains no
// seed.sql. RunSeed must return nil silently.
func TestRunSeed_MissingFileIsNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Use a brand-new empty directory so seed.sql is unambiguously absent.
	emptyDir := t.TempDir()

	// Pass a nil *sql.DB on purpose — RunSeed must short-circuit on the
	// missing file BEFORE touching the DB. If the implementation ever
	// regresses and tries to db.Exec(string(content)) with nil content,
	// this will surface as a nil-deref instead of a silent corruption.
	var db *sql.DB
	if err := postgres.RunSeed(db, emptyDir); err != nil {
		t.Fatalf("RunSeed against an empty directory should return nil; got: %v", err)
	}
}

// TestRunDemoSeed_AppliesIdempotently mirrors the RunSeed idempotency
// contract for the demo overlay. The compose demo stack
// (deploy/docker-compose.demo.yml) sets CERTCTL_DEMO_SEED=true; the
// server applies seed_demo.sql at every boot. Same constraint as the
// baseline seed: if any INSERT lacks ON CONFLICT, the server will
// crash-loop on restart.
//
// Witness: seed_demo.sql inserts t-platform into the teams table at line
// 11. That row is referenced by every demo-team-owned certificate, so
// duplicate-insertion would block the entire demo on restart.
func TestRunDemoSeed_AppliesIdempotently(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	migrationsPath := findMigrationsDir()

	// Order matters — RunSeed must run first so the FK targets the demo
	// seed depends on (rp-* renewal policies, etc.) exist before the
	// demo INSERTs run. This mirrors the order in cmd/server/main.go.
	if err := postgres.RunSeed(db, migrationsPath); err != nil {
		t.Fatalf("RunSeed prerequisite failed: %v", err)
	}

	if err := postgres.RunDemoSeed(db, migrationsPath); err != nil {
		t.Fatalf("RunDemoSeed (first call) returned error: %v", err)
	}
	if err := postgres.RunDemoSeed(db, migrationsPath); err != nil {
		t.Fatalf("RunDemoSeed (second call — idempotency check) returned error: %v", err)
	}

	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM teams WHERE id = 't-platform'`,
	).Scan(&count)
	if err != nil {
		t.Fatalf("witness query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("teams WHERE id='t-platform' returned %d rows after two RunDemoSeed calls; want exactly 1", count)
	}
}

// TestMigration000017_RetryIntervalRename verifies the U-3 ride-along
// column rename: renewal_policies.retry_interval_minutes →
// retry_interval_seconds (cat-o-retry_interval_unit_mismatch). The unit
// was always seconds in practice — the column name lied. Migration 000017
// renames the column with a DO $$ guard so re-application is safe.
//
// After all migrations have been applied (which the test harness does in
// freshSchema), the new column must exist and the old column must NOT.
// information_schema.columns is the source of truth for both checks.
func TestMigration000017_RetryIntervalRename(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// Helper — true iff the named column exists on renewal_policies.
	hasColumn := func(name string) bool {
		t.Helper()
		var n int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_name = 'renewal_policies' AND column_name = $1
		`, name).Scan(&n)
		if err != nil {
			t.Fatalf("information_schema query for column %q failed: %v", name, err)
		}
		return n > 0
	}

	if !hasColumn("retry_interval_seconds") {
		t.Error("renewal_policies.retry_interval_seconds is missing — migration 000017 did not apply, or it was applied before the rename block")
	}
	if hasColumn("retry_interval_minutes") {
		t.Error("renewal_policies.retry_interval_minutes still exists — the rename in migration 000017 must drop the old name (cat-o-retry_interval_unit_mismatch)")
	}
}

// TestMigration000017_NotificationCreatedAt verifies the U-3 ride-along
// column add: notification_events.created_at NOT NULL DEFAULT NOW()
// (cat-o-notification_created_at_dead_field). Pre-U-3 the Go domain had
// the field but the DB lacked the column, so the JSON API serialised
// 0001-01-01.
func TestMigration000017_NotificationCreatedAt(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	var dataType, isNullable, columnDefault sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name = 'notification_events' AND column_name = 'created_at'
	`).Scan(&dataType, &isNullable, &columnDefault)
	if err != nil {
		t.Fatalf("information_schema query for created_at failed: %v\n"+
			"Migration 000017 should have added notification_events.created_at TIMESTAMPTZ NOT NULL DEFAULT NOW().", err)
	}

	if dataType.String != "timestamp with time zone" {
		t.Errorf("notification_events.created_at data_type = %q, want %q",
			dataType.String, "timestamp with time zone")
	}
	if isNullable.String != "NO" {
		t.Errorf("notification_events.created_at is_nullable = %q, want NO (the column must be NOT NULL so legacy rows get the DEFAULT)",
			isNullable.String)
	}
	if columnDefault.String == "" {
		t.Error("notification_events.created_at has no DEFAULT — legacy rows added before migration 000017 would fail the NOT NULL gate without one")
	}
}

// TestMigration000017_HealthCheckOrphansDropped verifies the U-3
// ride-along column drop: network_scan_targets lost the orphan
// health_check_enabled / health_check_interval_seconds columns
// (cat-o-health_check_column_orphans). These were declared by an early
// migration but never wired into Go code — schema noise that confused
// operators reading raw SQL. Migration 000017 drops them.
func TestMigration000017_HealthCheckOrphansDropped(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	hasColumn := func(name string) bool {
		t.Helper()
		var n int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_name = 'network_scan_targets' AND column_name = $1
		`, name).Scan(&n)
		if err != nil {
			t.Fatalf("information_schema query for column %q failed: %v", name, err)
		}
		return n > 0
	}

	for _, col := range []string{"health_check_enabled", "health_check_interval_seconds"} {
		if hasColumn(col) {
			t.Errorf("network_scan_targets.%s still exists — migration 000017 must drop it (cat-o-health_check_column_orphans)", col)
		}
	}
}
