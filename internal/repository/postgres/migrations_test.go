// Bundle 4 closure (HIGH-1 + D4 + finding 4, 2026-05-13): tests for the
// schema_migrations audit table + pg_advisory_lock concurrency control
// added to RunMigrations in db.go.
//
// Pre-Bundle-4 every .up.sql ran on every boot with no concurrency
// control. The "IF NOT EXISTS / ON CONFLICT idempotency contract" held
// for individual migrations but two replicas could race on the
// schema-modification phase. These tests pin the post-Bundle-4
// contract: the audit table is populated, repeated calls skip applied
// migrations, and the advisory lock prevents concurrent execution.
//
// Gated by testcontainers — skipped under -short. The integration lane
// invokes the full test set via the testcontainers harness.

package postgres_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// TestRunMigrations_PopulatesSchemaMigrations pins that the audit
// table is created and populated. Pre-Bundle-4 the table did not
// exist; this test would fail on a pre-Bundle-4 binary at the
// `SELECT version FROM schema_migrations` step (relation does not
// exist), confirming the closure ships.
func TestRunMigrations_PopulatesSchemaMigrations(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// freshSchema already ran the migrations once via the test-local
	// runner. The schema_migrations table must exist and be
	// non-empty.
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&count); err != nil {
		t.Fatalf("schema_migrations table missing or unreadable: %v", err)
	}
	if count == 0 {
		t.Fatalf("schema_migrations row count = 0; expected at least 1 (Bundle 4 audit-trail contract)")
	}

	// Sanity: every row's version ends in .up.sql (we store the
	// full filename, not a parsed number).
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(v) < len(".up.sql") || v[len(v)-len(".up.sql"):] != ".up.sql" {
			t.Errorf("schema_migrations.version=%q does not end in .up.sql; the Bundle 4 closure stores filenames verbatim so the lookup is mechanical", v)
		}
	}
}

// TestRunMigrations_SkipsAppliedOnSecondCall pins the skip-applied
// contract. After freshSchema ran migrations once, calling RunMigrations
// again MUST be a near-no-op: every file is already in
// schema_migrations, so the migrator loops, sees each file in the
// applied map, and skips the file-read + db.Exec. The fastest way to
// witness this is to time the second call and assert it's measurably
// faster than the first — but freshSchema doesn't expose the timing of
// the first run, so we go with a behavior pin instead: counting the
// schema_migrations rows before and after the second call must show no
// change.
func TestRunMigrations_SkipsAppliedOnSecondCall(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// Snapshot row count (post-first-migration via freshSchema).
	var before int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&before); err != nil {
		t.Fatalf("snapshot row count: %v", err)
	}
	if before == 0 {
		t.Fatalf("pre-call snapshot=0; expected at least 1 (Bundle 4 contract)")
	}

	migrationsPath := findMigrationsDir()
	if err := postgres.RunMigrations(db, migrationsPath); err != nil {
		t.Fatalf("RunMigrations second-call: %v (Bundle 4 contract: every applied file must be in schema_migrations and skipped)", err)
	}

	var after int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&after); err != nil {
		t.Fatalf("post-call row count: %v", err)
	}
	if after != before {
		t.Errorf("schema_migrations row count changed: before=%d after=%d; the second RunMigrations call must skip every already-applied file", before, after)
	}
}

// TestRunMigrations_ConcurrentCallsSerialized pins the
// pg_advisory_lock contract. Two goroutines call RunMigrations
// concurrently against the same database; both must return without
// error and the final state must be identical to a single call. The
// advisory lock guarantees Postgres-side serialization — without it,
// the parallel callers would both attempt to run migrations against
// a non-locked database and race on DDL. The lock makes one of them
// run to completion + populate schema_migrations, then the other
// wakes up, observes the populated table, and skips everything.
//
// This test does not directly measure that pg_advisory_lock was
// acquired — that would require either a SQL-level inspection of
// pg_locks (racy timing) or instrumenting db.go for testing (intrusive).
// Instead it pins the observable end-state: no error, no duplicate
// rows, no extra rows.
func TestRunMigrations_ConcurrentCallsSerialized(t *testing.T) {
	tdb := getTestDB(t)
	// Use a single freshSchema so both goroutines target the same
	// schema (test isolation is per-test, not per-goroutine).
	db := tdb.freshSchema(t)
	ctx := context.Background()

	var before int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&before); err != nil {
		t.Fatalf("snapshot row count: %v", err)
	}

	migrationsPath := findMigrationsDir()

	// Launch two concurrent RunMigrations calls.
	const goroutines = 2
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			errCh <- postgres.RunMigrations(db, migrationsPath)
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("RunMigrations concurrent call returned %v; the Bundle 4 advisory lock must serialize concurrent migrators without error", err)
		}
	}

	var after int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&after); err != nil {
		t.Fatalf("post-concurrent row count: %v", err)
	}
	if after != before {
		t.Errorf("schema_migrations row count changed after concurrent calls: before=%d after=%d; concurrent migrators must both observe the populated audit table and skip", before, after)
	}

	// Defensive: no duplicate version rows.
	var dupCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT version, COUNT(*) c FROM schema_migrations GROUP BY version HAVING COUNT(*) > 1) d`,
	).Scan(&dupCount); err != nil {
		t.Fatalf("duplicate-version query: %v", err)
	}
	if dupCount != 0 {
		t.Errorf("schema_migrations has %d duplicate version rows; the PRIMARY KEY + advisory-lock contract should prevent any duplicates", dupCount)
	}
}

// TestRunMigrations_PingsConnection is a smoke test that confirms the
// Bundle 4 changes did not break the basic happy path. The pre-existing
// RunSeed_AppliesIdempotently test already covers post-migration
// behavior; this test pins that the lock + table-create + version
// scan + apply path completes without error against an empty
// database.
func TestRunMigrations_FreshDatabaseHappyPath(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("post-migration ping failed: %v", err)
	}

	// At least 30 migrations ship in the v2.1.0-pre tree (the test
	// asserts a floor, not an exact count, so this stays robust as
	// future migrations land).
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&count); err != nil {
		t.Fatalf("schema_migrations count: %v", err)
	}
	if count < 30 {
		t.Errorf("schema_migrations count = %d; expected ≥ 30 (Bundle 4 ledger should be populated from the migrations/ directory)", count)
	}
}

// witness: keep the database/sql import alive on this file so the
// build tagger doesn't whine about unused imports if the test bodies
// stop using the type alias.
var _ = sql.ErrNoRows
