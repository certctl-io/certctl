package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigration000015_AgentRetireRoundTrip is the Phase 2a Red regression test
// for I-004 ("Agent hard-delete cascades through deployment_targets + jobs").
//
// The fix depends on a new migration, 000015_agent_retire.up.sql + .down.sql,
// which must:
//
//  1. Add nullable `retired_at TIMESTAMPTZ` and `retired_reason TEXT`
//     columns to the `agents` table. These mirror the revoked_at /
//     revocation_reason pair on managed_certificates (migration 000005).
//
//  2. Add nullable `retired_at TIMESTAMPTZ` and `retired_reason TEXT` columns
//     to `deployment_targets`. When an agent is retired with cascade=true,
//     its deployment_targets must be soft-retired (not deleted) so audit
//     history — who deployed what to where, when — stays intact.
//
//  3. FLIP the foreign key on `deployment_targets.agent_id → agents.id`
//     from `ON DELETE CASCADE` (migration 000001, line 104) to
//     `ON DELETE RESTRICT`. This is the fail-closed change that makes a
//     bare `DELETE FROM agents WHERE id = $1` blow up at the DB layer
//     instead of silently vaporising every deployment_target row. Today
//     the CASCADE means the audit trail gets shredded with zero warning.
//
// The round-trip also validates that the down migration cleanly reverses all
// three changes, so an operator who lands on a rollback can still boot the
// server. Red-until-Green: this test compiles but fails until
// migrations/000015_agent_retire.up.sql + .down.sql exist with the right
// schema, because `freshSchema(t)` runs every `.up.sql` in lexical order —
// the new migration runs automatically once Phase 2b creates the files.
func TestMigration000015_AgentRetireRoundTrip(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// ─── Stage 1: Post-up assertions ─────────────────────────────────────
	//
	// After all .up.sql migrations (including the new 000015) have run, the
	// new columns and the flipped FK must be observable in the catalog.

	assertColumnExists(t, db, "agents", "retired_at")
	assertColumnExists(t, db, "agents", "retired_reason")
	assertColumnExists(t, db, "deployment_targets", "retired_at")
	assertColumnExists(t, db, "deployment_targets", "retired_reason")

	// The FK on deployment_targets.agent_id must be RESTRICT (confdeltype='r'),
	// not CASCADE (confdeltype='c'). This is the core fail-closed guarantee
	// that fixes I-004 at the storage layer.
	assertFKDeleteRule(t, db, "deployment_targets", "agent_id", "r")

	// The FK on jobs.agent_id is already SET NULL (confdeltype='n') per
	// migration 000001 line 146 — pin that it stays that way (or goes to
	// RESTRICT; either preserves audit history, both fail on 'c').
	assertFKDeleteRuleNot(t, db, "jobs", "agent_id", "c")

	// ─── Stage 2: Run the 000015 down migration manually ─────────────────
	//
	// testutil_test.go's runMigrations helper only runs *.up.sql. To exercise
	// the down migration I read and execute it by hand, then re-check the
	// catalog.

	downSQL := readMigrationFile(t, "000015_agent_retire.down.sql")
	if _, err := db.ExecContext(ctx, downSQL); err != nil {
		t.Fatalf("000015 down migration failed: %v", err)
	}

	// Stage 3: Post-down assertions — columns gone, FK restored to CASCADE.
	assertColumnGone(t, db, "agents", "retired_at")
	assertColumnGone(t, db, "agents", "retired_reason")
	assertColumnGone(t, db, "deployment_targets", "retired_at")
	assertColumnGone(t, db, "deployment_targets", "retired_reason")
	assertFKDeleteRule(t, db, "deployment_targets", "agent_id", "c")

	// ─── Stage 4: Re-run the up migration for idempotency ────────────────
	//
	// The up migration must be safely re-runnable — operators sometimes
	// re-apply by hand after a partial rollback. Use IF NOT EXISTS / ALTER
	// idempotently.

	upSQL := readMigrationFile(t, "000015_agent_retire.up.sql")
	if _, err := db.ExecContext(ctx, upSQL); err != nil {
		t.Fatalf("000015 up migration re-apply failed (must be idempotent): %v", err)
	}

	assertColumnExists(t, db, "agents", "retired_at")
	assertColumnExists(t, db, "agents", "retired_reason")
	assertColumnExists(t, db, "deployment_targets", "retired_at")
	assertColumnExists(t, db, "deployment_targets", "retired_reason")
	assertFKDeleteRule(t, db, "deployment_targets", "agent_id", "r")
}

// ─── Catalog helpers ──────────────────────────────────────────────────────
//
// These helpers scope every catalog query to the schema the test is actually
// running in by joining against current_schema(). Without that, a test
// running in schema test_xyz would accidentally inspect the public schema
// and green-light drift.

func assertColumnExists(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = $1
			  AND column_name = $2
		)`, table, column).Scan(&exists)
	if err != nil {
		t.Fatalf("column existence query failed for %s.%s: %v", table, column, err)
	}
	if !exists {
		t.Errorf("expected column %s.%s to exist after 000015 up (migration missing or drifted)", table, column)
	}
}

func assertColumnGone(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = $1
			  AND column_name = $2
		)`, table, column).Scan(&exists)
	if err != nil {
		t.Fatalf("column existence query failed for %s.%s: %v", table, column, err)
	}
	if exists {
		t.Errorf("expected column %s.%s to be removed after 000015 down (down migration is incomplete)", table, column)
	}
}

// assertFKDeleteRule asserts that the foreign key covering `table.column`
// (i.e. the FK whose constrained column matches) has the expected
// `confdeltype`. Per pg_constraint docs: 'r' = RESTRICT, 'c' = CASCADE,
// 'n' = SET NULL, 'd' = SET DEFAULT, 'a' = NO ACTION.
func assertFKDeleteRule(t *testing.T, db *sql.DB, table, column, want string) {
	t.Helper()
	got := lookupFKDeleteRule(t, db, table, column)
	if got != want {
		t.Errorf("FK on %s(%s): confdeltype=%q want %q (RESTRICT='r', CASCADE='c', SET NULL='n')",
			table, column, got, want)
	}
}

// assertFKDeleteRuleNot is the negative form — used for jobs.agent_id where
// multiple confdeltype values are acceptable (SET NULL and RESTRICT both
// preserve audit history) but CASCADE is strictly forbidden.
func assertFKDeleteRuleNot(t *testing.T, db *sql.DB, table, column, disallowed string) {
	t.Helper()
	got := lookupFKDeleteRule(t, db, table, column)
	if got == disallowed {
		t.Errorf("FK on %s(%s): confdeltype=%q; %q is forbidden (would destroy audit history on agent delete)",
			table, column, got, disallowed)
	}
}

// lookupFKDeleteRule returns the confdeltype for the FK constraint whose
// constrained table+column matches. Returns empty string if no FK found —
// that's treated as a test failure because the schema is supposed to have
// these FKs per migration 000001.
func lookupFKDeleteRule(t *testing.T, db *sql.DB, table, column string) string {
	t.Helper()

	// Join pg_constraint → pg_class (constrained rel) → pg_attribute
	// (constrained col) → pg_namespace (schema filter). Scoped to
	// current_schema() so schema-per-test isolation holds.
	const q = `
		SELECT c.confdeltype
		FROM pg_constraint c
		JOIN pg_class cl ON cl.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = cl.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
		WHERE n.nspname = current_schema()
		  AND c.contype = 'f'
		  AND cl.relname = $1
		  AND a.attname = $2
		LIMIT 1
	`
	var confdeltype string
	err := db.QueryRowContext(context.Background(), q, table, column).Scan(&confdeltype)
	if err == sql.ErrNoRows {
		t.Fatalf("no FK found on %s(%s) in current_schema (schema not migrated?)", table, column)
		return ""
	}
	if err != nil {
		t.Fatalf("FK lookup for %s(%s) failed: %v", table, column, err)
		return ""
	}
	return confdeltype
}

// readMigrationFile locates and loads a named migration file. Uses the same
// walk-up strategy as findMigrationsDir() in testutil_test.go so both helpers
// agree on where the migrations live.
func readMigrationFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(findMigrationsDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read migration file %s (expected at %s): %v", name, path, err)
	}
	// Defensive: a zero-byte down migration would produce false-positive
	// "success" below. Refuse to trust it.
	if strings.TrimSpace(string(data)) == "" {
		t.Fatalf("migration file %s is empty — down migration missing or truncated", name)
	}
	return string(data)
}
