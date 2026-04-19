package postgres_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestMigration000016_NotificationRetryRoundTrip is the Phase 1 Red regression
// test for I-005 ("failed webhook/email drops critical alerts — no retry, no
// DLQ, no escalation"). The fix depends on a new migration,
// 000016_notification_retry.up.sql + .down.sql, which must:
//
//  1. Add `retry_count INTEGER NOT NULL DEFAULT 0` on notification_events.
//     Mirrors migration 000015's column-nullability pattern: explicit
//     NOT NULL + default so existing rows backfill cleanly and the service
//     layer never has to nil-check the counter. The 0 default is what lets
//     the retry scheduler promote a row from failed → pending on its very
//     first sweep without a bespoke backfill.
//
//  2. Add `next_retry_at TIMESTAMPTZ` (nullable) on notification_events.
//     Populated by the service layer on every failed→pending transition
//     using exponential backoff (2^retry_count minutes, cap 1h). Nullable
//     because the field is only meaningful while a row sits in 'failed'
//     state; 'sent', 'pending', 'dead', and 'read' rows leave it NULL.
//
//  3. Add `last_error TEXT` (nullable) on notification_events. TEXT
//     (not VARCHAR(N)) because notifier errors can include full HTTP
//     response bodies, TLS handshake diagnostics, or stringified stack
//     traces. Truncation here would kick the operator back to the server
//     log, which is exactly the triage pain I-005 is meant to eliminate.
//
//  4. Create the partial retry-sweep index
//     `idx_notification_events_retry_sweep ON notification_events(next_retry_at)
//     WHERE status = 'failed' AND next_retry_at IS NOT NULL`.
//     The predicate keeps the index tiny in a healthy fleet — only failed
//     rows scheduled for retry participate; sent/pending/dead/read rows and
//     unscheduled failures are excluded. Makes the retry sweep in
//     RetryFailedNotifications O(retry-eligible) rather than O(total-events).
//
// The round-trip also validates that the down migration cleanly reverses all
// four schema additions, so an operator who lands on a rollback can still
// boot the server. Stage 4 asserts idempotency — the up migration must be
// safely re-runnable after a partial rollback, which requires ADD COLUMN
// IF NOT EXISTS and CREATE INDEX IF NOT EXISTS on every new object.
//
// Red-until-Green: this test compiles but fails until
// migrations/000016_notification_retry.up.sql + .down.sql exist with the
// right schema, because freshSchema(t) runs every `.up.sql` in lexical order
// — the new migration runs automatically once Phase 2 creates the files.
func TestMigration000016_NotificationRetryRoundTrip(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// ─── Stage 1: Post-up assertions ─────────────────────────────────────
	//
	// After every .up.sql migration (including the new 000016) has run, the
	// three new columns and the partial retry-sweep index must be observable
	// in the catalog.

	// All three retry columns must be present on notification_events.
	assertColumnExists(t, db, "notification_events", "retry_count")
	assertColumnExists(t, db, "notification_events", "next_retry_at")
	assertColumnExists(t, db, "notification_events", "last_error")

	// retry_count must be NOT NULL with a server-side default of 0. The
	// scheduler's failed→pending transition relies on reading the counter
	// without a COALESCE, and the back-fill on existing rows must be
	// deterministic; 0 is the only safe default for an attempt counter.
	assertColumnNotNull(t, db, "notification_events", "retry_count", true)
	assertColumnDefaultContains(t, db, "notification_events", "retry_count", "0")

	// next_retry_at and last_error are nullable by design — see the Stage 1
	// doc block above for why. A NOT NULL constraint here would force the
	// service layer to write sentinel values on every terminal-status
	// transition, which is worse than just leaving them NULL.
	assertColumnNotNull(t, db, "notification_events", "next_retry_at", false)
	assertColumnNotNull(t, db, "notification_events", "last_error", false)

	// The partial retry-sweep index must exist on notification_events and
	// must include the WHERE predicate that restricts it to failed+scheduled
	// rows. Without the predicate the index is merely an index on
	// next_retry_at — correct semantics, but it would balloon in a busy
	// fleet because every sent/read row would sit in it with a NULL key.
	assertIndexExists(t, db, "idx_notification_events_retry_sweep")
	assertIndexPredicateContains(t, db, "idx_notification_events_retry_sweep", "status = 'failed'")
	assertIndexPredicateContains(t, db, "idx_notification_events_retry_sweep", "next_retry_at IS NOT NULL")

	// ─── Stage 2: Run the 000016 down migration manually ─────────────────
	//
	// testutil_test.go's runMigrations helper only runs *.up.sql. To exercise
	// the down migration I read and execute it by hand, then re-check the
	// catalog.

	downSQL := readMigrationFile(t, "000016_notification_retry.down.sql")
	if _, err := db.ExecContext(ctx, downSQL); err != nil {
		t.Fatalf("000016 down migration failed: %v", err)
	}

	// Stage 3: Post-down assertions — all three columns removed, partial
	// index dropped.
	assertColumnGone(t, db, "notification_events", "retry_count")
	assertColumnGone(t, db, "notification_events", "next_retry_at")
	assertColumnGone(t, db, "notification_events", "last_error")
	assertIndexGone(t, db, "idx_notification_events_retry_sweep")

	// ─── Stage 4: Re-run the up migration for idempotency ────────────────
	//
	// The up migration must be safely re-runnable — operators sometimes
	// re-apply by hand after a partial rollback. Use ADD COLUMN IF NOT
	// EXISTS and CREATE INDEX IF NOT EXISTS so every converging run is a
	// no-op.

	upSQL := readMigrationFile(t, "000016_notification_retry.up.sql")
	if _, err := db.ExecContext(ctx, upSQL); err != nil {
		t.Fatalf("000016 up migration re-apply failed (must be idempotent): %v", err)
	}

	assertColumnExists(t, db, "notification_events", "retry_count")
	assertColumnExists(t, db, "notification_events", "next_retry_at")
	assertColumnExists(t, db, "notification_events", "last_error")
	assertIndexExists(t, db, "idx_notification_events_retry_sweep")
}

// ─── Extra catalog helpers for 000016 ─────────────────────────────────────
//
// These are additive to the column-existence and FK helpers defined in
// migration_000015_test.go. Both files live in `package postgres_test`, so
// assertColumnExists / assertColumnGone / readMigrationFile are already in
// scope from the 000015 test file and must not be redeclared.

// assertColumnNotNull asserts that the information_schema reports the
// expected nullability for a column. PG exposes `is_nullable` as the string
// 'YES' or 'NO'; we translate to a bool so the call site reads cleanly.
func assertColumnNotNull(t *testing.T, db *sql.DB, table, column string, wantNotNull bool) {
	t.Helper()
	var isNullable string
	err := db.QueryRowContext(context.Background(), `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = $1
		  AND column_name = $2
	`, table, column).Scan(&isNullable)
	if err == sql.ErrNoRows {
		t.Fatalf("column %s.%s not found in current_schema (migration missing?)", table, column)
	}
	if err != nil {
		t.Fatalf("is_nullable lookup for %s.%s failed: %v", table, column, err)
	}
	gotNotNull := isNullable == "NO"
	if gotNotNull != wantNotNull {
		t.Errorf("column %s.%s nullability: got NOT NULL=%v, want NOT NULL=%v (is_nullable=%q)",
			table, column, gotNotNull, wantNotNull, isNullable)
	}
}

// assertColumnDefaultContains asserts that the server-side DEFAULT clause for
// a column contains the expected substring. Postgres can render defaults in
// a few different normalized shapes (`0`, `(0)::integer`, `0::integer`),
// so substring matching is more robust than exact equality here.
func assertColumnDefaultContains(t *testing.T, db *sql.DB, table, column, wantSubstr string) {
	t.Helper()
	var columnDefault sql.NullString
	err := db.QueryRowContext(context.Background(), `
		SELECT column_default
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = $1
		  AND column_name = $2
	`, table, column).Scan(&columnDefault)
	if err == sql.ErrNoRows {
		t.Fatalf("column %s.%s not found in current_schema (migration missing?)", table, column)
	}
	if err != nil {
		t.Fatalf("column_default lookup for %s.%s failed: %v", table, column, err)
	}
	if !columnDefault.Valid {
		t.Errorf("column %s.%s has no DEFAULT clause; want substring %q", table, column, wantSubstr)
		return
	}
	if !strings.Contains(columnDefault.String, wantSubstr) {
		t.Errorf("column %s.%s DEFAULT = %q; want substring %q",
			table, column, columnDefault.String, wantSubstr)
	}
}

// assertIndexExists asserts that a named index exists in the current schema.
// Scoped via pg_indexes.schemaname = current_schema() so schema-per-test
// isolation holds.
func assertIndexExists(t *testing.T, db *sql.DB, indexName string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = current_schema()
			  AND indexname = $1
		)`, indexName).Scan(&exists)
	if err != nil {
		t.Fatalf("index existence query failed for %s: %v", indexName, err)
	}
	if !exists {
		t.Errorf("expected index %s to exist after 000016 up (migration missing or drifted)", indexName)
	}
}

// assertIndexGone is the negative form, used after the down migration to
// confirm the partial retry-sweep index has been dropped.
func assertIndexGone(t *testing.T, db *sql.DB, indexName string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = current_schema()
			  AND indexname = $1
		)`, indexName).Scan(&exists)
	if err != nil {
		t.Fatalf("index existence query failed for %s: %v", indexName, err)
	}
	if exists {
		t.Errorf("expected index %s to be removed after 000016 down (down migration is incomplete)", indexName)
	}
}

// assertIndexPredicateContains asserts that the reconstructed `indexdef`
// (pg_indexes.indexdef — the CREATE INDEX statement Postgres would emit to
// recreate the index) contains the expected substring. This is how we pin
// the WHERE predicate of a partial index without parsing the SQL.
//
// Postgres normalises the predicate (e.g. single-quoted literals stay
// single-quoted, column references are bare), so substring matching is both
// sufficient and robust against cosmetic reformatting.
func assertIndexPredicateContains(t *testing.T, db *sql.DB, indexName, wantSubstr string) {
	t.Helper()
	var indexdef string
	err := db.QueryRowContext(context.Background(), `
		SELECT indexdef
		FROM pg_indexes
		WHERE schemaname = current_schema()
		  AND indexname = $1
	`, indexName).Scan(&indexdef)
	if err == sql.ErrNoRows {
		t.Fatalf("index %s not found in current_schema (migration missing?)", indexName)
	}
	if err != nil {
		t.Fatalf("indexdef lookup for %s failed: %v", indexName, err)
	}
	if !strings.Contains(indexdef, wantSubstr) {
		t.Errorf("index %s definition missing expected predicate fragment %q\nfull indexdef: %s",
			indexName, wantSubstr, indexdef)
	}
}
