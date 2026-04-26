package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Bundle-6 / Audit M-017 / HIPAA §164.312(b):
//
// migrations/000018_audit_events_worm.up.sql installs a BEFORE UPDATE OR
// DELETE trigger on audit_events that raises check_violation. This test
// boots a real Postgres via testcontainers, runs all migrations (including
// 000018), then exercises the trigger:
//
//   INSERT a row → succeeds (append is allowed)
//   UPDATE the row → fails with check_violation
//   DELETE the row → fails with check_violation
//   INSERT a second row → succeeds (write path remains open)
//
// The test is gated by testing.Short() so the default `go test ./... -short`
// loop in CI doesn't require docker-in-docker. Run via:
//
//   go test -count=1 ./internal/repository/postgres/...

func TestAuditEventsWORM_AppendOnlyEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.teardown(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// INSERT — must succeed (append is the supported write path).
	_, err := tdb.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp)
		VALUES ('audit-bundle6-001', 'tester', 'User', 'create_certificate', 'certificate', 'mc-test-001', '{}'::jsonb, NOW())
	`)
	if err != nil {
		t.Fatalf("INSERT (append) should succeed: %v", err)
	}

	// UPDATE — trigger MUST fire and raise check_violation.
	_, err = tdb.db.ExecContext(ctx, `
		UPDATE audit_events SET actor = 'tampered' WHERE id = 'audit-bundle6-001'
	`)
	if err == nil {
		t.Fatal("UPDATE should fail with check_violation; got nil error (WORM trigger missing?)")
	}
	if !strings.Contains(err.Error(), "audit_events is append-only") {
		t.Errorf("UPDATE error should cite the WORM rationale; got: %v", err)
	}

	// DELETE — trigger MUST fire and raise check_violation.
	_, err = tdb.db.ExecContext(ctx, `
		DELETE FROM audit_events WHERE id = 'audit-bundle6-001'
	`)
	if err == nil {
		t.Fatal("DELETE should fail with check_violation; got nil error (WORM trigger missing?)")
	}
	if !strings.Contains(err.Error(), "audit_events is append-only") {
		t.Errorf("DELETE error should cite the WORM rationale; got: %v", err)
	}

	// INSERT again — confirm the write path remains open after a blocked
	// modification attempt (no trigger-state corruption).
	_, err = tdb.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp)
		VALUES ('audit-bundle6-002', 'tester', 'User', 'list_certificates', 'certificate', '*', '{}'::jsonb, NOW())
	`)
	if err != nil {
		t.Fatalf("INSERT after blocked UPDATE/DELETE should still succeed: %v", err)
	}

	// Sanity check: both INSERTs landed.
	var count int
	row := tdb.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE id IN ('audit-bundle6-001', 'audit-bundle6-002')`)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 rows, got %d (WORM trigger may be blocking INSERT)", count)
	}
}
