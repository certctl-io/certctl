package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Sprint 6 COMP-001-HASH closure tests. Migration 000047 installs the
// per-row hash chain on audit_events; this suite runs the live trigger
// against testcontainers + postgres:16-alpine + the migration runner
// from migrations_test.go.
//
// The tests cover four invariants:
//
//   1. Fresh table: a clean walk over zero rows returns
//      brokenAtID == "" + rowCount == 0.
//   2. Append: three inserts produce a strictly-linked chain (each
//      row's prev_hash equals the previous row's row_hash; row 0's
//      prev_hash is NULL).
//   3. Verifier-clean: after the append, audit_events_verify_chain()
//      returns brokenAtID == "" + rowCount == 3.
//   4. Verifier-detection: tampering with a row's `actor` (via the
//      compliance-superuser bypass — we ENABLE/DISABLE the WORM
//      trigger to simulate the threat model) makes
//      audit_events_verify_chain() return the tampered row's id +
//      its 0-indexed position.
//
// Gated by testing.Short() so the default `go test ./... -short` CI
// loop doesn't require docker-in-docker.

func TestAuditEventsHashChain_FreshTable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	tdb := setupTestDB(t)
	defer tdb.teardown(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var brokenID string
	var brokenPos int
	var rowCount int
	row := tdb.db.QueryRowContext(ctx, `SELECT COALESCE(first_break_id, ''), first_break_pos, row_count FROM audit_events_verify_chain()`)
	if err := row.Scan(&brokenID, &brokenPos, &rowCount); err != nil {
		t.Fatalf("verify_chain on empty table: %v", err)
	}
	if brokenID != "" || rowCount != 0 {
		t.Errorf("expected clean empty walk; got brokenID=%q rowCount=%d", brokenID, rowCount)
	}
}

func TestAuditEventsHashChain_AppendLinksRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	tdb := setupTestDB(t)
	defer tdb.teardown(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Insert three rows in chronological order. The BEFORE-INSERT
	// trigger populates prev_hash + row_hash on each.
	for i, id := range []string{"audit-chain-001", "audit-chain-002", "audit-chain-003"} {
		_, err := tdb.db.ExecContext(ctx, `
			INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp)
			VALUES ($1, 'tester', 'User', $2, 'certificate', 'mc-test', '{}'::jsonb, NOW() + ($3 || ' microsecond')::interval)
		`, id, fmt.Sprintf("action_%d", i), fmt.Sprintf("%d", i))
		if err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// Pull the three rows back in chain order. The first row's
	// prev_hash MUST be NULL (genesis); each subsequent row's
	// prev_hash MUST equal the previous row's row_hash.
	rows, err := tdb.db.QueryContext(ctx, `
		SELECT id, prev_hash, row_hash
		FROM audit_events
		ORDER BY timestamp ASC, id ASC
	`)
	if err != nil {
		t.Fatalf("select chain: %v", err)
	}
	defer rows.Close()

	type chainRow struct {
		ID       string
		PrevHash *string
		RowHash  string
	}
	var chain []chainRow
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.ID, &r.PrevHash, &r.RowHash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		chain = append(chain, r)
	}
	if len(chain) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(chain))
	}
	if chain[0].PrevHash != nil {
		t.Errorf("row 0 prev_hash should be NULL (genesis); got %q", *chain[0].PrevHash)
	}
	if chain[0].RowHash == "" {
		t.Errorf("row 0 row_hash should be non-empty")
	}
	for i := 1; i < len(chain); i++ {
		if chain[i].PrevHash == nil || *chain[i].PrevHash != chain[i-1].RowHash {
			t.Errorf("row %d prev_hash should equal row %d row_hash; prev=%v hash=%s",
				i, i-1, chain[i].PrevHash, chain[i-1].RowHash)
		}
	}

	// Verifier walks clean.
	var brokenID string
	var brokenPos int
	var rowCount int
	if err := tdb.db.QueryRowContext(ctx,
		`SELECT COALESCE(first_break_id, ''), first_break_pos, row_count FROM audit_events_verify_chain()`,
	).Scan(&brokenID, &brokenPos, &rowCount); err != nil {
		t.Fatalf("verify_chain: %v", err)
	}
	if brokenID != "" || rowCount != 3 {
		t.Errorf("verifier should report clean walk over 3 rows; got brokenID=%q pos=%d rows=%d",
			brokenID, brokenPos, rowCount)
	}
}

func TestAuditEventsHashChain_VerifierDetectsTampering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	tdb := setupTestDB(t)
	defer tdb.teardown(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed three rows. Use deterministic timestamps so the walk order
	// is unambiguous (timestamp ASC, id ASC).
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := []string{"audit-chain-t-001", "audit-chain-t-002", "audit-chain-t-003"}
	for i, id := range ids {
		_, err := tdb.db.ExecContext(ctx, `
			INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp)
			VALUES ($1, 'tester', 'User', $2, 'certificate', 'mc-test', '{}'::jsonb, $3)
		`, id, fmt.Sprintf("action_%d", i), base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// Simulate the compliance-superuser threat model: temporarily
	// disable the WORM trigger and rewrite the middle row's actor.
	// (Production deployments don't have routine ability to do this;
	// the threat is a backup-restore operator with PG-superuser
	// credentials, or post-compromise persistence.)
	if _, err := tdb.db.ExecContext(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_worm_trigger`); err != nil {
		t.Fatalf("disable worm: %v", err)
	}
	if _, err := tdb.db.ExecContext(ctx, `UPDATE audit_events SET actor = 'tampered' WHERE id = $1`, ids[1]); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	if _, err := tdb.db.ExecContext(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_worm_trigger`); err != nil {
		t.Fatalf("enable worm: %v", err)
	}

	// Verifier MUST detect the break at position 1 (the middle row's
	// 0-indexed position).
	var brokenID string
	var brokenPos int
	var rowCount int
	if err := tdb.db.QueryRowContext(ctx,
		`SELECT COALESCE(first_break_id, ''), first_break_pos, row_count FROM audit_events_verify_chain()`,
	).Scan(&brokenID, &brokenPos, &rowCount); err != nil {
		t.Fatalf("verify_chain: %v", err)
	}
	if brokenID != ids[1] {
		t.Errorf("expected break at %s; got %s", ids[1], brokenID)
	}
	if brokenPos != 1 {
		t.Errorf("expected break position 1; got %d", brokenPos)
	}
	if rowCount != 2 {
		// rowCount is "rows walked through the break"; the verifier
		// returns immediately on first mismatch so rowCount should be
		// position + 1 = 2.
		t.Errorf("expected row_count = 2 (walked through the break); got %d", rowCount)
	}
}

// _ = json.RawMessage ensures the encoding/json import survives
// linting even though the active test bodies don't reference it.
// Keeps room for future hash-chain tests that exercise details JSONB
// determinism without re-importing.
var _ = json.RawMessage(nil)
