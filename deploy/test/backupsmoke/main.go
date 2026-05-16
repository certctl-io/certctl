// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Command backupsmoke is the workload+verifier half of the
// backup/restore CI gate (acquisition-audit DEPL-005 + DATA-012
// closure, Sprint 4 ACQ, 2026-05-16).
//
// The companion shell harness `deploy/test/backup-restore-smoke.sh`
// orchestrates the dump/drop/restore lifecycle around two
// invocations of this program: one before the backup
// (--mode=workload) and one after the restore (--mode=verify). Both
// emit a small JSON snapshot to stdout; the shell harness diffs them
// and asserts the chain head + row count round-trip byte-for-byte.
//
// Modes
// =====
//
//	--mode=workload
//	  Run all up-migrations against `--migrations-path`, then
//	  generate `--rows` (default 24) audit_events rows representing
//	  an issue / renew / revoke / auth-login cycle. Emit a snapshot
//	  with the post-workload row_count + chain head row_hash.
//
//	--mode=verify
//	  Run `audit_events_verify_chain()` (the per-row hash-chain
//	  verifier installed by migration 000047) and capture
//	  first_break_id / first_break_pos / verifier_walked. Emit a
//	  snapshot with row_count + chain head row_hash + verifier
//	  output. No mutations.
//
// The CI assertion contract
// =========================
//
// After (workload → pg_dump -Fc → DROP + CREATE → pg_restore →
// verify), the shell asserts:
//
//	pre.row_count      == post.row_count
//	pre.chain_head_hash == post.chain_head_hash   (byte-exact)
//	post.first_break_id == ""                     (verifier clean)
//
// A pg_dump format-quirk that didn't preserve TIMESTAMPTZ
// microseconds would surface as a chain-head mismatch (the
// canonical payload re-formats `timestamp AT TIME ZONE 'UTC'` to
// microsecond ISO-8601 — any precision loss breaks the hash). A
// trigger-or-function regression would surface as a verifier non-
// empty first_break_id. The test exists to PROVE these properties
// under a real workload, not to defend against a known quirk.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// Snapshot is the on-the-wire shape emitted to stdout. The shell
// orchestrator parses it via python3 -c 'json.load(...)' and diffs
// the relevant fields. Keep it stable — any rename here must land
// alongside a shell-harness change.
type Snapshot struct {
	Phase          string `json:"phase"`
	RowCount       int    `json:"row_count"`
	ChainHead      string `json:"chain_head_hash"`
	FirstBreakID   string `json:"first_break_id,omitempty"`
	FirstBreakPos  int    `json:"first_break_pos,omitempty"`
	VerifierWalked int    `json:"verifier_walked,omitempty"`
}

func main() {
	var (
		mode           = flag.String("mode", "", "workload | verify")
		dbURL          = flag.String("db-url", os.Getenv("DATABASE_URL"), "Postgres URL (or set DATABASE_URL)")
		migrationsPath = flag.String("migrations-path", "./migrations", "Path to the migrations/ directory (workload mode only)")
		rows           = flag.Int("rows", 24, "Number of audit_events rows to insert (workload mode only)")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("--db-url or DATABASE_URL is required")
	}
	if *mode == "" {
		log.Fatal("--mode is required (workload | verify)")
	}

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("ping: %v", err)
	}

	switch *mode {
	case "workload":
		// Run all up-migrations end-to-end. The trigger + verifier
		// function installed by migration 000047 must be in place
		// before the inserts below; partial migration would mask a
		// real bug.
		if err := postgres.RunMigrations(db, *migrationsPath); err != nil {
			log.Fatalf("RunMigrations(%s): %v", *migrationsPath, err)
		}
		if err := runWorkload(ctx, db, *rows); err != nil {
			log.Fatalf("runWorkload: %v", err)
		}
		snap, err := snapshot(ctx, db, "workload", false)
		if err != nil {
			log.Fatalf("snapshot: %v", err)
		}
		emit(snap)
	case "verify":
		snap, err := snapshot(ctx, db, "verify", true)
		if err != nil {
			log.Fatalf("snapshot: %v", err)
		}
		emit(snap)
	default:
		log.Fatalf("unknown --mode=%q (workload | verify)", *mode)
	}
}

// runWorkload inserts n audit_events rows representing an
// issue / renew / revoke / auth-login cycle. Patterns mirror the
// shape the application emits (see internal/service/audit_*.go),
// so the canonical payload exercised here is representative.
//
// event_category is omitted on each INSERT — migration 000032 gave
// the column DEFAULT 'cert_lifecycle', which is also the value the
// application uses for cert lifecycle events. Auth rows get the
// default too, which is harmless for the round-trip property under
// test (only the canonical-payload byte sequence matters).
//
// Timestamps are monotonic via the `NOW() + ($interval ||
// ' microsecond')::interval` pattern from
// internal/repository/postgres/audit_chain_test.go — ordering
// determinism is necessary for the chain head to be stable across
// runs.
func runWorkload(ctx context.Context, db *sql.DB, n int) error {
	actions := []struct{ act, resType, resID string }{
		{"certificate.issue", "certificate", "mc-smoke"},
		{"certificate.renew", "certificate", "mc-smoke"},
		{"certificate.revoke", "certificate", "mc-smoke"},
		{"auth.login", "session", "sess-smoke"},
	}
	for i := 0; i < n; i++ {
		a := actions[i%len(actions)]
		id := fmt.Sprintf("audit-smoke-%04d", i)
		_, err := db.ExecContext(ctx, `
			INSERT INTO audit_events (
				id, actor, actor_type, action,
				resource_type, resource_id, details, timestamp
			)
			VALUES (
				$1, 'smoke-actor', 'User', $2,
				$3, $4, '{}'::jsonb,
				NOW() + ($5 || ' microsecond')::interval
			)
		`, id, a.act, a.resType, a.resID, fmt.Sprintf("%d", i))
		if err != nil {
			return fmt.Errorf("insert row %d (%s): %w", i, id, err)
		}
	}
	return nil
}

// snapshot reads the chain head + row count, optionally invoking
// the on-demand verifier. Verifier output goes in three additional
// fields so the workload-side snapshot can omit them via the
// `omitempty` tag.
func snapshot(ctx context.Context, db *sql.DB, phase string, runVerifier bool) (*Snapshot, error) {
	s := &Snapshot{Phase: phase}

	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&s.RowCount); err != nil {
		return nil, fmt.Errorf("count(audit_events): %w", err)
	}

	if err := db.QueryRowContext(ctx, `SELECT row_hash FROM audit_chain_head WHERE id = 1`).Scan(&s.ChainHead); err != nil {
		return nil, fmt.Errorf("read audit_chain_head: %w", err)
	}

	if runVerifier {
		var brokenID sql.NullString
		var brokenPos, walked int
		err := db.QueryRowContext(ctx, `
			SELECT first_break_id, first_break_pos, row_count
			FROM audit_events_verify_chain()
		`).Scan(&brokenID, &brokenPos, &walked)
		if err != nil {
			return nil, fmt.Errorf("audit_events_verify_chain(): %w", err)
		}
		if brokenID.Valid {
			s.FirstBreakID = brokenID.String
		}
		s.FirstBreakPos = brokenPos
		s.VerifierWalked = walked
	}

	return s, nil
}

// emit pretty-prints the snapshot to stdout. The trailing newline
// from json.Encoder is the right shape for both shell `tee` and
// python3 stdin handling.
func emit(s *Snapshot) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		log.Fatalf("encode snapshot: %v", err)
	}
}
