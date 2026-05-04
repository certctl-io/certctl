package postgres_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// TestNotificationRepository_RetryMethods is the Phase 1 Red regression test
// for the I-005 fix ("failed webhook/email drops critical alerts — no retry,
// no DLQ, no escalation"). It pins the four new repository methods the
// notification-retry scheduler loop will depend on:
//
//  1. ListRetryEligible(ctx, now, maxAttempts, limit) — the retry-sweep query.
//     Returns failed rows whose next_retry_at <= now AND retry_count <
//     maxAttempts. Everything else (sent/pending/dead/read, unscheduled
//     failures, exhausted rows) is excluded. Ordering is ASC on next_retry_at
//     so the oldest overdue row is processed first — same fairness guarantee
//     as I-001's RetryFailedJobs.
//
//  2. RecordFailedAttempt(ctx, id, lastError, nextRetryAt) — what the
//     scheduler calls after a notifier.Send() transient failure. Must
//     increment retry_count by exactly 1, overwrite last_error, overwrite
//     next_retry_at, and KEEP status='failed' so the row is still a
//     candidate for ListRetryEligible on the next sweep.
//
//  3. MarkAsDead(ctx, id, lastError) — the DLQ transition when retry_count
//     hits max_attempts. Flips status to 'dead', clears next_retry_at
//     (so the partial retry-sweep index drops the row), preserves
//     retry_count as historical evidence of how many attempts were spent,
//     and records the final transient error for operator triage.
//
//  4. Requeue(ctx, id) — the operator "try again" action fired from the
//     Dead letter tab in the UI. Flips status back to 'pending' (which is
//     what ProcessPendingNotifications picks up), resets retry_count to 0,
//     clears next_retry_at AND last_error. Valid from both 'dead' (normal
//     path) and 'failed' (operator rescuing a stuck row before the sweep
//     fires). Invalid from 'sent' / 'read' (terminal success states).
//
// Red-until-Green: this test file compiles only after Phase 2 adds
// ListRetryEligible, RecordFailedAttempt, MarkAsDead, and Requeue to
// postgres.NotificationRepository. Every subtest is testcontainers-gated
// via getTestDB(t).freshSchema(t), so `go test -short` skips them and CI
// without Docker stays green. Fixtures are inserted via raw SQL — Create()
// doesn't know about the new retry columns pre-Green, so the test bypasses
// it entirely. certificate_id is left NULL on every fixture row to dodge
// the FK to managed_certificates (the column is nullable per migration
// 000001, line 212).

// TestNotificationRepository_ListRetryEligible exercises the retry-sweep
// query. The test fixture deliberately seeds one row per excluded and
// included case so a single call to ListRetryEligible is the oracle:
// every row the query returns must be an "include", every row it skips
// must be an "exclude".
func TestNotificationRepository_ListRetryEligible(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	// Pin `now` so the test is deterministic. All "overdue" rows have
	// next_retry_at < now; all "future" rows have next_retry_at > now.
	now := time.Now().UTC().Truncate(time.Microsecond)
	past := now.Add(-5 * time.Minute)
	future := now.Add(5 * time.Minute)

	// Fixture grid — each row pins a specific edge of the query:
	//
	//   notif-overdue-1  status=failed, retry=1, next=past   → INCLUDE
	//   notif-overdue-2  status=failed, retry=3, next=past   → INCLUDE
	//                      (later next_retry_at than notif-overdue-1 by a
	//                      few seconds so ORDER BY is observable)
	//   notif-future     status=failed, retry=2, next=future → EXCLUDE
	//                      (CA hasn't hit backoff yet)
	//   notif-exhausted  status=failed, retry=5, next=past   → EXCLUDE
	//                      (retry_count >= max_attempts — sweep must skip
	//                      so we don't re-promote a row that's about to
	//                      be marked dead)
	//   notif-pending    status=pending, retry=0, next=NULL  → EXCLUDE
	//                      (healthy in-flight notification)
	//   notif-sent       status=sent, retry=0, next=NULL     → EXCLUDE
	//   notif-dead       status=dead, retry=5, next=NULL     → EXCLUDE
	//                      (already in DLQ — retrying it would reset the
	//                      dead-letter counter and lie to the operator)
	//   notif-unsched    status=failed, retry=1, next=NULL   → EXCLUDE
	//                      (failed row that somehow lost its next_retry_at
	//                      — partial index predicate strips it, and the
	//                      WHERE clause must mirror the predicate)
	rawInsert := func(id, status string, retryCount int, nextRetryAt *time.Time) {
		t.Helper()
		_, err := db.ExecContext(ctx, `
			INSERT INTO notification_events (
				id, type, channel, recipient, message, status, retry_count, next_retry_at
			) VALUES ($1, 'ExpirationWarning', 'Webhook', 'https://hooks.example.com/x',
			          'seed', $2, $3, $4)
		`, id, status, retryCount, nextRetryAt)
		if err != nil {
			t.Fatalf("raw insert for %s failed: %v", id, err)
		}
	}

	overdue1 := past.Add(-30 * time.Second) // oldest overdue
	overdue2 := past                        // second-oldest overdue
	rawInsert("notif-overdue-1", "failed", 1, &overdue1)
	rawInsert("notif-overdue-2", "failed", 3, &overdue2)
	rawInsert("notif-future", "failed", 2, &future)
	rawInsert("notif-exhausted", "failed", 5, &overdue1)
	rawInsert("notif-pending", "pending", 0, nil)
	rawInsert("notif-sent", "sent", 0, nil)
	rawInsert("notif-dead", "dead", 5, nil)
	rawInsert("notif-unsched", "failed", 1, nil)

	// Act — the central call under test.
	got, err := repo.ListRetryEligible(ctx, now, 5, 100)
	if err != nil {
		t.Fatalf("ListRetryEligible failed: %v", err)
	}

	// Assert inclusion: exactly the two overdue rows.
	if len(got) != 2 {
		t.Fatalf("ListRetryEligible returned %d rows, want 2 (overdue-1 + overdue-2); got IDs = %v",
			len(got), collectIDs(got))
	}

	// Assert ordering: ASC on next_retry_at. notif-overdue-1 has the
	// earlier next_retry_at (past - 30s), so it must come first.
	if got[0].ID != "notif-overdue-1" {
		t.Errorf("ListRetryEligible[0].ID = %q, want %q (ORDER BY next_retry_at ASC — oldest first)",
			got[0].ID, "notif-overdue-1")
	}
	if got[1].ID != "notif-overdue-2" {
		t.Errorf("ListRetryEligible[1].ID = %q, want %q", got[1].ID, "notif-overdue-2")
	}

	// Assert limit is respected. Re-run with limit=1 and confirm only the
	// oldest overdue row comes back — this is what lets the scheduler
	// chunk its sweep under load.
	limited, err := repo.ListRetryEligible(ctx, now, 5, 1)
	if err != nil {
		t.Fatalf("ListRetryEligible(limit=1) failed: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != "notif-overdue-1" {
		t.Errorf("ListRetryEligible(limit=1) returned %v, want [notif-overdue-1]", collectIDs(limited))
	}

	// Assert maxAttempts is respected. Re-run with maxAttempts=2 — this
	// flips notif-overdue-2 (retry_count=3) into the "exhausted" bucket
	// and must not come back. Only notif-overdue-1 (retry_count=1) qualifies.
	capped, err := repo.ListRetryEligible(ctx, now, 2, 100)
	if err != nil {
		t.Fatalf("ListRetryEligible(maxAttempts=2) failed: %v", err)
	}
	if len(capped) != 1 || capped[0].ID != "notif-overdue-1" {
		t.Errorf("ListRetryEligible(maxAttempts=2) returned %v, want [notif-overdue-1]", collectIDs(capped))
	}
}

// TestNotificationRepository_RecordFailedAttempt verifies the retry-bump
// UPDATE. The contract is: retry_count += 1, last_error = new msg,
// next_retry_at = new time, status STAYS 'failed'. Any other side effect
// (status flip, retry_count reset, sent_at mutation) is a bug.
func TestNotificationRepository_RecordFailedAttempt(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	initialRetry := past()
	_, err := db.ExecContext(ctx, `
		INSERT INTO notification_events (
			id, type, channel, recipient, message, status, retry_count, next_retry_at, last_error
		) VALUES ('notif-attempt-1', 'ExpirationWarning', 'Webhook',
		          'https://hooks.example.com/x', 'seed', 'failed', 2, $1, 'first failure')
	`, initialRetry)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	nextTry := time.Now().UTC().Add(8 * time.Minute).Truncate(time.Microsecond)
	if err := repo.RecordFailedAttempt(ctx, "notif-attempt-1", "connection refused", nextTry); err != nil {
		t.Fatalf("RecordFailedAttempt failed: %v", err)
	}

	// Re-read the row directly from the DB (bypassing the repo's List()
	// filter logic) so the assertion tests storage, not query plumbing.
	var (
		gotStatus     string
		gotRetryCount int
		gotNextRetry  *time.Time
		gotLastError  *string
	)
	err = db.QueryRowContext(ctx, `
		SELECT status, retry_count, next_retry_at, last_error
		FROM notification_events WHERE id = 'notif-attempt-1'
	`).Scan(&gotStatus, &gotRetryCount, &gotNextRetry, &gotLastError)
	if err != nil {
		t.Fatalf("post-update SELECT failed: %v", err)
	}

	if gotStatus != "failed" {
		t.Errorf("status = %q, want 'failed' (RecordFailedAttempt must preserve status so sweep re-picks the row)", gotStatus)
	}
	if gotRetryCount != 3 {
		t.Errorf("retry_count = %d, want 3 (must increment by exactly 1 from seeded 2)", gotRetryCount)
	}
	if gotNextRetry == nil || !gotNextRetry.Equal(nextTry) {
		t.Errorf("next_retry_at = %v, want %v", gotNextRetry, nextTry)
	}
	if gotLastError == nil || *gotLastError != "connection refused" {
		t.Errorf("last_error = %v, want 'connection refused'", gotLastError)
	}

	// Negative path: unknown id must surface "not found" — mirrors the
	// existing UpdateStatus contract so the scheduler can detect a
	// concurrent delete without guessing.
	if err := repo.RecordFailedAttempt(ctx, "notif-does-not-exist", "oops", nextTry); err == nil {
		t.Errorf("RecordFailedAttempt on unknown id succeeded; want error")
	}
}

// TestNotificationRepository_MarkAsDead verifies the DLQ transition. Flips
// status to 'dead', clears next_retry_at (so the partial retry-sweep
// index drops the row), writes final last_error, preserves retry_count as
// evidence of how many attempts were burned.
func TestNotificationRepository_MarkAsDead(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	lastAttempt := past()
	_, err := db.ExecContext(ctx, `
		INSERT INTO notification_events (
			id, type, channel, recipient, message, status, retry_count, next_retry_at, last_error
		) VALUES ('notif-dlq-1', 'ExpirationWarning', 'Webhook',
		          'https://hooks.example.com/x', 'seed', 'failed', 5, $1, 'prior failure')
	`, lastAttempt)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	if err := repo.MarkAsDead(ctx, "notif-dlq-1", "max attempts exceeded"); err != nil {
		t.Fatalf("MarkAsDead failed: %v", err)
	}

	var (
		gotStatus     string
		gotRetryCount int
		gotNextRetry  *time.Time
		gotLastError  *string
	)
	err = db.QueryRowContext(ctx, `
		SELECT status, retry_count, next_retry_at, last_error
		FROM notification_events WHERE id = 'notif-dlq-1'
	`).Scan(&gotStatus, &gotRetryCount, &gotNextRetry, &gotLastError)
	if err != nil {
		t.Fatalf("post-update SELECT failed: %v", err)
	}

	if gotStatus != "dead" {
		t.Errorf("status = %q, want 'dead' (DLQ transition)", gotStatus)
	}
	if gotNextRetry != nil {
		// next_retry_at MUST be NULL post-DLQ — the partial retry-sweep
		// index predicate is `status='failed' AND next_retry_at IS NOT NULL`,
		// so leaving a value here would only waste space; the status='dead'
		// half of the predicate already excludes the row from the sweep,
		// but operator dashboards treat a populated next_retry_at as "still
		// scheduled", which would be a lie.
		t.Errorf("next_retry_at = %v, want NULL (dead rows are terminal, not rescheduled)", gotNextRetry)
	}
	if gotRetryCount != 5 {
		// retry_count is audit evidence — how many attempts were burned
		// before the row was declared dead. Don't clobber it.
		t.Errorf("retry_count = %d, want 5 preserved (evidence of burned attempts)", gotRetryCount)
	}
	if gotLastError == nil || *gotLastError != "max attempts exceeded" {
		t.Errorf("last_error = %v, want 'max attempts exceeded'", gotLastError)
	}

	// Negative path: unknown id must surface "not found".
	if err := repo.MarkAsDead(ctx, "notif-does-not-exist", "oops"); err == nil {
		t.Errorf("MarkAsDead on unknown id succeeded; want error")
	}
}

// TestNotificationRepository_Requeue verifies the operator "try again"
// flow exposed by the Dead letter tab. The contract:
//
//   - Flips status → 'pending' regardless of prior ('dead' or 'failed').
//   - Resets retry_count to 0 — a manual requeue restarts the backoff
//     ladder; otherwise the operator's first retry would already be at
//     "wait 32 minutes" which defeats the point.
//   - Clears next_retry_at so the row is no longer in the retry-sweep
//     index (the scheduler would otherwise try to retry it *again* a
//     few seconds later).
//   - Clears last_error — the UI shouldn't show a stale error next to
//     a freshly-requeued row.
func TestNotificationRepository_Requeue(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	// Two fixtures — one dead (DLQ path, the normal case) and one failed
	// (operator rescuing a stuck-in-retry row before the sweep fires).
	// Both must accept Requeue; a status='sent' or 'read' row must NOT.
	_, err := db.ExecContext(ctx, `
		INSERT INTO notification_events (id, type, channel, recipient, message, status, retry_count, last_error)
		VALUES
		  ('notif-dead-ready', 'ExpirationWarning', 'Webhook', 'https://h/x', 'seed', 'dead', 5, 'gave up'),
		  ('notif-failed-hot', 'ExpirationWarning', 'Webhook', 'https://h/x', 'seed', 'failed', 2, 'transient'),
		  ('notif-sent-done',  'ExpirationWarning', 'Webhook', 'https://h/x', 'seed', 'sent',   0, NULL)
	`)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// Happy path 1: requeue a dead row.
	if err := repo.Requeue(ctx, "notif-dead-ready"); err != nil {
		t.Fatalf("Requeue(dead) failed: %v", err)
	}
	assertRequeued(t, db, ctx, "notif-dead-ready")

	// Happy path 2: requeue a failed row.
	if err := repo.Requeue(ctx, "notif-failed-hot"); err != nil {
		t.Fatalf("Requeue(failed) failed: %v", err)
	}
	assertRequeued(t, db, ctx, "notif-failed-hot")

	// Negative path: Requeue on unknown id is "not found", not a no-op
	// silent success — the handler needs to surface a 404 to the operator.
	if err := repo.Requeue(ctx, "notif-does-not-exist"); err == nil {
		t.Errorf("Requeue on unknown id succeeded; want error")
	}
}

// TestNotificationRepository_CreatedAt_IsPersisted is the U-3 ride-along
// regression for cat-o-notification_created_at_dead_field. Pre-U-3 the
// Go domain.NotificationEvent had a CreatedAt field but the DB had no
// column — JSON serialisation produced 0001-01-01T00:00:00Z, breaking
// timestamp ordering on operator dashboards. Post-U-3 migration 000017
// adds the column NOT NULL DEFAULT NOW(), Create populates it, and
// scanNotification reads it back.
//
// The contract under test is round-trip equivalence: the timestamp the
// caller sets goes into the DB and comes back out unchanged (modulo
// PostgreSQL's microsecond precision). Truncate to microseconds before
// comparing because TIMESTAMPTZ rounds nanoseconds away.
func TestNotificationRepository_CreatedAt_IsPersisted(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	// A specific, recognisable timestamp. Truncated to microseconds so
	// the post-roundtrip equality assertion isn't tripped up by Postgres
	// dropping the nanosecond tail.
	want := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)

	notif := &domain.NotificationEvent{
		Type:      domain.NotificationTypeExpirationWarning,
		Channel:   domain.NotificationChannelWebhook,
		Recipient: "https://hooks.example.com/u3",
		Message:   "U-3 round-trip witness",
		Status:    string(domain.NotificationStatusPending),
		CreatedAt: want,
	}
	if err := repo.Create(ctx, notif); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Re-read via List (which goes through scanNotification) so we're
	// testing both the INSERT and SELECT halves of the U-3 plumbing.
	got, err := repo.List(ctx, nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List returned %d rows, want 1", len(got))
	}
	if !got[0].CreatedAt.Equal(want) {
		t.Errorf("CreatedAt round-trip mismatch:\n  set:  %v\n  got:  %v\n"+
			"Pre-U-3 this would have come back as 0001-01-01 because the column didn't exist.",
			want, got[0].CreatedAt)
	}
}

// TestNotificationRepository_CreatedAt_DefaultsToNow verifies the helper
// behavior in Create: when the caller hands over an event with the
// zero-value CreatedAt, Create substitutes time.Now() rather than
// trusting the DB DEFAULT. This keeps wire-level JSON consistent with
// what the row will hold once it's read back, and avoids a clock-skew
// gap between "Go computed the timestamp" and "DB applied DEFAULT NOW()".
func TestNotificationRepository_CreatedAt_DefaultsToNow(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	ctx := context.Background()

	before := time.Now().UTC().Add(-time.Second)

	notif := &domain.NotificationEvent{
		Type:      domain.NotificationTypeExpirationWarning,
		Channel:   domain.NotificationChannelWebhook,
		Recipient: "https://hooks.example.com/zerotime",
		Message:   "U-3 zero-time fallback",
		Status:    string(domain.NotificationStatusPending),
		// CreatedAt left zero on purpose — the contract is that Create
		// fills it in from time.Now() when it's unset.
	}
	if err := repo.Create(ctx, notif); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	after := time.Now().UTC().Add(time.Second)

	if notif.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt is still zero after Create — the fallback in NotificationRepository.Create did not fire")
	}
	if notif.CreatedAt.Before(before) || notif.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v is outside the [%v, %v] window — the substituted time.Now() should fall inside the test's wall-clock bracket",
			notif.CreatedAt, before, after)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// past returns a stable "5 minutes ago" time for fixture seeding. Truncated
// to microseconds so round-tripping through Postgres TIMESTAMPTZ doesn't
// introduce a sub-microsecond diff that breaks equality assertions.
func past() time.Time {
	return time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Microsecond)
}

// collectIDs pulls the IDs out of a slice of events for readable test
// failure output. Without it, a failure prints "[0xc00012... 0xc00013...]"
// which is useless when diagnosing a mis-sorted sweep.
func collectIDs(events []*domain.NotificationEvent) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	return ids
}

// assertRequeued is the shared "did Requeue do exactly what the contract
// promises?" assertion. Re-reads the row and checks all four mutations
// atomically so every Requeue test path gets the same rigor: status flipped
// to 'pending', retry_count reset to 0, next_retry_at cleared, last_error
// cleared. Any one of these missing is a contract violation.
func assertRequeued(t *testing.T, db *sql.DB, ctx context.Context, id string) {
	t.Helper()
	var (
		gotStatus     string
		gotRetryCount int
		gotNextRetry  *time.Time
		gotLastError  *string
	)
	err := db.QueryRowContext(ctx, `
		SELECT status, retry_count, next_retry_at, last_error
		FROM notification_events WHERE id = $1
	`, id).Scan(&gotStatus, &gotRetryCount, &gotNextRetry, &gotLastError)
	if err != nil {
		t.Fatalf("post-Requeue SELECT for %s failed: %v", id, err)
	}
	if gotStatus != "pending" {
		t.Errorf("%s.status = %q, want 'pending' (Requeue must re-open the row for ProcessPendingNotifications)",
			id, gotStatus)
	}
	if gotRetryCount != 0 {
		t.Errorf("%s.retry_count = %d, want 0 (Requeue restarts the backoff ladder so the operator's first retry isn't already at hour-long waits)",
			id, gotRetryCount)
	}
	if gotNextRetry != nil {
		t.Errorf("%s.next_retry_at = %v, want NULL (a fresh pending row must not sit in the retry-sweep index)",
			id, gotNextRetry)
	}
	if gotLastError != nil {
		t.Errorf("%s.last_error = %v, want NULL (stale errors on freshly-requeued rows mislead the UI)",
			id, *gotLastError)
	}
}
