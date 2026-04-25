package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// NotificationRepository implements repository.NotificationRepository
type NotificationRepository struct {
	db *sql.DB
}

// NewNotificationRepository creates a new NotificationRepository
func NewNotificationRepository(db *sql.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

// Create stores a new notification.
//
// U-3 ride-along (cat-o-notification_created_at_dead_field, P2): the
// `created_at` column is added to notification_events by migration 000017.
// Pre-U-3 the Go domain.NotificationEvent had a CreatedAt field but the
// INSERT path never set it AND no DB column existed — the JSON API
// serialised the field as `0001-01-01T00:00:00Z`, breaking timestamp
// ordering on operator dashboards and any consumer that filtered by age.
// Post-U-3 the column exists with a NOT NULL DEFAULT NOW() backstop, and
// this INSERT explicitly sets it from the domain field. If the caller
// hasn't populated CreatedAt (zero-value time.Time) we substitute
// time.Now() so the row never carries the placeholder zero-time forward
// — the DEFAULT would handle this too, but emitting the value explicitly
// keeps the wire-level JSON consistent with what the row will hold once
// scanNotification reads it back, and prevents a clock-skew gap between
// "Go computed CreatedAt" and "DB applied DEFAULT NOW()" on the read path.
func (r *NotificationRepository) Create(ctx context.Context, notif *domain.NotificationEvent) error {
	if notif.ID == "" {
		notif.ID = uuid.New().String()
	}
	if notif.CreatedAt.IsZero() {
		notif.CreatedAt = time.Now()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO notification_events (
			id, type, certificate_id, channel, recipient, message, sent_at, status, error, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, notif.ID, notif.Type, notif.CertificateID, notif.Channel, notif.Recipient,
		notif.Message, notif.SentAt, notif.Status, notif.Error, notif.CreatedAt).Scan(&notif.ID)

	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}

// List returns notifications matching the filter criteria
func (r *NotificationRepository) List(ctx context.Context, filter *repository.NotificationFilter) ([]*domain.NotificationEvent, error) {
	if filter == nil {
		filter = &repository.NotificationFilter{}
	}

	// Set defaults
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage == 0 || filter.PerPage > 500 {
		filter.PerPage = 50
	}

	// Build WHERE clause
	var whereConditions []string
	var args []interface{}
	argCount := 1

	if filter.CertificateID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("certificate_id = $%d", argCount))
		args = append(args, filter.CertificateID)
		argCount++
	}
	if filter.Type != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("type = $%d", argCount))
		args = append(args, filter.Type)
		argCount++
	}
	if filter.Status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, filter.Status)
		argCount++
	}
	if filter.MessageLike != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("message LIKE $%d", argCount))
		args = append(args, filter.MessageLike)
		argCount++
	}
	if filter.Channel != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("channel = $%d", argCount))
		args = append(args, filter.Channel)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notification_events %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count notifications: %w", err)
	}

	// Get paginated results. I-005 extends the SELECT with the three retry
	// columns (retry_count / next_retry_at / last_error) so scanNotification
	// can populate the new fields on domain.NotificationEvent. U-3 extends
	// it once more with `created_at` (column added by migration 000017) so
	// the field is no longer serialized as 0001-01-01. The column order
	// here MUST stay in lockstep with scanNotification below.
	offset := (filter.Page - 1) * filter.PerPage
	query := fmt.Sprintf(`
		SELECT id, type, certificate_id, channel, recipient, message, sent_at, status, error,
		       retry_count, next_retry_at, last_error, created_at
		FROM notification_events
		%s
		ORDER BY sent_at DESC NULLS LAST
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, filter.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	var notifs []*domain.NotificationEvent
	for rows.Next() {
		notif, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		notifs = append(notifs, notif)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating notification rows: %w", err)
	}

	return notifs, nil
}

// UpdateStatus updates a notification's delivery status
func (r *NotificationRepository) UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE notification_events SET status = $1, sent_at = $2 WHERE id = $3
	`, status, sentAt, id)

	if err != nil {
		return fmt.Errorf("failed to update notification status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("notification not found")
	}

	return nil
}

// scanNotification scans a notification from a row or rows.
//
// I-005 extended the scan list from 9 → 12 columns (adds retry_count,
// next_retry_at, last_error). U-3 extends it once more to 13 columns by
// appending `created_at` (column added by migration 000017,
// cat-o-notification_created_at_dead_field). CreatedAt scans into a
// non-pointer time.Time because the migration declares the column
// NOT NULL with DEFAULT NOW().
//
// Every caller — List, ListRetryEligible, and the four other I-005 retry
// methods below — funnels rows through this helper, so the SELECT column
// order in every query must match the Scan order here exactly. RetryCount
// scans into an `int` (migration 000016 declares the column NOT NULL with
// DEFAULT 0), while NextRetryAt and LastError scan into pointer types
// because the column is nullable — a healthy pending/sent/dead row leaves
// both NULL.
func scanNotification(scanner interface {
	Scan(...interface{}) error
}) (*domain.NotificationEvent, error) {
	var notif domain.NotificationEvent
	err := scanner.Scan(&notif.ID, &notif.Type, &notif.CertificateID, &notif.Channel,
		&notif.Recipient, &notif.Message, &notif.SentAt, &notif.Status, &notif.Error,
		&notif.RetryCount, &notif.NextRetryAt, &notif.LastError, &notif.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to scan notification: %w", err)
	}

	return &notif, nil
}

// ─── I-005 retry/DLQ methods ─────────────────────────────────────────────
//
// The four methods below implement the repository half of the I-005
// notification retry + dead-letter queue fix. The retry scheduler loop
// (added alongside these in internal/scheduler/scheduler.go) drives them in
// a strict cycle:
//
//    ┌─► ListRetryEligible(ctx, now, maxAttempts, limit)
//    │         (oldest overdue failed rows first)
//    │            │
//    │            ├──► notifier.Send() succeeds → UpdateStatus('sent')
//    │            │
//    │            ├──► transient failure, retry_count+1 < maxAttempts
//    │            │        → RecordFailedAttempt(id, err, next)
//    │            │
//    │            └──► transient failure, retry_count+1 == maxAttempts
//    │                     → MarkAsDead(id, err)
//    │
//    └──◄ Requeue(id) ────── operator "try again" from Dead-letter tab
//
// The WHERE clauses in every UPDATE are scoped by id (not by status), so
// status invariants ("you can't requeue a sent row", "you can't mark a
// dead row as dead again") live in the service layer. The repo layer is
// deliberately thin — it mirrors the postgres CHECK constraints and
// trusts the service to hand it rows in a sane state. The one exception
// is "row must exist": each method returns an error on zero RowsAffected,
// matching the pre-existing UpdateStatus contract above so the scheduler
// can detect a concurrent delete without guessing.

// listRetryEligibleDefaultLimit caps a caller that passes limit <= 0.
// Picked high enough that normal sweeps never hit it (a healthy fleet
// should have tens of overdue rows at most, not thousands), but finite
// so a pathological call (wrong arg in a future refactor, bad MCP tool
// wiring) cannot scan the entire notification_events table.
const listRetryEligibleDefaultLimit = 1000

// ListRetryEligible returns failed notification rows whose next_retry_at
// is due and whose retry_count has not yet reached the configured
// max_attempts.
//
// The WHERE clause is the exact dual of the partial retry-sweep index
// predicate from migration 000016:
//
//	WHERE status = 'failed'
//	  AND next_retry_at IS NOT NULL
//	  AND next_retry_at <= $1
//	  AND retry_count   <  $2
//
// Because the index is partial on the first two conjuncts, the planner
// uses it to satisfy the range scan on next_retry_at; the retry_count
// filter is applied as a residual on the (very small) candidate set.
//
// ORDER BY next_retry_at ASC matches the fairness guarantee called out
// in the test file: oldest overdue row goes first, so a backed-up
// scheduler doesn't starve the notifications that have been waiting
// longest. The same order is what I-001's RetryFailedJobs uses.
func (r *NotificationRepository) ListRetryEligible(ctx context.Context, now time.Time, maxAttempts, limit int) ([]*domain.NotificationEvent, error) {
	if limit <= 0 {
		limit = listRetryEligibleDefaultLimit
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, channel, recipient, message, sent_at, status, error,
		       retry_count, next_retry_at, last_error, created_at
		FROM notification_events
		WHERE status = 'failed'
		  AND next_retry_at IS NOT NULL
		  AND next_retry_at <= $1
		  AND retry_count    < $2
		ORDER BY next_retry_at ASC
		LIMIT $3
	`, now, maxAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query retry-eligible notifications: %w", err)
	}
	defer rows.Close()

	var notifs []*domain.NotificationEvent
	for rows.Next() {
		notif, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		notifs = append(notifs, notif)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating retry-eligible notification rows: %w", err)
	}

	return notifs, nil
}

// RecordFailedAttempt is called by the retry sweep after a notifier.Send
// transient failure. It increments retry_count by exactly 1, overwrites
// last_error and next_retry_at, and deliberately DOES NOT touch status —
// the row must remain 'failed' so the next ListRetryEligible tick can
// pick it up again (unless the service layer has decided this attempt
// exhausts max_attempts, in which case it calls MarkAsDead directly
// instead of calling RecordFailedAttempt).
//
// The +1 is done server-side (SET retry_count = retry_count + 1) rather
// than client-side so a race between two scheduler instances cannot lose
// an attempt. Only one scheduler should be running in a healthy deploy,
// but the cheap arithmetic here survives a split-brain without lying
// about attempt counts.
func (r *NotificationRepository) RecordFailedAttempt(ctx context.Context, id string, lastError string, nextRetryAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE notification_events
		SET retry_count   = retry_count + 1,
		    last_error    = $1,
		    next_retry_at = $2
		WHERE id = $3
	`, lastError, nextRetryAt, id)
	if err != nil {
		return fmt.Errorf("failed to record notification retry attempt: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		// Same "not found" error shape as UpdateStatus above. The scheduler
		// logs-and-continues on this so a concurrently-deleted row doesn't
		// break the sweep.
		return fmt.Errorf("notification not found")
	}
	return nil
}

// MarkAsDead performs the DLQ transition. Flips status='dead' so the
// partial retry-sweep index drops the row (the index predicate requires
// status='failed'), clears next_retry_at so operator dashboards don't
// claim the row is still "scheduled to retry", writes the final
// last_error for triage, and PRESERVES retry_count as historical evidence
// of how many attempts were burned before the row was declared dead.
// The retry_count value is operator-visible in the Dead letter tab so
// on-call can tell "this notification died on attempt 5" vs "this one
// died on attempt 1 because the recipient webhook was malformed from the
// start".
func (r *NotificationRepository) MarkAsDead(ctx context.Context, id string, lastError string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE notification_events
		SET status        = 'dead',
		    next_retry_at = NULL,
		    last_error    = $1
		WHERE id = $2
	`, lastError, id)
	if err != nil {
		return fmt.Errorf("failed to mark notification as dead: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("notification not found")
	}
	return nil
}

// Requeue is the operator "try again" action fired from the Dead letter
// tab. Flips status='pending' so ProcessPendingNotifications picks the
// row up again, resets retry_count to 0 (otherwise the operator's first
// retry would immediately sit at the top of the backoff ladder), clears
// next_retry_at so the row is no longer in the retry-sweep index, and
// clears last_error so the UI doesn't render a stale error badge next
// to a freshly-requeued row.
//
// The service layer is responsible for forbidding Requeue on 'sent' or
// 'read' rows (terminal success states). This repo layer deliberately
// doesn't filter by current status — an operator action has already
// passed a human-in-the-loop guard by the time it reaches the DB, and
// the test suite only exercises the Requeue-from-{dead,failed} paths.
// Matches how UpdateStatus doesn't filter by current status either.
func (r *NotificationRepository) Requeue(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE notification_events
		SET status        = 'pending',
		    retry_count   = 0,
		    next_retry_at = NULL,
		    last_error    = NULL
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("failed to requeue notification: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("notification not found")
	}
	return nil
}

// CountByStatus returns the number of notification_events rows matching the
// given status string. Implemented as a direct COUNT(*) rather than via List
// because List resets filter.PerPage>500 to 50 (see line 57 quirk), which
// would produce undercounts on high-volume deployments. I-005 Phase 2 Green —
// backs StatsService.GetDashboardSummary.NotificationsDead and the Prometheus
// counter certctl_notification_dead_total.
func (r *NotificationRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_events WHERE status = $1`,
		status,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count notifications by status: %w", err)
	}
	return count, nil
}
