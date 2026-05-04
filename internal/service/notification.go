package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// I-005 retry + DLQ knobs. These pin the operator-approved retry budget and
// the defense-in-depth ceiling on the exponential backoff curve used by
// RetryFailedNotifications.
//
// Values match those the Phase 1 Red tests assert against (see
// i005MaxAttempts / i005BackoffCap in notification_test.go:600-608) — the
// production identifiers are distinct because this file and its tests share
// `package service`, so a single shared name would collide at compile time.
// The test comment explicitly notes "Phase 2 is free to thread this from
// config"; when that wiring lands, these become package-level defaults the
// scheduler can override. For now they are the single source of truth.
const (
	// notifRetryMaxAttempts is the attempt budget *before* the current
	// attempt: a row at retry_count == notifRetryMaxAttempts-1 that fails
	// this tick transitions to 'dead' instead of being re-armed. The
	// repository's ListRetryEligible filter also uses this value as a
	// guard (`AND retry_count < $2`) so a DLQ row is never re-swept.
	notifRetryMaxAttempts = 5

	// notifRetryBackoffCap is the 1h ceiling on `2^retry_count` minutes.
	// With max_attempts=5 the deepest actually-schedulable wait is 2^3=8m
	// (retry_count=3 → 8m, then retry_count=4 → 'dead'), so the cap is a
	// ceiling-assertion today — but it must stay in place so a later
	// increase in max_attempts cannot push next_retry_at past 1h without
	// an explicit policy decision.
	notifRetryBackoffCap = time.Hour

	// notifRetrySweepLimit caps a single retry tick at this many rows so
	// a large burst of dead-letter-bound mail cannot monopolize the 2m
	// tick budget. Mirrors the 1000-row cap on ProcessPendingNotifications
	// at notification.go:244 for operational symmetry.
	notifRetrySweepLimit = 1000
)

// NotificationService provides business logic for managing notifications.
type NotificationService struct {
	notifRepo        repository.NotificationRepository
	ownerRepo        repository.OwnerRepository
	notifierRegistry map[string]Notifier

	// expiryAlertMetrics — when set via SetExpiryAlertMetrics, every call
	// to SendThresholdAlertOnChannel reports its outcome (success / failure)
	// to the metric sink so the Prometheus exposer surfaces
	// certctl_expiry_alerts_total{channel,threshold,result}. Rank 4 of the
	// 2026-05-03 Infisical deep-research deliverable. Nil leaves the
	// dispatch path unchanged (no metric emission, but alerts still fire).
	expiryAlertMetrics ExpiryAlertRecorder
}

// ExpiryAlertRecorder is the metric-sink surface SendThresholdAlertOnChannel
// uses. result is one of: "success", "failure", "deduped". Implementations
// MUST be goroutine-safe — RecordExpiryAlert is called from the renewal
// loop's own goroutine on every threshold-channel tick.
//
// service.ExpiryAlertMetrics satisfies this interface. cmd/server wires
// the same instance into the service (recording side) and into
// MetricsHandler (exposing side, for the Prometheus emitter).
type ExpiryAlertRecorder interface {
	RecordExpiryAlert(channel string, threshold int, result string)
}

// SetExpiryAlertMetrics wires the per-(channel, threshold, result) counter
// table for expiry-alert dispatch. Pass nil to disable recording. Safe to
// call before any SendThresholdAlertOnChannel call; calling later just
// means earlier calls didn't increment the counters.
func (s *NotificationService) SetExpiryAlertMetrics(r ExpiryAlertRecorder) {
	s.expiryAlertMetrics = r
}

// recordExpiryAlert is the internal hook used by SendThresholdAlertOnChannel
// to report per-(channel, threshold, result) counts. Nil-safe.
func (s *NotificationService) recordExpiryAlert(channel string, threshold int, result string) {
	if s == nil || s.expiryAlertMetrics == nil {
		return
	}
	s.expiryAlertMetrics.RecordExpiryAlert(channel, threshold, result)
}

// RecordExpiryAlertDeduped is the public hook RenewalService uses to report
// (channel, threshold, "deduped") — dedup happens before
// SendThresholdAlertOnChannel runs, so the call site is in the caller, not
// the dispatch helper. Kept on NotificationService rather than exposed on
// the recorder directly so callers don't need to know whether the recorder
// is wired.
func (s *NotificationService) RecordExpiryAlertDeduped(channel string, threshold int) {
	s.recordExpiryAlert(channel, threshold, "deduped")
}

// Notifier defines the interface for notification channels (email, Slack, webhooks, etc.).
type Notifier interface {
	// Send delivers a notification and returns error if unsuccessful.
	Send(ctx context.Context, recipient string, subject string, body string) error
	// Channel returns the channel identifier (e.g., "email", "slack").
	Channel() string
}

// NewNotificationService creates a new notification service.
func NewNotificationService(
	notifRepo repository.NotificationRepository,
	notifierRegistry map[string]Notifier,
) *NotificationService {
	return &NotificationService{
		notifRepo:        notifRepo,
		notifierRegistry: notifierRegistry,
	}
}

// SetOwnerRepo sets the owner repository for email resolution.
// Called after construction to avoid circular dependency during initialization.
func (s *NotificationService) SetOwnerRepo(ownerRepo repository.OwnerRepository) {
	s.ownerRepo = ownerRepo
}

// resolveRecipient resolves an owner ID to an email address.
// Falls back to the raw owner ID if the owner repo is not set or lookup fails.
func (s *NotificationService) resolveRecipient(ctx context.Context, ownerID string) string {
	if s.ownerRepo == nil || ownerID == "" {
		return ownerID
	}
	owner, err := s.ownerRepo.Get(ctx, ownerID)
	if err != nil || owner == nil || owner.Email == "" {
		return ownerID
	}
	return owner.Email
}

// SendExpirationWarning sends a certificate expiration warning for a specific threshold.
func (s *NotificationService) SendExpirationWarning(ctx context.Context, cert *domain.ManagedCertificate, daysUntilExpiry int) error {
	return s.SendThresholdAlert(ctx, cert, daysUntilExpiry, daysUntilExpiry)
}

// SendThresholdAlert sends an expiration alert for a specific threshold via
// the Email channel. Preserved for backwards-compat with non-policy callers
// (admin "send test alert" surfaces in the GUI, etc.); equivalent to
// SendThresholdAlertOnChannel(ctx, cert, days, threshold,
// domain.NotificationChannelEmail).
//
// Policy-driven dispatch in RenewalService.sendThresholdAlerts uses
// SendThresholdAlertOnChannel directly with the channel resolved from the
// per-policy AlertChannels matrix. Rank 4 of the 2026-05-03 Infisical
// deep-research deliverable.
func (s *NotificationService) SendThresholdAlert(ctx context.Context, cert *domain.ManagedCertificate, daysUntilExpiry int, threshold int) error {
	return s.SendThresholdAlertOnChannel(ctx, cert, daysUntilExpiry, threshold, domain.NotificationChannelEmail)
}

// SendThresholdAlertOnChannel sends an expiration alert for a specific
// (cert, threshold, channel) triple. The channel must be one of the
// closed-enum NotificationChannel values; off-enum channels surface as a
// failure metric increment + ERROR log + a wrapped error so the caller can
// react (typically: log and continue with the next channel in the
// policy's tier list — see RenewalService.sendThresholdAlerts).
//
// The notification record is persisted with the channel field set to the
// requested value, and the message body carries the [threshold:N] tag for
// dedup at HasThresholdNotification's substring filter. Combined with the
// repository.NotificationFilter.Channel field, this gives us per-(cert,
// threshold, channel) dedup so a transient PagerDuty 5xx today does NOT
// suppress today's Slack delivery and tomorrow's PagerDuty retry will
// still fire.
//
// Result is reported to expiryAlertMetrics (when wired): "success" on
// successful send, "failure" on send error or persistence error.
// "deduped" results are reported by the caller (sendThresholdAlerts) since
// dedup happens before this method runs.
func (s *NotificationService) SendThresholdAlertOnChannel(
	ctx context.Context, cert *domain.ManagedCertificate, daysUntilExpiry int,
	threshold int, channel domain.NotificationChannel,
) error {
	if !domain.IsValidNotificationChannel(string(channel)) {
		s.recordExpiryAlert(string(channel), threshold, "failure")
		return fmt.Errorf("invalid notification channel %q for threshold %d", channel, threshold)
	}

	var body string
	if threshold <= 0 {
		body = fmt.Sprintf(
			"[EXPIRED] The certificate for %s has expired (%s).\n\nImmediate action required.\n\n[threshold:%d]",
			cert.CommonName, cert.ExpiresAt.Format("2006-01-02"), threshold,
		)
	} else {
		body = fmt.Sprintf(
			"The certificate for %s will expire in %d days (%s).\n\nPlease schedule renewal.\n\n[threshold:%d]",
			cert.CommonName, daysUntilExpiry, cert.ExpiresAt.Format("2006-01-02"), threshold,
		)
	}

	notif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          domain.NotificationTypeExpirationWarning,
		Channel:       channel,
		Recipient:     s.resolveRecipient(ctx, cert.OwnerID),
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		s.recordExpiryAlert(string(channel), threshold, "failure")
		return fmt.Errorf("failed to create notification: %w", err)
	}

	if err := s.sendNotification(ctx, notif); err != nil {
		s.recordExpiryAlert(string(channel), threshold, "failure")
		return err
	}
	s.recordExpiryAlert(string(channel), threshold, "success")
	return nil
}

// HasThresholdNotification checks whether an expiration warning has already
// been sent for a specific (cert, threshold) pair via the Email channel.
// Preserved for backwards-compat. Equivalent to
// HasThresholdNotificationOnChannel(ctx, certID, threshold, "Email").
//
// New callers driven by the per-policy channel matrix should use
// HasThresholdNotificationOnChannel directly with the explicit channel —
// see RenewalService.sendThresholdAlerts.
func (s *NotificationService) HasThresholdNotification(ctx context.Context, certID string, threshold int) (bool, error) {
	return s.HasThresholdNotificationOnChannel(ctx, certID, threshold, domain.NotificationChannelEmail)
}

// HasThresholdNotificationOnChannel reports whether an ExpirationWarning
// notification has already been persisted for a specific (cert, threshold,
// channel) triple. Used to dedupe per-channel fan-out so a successful
// PagerDuty page today doesn't fire again tomorrow when the renewal loop
// re-checks the same threshold (and so a transient PagerDuty 5xx today
// doesn't suppress tomorrow's successful retry).
//
// The match is on the substring "[threshold:N]" in the stored message body
// (the same dedup pattern used by HasThresholdNotification pre-2026-05-03)
// AND the channel column. Both filters apply; a match requires both.
//
// channel == "" preserves the legacy (cert, threshold) dedup for the same
// reason HasThresholdNotification kept its old shape — admin-surface
// callers still need that behaviour.
func (s *NotificationService) HasThresholdNotificationOnChannel(
	ctx context.Context, certID string, threshold int, channel domain.NotificationChannel,
) (bool, error) {
	filter := &repository.NotificationFilter{
		CertificateID: certID,
		Type:          string(domain.NotificationTypeExpirationWarning),
		MessageLike:   fmt.Sprintf("%%[threshold:%d]%%", threshold),
		Channel:       string(channel),
		PerPage:       1,
	}

	existing, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("failed to check existing notifications: %w", err)
	}

	return len(existing) > 0, nil
}

// SendRenewalNotification sends a renewal success or failure notification.
func (s *NotificationService) SendRenewalNotification(ctx context.Context, cert *domain.ManagedCertificate, success bool, err error) error {
	var body string
	if success {
		body = fmt.Sprintf(
			"The certificate for %s has been successfully renewed.\n\nNew expiry: %s",
			cert.CommonName, cert.ExpiresAt.Format("2006-01-02"),
		)
	} else {
		body = fmt.Sprintf(
			"The certificate for %s failed to renew.\n\nError: %v\n\nPlease investigate.",
			cert.CommonName, err,
		)
	}

	var notifType domain.NotificationType
	if success {
		notifType = domain.NotificationTypeRenewalSuccess
	} else {
		notifType = domain.NotificationTypeRenewalFailure
	}

	notif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          notifType,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     s.resolveRecipient(ctx, cert.OwnerID),
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return s.sendNotification(ctx, notif)
}

// SendDeploymentNotification sends a deployment success or failure notification.
func (s *NotificationService) SendDeploymentNotification(ctx context.Context, cert *domain.ManagedCertificate, target *domain.DeploymentTarget, success bool, err error) error {
	var body string

	if success {
		body = fmt.Sprintf(
			"The certificate for %s has been successfully deployed to %s.",
			cert.CommonName, target.Name,
		)
	} else {
		body = fmt.Sprintf(
			"The certificate for %s failed to deploy to %s.\n\nError: %v\n\nPlease investigate.",
			cert.CommonName, target.Name, err,
		)
	}

	notifType := domain.NotificationTypeDeploymentSuccess
	if !success {
		notifType = domain.NotificationTypeDeploymentFailure
	}

	notif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          notifType,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     s.resolveRecipient(ctx, cert.OwnerID),
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return s.sendNotification(ctx, notif)
}

// SendRevocationNotification sends a certificate revocation notification.
func (s *NotificationService) SendRevocationNotification(ctx context.Context, cert *domain.ManagedCertificate, reason string) error {
	body := fmt.Sprintf(
		"[REVOKED] The certificate for %s has been revoked.\n\nReason: %s\n\nThis certificate is no longer valid.",
		cert.CommonName, reason,
	)

	notif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          domain.NotificationTypeRevocation,
		Channel:       domain.NotificationChannelWebhook,
		Recipient:     s.resolveRecipient(ctx, cert.OwnerID),
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		return fmt.Errorf("failed to create revocation notification: %w", err)
	}

	// Also send via email channel
	emailNotif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          domain.NotificationTypeRevocation,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     s.resolveRecipient(ctx, cert.OwnerID),
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, emailNotif); err != nil {
		slog.Error("failed to create email revocation notification", "error", err)
	}

	// Attempt immediate send for both
	if err := s.sendNotification(ctx, notif); err != nil {
		slog.Error("failed to send webhook revocation notification", "error", err)
	}
	return s.sendNotification(ctx, emailNotif)
}

// ProcessPendingNotifications sends all pending notifications in batch.
func (s *NotificationService) ProcessPendingNotifications(ctx context.Context) error {
	filter := &repository.NotificationFilter{
		Status:  "pending",
		PerPage: 1000,
	}

	pending, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list pending notifications: %w", err)
	}

	var failedCount int

	for _, notif := range pending {
		if err := s.sendNotification(ctx, notif); err != nil {
			slog.Error("failed to send notification", "notification_id", notif.ID, "error", err)
			failedCount++
		}
	}

	if failedCount > 0 {
		return fmt.Errorf("failed to send %d out of %d notifications", failedCount, len(pending))
	}

	return nil
}

// sendNotification delivers a single notification via the appropriate channel.
func (s *NotificationService) sendNotification(ctx context.Context, notif *domain.NotificationEvent) error {
	// Get the appropriate notifier for the channel
	notifier, ok := s.notifierRegistry[string(notif.Channel)]
	if !ok {
		// No notifier configured for this channel — mark as sent (demo mode)
		if updateErr := s.notifRepo.UpdateStatus(ctx, notif.ID, "sent", time.Now()); updateErr != nil {
			slog.Error("failed to update notification status", "notification_id", notif.ID, "error", updateErr)
		}
		return nil
	}

	// Send the notification
	if err := notifier.Send(ctx, notif.Recipient, string(notif.Type), notif.Message); err != nil {
		// Update status to failed
		if updateErr := s.notifRepo.UpdateStatus(ctx, notif.ID, "failed", time.Time{}); updateErr != nil {
			slog.Error("failed to update notification status", "notification_id", notif.ID, "error", updateErr)
		}
		return fmt.Errorf("failed to send via %s: %w", notif.Channel, err)
	}

	// Update status to sent
	if err := s.notifRepo.UpdateStatus(ctx, notif.ID, "sent", time.Now()); err != nil {
		slog.Error("failed to update notification status", "notification_id", notif.ID, "error", err)
	}

	return nil
}

// RegisterNotifier registers a new notification channel handler.
func (s *NotificationService) RegisterNotifier(channel string, notifier Notifier) {
	if s.notifierRegistry == nil {
		s.notifierRegistry = make(map[string]Notifier)
	}
	s.notifierRegistry[channel] = notifier
}

// GetNotificationHistory returns all notifications for a certificate.
func (s *NotificationService) GetNotificationHistory(ctx context.Context, certID string) ([]*domain.NotificationEvent, error) {
	filter := &repository.NotificationFilter{
		CertificateID: certID,
		PerPage:       1000,
	}

	notifications, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list notifications: %w", err)
	}

	return notifications, nil
}

// ListNotifications returns paginated notifications (handler interface method).
func (s *NotificationService) ListNotifications(ctx context.Context, page, perPage int) ([]domain.NotificationEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	filter := &repository.NotificationFilter{
		Page:    page,
		PerPage: perPage,
	}

	notifications, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list notifications: %w", err)
	}

	var result []domain.NotificationEvent
	for _, n := range notifications {
		if n != nil {
			result = append(result, *n)
		}
	}

	total := int64(len(result))
	return result, total, nil
}

// GetNotification returns a single notification (handler interface method).
func (s *NotificationService) GetNotification(ctx context.Context, id string) (*domain.NotificationEvent, error) {
	filter := &repository.NotificationFilter{
		PerPage: 1,
	}

	notifications, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get notification: %w", err)
	}

	// Find notification with matching ID (repository filter doesn't support ID directly)
	for _, n := range notifications {
		if n != nil && n.ID == id {
			return n, nil
		}
	}

	return nil, fmt.Errorf("notification not found")
}

// MarkAsRead marks a notification as read (handler interface method).
func (s *NotificationService) MarkAsRead(ctx context.Context, id string) error {
	return s.notifRepo.UpdateStatus(ctx, id, "read", time.Now())
}

// ─── I-005 retry + DLQ surface (Phase 2 Green) ───────────────────────────
//
// The three methods below close the retry loop the Phase 1 Red tests pin at
// notification_test.go:600-917 and notification_handler_test.go:443-519:
//
//   1. RetryFailedNotifications — scheduler entry point. Pulls failed rows
//      whose next_retry_at has elapsed, retries delivery, rewrites retry
//      bookkeeping per the pre-increment backoff contract, and transitions
//      exhausted rows to 'dead' (DLQ). Per-row errors never bubble — a
//      single bad recipient cannot stall the tick. Mirrors the ordering
//      the ProcessPendingNotifications loop uses at notification.go:242.
//
//   2. RequeueNotification — operator-driven escape hatch from 'dead' back
//      to 'pending'. Pass-through to the repo's Requeue method with clean
//      error wrapping so repo-layer failures ("pg: deadlock detected")
//      surface in the UI instead of silently succeeding.
//
//   3. ListNotificationsByStatus — Dead letter tab support. Thin filter
//      wrapper around the existing List query; the Phase 2 Green handler
//      routes `?status=…` through this method while preserving the
//      unfiltered path through ListNotifications (handler_test pins both).
//
// Sibling scheduler loops I-001 (job retry) and I-003 (job timeout) already
// ship the 10-loop topology these methods plug into; the 11th loop added
// by this milestone calls RetryFailedNotifications on a 2m tick, matching
// the CERTCTL_NOTIFICATION_RETRY_INTERVAL default pinned in config/
// scheduler Phase 2 Green edits that follow this one.

// RetryFailedNotifications is the scheduler entry point for the I-005
// retry sweep. Semantics (pinned by notification_test.go:635-843):
//
//   - A ListRetryEligible failure short-circuits with a wrapped error so
//     the caller's tick counter reflects the outage. Crucially, zero
//     notifier.Send calls fire in this path — we never got a canonical
//     set of rows, and issuing any sends risks double-delivery when the
//     DB comes back.
//
//   - Per-row failures are logged but NEVER returned. That contract comes
//     straight from ProcessPendingNotifications (notification.go:242-267);
//     the retry loop inherits it so a single 4xx response can't freeze
//     every downstream row in the sweep.
//
//   - Success promotes the row directly to 'sent' via UpdateStatus. The
//     retry_count field is *not* incremented on success — that would
//     falsify the audit-trail signal "this row was delivered on attempt
//     N". The mock's UpdateStatus does a plain status write with no retry
//     mutation (testutil_test.go:446-459), matching the postgres impl.
//
//   - Failure uses pre-increment exponential backoff:
//     wait = min(2^retry_count * time.Minute, notifRetryBackoffCap)
//     where retry_count is the row's value *before* this attempt. The
//     repo layer's RecordFailedAttempt then increments retry_count by 1
//     server-side. This asymmetry keeps the service stateless — the
//     service reads retry_count to compute the wait, but never writes it
//     directly; the write is exclusively the repo's responsibility.
//
//   - Exhaustion transitions to 'dead' when retry_count == max-1, because
//     RecordFailedAttempt's ++ would push retry_count to max and the next
//     sweep's `retry_count < max` filter in ListRetryEligible would then
//     silently skip the row forever (a zombie-failed row nobody sees).
//     MarkAsDead clears next_retry_at to evict the row from the partial
//     retry-sweep index as well, so it stops scanning past dead rows.
//
//   - A row whose Channel has no registered notifier is promoted to
//     'sent' (demo-mode parity with sendNotification's fallback at
//     notification.go:272-279). This branch should not normally fire for
//     retry rows — they were created *by* a notifier that failed — but
//     defensive handling guards against config drift (notifier disabled
//     between Create and retry) that would otherwise wedge the row.
func (s *NotificationService) RetryFailedNotifications(ctx context.Context) error {
	now := time.Now()

	rows, err := s.notifRepo.ListRetryEligible(ctx, now, notifRetryMaxAttempts, notifRetrySweepLimit)
	if err != nil {
		return fmt.Errorf("failed to list retry-eligible notifications: %w", err)
	}

	for _, row := range rows {
		if row == nil {
			continue
		}

		notifier, ok := s.notifierRegistry[string(row.Channel)]
		if !ok {
			// No notifier wired for this channel — promote to 'sent' to
			// avoid looping forever over a row that has nowhere to go.
			// See notification.go:272-279 for the sibling demo-mode path.
			if updateErr := s.notifRepo.UpdateStatus(ctx, row.ID, string(domain.NotificationStatusSent), time.Now()); updateErr != nil {
				slog.Error("failed to promote retry row with missing notifier to sent",
					"notification_id", row.ID, "channel", row.Channel, "error", updateErr)
			}
			continue
		}

		sendErr := notifier.Send(ctx, row.Recipient, string(row.Type), row.Message)
		if sendErr == nil {
			// Success: promote straight to 'sent' without touching
			// retry_count — the audit trail must preserve "this row was
			// delivered on attempt N", and the mock's UpdateStatus is a
			// plain status write (no retry_count reset). Errors here are
			// logged, never returned.
			if updateErr := s.notifRepo.UpdateStatus(ctx, row.ID, string(domain.NotificationStatusSent), time.Now()); updateErr != nil {
				slog.Error("failed to mark retried notification as sent",
					"notification_id", row.ID, "error", updateErr)
			}
			continue
		}

		// Failure path. Compute pre-increment backoff first so the
		// exhaustion branch and the reschedule branch see an identical
		// `wait` derivation — easier to audit against the test window
		// assertions at notification_test.go:739-743 and :796-801.
		wait := time.Duration(1<<row.RetryCount) * time.Minute
		if wait > notifRetryBackoffCap {
			wait = notifRetryBackoffCap
		}

		// Exhaustion: this attempt consumes the final slot of the attempt
		// budget. Transition to 'dead' and let MarkAsDead clear
		// next_retry_at so the retry-sweep index stops hitting the row.
		if row.RetryCount >= notifRetryMaxAttempts-1 {
			if markErr := s.notifRepo.MarkAsDead(ctx, row.ID, sendErr.Error()); markErr != nil {
				slog.Error("failed to mark exhausted notification as dead",
					"notification_id", row.ID, "retry_count", row.RetryCount,
					"send_error", sendErr, "mark_error", markErr)
			}
			continue
		}

		// Non-terminal: hand the lastError + nextRetryAt off to the repo,
		// which increments retry_count by exactly 1 and keeps the row in
		// 'failed' state so the next tick picks it up.
		nextRetryAt := time.Now().Add(wait)
		if recErr := s.notifRepo.RecordFailedAttempt(ctx, row.ID, sendErr.Error(), nextRetryAt); recErr != nil {
			slog.Error("failed to record notification retry attempt",
				"notification_id", row.ID, "retry_count", row.RetryCount,
				"next_retry_at", nextRetryAt, "send_error", sendErr, "record_error", recErr)
		}
	}

	return nil
}

// RequeueNotification is the operator-driven escape hatch from 'dead' back
// to 'pending'. It resets all retry bookkeeping — retry_count → 0,
// next_retry_at → NULL, last_error → NULL — so ProcessPendingNotifications
// treats the requeued row as a fresh attempt on its next tick. Identical on
// the wire to a newly-created notification.
//
// Behavior contract (pinned by notification_test.go:849-917):
//
//   - Success path delegates to the repo's Requeue, which performs the
//     status/retry_count/next_retry_at/last_error reset atomically. The
//     service adds no extra bookkeeping; the audit trail already captures
//     the transition via the upstream API call.
//
//   - Error path wraps the repo error with context so a failure like
//     "pg: deadlock detected" surfaces in the handler response and the
//     operator UI. The service has no fallback — a silent "success" that
//     didn't actually mutate the row would be worse than a loud error.
func (s *NotificationService) RequeueNotification(ctx context.Context, id string) error {
	if err := s.notifRepo.Requeue(ctx, id); err != nil {
		return fmt.Errorf("failed to requeue notification: %w", err)
	}
	return nil
}

// ListNotificationsByStatus returns paginated notifications filtered by
// status. It mirrors ListNotifications's shape but threads a Status filter
// into the NotificationFilter so the Phase 2 Green handler can route
// `?status=dead` (Dead letter tab) through this method while keeping the
// unfiltered path on ListNotifications for backward compat.
//
// Pinned by notification_handler_test.go:443-519 — the handler test asserts
// that a request with `?status=dead&page=1&per_page=50` lands on exactly
// this signature (`status string, page, perPage int`) and that requests
// without a status param do NOT call it. Keep the returned shape identical
// to ListNotifications so the handler can reuse its JSON-encoding path.
func (s *NotificationService) ListNotificationsByStatus(ctx context.Context, status string, page, perPage int) ([]domain.NotificationEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	filter := &repository.NotificationFilter{
		Status:  status,
		Page:    page,
		PerPage: perPage,
	}

	notifications, err := s.notifRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list notifications by status: %w", err)
	}

	result := make([]domain.NotificationEvent, 0, len(notifications))
	for _, n := range notifications {
		if n != nil {
			result = append(result, *n)
		}
	}

	total := int64(len(result))
	return result, total, nil
}
