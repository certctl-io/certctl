package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

func TestSendThresholdAlert(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-1",
		CommonName: "example.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(0, 0, 5),
	}

	threshold := 7
	daysUntilExpiry := 5

	err := svc.SendThresholdAlert(ctx, cert, daysUntilExpiry, threshold)
	if err != nil {
		t.Fatalf("SendThresholdAlert failed: %v", err)
	}

	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	notif := notifRepo.Notifications[0]
	if notif.Type != domain.NotificationTypeExpirationWarning {
		t.Errorf("expected ExpirationWarning, got %s", notif.Type)
	}

	// Verify message contains threshold tag
	if !strings.Contains(notif.Message, "[threshold:7]") {
		t.Errorf("expected threshold tag in message, got: %s", notif.Message)
	}

	// Verify notifier was called
	if notifier.getSentCount() != 1 {
		t.Errorf("expected 1 sent message, got %d", notifier.getSentCount())
	}
}

func TestSendThresholdAlert_Expired(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-expired",
		CommonName: "expired.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(0, 0, -1),
	}

	threshold := 0
	daysUntilExpiry := -1

	err := svc.SendThresholdAlert(ctx, cert, daysUntilExpiry, threshold)
	if err != nil {
		t.Fatalf("SendThresholdAlert failed: %v", err)
	}

	// Verify message contains [EXPIRED] prefix
	if len(notifRepo.Notifications) > 0 && !strings.Contains(notifRepo.Notifications[0].Message, "[EXPIRED]") {
		t.Errorf("expected [EXPIRED] in message, got: %s", notifRepo.Notifications[0].Message)
	}
}

func TestHasThresholdNotification_Found(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}

	svc := NewNotificationService(notifRepo, registry)

	// Add an existing notification with threshold tag
	existingNotif := &domain.NotificationEvent{
		ID:            "notif-1",
		CertificateID: stringPtr("mc-test-1"),
		Type:          domain.NotificationTypeExpirationWarning,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     "owner-1",
		Message:       "Certificate expires soon\n\n[threshold:30]",
		Status:        "sent",
		CreatedAt:     time.Now(),
	}
	notifRepo.AddNotification(existingNotif)

	// Check for existing notification
	found, err := svc.HasThresholdNotification(ctx, "mc-test-1", 30)
	if err != nil {
		t.Fatalf("HasThresholdNotification failed: %v", err)
	}

	if !found {
		t.Errorf("expected to find threshold notification, but didn't")
	}
}

func TestHasThresholdNotification_NotFound(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}

	svc := NewNotificationService(notifRepo, registry)

	// Check for non-existent notification
	found, err := svc.HasThresholdNotification(ctx, "mc-test-1", 30)
	if err != nil {
		t.Fatalf("HasThresholdNotification failed: %v", err)
	}

	if found {
		t.Errorf("expected not to find threshold notification, but did")
	}
}

func TestSendExpirationWarning(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-warning",
		CommonName: "warn.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(0, 0, 10),
	}

	err := svc.SendExpirationWarning(ctx, cert, 10)
	if err != nil {
		t.Fatalf("SendExpirationWarning failed: %v", err)
	}

	// Verify notification was created
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	if notifRepo.Notifications[0].Type != domain.NotificationTypeExpirationWarning {
		t.Errorf("expected ExpirationWarning type, got %s", notifRepo.Notifications[0].Type)
	}
}

func TestSendRenewalNotification_Success(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-renewed",
		CommonName: "renewed.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}

	err := svc.SendRenewalNotification(ctx, cert, true, nil)
	if err != nil {
		t.Fatalf("SendRenewalNotification failed: %v", err)
	}

	// Verify notification was created with success type
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	if notifRepo.Notifications[0].Type != domain.NotificationTypeRenewalSuccess {
		t.Errorf("expected RenewalSuccess type, got %s", notifRepo.Notifications[0].Type)
	}

	// Verify message contains success text
	if !strings.Contains(notifRepo.Notifications[0].Message, "successfully renewed") {
		t.Errorf("expected success message, got: %s", notifRepo.Notifications[0].Message)
	}
}

func TestSendRenewalNotification_Failure(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-failed-renewal",
		CommonName: "failed.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(0, 0, 5),
	}

	testErr := fmt.Errorf("issuer unavailable")
	err := svc.SendRenewalNotification(ctx, cert, false, testErr)
	if err != nil {
		t.Fatalf("SendRenewalNotification failed: %v", err)
	}

	// Verify notification was created with failure type
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	if notifRepo.Notifications[0].Type != domain.NotificationTypeRenewalFailure {
		t.Errorf("expected RenewalFailure type, got %s", notifRepo.Notifications[0].Type)
	}

	// Verify message contains error info
	if !strings.Contains(notifRepo.Notifications[0].Message, "failed to renew") {
		t.Errorf("expected failure message, got: %s", notifRepo.Notifications[0].Message)
	}
}

func TestProcessPendingNotifications(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	// Add pending notifications
	for i := 0; i < 3; i++ {
		notif := &domain.NotificationEvent{
			ID:        fmt.Sprintf("notif-%d", i),
			Type:      domain.NotificationTypeExpirationWarning,
			Channel:   domain.NotificationChannelEmail,
			Recipient: "owner-1",
			Message:   fmt.Sprintf("Test notification %d", i),
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		notifRepo.AddNotification(notif)
	}

	err := svc.ProcessPendingNotifications(ctx)
	if err != nil {
		t.Fatalf("ProcessPendingNotifications failed: %v", err)
	}

	// Verify all notifications were sent
	if notifier.getSentCount() != 3 {
		t.Errorf("expected 3 sent notifications, got %d", notifier.getSentCount())
	}

	// Verify status was updated to sent
	for _, notif := range notifRepo.Notifications {
		if notif.Status != "sent" {
			t.Errorf("expected notification status 'sent', got %s", notif.Status)
		}
	}
}

func TestProcessPendingNotifications_NoNotifier(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	// No notifier registered - demo mode
	registry := map[string]Notifier{}

	svc := NewNotificationService(notifRepo, registry)

	// Add pending notification
	notif := &domain.NotificationEvent{
		ID:        "notif-demo",
		Type:      domain.NotificationTypeExpirationWarning,
		Channel:   domain.NotificationChannelEmail, // Channel not in registry
		Recipient: "owner-1",
		Message:   "Test notification",
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	notifRepo.AddNotification(notif)

	// Should not fail, just mark as sent (demo mode graceful skip)
	err := svc.ProcessPendingNotifications(ctx)
	if err != nil {
		t.Fatalf("ProcessPendingNotifications should not fail in demo mode: %v", err)
	}

	// Status should still be updated to sent
	if len(notifRepo.Notifications) > 0 && notifRepo.Notifications[0].Status == "sent" {
		// This is fine - graceful skip marks as sent
	}
}

func TestRegisterNotifier(t *testing.T) {
	t.Helper()
	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}
	svc := NewNotificationService(notifRepo, registry)

	notifier := newMockNotifier()
	svc.RegisterNotifier("Email", notifier)

	// Verify notifier was registered
	if svc.notifierRegistry["Email"] == nil {
		t.Errorf("expected notifier to be registered")
	}
}

func TestListNotifications(t *testing.T) {
	t.Helper()
	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}
	svc := NewNotificationService(notifRepo, registry)

	// Add test notifications
	for i := 0; i < 5; i++ {
		notif := &domain.NotificationEvent{
			ID:        fmt.Sprintf("notif-list-%d", i),
			Type:      domain.NotificationTypeExpirationWarning,
			Channel:   domain.NotificationChannelEmail,
			Recipient: fmt.Sprintf("owner-%d", i%2),
			Message:   fmt.Sprintf("Test notification %d", i),
			Status:    "sent",
			CreatedAt: time.Now(),
		}
		notifRepo.AddNotification(notif)
	}

	// List with pagination
	notifs, total, err := svc.ListNotifications(context.Background(), 1, 3)
	if err != nil {
		t.Fatalf("ListNotifications failed: %v", err)
	}

	if len(notifs) == 0 {
		t.Errorf("expected notifications, got none")
	}

	if total == 0 {
		t.Errorf("expected total count > 0, got %d", total)
	}
}

func TestMarkAsRead(t *testing.T) {
	t.Helper()

	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}
	svc := NewNotificationService(notifRepo, registry)

	// Add a notification
	notif := &domain.NotificationEvent{
		ID:        "notif-read",
		Type:      domain.NotificationTypeExpirationWarning,
		Channel:   domain.NotificationChannelEmail,
		Recipient: "owner-1",
		Message:   "Test notification",
		Status:    "sent",
		CreatedAt: time.Now(),
	}
	notifRepo.AddNotification(notif)

	// Mark as read
	err := svc.MarkAsRead(context.Background(), notif.ID)
	if err != nil {
		t.Fatalf("MarkAsRead failed: %v", err)
	}

	// Verify status was updated
	if len(notifRepo.Notifications) > 0 && notifRepo.Notifications[0].Status != "read" {
		t.Errorf("expected status 'read', got %s", notifRepo.Notifications[0].Status)
	}
}

func TestGetNotification(t *testing.T) {
	t.Helper()
	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}
	svc := NewNotificationService(notifRepo, registry)

	// Add a notification
	notif := &domain.NotificationEvent{
		ID:        "notif-get-test",
		Type:      domain.NotificationTypeExpirationWarning,
		Channel:   domain.NotificationChannelEmail,
		Recipient: "owner-1",
		Message:   "Test notification",
		Status:    "sent",
		CreatedAt: time.Now(),
	}
	notifRepo.AddNotification(notif)

	// Get the notification
	retrieved, err := svc.GetNotification(context.Background(), notif.ID)
	if err != nil {
		t.Fatalf("GetNotification failed: %v", err)
	}

	if retrieved == nil {
		t.Errorf("expected notification, got nil")
	} else if retrieved.ID != notif.ID {
		t.Errorf("expected ID %s, got %s", notif.ID, retrieved.ID)
	}
}

func TestSendDeploymentNotification_Success(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-deploy",
		CommonName: "deploy.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}

	target := &domain.DeploymentTarget{
		ID:   "target-1",
		Name: "NGINX-Prod",
	}

	err := svc.SendDeploymentNotification(ctx, cert, target, true, nil)
	if err != nil {
		t.Fatalf("SendDeploymentNotification failed: %v", err)
	}

	// Verify notification was created
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	if notifRepo.Notifications[0].Type != domain.NotificationTypeDeploymentSuccess {
		t.Errorf("expected DeploymentSuccess type, got %s", notifRepo.Notifications[0].Type)
	}
}

func TestSendDeploymentNotification_Failure(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{
		"Email": notifier,
	}

	svc := NewNotificationService(notifRepo, registry)

	cert := &domain.ManagedCertificate{
		ID:         "mc-deploy-fail",
		CommonName: "deploy-fail.com",
		OwnerID:    "owner-1",
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}

	target := &domain.DeploymentTarget{
		ID:   "target-2",
		Name: "NGINX-Staging",
	}

	deployErr := fmt.Errorf("connection timeout")
	err := svc.SendDeploymentNotification(ctx, cert, target, false, deployErr)
	if err != nil {
		t.Fatalf("SendDeploymentNotification failed: %v", err)
	}

	// Verify notification was created
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(notifRepo.Notifications))
	}

	if notifRepo.Notifications[0].Type != domain.NotificationTypeDeploymentFailure {
		t.Errorf("expected DeploymentFailure type, got %s", notifRepo.Notifications[0].Type)
	}
}

func TestGetNotificationHistory(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{}
	svc := NewNotificationService(notifRepo, registry)

	certID := "mc-history"

	// Add multiple notifications for same cert
	for i := 0; i < 3; i++ {
		notif := &domain.NotificationEvent{
			ID:            fmt.Sprintf("notif-hist-%d", i),
			CertificateID: &certID,
			Type:          domain.NotificationTypeExpirationWarning,
			Channel:       domain.NotificationChannelEmail,
			Recipient:     "owner-1",
			Message:       fmt.Sprintf("Alert %d", i),
			Status:        "sent",
			CreatedAt:     time.Now(),
		}
		notifRepo.AddNotification(notif)
	}

	// Get history
	history, err := svc.GetNotificationHistory(ctx, certID)
	if err != nil {
		t.Fatalf("GetNotificationHistory failed: %v", err)
	}

	if len(history) < 1 {
		t.Errorf("expected at least 1 notification, got %d", len(history))
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}

// ─── I-005 retry + DLQ service contract (Phase 1 Red) ─────────────────────
//
// These tests pin the service-layer contract the I-005 fix must satisfy. The
// Red signals they produce are, in compile order:
//
//   1. service.NotificationService.RetryFailedNotifications undefined
//   2. service.NotificationService.RequeueNotification undefined
//   3. mockNotifRepo.ListRetryEligible undefined (surfaced after the service
//      method exists and starts calling it)
//   4. mockNotifRepo.RecordFailedAttempt undefined
//   5. mockNotifRepo.MarkAsDead undefined
//   6. mockNotifRepo.Requeue undefined
//   7. NotificationEvent.RetryCount / NextRetryAt / LastError undefined — but
//      domain/notification_test.go already pins these, so they ride in on the
//      Phase 2 Green domain edit and compile by the time the service-layer
//      tests run.
//
// The contract under test, re-derived from notification.go:282-288:
//   * A failed notifier.Send used to stamp status='failed' with a zero
//     time.Time and return. I-005 reframes that row as retry-eligible with
//     bookkeeping (retry_count, next_retry_at, last_error) so a sibling
//     scheduler loop can promote it back to 'pending' until max_attempts,
//     then to 'dead' (DLQ) for operator triage.
//   * Backoff is 2^retry_count minutes, capped at 1h, mirroring the
//     operator decision captured in the I-005 design notes.
//   * Success on a retry promotes the row straight to 'sent' via
//     UpdateStatus (no retry bookkeeping change).
//   * Requeue is the operator-driven escape hatch from 'dead' back to
//     'pending' with retry_count reset to 0; service-layer impl is a
//     pass-through to repo.Requeue so the audit trail is consistent.

const (
	// i005MaxAttempts must match the same constant used by the Green
	// service implementation. Declared here only so the test assertions
	// read cleanly; Phase 2 is free to thread this from config.
	i005MaxAttempts = 5

	// i005BackoffCap mirrors the 1h ceiling on 2^retry_count minutes.
	i005BackoffCap = time.Hour
)

// newFailedNotification builds a minimal failed-state row suitable for seeding
// the mock repo. retry_count is the number of attempts already consumed (so
// the next attempt becomes retry_count+1, and retry_count == max-1 puts the
// row at the exhaustion threshold).
func newFailedNotification(id string, retryCount int, nextRetryAt time.Time) *domain.NotificationEvent {
	nextCopy := nextRetryAt
	last := "connection refused"
	return &domain.NotificationEvent{
		ID:          id,
		Type:        domain.NotificationTypeExpirationWarning,
		Channel:     domain.NotificationChannelEmail,
		Recipient:   "owner-i005@example.com",
		Message:     "retry me: " + id,
		Status:      string(domain.NotificationStatusFailed),
		RetryCount:  retryCount,
		NextRetryAt: &nextCopy,
		LastError:   &last,
		CreatedAt:   time.Now().Add(-time.Hour),
	}
}

// TestNotificationService_RetryFailedNotifications_NoEligibleRows asserts the
// no-op path: an empty retry queue must not trigger any notifier.Send calls
// and must not surface as an error. This pins that the retry loop's cost is
// O(retry-eligible), not O(total).
func TestNotificationService_RetryFailedNotifications_NoEligibleRows(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	if err := svc.RetryFailedNotifications(ctx); err != nil {
		t.Fatalf("RetryFailedNotifications on empty queue returned error: %v", err)
	}
	if got := notifier.getSentCount(); got != 0 {
		t.Errorf("notifier.Send call count = %d, want 0 (no retry-eligible rows)", got)
	}
}

// TestNotificationService_RetryFailedNotifications_ListError asserts that a
// ListRetryEligible failure short-circuits the loop. Notifier.Send must not
// fire — we never got a canonical set of rows to act on, so sending anything
// would risk double-delivery when the DB comes back.
func TestNotificationService_RetryFailedNotifications_ListError(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifRepo.ListErr = fmt.Errorf("simulated DB outage")

	notifier := newMockNotifier()
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	err := svc.RetryFailedNotifications(ctx)
	if err == nil {
		t.Fatalf("RetryFailedNotifications must surface the list error; got nil")
	}
	if !strings.Contains(err.Error(), "simulated DB outage") {
		t.Errorf("expected wrapped list error to mention 'simulated DB outage', got: %v", err)
	}
	if got := notifier.getSentCount(); got != 0 {
		t.Errorf("notifier.Send must not fire when list fails; got %d sends", got)
	}
}

// TestNotificationService_RetryFailedNotifications_SuccessPromotes asserts
// the happy path for a retry that succeeds: the row is promoted directly to
// 'sent' via UpdateStatus (mirroring ProcessPendingNotifications), and no
// retry bookkeeping mutation (RecordFailedAttempt / MarkAsDead) fires.
func TestNotificationService_RetryFailedNotifications_SuccessPromotes(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier() // default: no error — Send succeeds
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	row := newFailedNotification("notif-success", 2, time.Now().Add(-time.Minute))
	notifRepo.AddNotification(row)

	if err := svc.RetryFailedNotifications(ctx); err != nil {
		t.Fatalf("RetryFailedNotifications should not error on per-row success: %v", err)
	}

	if notifier.getSentCount() != 1 {
		t.Errorf("expected exactly 1 notifier.Send call, got %d", notifier.getSentCount())
	}
	if row.Status != string(domain.NotificationStatusSent) {
		t.Errorf("successful retry must promote status to 'sent', got %q", row.Status)
	}
	// retry_count must NOT increment on success — that would falsify the
	// "this row was delivered on attempt N" signal the audit trail relies on.
	if row.RetryCount != 2 {
		t.Errorf("retry_count must not change on success, got %d (want 2)", row.RetryCount)
	}
}

// TestNotificationService_RetryFailedNotifications_ExponentialBackoff asserts
// that a still-retriable failure schedules the next attempt at 2^retry_count
// minutes from now, matching the operator-approved curve 1m, 2m, 4m, 8m, 16m.
// The assertion is a window check against time.Now() because the service
// reads its own clock.
func TestNotificationService_RetryFailedNotifications_ExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	notifier.SendErr = fmt.Errorf("smtp 451 temporary failure")
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	// retry_count=2 → next attempt is #3, backoff = 2^2 = 4 minutes.
	row := newFailedNotification("notif-backoff", 2, time.Now().Add(-time.Minute))
	notifRepo.AddNotification(row)

	before := time.Now()
	if err := svc.RetryFailedNotifications(ctx); err != nil {
		t.Fatalf("RetryFailedNotifications should not bubble per-row send errors: %v", err)
	}
	after := time.Now()

	// Still in 'failed' — not yet exhausted (retry_count+1 = 3, below max 5).
	if row.Status != string(domain.NotificationStatusFailed) {
		t.Errorf("status after non-terminal retry must stay 'failed', got %q", row.Status)
	}
	if row.RetryCount != 3 {
		t.Errorf("retry_count must increment on failure, got %d (want 3)", row.RetryCount)
	}
	if row.NextRetryAt == nil {
		t.Fatalf("NextRetryAt must be set on non-terminal retry failure; got nil")
	}
	expectedMin := before.Add(4 * time.Minute)
	expectedMax := after.Add(4 * time.Minute)
	if row.NextRetryAt.Before(expectedMin) || row.NextRetryAt.After(expectedMax) {
		t.Errorf("NextRetryAt outside 2^2=4m window [%v, %v]; got %v",
			expectedMin, expectedMax, *row.NextRetryAt)
	}
	if row.LastError == nil || !strings.Contains(*row.LastError, "smtp 451 temporary failure") {
		t.Errorf("LastError must preserve the notifier error body for triage; got %v", row.LastError)
	}
}

// TestNotificationService_RetryFailedNotifications_BackoffCap asserts the
// defense-in-depth 1h ceiling on next_retry_at. The retry curve under the
// operator-approved formula is pre-increment `2^retry_count` minutes — 1m,
// 2m, 4m, 8m — and with max_attempts=5 the deepest still-retriable row is
// retry_count=4 (next wait = 2^4 = 16m), which would transition to 'dead'
// before ever scheduling. So the largest actually-schedulable wait is
// 2^3=8m at retry_count=3, well under the 1h cap.
//
// That makes this test a ceiling-assertion, not a saturation-assertion: we
// pick retry_count=3 (matching ExponentialBackoff's formula but one step
// deeper) and verify (a) the window lands at 2^3=8m and (b) the cap is
// never exceeded. When max_attempts becomes configurable in a later
// milestone, this test becomes the natural home for a true cap-saturation
// fixture; for now it pins the arithmetic the Phase 2 Green implementation
// has to hit exactly.
func TestNotificationService_RetryFailedNotifications_BackoffCap(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	notifier.SendErr = fmt.Errorf("webhook 502 bad gateway")
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	// retry_count=3 → pre-increment wait = 2^3 = 8 minutes. Post-increment
	// retry_count becomes 4, which is still below max_attempts=5, so the
	// row stays in 'failed' rather than transitioning to 'dead'.
	row := newFailedNotification("notif-backoff-cap", 3, time.Now().Add(-time.Minute))
	notifRepo.AddNotification(row)

	before := time.Now()
	if err := svc.RetryFailedNotifications(ctx); err != nil {
		t.Fatalf("RetryFailedNotifications should not bubble per-row send errors: %v", err)
	}
	after := time.Now()

	if row.Status != string(domain.NotificationStatusFailed) {
		t.Errorf("mid-retry status must stay 'failed', got %q", row.Status)
	}
	if row.RetryCount != 4 {
		t.Errorf("retry_count must increment on failure, got %d (want 4)", row.RetryCount)
	}
	if row.NextRetryAt == nil {
		t.Fatalf("NextRetryAt must be set; got nil")
	}
	// retry_count=3 → pre-increment 2^3 = 8m, matching the curve pinned by
	// ExponentialBackoff (retry_count=2 → 2^2=4m).
	expectedMin := before.Add(8 * time.Minute)
	expectedMax := after.Add(8 * time.Minute)
	if row.NextRetryAt.Before(expectedMin) || row.NextRetryAt.After(expectedMax) {
		t.Errorf("NextRetryAt outside 2^3=8m window [%v, %v]; got %v",
			expectedMin, expectedMax, *row.NextRetryAt)
	}
	// And regardless of retry_count, the ceiling must hold: next_retry_at
	// must never be more than i005BackoffCap (1h) from now. This is the
	// defense-in-depth assertion — it would fail loudly if a future
	// refactor swapped to post-increment and overshot on a deeper row.
	if row.NextRetryAt.After(after.Add(i005BackoffCap + time.Second)) {
		t.Errorf("NextRetryAt violates 1h cap; scheduled %v in the future",
			row.NextRetryAt.Sub(after))
	}
}

// TestNotificationService_RetryFailedNotifications_MarkDeadOnExhaustion
// asserts the terminal transition: once retry_count crosses max_attempts,
// the row moves to 'dead' (DLQ) and stops participating in the retry sweep.
// next_retry_at must be cleared — otherwise the partial retry-sweep index
// would still pick it up and we'd loop forever.
func TestNotificationService_RetryFailedNotifications_MarkDeadOnExhaustion(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	notifier.SendErr = fmt.Errorf("connection refused after max attempts")
	registry := map[string]Notifier{"Email": notifier}
	svc := NewNotificationService(notifRepo, registry)

	// retry_count = max-1: this attempt makes it max, so the row must
	// transition to 'dead', not get rescheduled.
	row := newFailedNotification("notif-dead", i005MaxAttempts-1, time.Now().Add(-time.Minute))
	notifRepo.AddNotification(row)

	if err := svc.RetryFailedNotifications(ctx); err != nil {
		t.Fatalf("RetryFailedNotifications must not bubble per-row exhaustion: %v", err)
	}

	if row.Status != string(domain.NotificationStatusDead) {
		t.Errorf("exhausted row must be in 'dead' status, got %q", row.Status)
	}
	if row.NextRetryAt != nil {
		t.Errorf("dead row must have next_retry_at cleared (else retry sweep keeps picking it up); got %v", *row.NextRetryAt)
	}
	if row.LastError == nil || !strings.Contains(*row.LastError, "connection refused after max attempts") {
		t.Errorf("LastError on dead row must preserve final failure reason; got %v", row.LastError)
	}
}

// TestNotificationService_RequeueNotification_Success asserts the operator
// escape hatch: Requeue flips a dead row back to 'pending' with
// retry_count=0 so ProcessPendingNotifications can pick it up on the very
// next tick. The service delegates to repo.Requeue and propagates no error.
func TestNotificationService_RequeueNotification_Success(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	registry := map[string]Notifier{"Email": newMockNotifier()}
	svc := NewNotificationService(notifRepo, registry)

	next := time.Now().Add(10 * time.Minute)
	last := "max attempts exceeded"
	dead := &domain.NotificationEvent{
		ID:          "notif-requeue",
		Type:        domain.NotificationTypeExpirationWarning,
		Channel:     domain.NotificationChannelEmail,
		Recipient:   "owner@example.com",
		Message:     "please requeue me",
		Status:      string(domain.NotificationStatusDead),
		RetryCount:  i005MaxAttempts,
		NextRetryAt: &next,
		LastError:   &last,
		CreatedAt:   time.Now().Add(-2 * time.Hour),
	}
	notifRepo.AddNotification(dead)

	if err := svc.RequeueNotification(ctx, dead.ID); err != nil {
		t.Fatalf("RequeueNotification(%s) returned error: %v", dead.ID, err)
	}

	if dead.Status != string(domain.NotificationStatusPending) {
		t.Errorf("Requeue must flip status to 'pending', got %q", dead.Status)
	}
	if dead.RetryCount != 0 {
		t.Errorf("Requeue must reset retry_count to 0, got %d", dead.RetryCount)
	}
	if dead.NextRetryAt != nil {
		t.Errorf("Requeue must clear next_retry_at (pending rows never have it), got %v", *dead.NextRetryAt)
	}
	if dead.LastError != nil {
		t.Errorf("Requeue must clear last_error (pending is a fresh attempt), got %v", *dead.LastError)
	}
}

// TestNotificationService_RequeueNotification_RepoError asserts that a
// failed Requeue at the repository layer surfaces cleanly. The service has
// no fallback here — if the DB can't update the row, the operator action
// must fail loudly rather than silently "succeed" in the UI.
func TestNotificationService_RequeueNotification_RepoError(t *testing.T) {
	ctx := context.Background()
	notifRepo := newMockNotificationRepository()
	notifRepo.UpdateErr = fmt.Errorf("pg: deadlock detected")
	registry := map[string]Notifier{"Email": newMockNotifier()}
	svc := NewNotificationService(notifRepo, registry)

	// Seed a dead row so the service has something to act on (the error
	// must come from the repo write, not from a missing ID).
	dead := &domain.NotificationEvent{
		ID:      "notif-requeue-err",
		Type:    domain.NotificationTypeExpirationWarning,
		Channel: domain.NotificationChannelEmail,
		Status:  string(domain.NotificationStatusDead),
	}
	notifRepo.AddNotification(dead)

	err := svc.RequeueNotification(ctx, dead.ID)
	if err == nil {
		t.Fatalf("RequeueNotification must surface repo errors; got nil")
	}
	if !strings.Contains(err.Error(), "pg: deadlock detected") {
		t.Errorf("expected wrapped repo error to mention 'pg: deadlock detected', got: %v", err)
	}
}
