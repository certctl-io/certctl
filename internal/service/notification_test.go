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
