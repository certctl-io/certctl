package service

import (
	"context"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// NotificationService provides business logic for managing notifications.
type NotificationService struct {
	notifRepo        repository.NotificationRepository
	notifierRegistry map[string]Notifier
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

// SendExpirationWarning sends a certificate expiration warning for a specific threshold.
func (s *NotificationService) SendExpirationWarning(ctx context.Context, cert *domain.ManagedCertificate, daysUntilExpiry int) error {
	return s.SendThresholdAlert(ctx, cert, daysUntilExpiry, daysUntilExpiry)
}

// SendThresholdAlert sends an expiration alert for a specific threshold (e.g., 30-day, 14-day, expired).
// The threshold parameter indicates which configured threshold triggered the alert.
func (s *NotificationService) SendThresholdAlert(ctx context.Context, cert *domain.ManagedCertificate, daysUntilExpiry int, threshold int) error {
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

	// Create notification record
	notif := &domain.NotificationEvent{
		ID:            generateID("notif"),
		CertificateID: &cert.ID,
		Type:          domain.NotificationTypeExpirationWarning,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     cert.OwnerID,
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	// Attempt immediate send
	return s.sendNotification(ctx, notif)
}

// HasThresholdNotification checks whether an expiration warning has already been sent
// for a specific certificate and threshold combination. Used for deduplication.
func (s *NotificationService) HasThresholdNotification(ctx context.Context, certID string, threshold int) (bool, error) {
	filter := &repository.NotificationFilter{
		CertificateID: certID,
		Type:          string(domain.NotificationTypeExpirationWarning),
		MessageLike:   fmt.Sprintf("%%[threshold:%d]%%", threshold),
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
		Recipient:     cert.OwnerID,
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
		Recipient:     cert.OwnerID,
		Message:       body,
		Status:        "pending",
		CreatedAt:     time.Now(),
	}

	if err := s.notifRepo.Create(ctx, notif); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return s.sendNotification(ctx, notif)
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
			fmt.Printf("failed to send notification %s: %v\n", notif.ID, err)
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
		_ = s.notifRepo.UpdateStatus(ctx, notif.ID, "sent", time.Now())
		return nil
	}

	// Send the notification
	if err := notifier.Send(ctx, notif.Recipient, string(notif.Type), notif.Message); err != nil {
		// Update status to failed
		_ = s.notifRepo.UpdateStatus(ctx, notif.ID, "failed", time.Time{})
		return fmt.Errorf("failed to send via %s: %w", notif.Channel, err)
	}

	// Update status to sent
	if err := s.notifRepo.UpdateStatus(ctx, notif.ID, "sent", time.Now()); err != nil {
		fmt.Printf("failed to update notification status: %v\n", err)
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
func (s *NotificationService) ListNotifications(page, perPage int) ([]domain.NotificationEvent, int64, error) {
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

	notifications, err := s.notifRepo.List(context.Background(), filter)
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
func (s *NotificationService) GetNotification(id string) (*domain.NotificationEvent, error) {
	filter := &repository.NotificationFilter{
		PerPage: 1,
	}

	notifications, err := s.notifRepo.List(context.Background(), filter)
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
func (s *NotificationService) MarkAsRead(id string) error {
	return s.notifRepo.UpdateStatus(context.Background(), id, "read", time.Now())
}
