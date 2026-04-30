package domain

import (
	"testing"
	"time"
)

func TestNotificationType_Constants(t *testing.T) {
	tests := map[string]NotificationType{
		"ExpirationWarning": NotificationTypeExpirationWarning,
		"RenewalSuccess":    NotificationTypeRenewalSuccess,
		"RenewalFailure":    NotificationTypeRenewalFailure,
		"DeploymentSuccess": NotificationTypeDeploymentSuccess,
		"DeploymentFailure": NotificationTypeDeploymentFailure,
		"PolicyViolation":   NotificationTypePolicyViolation,
		"Revocation":        NotificationTypeRevocation,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestNotificationChannel_Constants(t *testing.T) {
	tests := map[string]NotificationChannel{
		"Email":     NotificationChannelEmail,
		"Webhook":   NotificationChannelWebhook,
		"Slack":     NotificationChannelSlack,
		"Teams":     NotificationChannelTeams,
		"PagerDuty": NotificationChannelPagerDuty,
		"OpsGenie":  NotificationChannelOpsGenie,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestNotificationEvent_Fields(t *testing.T) {
	// This test verifies the NotificationEvent struct can be instantiated
	// with all expected fields.
	certID := "mc-123"
	errorMsg := "failed to send"
	event := &NotificationEvent{
		ID:            "notif-1",
		Type:          NotificationTypeExpirationWarning,
		CertificateID: &certID,
		Channel:       NotificationChannelSlack,
		Recipient:     "alerts@example.com",
		Message:       "Certificate expiring in 30 days",
		Status:        "sent",
		Error:         &errorMsg,
	}

	if event.ID != "notif-1" {
		t.Errorf("expected ID 'notif-1', got %s", event.ID)
	}

	if event.Type != NotificationTypeExpirationWarning {
		t.Errorf("expected type ExpirationWarning, got %s", string(event.Type))
	}

	if event.Channel != NotificationChannelSlack {
		t.Errorf("expected channel Slack, got %s", string(event.Channel))
	}

	if event.CertificateID == nil || *event.CertificateID != "mc-123" {
		t.Errorf("expected CertificateID mc-123, got %v", event.CertificateID)
	}

	if event.Error == nil || *event.Error != "failed to send" {
		t.Errorf("expected error 'failed to send', got %v", event.Error)
	}
}

// TestNotificationStatus_Constants verifies that I-005 introduces a typed
// NotificationStatus alongside canonical lowercase string constants covering
// the pending → sent, pending → failed → dead, and pending → read transitions.
// The Red signal here is a compile error: the type and the NotificationStatusDead
// constant do not exist before Phase 2 Green.
func TestNotificationStatus_Constants(t *testing.T) {
	tests := map[string]NotificationStatus{
		"pending": NotificationStatusPending,
		"sent":    NotificationStatusSent,
		"failed":  NotificationStatusFailed,
		"dead":    NotificationStatusDead,
		"read":    NotificationStatusRead,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

// TestNotificationEvent_RetryFields verifies the I-005 retry/DLQ columns are
// surfaced on the domain model: a RetryCount counter, a nullable NextRetryAt
// timestamp used by the retry-sweep partial index, and a nullable LastError
// string preserving the most recent transient failure for operator triage.
// The Red signal is a compile error — these fields do not exist yet.
func TestNotificationEvent_RetryFields(t *testing.T) {
	next := time.Now().Add(2 * time.Minute)
	lastErr := "connection refused"
	event := &NotificationEvent{
		ID:          "notif-retry-001",
		Type:        NotificationTypeExpirationWarning,
		Channel:     NotificationChannelWebhook,
		Recipient:   "https://hooks.example.com/certs",
		Message:     "retry me",
		Status:      string(NotificationStatusFailed),
		RetryCount:  3,
		NextRetryAt: &next,
		LastError:   &lastErr,
	}

	if event.RetryCount != 3 {
		t.Errorf("expected RetryCount 3, got %d", event.RetryCount)
	}
	if event.NextRetryAt == nil || !event.NextRetryAt.Equal(next) {
		t.Errorf("expected NextRetryAt %v, got %v", next, event.NextRetryAt)
	}
	if event.LastError == nil || *event.LastError != "connection refused" {
		t.Errorf("expected LastError 'connection refused', got %v", event.LastError)
	}
}
