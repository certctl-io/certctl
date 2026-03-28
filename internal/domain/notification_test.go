package domain

import "testing"

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
