package email

import (
	"context"
	"fmt"
)

// NotifierAdapter bridges the email.Connector (notifier.Connector interface) to the
// service.Notifier interface used by the notification registry. This adapter allows
// the existing email SMTP connector to be registered alongside Slack, Teams, etc.
type NotifierAdapter struct {
	connector *Connector
}

// NewNotifierAdapter wraps an email.Connector to implement service.Notifier.
func NewNotifierAdapter(c *Connector) *NotifierAdapter {
	return &NotifierAdapter{connector: c}
}

// Channel returns the notification channel identifier.
func (a *NotifierAdapter) Channel() string {
	return "Email"
}

// Send delivers a notification via SMTP email.
// The recipient is the email address, subject is used as the email subject,
// and body is the email body content.
func (a *NotifierAdapter) Send(ctx context.Context, recipient string, subject string, body string) error {
	if recipient == "" {
		return fmt.Errorf("email: recipient address is required")
	}
	return a.connector.sendEmail(ctx, recipient, subject, body)
}

// SendHTML delivers an HTML email notification via SMTP.
// Used by the digest service for rich HTML digest emails.
func (a *NotifierAdapter) SendHTML(ctx context.Context, recipient string, subject string, htmlBody string) error {
	if recipient == "" {
		return fmt.Errorf("email: recipient address is required")
	}
	return a.connector.sendHTMLEmail(ctx, recipient, subject, htmlBody)
}
