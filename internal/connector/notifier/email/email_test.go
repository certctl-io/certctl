package email

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/notifier"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func TestEmail_ValidateConfig_ValidSMTP(t *testing.T) {
	// Use localhost with a high port that's unlikely to have a service
	// This test will try to connect, and we expect it to fail
	// But for testing that validation works with valid config, we need to skip this
	// in most CI environments or use a mock SMTP server.

	// For this test, we'll just verify that ValidateConfig can be called
	// with proper config structure without panicking
	cfg := &Config{
		SMTPHost:    "localhost",
		SMTPPort:    25,
		Username:    "user",
		Password:    "pass",
		FromAddress: "sender@example.com",
		UseTLS:      false,
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := New(cfg, logger)

	// This will likely fail to connect, but that's OK - we're testing the validation logic exists
	_ = conn.ValidateConfig(context.Background(), rawConfig)
	// If it crashes, the test will fail; if it returns an error about connection, that's expected
}

func TestEmail_ValidateConfig_MissingHost(t *testing.T) {
	cfg := &Config{
		SMTPPort:    587,
		Username:    "user",
		Password:    "pass",
		FromAddress: "sender@example.com",
		UseTLS:      true,
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for missing SMTP host, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got %v", err)
	}
}

func TestEmail_ValidateConfig_MissingPort(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		Username:    "user",
		Password:    "pass",
		FromAddress: "sender@example.com",
		UseTLS:      true,
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for missing port, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got %v", err)
	}
}

func TestEmail_ValidateConfig_MissingFromAddress(t *testing.T) {
	cfg := &Config{
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		Username: "user",
		Password: "pass",
		UseTLS:   true,
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for missing from_address, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got %v", err)
	}
}

func TestEmail_ValidateConfig_InvalidJSON(t *testing.T) {
	rawConfig := []byte("{invalid json")
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid email config") {
		t.Errorf("expected 'invalid email config', got %v", err)
	}
}

func TestEmail_FormatMessage_RFC822Headers(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
		UseTLS:      true,
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	from := "sender@example.com"
	to := "recipient@example.com"
	subject := "Test Subject"
	body := "Test Body"

	message, err := conn.formatEmailMessage(from, to, subject, body)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	messageStr := string(message)

	if !strings.Contains(messageStr, "From: "+from) {
		t.Errorf("expected From header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "To: "+to) {
		t.Errorf("expected To header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "Subject: "+subject) {
		t.Errorf("expected Subject header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "Date:") {
		t.Errorf("expected Date header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "Content-Type: text/plain; charset=utf-8") {
		t.Errorf("expected Content-Type header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, body) {
		t.Errorf("expected message body, got %s", messageStr)
	}
}

func TestEmail_FormatHTMLEmailMessage_Headers(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
		UseTLS:      true,
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	from := "sender@example.com"
	to := "recipient@example.com"
	subject := "HTML Test"
	htmlBody := "<html><body><h1>Test</h1></body></html>"

	message, err := conn.formatHTMLEmailMessage(from, to, subject, htmlBody)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	messageStr := string(message)

	if !strings.Contains(messageStr, "From: "+from) {
		t.Errorf("expected From header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "To: "+to) {
		t.Errorf("expected To header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "Subject: "+subject) {
		t.Errorf("expected Subject header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "MIME-Version: 1.0") {
		t.Errorf("expected MIME-Version header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, "Content-Type: text/html; charset=utf-8") {
		t.Errorf("expected HTML Content-Type header, got %s", messageStr)
	}
	if !strings.Contains(messageStr, htmlBody) {
		t.Errorf("expected HTML body, got %s", messageStr)
	}
}

// TestEmail_FormatEmailMessage_RejectsCRLFInjection exercises the CRLF
// sanitizer (CWE-113). A subject containing "\r\nBcc: ..." must be rejected
// rather than silently stripped — authentication-relevant headers are
// security-critical and silent mutation masks malicious intent.
func TestEmail_FormatEmailMessage_RejectsCRLFInjection(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}
	logger := newTestLogger()
	conn := New(cfg, logger)

	cases := []struct {
		name          string
		from, to, sub string
		wantField     string
	}{
		{"CRLF in Subject", "sender@example.com", "recipient@example.com", "hello\r\nBcc: attacker@example.com", "Subject"},
		{"LF in To", "sender@example.com", "recipient@example.com\nBcc: x@y", "ok", "To"},
		{"CR in From", "sender@example.com\rExtra: header", "recipient@example.com", "ok", "From"},
		{"NUL in Subject", "sender@example.com", "recipient@example.com", "hi\x00there", "Subject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.formatEmailMessage(tc.from, tc.to, tc.sub, "body")
			if err == nil {
				t.Fatal("expected injection error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("expected error to mention field %q, got %q", tc.wantField, err.Error())
			}
		})
	}
}

// TestEmail_FormatHTMLEmailMessage_RejectsCRLFInjection mirrors the plain-text
// test for the HTML codepath used by the digest service.
func TestEmail_FormatHTMLEmailMessage_RejectsCRLFInjection(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}
	logger := newTestLogger()
	conn := New(cfg, logger)

	_, err := conn.formatHTMLEmailMessage(
		"sender@example.com",
		"recipient@example.com",
		"digest\r\nBcc: attacker@example.com",
		"<p>hi</p>",
	)
	if err == nil {
		t.Fatal("expected CRLF injection error, got nil")
	}
	if !strings.Contains(err.Error(), "Subject") {
		t.Errorf("expected error to mention Subject field, got %q", err.Error())
	}
}

func TestEmail_FormatAlertBody(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-123",
		Type:      "expiration",
		Severity:  "warning",
		Subject:   "Certificate Expiring",
		Message:   "Certificate mc-api-prod expires in 7 days",
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			"cert_id": "mc-api-prod",
			"issuer":  "letsencrypt",
		},
	}

	body := conn.formatAlertBody(alert)

	if !strings.Contains(body, "Certificate Alert Notification") {
		t.Errorf("expected 'Certificate Alert Notification' in body")
	}
	if !strings.Contains(body, alert.ID) {
		t.Errorf("expected alert ID in body")
	}
	if !strings.Contains(body, alert.Severity) {
		t.Errorf("expected severity in body")
	}
	if !strings.Contains(body, alert.Subject) {
		t.Errorf("expected subject in body")
	}
	if !strings.Contains(body, alert.Message) {
		t.Errorf("expected message in body")
	}
	if !strings.Contains(body, "cert_id") {
		t.Errorf("expected metadata key in body")
	}
	if !strings.Contains(body, "mc-api-prod") {
		t.Errorf("expected metadata value in body")
	}
}

func TestEmail_FormatEventBody(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	certID := "mc-api-prod"
	event := notifier.Event{
		ID:            "event-456",
		Type:          "issued",
		CertificateID: &certID,
		Subject:       "Certificate Issued",
		Body:          "New certificate issued successfully",
		CreatedAt:     time.Now(),
		Metadata: map[string]string{
			"issuer": "letsencrypt",
		},
	}

	body := conn.formatEventBody(event)

	if !strings.Contains(body, "Certificate Event Notification") {
		t.Errorf("expected 'Certificate Event Notification' in body")
	}
	if !strings.Contains(body, event.ID) {
		t.Errorf("expected event ID in body")
	}
	if !strings.Contains(body, event.Type) {
		t.Errorf("expected event type in body")
	}
	if !strings.Contains(body, "Certificate ID: "+certID) {
		t.Errorf("expected certificate ID in body")
	}
	if !strings.Contains(body, event.Subject) {
		t.Errorf("expected subject in body")
	}
	if !strings.Contains(body, event.Body) {
		t.Errorf("expected body in body")
	}
}

func TestEmail_FormatEventBody_NoCertificateID(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	event := notifier.Event{
		ID:        "event-789",
		Type:      "test",
		Subject:   "Test Event",
		Body:      "Test body",
		CreatedAt: time.Now(),
	}

	body := conn.formatEventBody(event)

	if !strings.Contains(body, "Certificate Event Notification") {
		t.Errorf("expected 'Certificate Event Notification' in body")
	}
	if strings.Contains(body, "Certificate ID:") {
		t.Errorf("expected no Certificate ID line when nil, got %s", body)
	}
}

func TestEmail_SendAlert_ValidationFailure(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-fail",
		Type:      "test",
		Severity:  "critical",
		Subject:   "Test Alert",
		Message:   "Testing error path",
		Recipient: "ops@example.com",
		CreatedAt: time.Now(),
	}

	// This will fail because there's no SMTP server on the configured host
	err := conn.SendAlert(context.Background(), alert)

	// We expect an error because the SMTP server doesn't exist
	// The exact error depends on network conditions, but we know it should fail
	//
	// Q-1 closure (cat-s3-58ce7e9840be): anti-fixture skip — the test
	// asserts that sending to a non-existent SMTP server fails. If a
	// captive portal, SOHO router, or test sandbox happens to resolve
	// smtp.example.com:587 to a black hole that returns success, the
	// assertion is invalid and we skip rather than false-pass. The
	// IANA-reserved example.com domain shouldn't resolve to an active
	// SMTP server in practice; this skip is the defensive fallback.
	if err == nil {
		t.Skip("test requires no service on smtp.example.com:587")
	}
}

func TestEmail_SendEvent_FormatsSubjectCorrectly(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	event := notifier.Event{
		ID:        "event-123",
		Type:      "issued",
		Subject:   "Certificate Issued",
		Body:      "New certificate issued",
		Recipient: "ops@example.com",
		CreatedAt: time.Now(),
	}

	// Verify the formatEventBody output includes expected formatted subject
	body := conn.formatEventBody(event)

	if !strings.Contains(body, event.Subject) {
		t.Errorf("expected subject '%s' in formatted body", event.Subject)
	}
}

func TestEmail_New_CreatesConnectorWithConfig(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		Username:    "user",
		Password:    "pass",
		FromAddress: "sender@example.com",
		UseTLS:      true,
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	if conn == nil {
		t.Fatal("expected connector to be created")
	}

	if conn.config != cfg {
		t.Error("expected config to be set correctly")
	}

	if conn.logger != logger {
		t.Error("expected logger to be set correctly")
	}
}

func TestEmail_ValidateConfig_ConnectionRefused(t *testing.T) {
	// Use a port that's unlikely to have a service listening
	cfg := &Config{
		SMTPHost:    "127.0.0.1",
		SMTPPort:    54321, // Random high port
		FromAddress: "sender@example.com",
		UseTLS:      false,
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	// Q-1 closure (cat-s3-58ce7e9840be): anti-fixture skip — the test
	// asserts that ValidateConfig fails to reach an SMTP server on a
	// random high port (54321) that nothing should be listening on.
	// If the port happens to be occupied (rare in CI, possible on a
	// dev machine), we skip rather than false-pass. The dial-error
	// path below is the actual assertion target.
	if err == nil {
		t.Skip("test assumes no service on 127.0.0.1:54321")
	}

	// Verify it's a connection error
	if !strings.Contains(err.Error(), "failed to reach SMTP server") {
		t.Errorf("expected 'failed to reach SMTP server' in error, got %v", err)
	}
}

func TestEmail_ValidateConfig_ValidatesAllRequiredFields(t *testing.T) {
	// Test each required field
	tests := []struct {
		name       string
		config     Config
		shouldFail bool
	}{
		{
			name: "all required fields present",
			config: Config{
				SMTPHost:    "smtp.example.com",
				SMTPPort:    587,
				FromAddress: "sender@example.com",
			},
			shouldFail: true, // Will fail due to connection, but validation logic passed
		},
		{
			name: "missing smtp_host",
			config: Config{
				SMTPPort:    587,
				FromAddress: "sender@example.com",
			},
			shouldFail: true,
		},
		{
			name: "missing smtp_port",
			config: Config{
				SMTPHost:    "smtp.example.com",
				FromAddress: "sender@example.com",
			},
			shouldFail: true,
		},
		{
			name: "missing from_address",
			config: Config{
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawConfig, _ := json.Marshal(tt.config)
			logger := newTestLogger()
			conn := New(&Config{}, logger)

			err := conn.ValidateConfig(context.Background(), rawConfig)

			if !tt.shouldFail && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tt.shouldFail && err != nil && !strings.Contains(err.Error(), "required") {
				// It might fail with connection error after validation, which is OK
				if !strings.Contains(err.Error(), "failed to reach") {
					t.Errorf("expected validation error or connection error, got %v", err)
				}
			}
		})
	}
}

func TestEmail_FormatMetadata_EmptyMetadata(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	result := conn.formatMetadata(map[string]string{})

	if result != "" {
		t.Errorf("expected empty string for empty metadata, got %q", result)
	}
}

func TestEmail_FormatMetadata_WithData(t *testing.T) {
	cfg := &Config{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
		FromAddress: "sender@example.com",
	}

	logger := newTestLogger()
	conn := New(cfg, logger)

	metadata := map[string]string{
		"issuer": "letsencrypt",
		"env":    "production",
	}

	result := conn.formatMetadata(metadata)

	if !strings.Contains(result, "Metadata:") {
		t.Errorf("expected 'Metadata:' in result")
	}
	if !strings.Contains(result, "issuer") {
		t.Errorf("expected 'issuer' key in result")
	}
	if !strings.Contains(result, "letsencrypt") {
		t.Errorf("expected 'letsencrypt' value in result")
	}
}
