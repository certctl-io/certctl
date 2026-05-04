package email

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/connector/notifier"
	"github.com/certctl-io/certctl/internal/validation"
)

// Config represents the email notifier configuration.
type Config struct {
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	UseTLS      bool   `json:"tls"`
}

// Connector implements the notifier.Connector interface for email notifications.
// It sends alert and event notifications via SMTP.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new email notifier with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// ValidateConfig checks that the SMTP server is reachable and credentials are valid.
// It attempts to connect to the SMTP server to verify connectivity.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid email config: %w", err)
	}

	if cfg.SMTPHost == "" || cfg.SMTPPort == 0 || cfg.FromAddress == "" {
		return fmt.Errorf("email smtp_host, smtp_port, and from_address are required")
	}

	c.logger.Info("validating email configuration",
		"smtp_host", cfg.SMTPHost,
		"smtp_port", cfg.SMTPPort)

	// Test SMTP connectivity with timeout
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to reach SMTP server %s: %w", addr, err)
	}
	defer conn.Close()

	c.config = &cfg
	c.logger.Info("email configuration validated")
	return nil
}

// SendAlert sends an alert notification via SMTP.
// It formats the alert as an email message and sends it to the recipient.
func (c *Connector) SendAlert(ctx context.Context, alert notifier.Alert) error {
	c.logger.Info("sending email alert",
		"alert_id", alert.ID,
		"severity", alert.Severity,
		"recipient", alert.Recipient)

	// Format email subject and body
	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Subject)
	body := c.formatAlertBody(alert)

	// Send email
	if err := c.sendEmail(ctx, alert.Recipient, subject, body); err != nil {
		c.logger.Error("failed to send alert email",
			"alert_id", alert.ID,
			"error", err)
		return fmt.Errorf("failed to send alert email: %w", err)
	}

	c.logger.Info("alert email sent successfully",
		"alert_id", alert.ID,
		"recipient", alert.Recipient)
	return nil
}

// SendEvent sends an event notification via SMTP.
// It formats the event as an email message and sends it to the recipient.
func (c *Connector) SendEvent(ctx context.Context, event notifier.Event) error {
	c.logger.Info("sending email event",
		"event_id", event.ID,
		"event_type", event.Type,
		"recipient", event.Recipient)

	// Format email subject and body
	subject := fmt.Sprintf("[Event] %s", event.Subject)
	body := c.formatEventBody(event)

	// Send email
	if err := c.sendEmail(ctx, event.Recipient, subject, body); err != nil {
		c.logger.Error("failed to send event email",
			"event_id", event.ID,
			"error", err)
		return fmt.Errorf("failed to send event email: %w", err)
	}

	c.logger.Info("event email sent successfully",
		"event_id", event.ID,
		"recipient", event.Recipient)
	return nil
}

// sendEmail sends an email message using the configured SMTP server.
// It handles both TLS and plain authentication modes.
//
// Header values (From, To, Subject) are validated up-front to reject CR, LF,
// and NUL characters. This blocks SMTP header injection (CWE-113) and also
// prevents injection into the SMTP envelope commands MAIL FROM and RCPT TO,
// since net/smtp does not sanitize those inputs itself.
func (c *Connector) sendEmail(ctx context.Context, to, subject, body string) error {
	if err := validation.ValidateHeaderValue("From", c.config.FromAddress); err != nil {
		return fmt.Errorf("invalid sender: %w", err)
	}
	if err := validation.ValidateHeaderValue("To", to); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	if err := validation.ValidateHeaderValue("Subject", subject); err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}

	addr := net.JoinHostPort(c.config.SMTPHost, strconv.Itoa(c.config.SMTPPort))

	// Connect to SMTP server
	var auth smtp.Auth
	if c.config.Username != "" && c.config.Password != "" {
		auth = smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.SMTPHost)
	}

	var conn net.Conn
	var err error

	if c.config.UseTLS {
		// Connect with TLS
		tlsConfig := &tls.Config{
			ServerName: c.config.SMTPHost,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect via TLS: %w", err)
		}
	} else {
		// Connect without TLS
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, c.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// Authenticate if credentials provided
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Send email
	if err := client.Mail(c.config.FromAddress); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer wc.Close()

	// Format and write email headers and body. The format function
	// re-validates header values as defense-in-depth; the early-return
	// above should have already caught any injection attempt.
	message, err := c.formatEmailMessage(c.config.FromAddress, to, subject, body)
	if err != nil {
		return fmt.Errorf("failed to format message: %w", err)
	}
	if _, err := wc.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("failed to quit SMTP: %w", err)
	}

	return nil
}

// sendHTMLEmail sends an HTML email message using the configured SMTP server.
// Used by the digest service for rich HTML digest emails.
//
// Header values (From, To, Subject) are validated up-front to reject CR, LF,
// and NUL characters. This blocks SMTP header injection (CWE-113) and also
// prevents injection into the SMTP envelope commands MAIL FROM and RCPT TO,
// since net/smtp does not sanitize those inputs itself.
func (c *Connector) sendHTMLEmail(ctx context.Context, to, subject, htmlBody string) error {
	if err := validation.ValidateHeaderValue("From", c.config.FromAddress); err != nil {
		return fmt.Errorf("invalid sender: %w", err)
	}
	if err := validation.ValidateHeaderValue("To", to); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	if err := validation.ValidateHeaderValue("Subject", subject); err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}

	addr := net.JoinHostPort(c.config.SMTPHost, strconv.Itoa(c.config.SMTPPort))

	var auth smtp.Auth
	if c.config.Username != "" && c.config.Password != "" {
		auth = smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.SMTPHost)
	}

	var conn net.Conn
	var err error

	if c.config.UseTLS {
		tlsConfig := &tls.Config{
			ServerName: c.config.SMTPHost,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect via TLS: %w", err)
		}
	} else {
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := client.Mail(c.config.FromAddress); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer wc.Close()

	// The format function re-validates header values as defense-in-depth;
	// the early-return above should have already caught any injection attempt.
	message, err := c.formatHTMLEmailMessage(c.config.FromAddress, to, subject, htmlBody)
	if err != nil {
		return fmt.Errorf("failed to format message: %w", err)
	}
	if _, err := wc.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("failed to quit SMTP: %w", err)
	}

	return nil
}

// formatEmailMessage formats an email message with standard headers.
// It rejects any header value containing CR, LF, or NUL bytes to prevent
// SMTP header injection (CWE-113). See internal/validation.ValidateHeaderValue.
// The body is not validated — CR/LF in the body is legitimate content, and
// SMTP dot-stuffing / length framing are handled by net/smtp.
func (c *Connector) formatEmailMessage(from, to, subject, body string) ([]byte, error) {
	if err := validation.ValidateHeaderValue("From", from); err != nil {
		return nil, err
	}
	if err := validation.ValidateHeaderValue("To", to); err != nil {
		return nil, err
	}
	if err := validation.ValidateHeaderValue("Subject", subject); err != nil {
		return nil, err
	}
	message := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		from,
		to,
		subject,
		time.Now().Format(time.RFC1123Z),
		body,
	)
	return []byte(message), nil
}

// formatHTMLEmailMessage formats an HTML email message with MIME headers.
// It rejects any header value containing CR, LF, or NUL bytes to prevent
// SMTP header injection (CWE-113). See internal/validation.ValidateHeaderValue.
// The HTML body is not validated at this layer — CR/LF in HTML content is
// legitimate, and SMTP dot-stuffing / length framing are handled by net/smtp.
func (c *Connector) formatHTMLEmailMessage(from, to, subject, htmlBody string) ([]byte, error) {
	if err := validation.ValidateHeaderValue("From", from); err != nil {
		return nil, err
	}
	if err := validation.ValidateHeaderValue("To", to); err != nil {
		return nil, err
	}
	if err := validation.ValidateHeaderValue("Subject", subject); err != nil {
		return nil, err
	}
	message := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s",
		from,
		to,
		subject,
		time.Now().Format(time.RFC1123Z),
		htmlBody,
	)
	return []byte(message), nil
}

// formatAlertBody formats an alert notification as email body text.
//
// CodeQL go/email-injection (CWE-640 / OWASP Content Spoofing) defense:
// every field interpolated into the body that may carry attacker-
// controlled content (alert.Subject, alert.Message, alert.Metadata
// values, alert.ID / Type / Severity which originate from the API
// surface) is routed through validation.SanitizeEmailBodyValue before
// formatting. The sanitizer strips NUL bytes (RFC 5321 §4.5.2 violation),
// bare CR/LF within a single field (forged header-boundary attempts),
// bidi-override Unicode (visually-spoofable URLs), zero-width / invisible
// codepoints, and C0/C1 control chars. CreatedAt is a time.Time —
// formatted via RFC3339; not user-controllable so unsanitized.
//
// Header values (From, To, Subject) are protected separately by
// validation.ValidateHeaderValue at sendEmail entry (CWE-113 SMTP header
// injection — see commit 9e957c3).
func (c *Connector) formatAlertBody(alert notifier.Alert) string {
	body := fmt.Sprintf(`
Certificate Alert Notification
================================

Alert ID: %s
Type: %s
Severity: %s
Created: %s

Subject: %s

Message:
%s

%s
`,
		validation.SanitizeEmailBodyValue(alert.ID),
		validation.SanitizeEmailBodyValue(alert.Type),
		validation.SanitizeEmailBodyValue(alert.Severity),
		alert.CreatedAt.Format(time.RFC3339),
		validation.SanitizeEmailBodyValue(alert.Subject),
		validation.SanitizeEmailBodyValue(alert.Message),
		c.formatMetadata(alert.Metadata),
	)

	return body
}

// formatEventBody formats an event notification as email body text.
//
// Same CodeQL go/email-injection mitigation as formatAlertBody — every
// user-controllable interpolated field routes through
// validation.SanitizeEmailBodyValue. CreatedAt is unsanitized (time.Time
// → RFC3339 is structural, not user-controllable).
func (c *Connector) formatEventBody(event notifier.Event) string {
	certInfo := ""
	if event.CertificateID != nil {
		certInfo = fmt.Sprintf("Certificate ID: %s\n", validation.SanitizeEmailBodyValue(*event.CertificateID))
	}

	body := fmt.Sprintf(`
Certificate Event Notification
================================

Event ID: %s
Type: %s
Created: %s

%sSubject: %s

Body:
%s

%s
`,
		validation.SanitizeEmailBodyValue(event.ID),
		validation.SanitizeEmailBodyValue(event.Type),
		event.CreatedAt.Format(time.RFC3339),
		certInfo,
		validation.SanitizeEmailBodyValue(event.Subject),
		validation.SanitizeEmailBodyValue(event.Body),
		c.formatMetadata(event.Metadata),
	)

	return body
}

// formatMetadata formats metadata as a readable string.
//
// Both keys and values can carry attacker-controlled content (cert
// subject DN fragments, discovered cert metadata, owner/team labels —
// all originate from API surfaces an attacker may influence). Both are
// routed through validation.SanitizeEmailBodyValue. Closes the
// CodeQL go/email-injection finding alongside formatAlertBody +
// formatEventBody.
func (c *Connector) formatMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}

	metadataStr := "\nMetadata:\n"
	for key, value := range metadata {
		metadataStr += fmt.Sprintf("  %s: %s\n",
			validation.SanitizeEmailBodyValue(key),
			validation.SanitizeEmailBodyValue(value),
		)
	}

	return metadataStr
}
