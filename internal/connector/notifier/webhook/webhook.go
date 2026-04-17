package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/connector/notifier"
	"github.com/shankar0123/certctl/internal/validation"
)

// webhookClientTimeout bounds every outbound webhook request and its
// resolution/dial phase. Kept as a package-level constant so the timeout is
// shared by the transport dialer and the http.Client, and so tests can reason
// about it without plumbing configuration.
const webhookClientTimeout = 30 * time.Second

// Config represents the webhook notifier configuration.
type Config struct {
	URL     string            `json:"url"`
	Secret  string            `json:"secret,omitempty"`  // Secret for HMAC-SHA256 signature
	Headers map[string]string `json:"headers,omitempty"` // Custom headers to include
}

// Connector implements the notifier.Connector interface for webhook notifications.
// It sends alert and event notifications via HTTP POST with optional HMAC signing.
//
// validateURL is injected so that the production constructor (New) installs the
// strict validation.ValidateSafeURL guard while newForTest can install a
// permissive validator. This is the only way to keep the production SSRF
// defence unconditionally on in real code while still allowing tests to point
// at httptest loopback servers. Without this seam, every test using
// httptest.NewServer would be blocked by the guard's loopback rejection — that
// is the correct behaviour in production but makes legitimate unit tests
// impossible to write. The test seam is unexported so no external caller can
// use it to disable the guard.
type Connector struct {
	config      *Config
	logger      *slog.Logger
	client      *http.Client
	validateURL func(string) error
}

// New creates a new webhook notifier with the given configuration and logger.
//
// The returned connector uses an http.Transport whose DialContext is hardened
// by validation.SafeHTTPDialContext. That guard re-resolves the target host
// at dial time and refuses any connection whose resolved address lies in a
// reserved range (loopback, cloud-metadata link-local, multicast, broadcast,
// unspecified, IPv6 link-local/multicast). This is the authoritative SSRF
// defence; validation.ValidateSafeURL inside ValidateConfig/postWebhook is a
// fast early diagnostic. The two layers together defeat both misconfigured
// URLs and DNS-rebinding attacks where a name's resolved address changes
// between validation and dial.
func New(config *Config, logger *slog.Logger) *Connector {
	transport := &http.Transport{
		DialContext:           validation.SafeHTTPDialContext(webhookClientTimeout),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Connector{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout:   webhookClientTimeout,
			Transport: transport,
		},
		validateURL: validation.ValidateSafeURL,
	}
}

// newForTest is an unexported constructor used exclusively by the webhook
// package's own tests. It installs a permissive URL validator and the stdlib
// default transport so tests can point the connector at httptest loopback
// servers (127.0.0.1), which the production SafeHTTPDialContext guard would
// correctly reject. Production callers cannot reach this constructor because
// it is unexported; only same-package tests (package webhook) can use it.
// The SSRF-rejection tests that verify the guard itself still call New so
// they exercise the real, strict validator.
func newForTest(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: webhookClientTimeout,
		},
		validateURL: func(string) error { return nil },
	}
}

// ValidateConfig checks that the webhook URL is valid and reachable.
// It performs a test request to verify the endpoint is accessible.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid webhook config: %w", err)
	}

	if cfg.URL == "" {
		return fmt.Errorf("webhook url is required")
	}

	// SSRF guard (CWE-918). Reject reserved-address URLs before issuing any
	// outbound HTTP — this catches the obvious 127.0.0.1 / ::1 /
	// 169.254.169.254 / 0.0.0.0 cases at config-ingestion time and produces
	// a clear operator-facing error. The authoritative, TOCTOU-safe check
	// still runs at dial time inside SafeHTTPDialContext. Routed through
	// c.validateURL so newForTest can install a permissive validator for
	// same-package unit tests; production New always wires
	// validation.ValidateSafeURL here.
	if err := c.validateURL(cfg.URL); err != nil {
		return fmt.Errorf("webhook url rejected: %w", err)
	}

	c.logger.Info("validating webhook configuration", "url", cfg.URL)

	// Test webhook connectivity with a HEAD request
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach webhook endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Accept any 2xx or 3xx status code as valid
	if resp.StatusCode >= 400 {
		c.logger.Warn("webhook validation: endpoint returned error status",
			"status_code", resp.StatusCode)
		// Still allow configuration; the endpoint might be designed to accept POST
	}

	c.config = &cfg
	c.logger.Info("webhook configuration validated")
	return nil
}

// SendAlert sends an alert notification via webhook.
// It POSTs the alert as JSON to the configured webhook URL with optional HMAC signature.
func (c *Connector) SendAlert(ctx context.Context, alert notifier.Alert) error {
	c.logger.Info("sending webhook alert",
		"alert_id", alert.ID,
		"severity", alert.Severity)

	// Format payload
	payload := map[string]interface{}{
		"type":       "alert",
		"alert_id":   alert.ID,
		"severity":   alert.Severity,
		"subject":    alert.Subject,
		"message":    alert.Message,
		"recipient":  alert.Recipient,
		"created_at": alert.CreatedAt,
		"metadata":   alert.Metadata,
	}

	if err := c.postWebhook(ctx, payload); err != nil {
		c.logger.Error("failed to send alert via webhook",
			"alert_id", alert.ID,
			"error", err)
		return fmt.Errorf("failed to send alert via webhook: %w", err)
	}

	c.logger.Info("alert sent via webhook", "alert_id", alert.ID)
	return nil
}

// SendEvent sends an event notification via webhook.
// It POSTs the event as JSON to the configured webhook URL with optional HMAC signature.
func (c *Connector) SendEvent(ctx context.Context, event notifier.Event) error {
	c.logger.Info("sending webhook event",
		"event_id", event.ID,
		"event_type", event.Type)

	// Format payload
	payload := map[string]interface{}{
		"type":       "event",
		"event_id":   event.ID,
		"event_type": event.Type,
		"subject":    event.Subject,
		"body":       event.Body,
		"recipient":  event.Recipient,
		"created_at": event.CreatedAt,
	}

	if event.CertificateID != nil {
		payload["certificate_id"] = *event.CertificateID
	}

	if event.Metadata != nil {
		payload["metadata"] = event.Metadata
	}

	if err := c.postWebhook(ctx, payload); err != nil {
		c.logger.Error("failed to send event via webhook",
			"event_id", event.ID,
			"error", err)
		return fmt.Errorf("failed to send event via webhook: %w", err)
	}

	c.logger.Info("event sent via webhook", "event_id", event.ID)
	return nil
}

// postWebhook sends a payload to the webhook URL with proper headers and signing.
// If a secret is configured, it signs the payload using HMAC-SHA256 and includes
// the signature in the X-Signature header.
//
// The URL is re-validated here even though ValidateConfig already accepted it:
// configuration can be mutated in place, reloaded dynamically, or set directly
// by tests that bypass ValidateConfig, so this call is a defence-in-depth
// guard that fails closed before any outbound request is built. Authoritative
// DNS-rebinding defence still runs at dial time via SafeHTTPDialContext.
func (c *Connector) postWebhook(ctx context.Context, payload interface{}) error {
	if err := c.validateURL(c.config.URL); err != nil {
		return fmt.Errorf("webhook url rejected: %w", err)
	}

	// Marshal payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.URL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set standard headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certctl-notifier/1.0")

	// Add custom headers from configuration
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	// Sign payload if secret is configured
	if c.config.Secret != "" {
		signature := c.signPayload(jsonData)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Signature-Algorithm", "sha256")
	}

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error logging
	respBody, _ := io.ReadAll(resp.Body)

	// Accept 2xx status codes as success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Debug("webhook request successful",
		"status_code", resp.StatusCode,
		"url", c.config.URL)

	return nil
}

// signPayload computes an HMAC-SHA256 signature of the payload using the configured secret.
// The signature is returned as a hex-encoded string in the format "sha256=<hex>".
func (c *Connector) signPayload(data []byte) string {
	h := hmac.New(sha256.New, []byte(c.config.Secret))
	h.Write(data)
	signature := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("sha256=%s", signature)
}
