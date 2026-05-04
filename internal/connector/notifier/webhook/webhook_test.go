package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/notifier"
)

func TestWebhook_ValidateConfig_ValidURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
	}

	rawConfig, _ := json.Marshal(cfg)

	// Create a new logger (or use test logger)
	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestWebhook_ValidateConfig_MissingURL(t *testing.T) {
	cfg := &Config{
		URL: "",
	}

	rawConfig, _ := json.Marshal(cfg)
	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "webhook url is required") {
		t.Errorf("expected 'webhook url is required', got %v", err)
	}
}

func TestWebhook_ValidateConfig_InvalidJSON(t *testing.T) {
	rawConfig := []byte("{invalid json")
	logger := newTestLogger()
	conn := New(&Config{}, logger)

	err := conn.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid webhook config") {
		t.Errorf("expected 'invalid webhook config', got %v", err)
	}
}

func TestWebhook_SendAlert_Success(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-123",
		Type:      "expiration",
		Severity:  "warning",
		Subject:   "Certificate Expiring",
		Message:   "Certificate mc-api-prod expires in 7 days",
		Recipient: "ops@example.com",
		Metadata:  map[string]string{"cert_id": "mc-api-prod"},
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedPayload["type"] != "alert" {
		t.Errorf("expected type 'alert', got %v", receivedPayload["type"])
	}
	if receivedPayload["alert_id"] != "alert-123" {
		t.Errorf("expected alert_id 'alert-123', got %v", receivedPayload["alert_id"])
	}
	if receivedPayload["severity"] != "warning" {
		t.Errorf("expected severity 'warning', got %v", receivedPayload["severity"])
	}
	if receivedPayload["subject"] != "Certificate Expiring" {
		t.Errorf("expected subject 'Certificate Expiring', got %v", receivedPayload["subject"])
	}
	if receivedPayload["message"] != "Certificate mc-api-prod expires in 7 days" {
		t.Errorf("expected correct message, got %v", receivedPayload["message"])
	}
}

func TestWebhook_SendAlert_HMACSignature(t *testing.T) {
	var receivedSignature string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-Signature")
		sigAlgo := r.Header.Get("X-Signature-Algorithm")

		if sigAlgo != "sha256" {
			t.Errorf("expected algorithm sha256, got %s", sigAlgo)
		}

		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secret := "my-secret-key"
	cfg := &Config{
		URL:    server.URL,
		Secret: secret,
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-456",
		Type:      "expiration",
		Severity:  "critical",
		Subject:   "Critical: Certificate Expired",
		Message:   "Certificate is already expired",
		Recipient: "admin@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify signature
	expectedSignature := computeHMACSHA256(receivedBody, secret)
	if receivedSignature != expectedSignature {
		t.Errorf("expected signature %s, got %s", expectedSignature, receivedSignature)
	}
}

func TestWebhook_SendAlert_NoSignatureWithoutSecret(t *testing.T) {
	var hasSignatureHeader bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasSignatureHeader = r.Header["X-Signature"]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL:    server.URL,
		Secret: "",
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-789",
		Type:      "expiration",
		Severity:  "info",
		Subject:   "Renewal Complete",
		Message:   "Certificate renewed successfully",
		Recipient: "ops@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasSignatureHeader {
		t.Error("expected no X-Signature header when secret is empty")
	}
}

func TestWebhook_SendAlert_CustomHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"X-Custom":      "custom-value",
		},
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-custom",
		Type:      "test",
		Severity:  "info",
		Subject:   "Test",
		Message:   "Test message",
		Recipient: "test@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth := receivedHeaders.Get("Authorization"); auth != "Bearer token123" {
		t.Errorf("expected Authorization header 'Bearer token123', got %s", auth)
	}
	if custom := receivedHeaders.Get("X-Custom"); custom != "custom-value" {
		t.Errorf("expected X-Custom header 'custom-value', got %s", custom)
	}
}

func TestWebhook_SendAlert_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	alert := notifier.Alert{
		ID:        "alert-error",
		Type:      "test",
		Severity:  "error",
		Subject:   "Test Error",
		Message:   "Testing error handling",
		Recipient: "admin@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain '500', got %v", err)
	}
}

func TestWebhook_SendEvent_Success(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	certID := "mc-api-prod"
	event := notifier.Event{
		ID:            "event-123",
		Type:          "issued",
		CertificateID: &certID,
		Subject:       "Certificate Issued",
		Body:          "New certificate issued for mc-api-prod",
		Recipient:     "ops@example.com",
		Metadata:      map[string]string{"issuer": "letsencrypt"},
		CreatedAt:     time.Now(),
	}

	err := conn.SendEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedPayload["type"] != "event" {
		t.Errorf("expected type 'event', got %v", receivedPayload["type"])
	}
	if receivedPayload["event_id"] != "event-123" {
		t.Errorf("expected event_id 'event-123', got %v", receivedPayload["event_id"])
	}
	if receivedPayload["event_type"] != "issued" {
		t.Errorf("expected event_type 'issued', got %v", receivedPayload["event_type"])
	}
	if receivedPayload["certificate_id"] != "mc-api-prod" {
		t.Errorf("expected certificate_id 'mc-api-prod', got %v", receivedPayload["certificate_id"])
	}
}

func TestWebhook_SendEvent_WithoutCertificateID(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		URL: server.URL,
	}

	logger := newTestLogger()
	conn := newForTest(cfg, logger)

	event := notifier.Event{
		ID:        "event-456",
		Type:      "test",
		Subject:   "Test Event",
		Body:      "Test body",
		Recipient: "test@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Ensure certificate_id is not in payload when nil
	if _, hasKey := receivedPayload["certificate_id"]; hasKey && receivedPayload["certificate_id"] != nil {
		t.Errorf("expected no certificate_id in payload, got %v", receivedPayload["certificate_id"])
	}
}

// The SSRF tests below exercise the CWE-918 guard added alongside H-4. Each
// case pairs a reserved-address URL with the call surface that should reject
// it. ValidateConfig is the early-fail path; SendAlert/SendEvent reach the
// same guard via postWebhook and are the defence-in-depth that still rejects
// even when ValidateConfig was bypassed (e.g. dynamic config reload mutating
// c.config.URL in place).

func TestWebhook_ValidateConfig_RejectsReservedURLs(t *testing.T) {
	// These must all fail at config-ingestion time without ever opening a
	// socket — the reserved-address filter is the whole point of H-4.
	cases := []struct {
		name string
		url  string
	}{
		{"loopback v4", "http://127.0.0.1/hook"},
		{"loopback v4 with port", "http://127.0.0.1:8080/"},
		{"loopback v6 bracketed", "http://[::1]/hook"},
		{"AWS metadata", "http://169.254.169.254/latest/meta-data/"},
		{"generic link-local", "http://169.254.1.2/"},
		{"unspecified v4", "http://0.0.0.0/"},
		{"unspecified v6", "http://[::]/"},
		{"IPv6 link-local", "http://[fe80::1]/"},
		{"multicast", "https://224.0.0.5/"},
		{"broadcast", "http://255.255.255.255/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{URL: tc.url}
			rawConfig, _ := json.Marshal(cfg)
			conn := New(cfg, newTestLogger())

			err := conn.ValidateConfig(context.Background(), rawConfig)
			if err == nil {
				t.Fatalf("ValidateConfig(%q) returned nil, want SSRF rejection", tc.url)
			}
			if !strings.Contains(err.Error(), "reserved") && !strings.Contains(err.Error(), "rejected") {
				t.Errorf("expected reserved/rejected error, got %q", err.Error())
			}
		})
	}
}

func TestWebhook_ValidateConfig_RejectsDangerousSchemes(t *testing.T) {
	// Only http(s) is a legitimate webhook transport. Every other scheme is
	// an SSRF amplifier (file, gopher, ftp, javascript, data, ldap, dict,
	// jar) and must be refused at config time.
	cases := []struct {
		name string
		url  string
	}{
		{"file", "file:///etc/passwd"},
		{"gopher", "gopher://example.com/_x"},
		{"ftp", "ftp://example.com/"},
		{"javascript", "javascript:alert(1)"},
		{"data", "data:text/plain;base64,SGVsbG8="},
		{"ldap", "ldap://example.com/"},
		{"dict", "dict://example.com:2628/d:foo"},
		{"jar", "jar:http://example.com/foo.jar!/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{URL: tc.url}
			rawConfig, _ := json.Marshal(cfg)
			conn := New(cfg, newTestLogger())

			err := conn.ValidateConfig(context.Background(), rawConfig)
			if err == nil {
				t.Fatalf("ValidateConfig(%q) returned nil, want scheme rejection", tc.url)
			}
			if !strings.Contains(err.Error(), "rejected") && !strings.Contains(err.Error(), "scheme") {
				t.Errorf("expected scheme/rejected error, got %q", err.Error())
			}
		})
	}
}

func TestWebhook_SendAlert_RejectsReservedURLInPostWebhook(t *testing.T) {
	// Simulate config drift: URL was legitimate at ValidateConfig time but
	// has since been rewritten to an SSRF target. postWebhook must catch
	// this on every call without ever hitting the wire.
	cfg := &Config{URL: "http://169.254.169.254/latest/meta-data/"}
	conn := New(cfg, newTestLogger())

	alert := notifier.Alert{
		ID:        "alert-ssrf",
		Type:      "test",
		Severity:  "info",
		Subject:   "Test",
		Message:   "Test",
		Recipient: "ops@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendAlert(context.Background(), alert)
	if err == nil {
		t.Fatal("SendAlert returned nil, want SSRF rejection from postWebhook")
	}
	if !strings.Contains(err.Error(), "reserved") && !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected reserved/rejected error, got %q", err.Error())
	}
}

func TestWebhook_SendEvent_RejectsReservedURLInPostWebhook(t *testing.T) {
	cfg := &Config{URL: "http://[::1]:9/webhook"}
	conn := New(cfg, newTestLogger())

	event := notifier.Event{
		ID:        "event-ssrf",
		Type:      "test",
		Subject:   "Test",
		Body:      "Test",
		Recipient: "ops@example.com",
		CreatedAt: time.Now(),
	}

	err := conn.SendEvent(context.Background(), event)
	if err == nil {
		t.Fatal("SendEvent returned nil, want SSRF rejection from postWebhook")
	}
	if !strings.Contains(err.Error(), "reserved") && !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected reserved/rejected error, got %q", err.Error())
	}
}

// Helper function to compute HMAC-SHA256 signature
func computeHMACSHA256(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	signature := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("sha256=%s", signature)
}

// Helper function to create a test logger
func newTestLogger() *slog.Logger {
	// Return a discard logger for tests
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
