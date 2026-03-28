package pagerduty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPagerDuty_Channel(t *testing.T) {
	n := New(Config{RoutingKey: "test-key"})
	if n.Channel() != "PagerDuty" {
		t.Errorf("expected channel PagerDuty, got %s", n.Channel())
	}
}

func TestPagerDuty_DefaultSeverity(t *testing.T) {
	n := New(Config{RoutingKey: "test-key"})
	if n.config.Severity != "warning" {
		t.Errorf("expected default severity 'warning', got %s", n.config.Severity)
	}
}

func TestPagerDuty_CustomSeverity(t *testing.T) {
	n := New(Config{RoutingKey: "test-key", Severity: "critical"})
	if n.config.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %s", n.config.Severity)
	}
}

func TestPagerDuty_SendSuccess(t *testing.T) {
	var receivedEvent pdEvent

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedEvent); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Override the events URL for testing — use a custom HTTP client that redirects
	n := New(Config{RoutingKey: "test-routing-key", Severity: "error"})
	// We can't easily override the const URL, so test with a direct HTTP call approach.
	// Instead, test the payload structure by calling Send with a mock server.
	// We need to make the notifier use our test server URL.
	// The simplest way: create the notifier, then manually set the URL by using the test server.
	// Since eventsAPIURL is a const, we'll test by replacing the http client's transport.

	// Alternative approach: just test that the method constructs the right payload
	// by using a custom transport that intercepts the request.
	n.httpClient = server.Client()

	// For this test, we need to override the target URL. Since it's a package-level const,
	// we'll create a custom RoundTripper that redirects to our test server.
	originalURL := eventsAPIURL
	_ = originalURL // just to avoid unused var in case we reference it

	transport := &urlRewriteTransport{
		target:    server.URL,
		transport: http.DefaultTransport,
	}
	n.httpClient = &http.Client{Transport: transport}

	err := n.Send(context.Background(), "oncall@example.com", "Cert Expired", "mc-api-prod has expired")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedEvent.RoutingKey != "test-routing-key" {
		t.Errorf("expected routing key test-routing-key, got %s", receivedEvent.RoutingKey)
	}
	if receivedEvent.EventAction != "trigger" {
		t.Errorf("expected event action trigger, got %s", receivedEvent.EventAction)
	}
	if receivedEvent.Payload.Summary != "Cert Expired" {
		t.Errorf("expected summary 'Cert Expired', got %s", receivedEvent.Payload.Summary)
	}
	if receivedEvent.Payload.Severity != "error" {
		t.Errorf("expected severity error, got %s", receivedEvent.Payload.Severity)
	}
	if receivedEvent.Payload.Source != "certctl" {
		t.Errorf("expected source certctl, got %s", receivedEvent.Payload.Source)
	}
	if receivedEvent.Payload.CustomDetails["body"] != "mc-api-prod has expired" {
		t.Errorf("expected body in custom_details, got %v", receivedEvent.Payload.CustomDetails)
	}
	if receivedEvent.Payload.CustomDetails["recipient"] != "oncall@example.com" {
		t.Errorf("expected recipient in custom_details, got %v", receivedEvent.Payload.CustomDetails)
	}
}

func TestPagerDuty_SendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"invalid","message":"bad routing key"}`))
	}))
	defer server.Close()

	n := New(Config{RoutingKey: "bad-key"})
	n.httpClient = &http.Client{Transport: &urlRewriteTransport{target: server.URL, transport: http.DefaultTransport}}

	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("expected HTTP 400 in error, got %v", err)
	}
}

func TestPagerDuty_SendConnectionError(t *testing.T) {
	n := New(Config{RoutingKey: "test-key"})
	n.httpClient = &http.Client{Transport: &urlRewriteTransport{target: "http://127.0.0.1:1", transport: http.DefaultTransport}}

	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected 'request failed' in error, got %v", err)
	}
}

func TestPagerDuty_ClientHasTimeout(t *testing.T) {
	n := New(Config{RoutingKey: "test-key"})
	if n.httpClient.Timeout == 0 {
		t.Fatal("expected HTTP client timeout to be set, got 0")
	}
	expectedTimeout := 10 * time.Second
	if n.httpClient.Timeout != expectedTimeout {
		t.Errorf("expected timeout %v, got %v", expectedTimeout, n.httpClient.Timeout)
	}
}

// urlRewriteTransport redirects all requests to a test server URL.
type urlRewriteTransport struct {
	target    string
	transport http.RoundTripper
}

func (t *urlRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.target, "http://")
	return t.transport.RoundTrip(req)
}
