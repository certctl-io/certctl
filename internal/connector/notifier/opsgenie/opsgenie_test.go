package opsgenie

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOpsGenie_Channel(t *testing.T) {
	n := New(Config{APIKey: "test-key"})
	if n.Channel() != "OpsGenie" {
		t.Errorf("expected channel OpsGenie, got %s", n.Channel())
	}
}

func TestOpsGenie_DefaultPriority(t *testing.T) {
	n := New(Config{APIKey: "test-key"})
	if n.config.Priority != "P3" {
		t.Errorf("expected default priority P3, got %s", n.config.Priority)
	}
}

func TestOpsGenie_CustomPriority(t *testing.T) {
	n := New(Config{APIKey: "test-key", Priority: "P1"})
	if n.config.Priority != "P1" {
		t.Errorf("expected priority P1, got %s", n.config.Priority)
	}
}

func TestOpsGenie_SendSuccess(t *testing.T) {
	var receivedAlert ogAlert
	var receivedAuthHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}
		receivedAuthHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&receivedAlert); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	n := New(Config{
		APIKey:   "test-api-key-123",
		Priority: "P2",
		Tags:     []string{"certctl", "production"},
	})
	// Override HTTP client to hit test server
	n.httpClient = &http.Client{Transport: &urlRewriteTransport{target: server.URL, transport: http.DefaultTransport}}

	err := n.Send(context.Background(), "ops-team", "Key Compromise", "Certificate mc-api-prod may have compromised private key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuthHeader != "GenieKey test-api-key-123" {
		t.Errorf("expected GenieKey auth header, got %s", receivedAuthHeader)
	}
	if receivedAlert.Message != "Key Compromise" {
		t.Errorf("expected message 'Key Compromise', got %s", receivedAlert.Message)
	}
	if receivedAlert.Description != "Certificate mc-api-prod may have compromised private key" {
		t.Errorf("expected description with cert details, got %s", receivedAlert.Description)
	}
	if receivedAlert.Priority != "P2" {
		t.Errorf("expected priority P2, got %s", receivedAlert.Priority)
	}
	if receivedAlert.Source != "certctl" {
		t.Errorf("expected source certctl, got %s", receivedAlert.Source)
	}
	if len(receivedAlert.Tags) != 2 || receivedAlert.Tags[0] != "certctl" {
		t.Errorf("expected tags [certctl, production], got %v", receivedAlert.Tags)
	}
}

func TestOpsGenie_SendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"API key is invalid"}`))
	}))
	defer server.Close()

	n := New(Config{APIKey: "bad-key"})
	n.httpClient = &http.Client{Transport: &urlRewriteTransport{target: server.URL, transport: http.DefaultTransport}}

	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("expected HTTP 401 in error, got %v", err)
	}
}

func TestOpsGenie_SendConnectionError(t *testing.T) {
	n := New(Config{APIKey: "test-key"})
	n.httpClient = &http.Client{Transport: &urlRewriteTransport{target: "http://127.0.0.1:1", transport: http.DefaultTransport}}

	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected 'request failed' in error, got %v", err)
	}
}

func TestOpsGenie_ClientHasTimeout(t *testing.T) {
	n := New(Config{APIKey: "test-key"})
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
