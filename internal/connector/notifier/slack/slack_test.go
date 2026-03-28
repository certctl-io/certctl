package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlack_Channel(t *testing.T) {
	n := New(Config{WebhookURL: "https://hooks.slack.com/test"})
	if n.Channel() != "Slack" {
		t.Errorf("expected channel Slack, got %s", n.Channel())
	}
}

func TestSlack_SendSuccess(t *testing.T) {
	var receivedPayload slackMessage

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

	n := New(Config{WebhookURL: server.URL})
	err := n.Send(context.Background(), "ops@example.com", "Cert Expiring", "mc-api-prod expires in 7 days")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(receivedPayload.Text, "*Cert Expiring*") {
		t.Errorf("expected bold subject in text, got %q", receivedPayload.Text)
	}
	if !strings.Contains(receivedPayload.Text, "mc-api-prod expires in 7 days") {
		t.Errorf("expected body in text, got %q", receivedPayload.Text)
	}
}

func TestSlack_SendWithOverrides(t *testing.T) {
	var receivedPayload slackMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New(Config{
		WebhookURL:      server.URL,
		ChannelOverride: "#alerts",
		Username:        "certctl-bot",
		IconEmoji:       ":lock:",
	})
	err := n.Send(context.Background(), "", "Test", "body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedPayload.Channel != "#alerts" {
		t.Errorf("expected channel #alerts, got %s", receivedPayload.Channel)
	}
	if receivedPayload.Username != "certctl-bot" {
		t.Errorf("expected username certctl-bot, got %s", receivedPayload.Username)
	}
	if receivedPayload.IconEmoji != ":lock:" {
		t.Errorf("expected icon_emoji :lock:, got %s", receivedPayload.IconEmoji)
	}
}

func TestSlack_SendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("invalid_token"))
	}))
	defer server.Close()

	n := New(Config{WebhookURL: server.URL})
	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("expected HTTP 403 in error, got %v", err)
	}
}

func TestSlack_SendConnectionError(t *testing.T) {
	n := New(Config{WebhookURL: "http://127.0.0.1:1"})
	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected 'request failed' in error, got %v", err)
	}
}

func TestSlack_ClientHasTimeout(t *testing.T) {
	n := New(Config{WebhookURL: "https://hooks.slack.com/test"})
	if n.httpClient.Timeout == 0 {
		t.Fatal("expected HTTP client timeout to be set, got 0")
	}
	expectedTimeout := 10 * time.Second
	if n.httpClient.Timeout != expectedTimeout {
		t.Errorf("expected timeout %v, got %v", expectedTimeout, n.httpClient.Timeout)
	}
}
