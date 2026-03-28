package teams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTeams_Channel(t *testing.T) {
	n := New(Config{WebhookURL: "https://outlook.office.com/webhook/test"})
	if n.Channel() != "Teams" {
		t.Errorf("expected channel Teams, got %s", n.Channel())
	}
}

func TestTeams_SendSuccess(t *testing.T) {
	var receivedCard teamsMessageCard

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedCard); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New(Config{WebhookURL: server.URL})
	err := n.Send(context.Background(), "team@example.com", "Renewal Failed", "Certificate mc-api-prod renewal failed after 3 attempts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedCard.Type != "MessageCard" {
		t.Errorf("expected @type MessageCard, got %s", receivedCard.Type)
	}
	if receivedCard.Summary != "Renewal Failed" {
		t.Errorf("expected summary 'Renewal Failed', got %s", receivedCard.Summary)
	}
	if receivedCard.ThemeColor != "0076D7" {
		t.Errorf("expected theme color 0076D7, got %s", receivedCard.ThemeColor)
	}
	if len(receivedCard.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(receivedCard.Sections))
	}
	if receivedCard.Sections[0].ActivityTitle != "Renewal Failed" {
		t.Errorf("expected section title 'Renewal Failed', got %s", receivedCard.Sections[0].ActivityTitle)
	}
	if !strings.Contains(receivedCard.Sections[0].Text, "mc-api-prod") {
		t.Errorf("expected body to contain cert ID, got %s", receivedCard.Sections[0].Text)
	}
	if !receivedCard.Sections[0].Markdown {
		t.Error("expected markdown=true in section")
	}
}

func TestTeams_SendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	n := New(Config{WebhookURL: server.URL})
	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("expected HTTP 400 in error, got %v", err)
	}
}

func TestTeams_SendConnectionError(t *testing.T) {
	n := New(Config{WebhookURL: "http://127.0.0.1:1"})
	err := n.Send(context.Background(), "", "Test", "body")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected 'request failed' in error, got %v", err)
	}
}

func TestTeams_ClientHasTimeout(t *testing.T) {
	n := New(Config{WebhookURL: "https://outlook.office.com/webhook/test"})
	if n.httpClient.Timeout == 0 {
		t.Fatal("expected HTTP client timeout to be set, got 0")
	}
	expectedTimeout := 10 * time.Second
	if n.httpClient.Timeout != expectedTimeout {
		t.Errorf("expected timeout %v, got %v", expectedTimeout, n.httpClient.Timeout)
	}
}
