package teams

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds configuration for the Microsoft Teams notifier.
type Config struct {
	// WebhookURL is the Teams incoming webhook URL.
	WebhookURL string `json:"webhook_url"`
}

// Notifier sends notifications to Microsoft Teams via incoming webhooks.
type Notifier struct {
	config     Config
	httpClient *http.Client
}

// New creates a new Teams notifier.
func New(config Config) *Notifier {
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Channel returns the channel identifier.
func (n *Notifier) Channel() string {
	return "Teams"
}

// Send delivers a notification to Teams via webhook using MessageCard format.
func (n *Notifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	card := teamsMessageCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: "0076D7",
		Summary:    subject,
		Sections: []teamsSection{
			{
				ActivityTitle: subject,
				Text:          body,
				Markdown:      true,
			},
		},
	}

	jsonBytes, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("teams: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.config.WebhookURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("teams: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("teams: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("teams: webhook returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type teamsMessageCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor"`
	Summary    string         `json:"summary"`
	Sections   []teamsSection `json:"sections"`
}

type teamsSection struct {
	ActivityTitle string `json:"activityTitle"`
	Text          string `json:"text"`
	Markdown      bool   `json:"markdown"`
}
