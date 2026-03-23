package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds configuration for the Slack notifier.
type Config struct {
	// WebhookURL is the Slack incoming webhook URL.
	WebhookURL string `json:"webhook_url"`
	// ChannelOverride optionally overrides the webhook's default channel.
	ChannelOverride string `json:"channel,omitempty"`
	// Username optionally sets the bot display name.
	Username string `json:"username,omitempty"`
	// IconEmoji optionally sets the bot icon (e.g., ":lock:").
	IconEmoji string `json:"icon_emoji,omitempty"`
}

// Notifier sends notifications to Slack via incoming webhooks.
type Notifier struct {
	config     Config
	httpClient *http.Client
}

// New creates a new Slack notifier.
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
	return "Slack"
}

// Send delivers a notification to Slack via webhook.
func (n *Notifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	payload := slackMessage{
		Text: fmt.Sprintf("*%s*\n%s", subject, body),
	}

	if n.config.ChannelOverride != "" {
		payload.Channel = n.config.ChannelOverride
	}
	if n.config.Username != "" {
		payload.Username = n.config.Username
	}
	if n.config.IconEmoji != "" {
		payload.IconEmoji = n.config.IconEmoji
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.config.WebhookURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("slack: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack: webhook returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type slackMessage struct {
	Text      string `json:"text"`
	Channel   string `json:"channel,omitempty"`
	Username  string `json:"username,omitempty"`
	IconEmoji string `json:"icon_emoji,omitempty"`
}
