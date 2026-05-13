package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/certctl-io/certctl/internal/validation"
)

// slackClientTimeout bounds every outbound Slack webhook request and
// its resolution/dial phase. Shared by the transport dialer (SSRF
// guard) and the http.Client so DNS rebinding and the read/write
// budget land on the same time horizon.
const slackClientTimeout = 10 * time.Second

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
//
// Bundle 5 closure (audit R7): the HTTP transport now wraps
// validation.SafeHTTPDialContext so outbound webhook calls cannot be
// pointed at reserved-address ranges (cloud metadata 169.254.169.254,
// in-cluster ::1 / 127.0.0.1 / 10.0.0.0/8 / 172.16.0.0/12 /
// 192.168.0.0/16, IPv6 link-local fe80::/10) via DNS rebinding or
// operator-supplied raw IPs. Webhook URLs are operator-configured but
// flow through the dynamic-config GUI (issuers + targets) which
// untrusted-actor edits can reach with the right RBAC scope; without
// the dial-time guard, a notifier config update would be an SSRF
// pivot into instance metadata services. Mirrors the
// internal/connector/notifier/webhook hardening pattern.
func New(config Config) *Notifier {
	transport := &http.Transport{
		DialContext:           validation.SafeHTTPDialContext(slackClientTimeout),
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout:   slackClientTimeout,
			Transport: transport,
		},
	}
}

// newForTest is the test-only constructor that bypasses the
// SafeHTTPDialContext guard so unit tests using httptest.NewServer
// (which binds to 127.0.0.1) can exercise the rest of the notifier
// path. The exported `New` is the only production constructor and
// installs the dial-time SSRF guard unconditionally. Mirrors the
// internal/connector/notifier/webhook seam (newForTest there).
func newForTest(config Config) *Notifier {
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: slackClientTimeout,
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
