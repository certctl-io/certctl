package pagerduty

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const eventsAPIURL = "https://events.pagerduty.com/v2/enqueue"

// Config holds configuration for the PagerDuty notifier.
type Config struct {
	// RoutingKey is the PagerDuty Events API v2 integration/routing key.
	RoutingKey string `json:"routing_key"`
	// Severity is the default event severity (critical, error, warning, info).
	// Defaults to "warning" if not set.
	Severity string `json:"severity,omitempty"`
}

// Notifier sends notifications to PagerDuty via the Events API v2.
type Notifier struct {
	config     Config
	httpClient *http.Client
}

// New creates a new PagerDuty notifier.
func New(config Config) *Notifier {
	if config.Severity == "" {
		config.Severity = "warning"
	}
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Channel returns the channel identifier.
func (n *Notifier) Channel() string {
	return "PagerDuty"
}

// Send delivers a notification to PagerDuty as a trigger event.
func (n *Notifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	event := pdEvent{
		RoutingKey:  n.config.RoutingKey,
		EventAction: "trigger",
		Payload: pdPayload{
			Summary:  subject,
			Severity: n.config.Severity,
			Source:   "certctl",
			CustomDetails: map[string]string{
				"body":      body,
				"recipient": recipient,
			},
		},
	}

	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("pagerduty: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eventsAPIURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("pagerduty: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pagerduty: API returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	Payload     pdPayload `json:"payload"`
}

type pdPayload struct {
	Summary       string            `json:"summary"`
	Severity      string            `json:"severity"`
	Source        string            `json:"source"`
	CustomDetails map[string]string `json:"custom_details,omitempty"`
}
