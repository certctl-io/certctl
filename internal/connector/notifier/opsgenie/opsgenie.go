package opsgenie

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const alertAPIURL = "https://api.opsgenie.com/v2/alerts"

// Config holds configuration for the OpsGenie notifier.
type Config struct {
	// APIKey is the OpsGenie API integration key.
	APIKey string `json:"api_key"`
	// Priority is the default alert priority (P1-P5). Defaults to "P3".
	Priority string `json:"priority,omitempty"`
	// Tags are default tags applied to all alerts.
	Tags []string `json:"tags,omitempty"`
}

// Notifier sends notifications to OpsGenie via the Alert API.
type Notifier struct {
	config     Config
	httpClient *http.Client
}

// New creates a new OpsGenie notifier.
func New(config Config) *Notifier {
	if config.Priority == "" {
		config.Priority = "P3"
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
	return "OpsGenie"
}

// Send delivers a notification to OpsGenie as an alert.
func (n *Notifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	alert := ogAlert{
		Message:     subject,
		Description: body,
		Priority:    n.config.Priority,
		Source:      "certctl",
		Tags:        n.config.Tags,
	}

	jsonBytes, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("opsgenie: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, alertAPIURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("opsgenie: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+n.config.APIKey)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("opsgenie: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("opsgenie: API returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type ogAlert struct {
	Message     string   `json:"message"`
	Description string   `json:"description,omitempty"`
	Priority    string   `json:"priority,omitempty"`
	Source      string   `json:"source,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}
