package notifier

import (
	"context"
	"encoding/json"
	"time"
)

// Connector defines the interface for sending notifications about certificate events.
type Connector interface {
	// ValidateConfig validates the notifier configuration.
	ValidateConfig(ctx context.Context, config json.RawMessage) error

	// SendAlert sends an alert notification.
	SendAlert(ctx context.Context, alert Alert) error

	// SendEvent sends an event notification.
	SendEvent(ctx context.Context, event Event) error
}

// Alert represents a notification alert with urgency.
type Alert struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Subject   string            `json:"subject"`
	Message   string            `json:"message"`
	Recipient string            `json:"recipient"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Event represents a notification event with contextual information.
type Event struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	CertificateID *string           `json:"certificate_id,omitempty"`
	Recipient     string            `json:"recipient"`
	Subject       string            `json:"subject"`
	Body          string            `json:"body"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}
