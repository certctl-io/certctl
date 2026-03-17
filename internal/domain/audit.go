package domain

import (
	"encoding/json"
	"time"
)

// AuditEvent records an action taken in the control plane.
type AuditEvent struct {
	ID           string          `json:"id"`
	Actor        string          `json:"actor"`
	ActorType    ActorType       `json:"actor_type"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Details      json.RawMessage `json:"details"`
	Timestamp    time.Time       `json:"timestamp"`
}

// ActorType represents the entity performing an action.
type ActorType string

const (
	ActorTypeUser   ActorType = "User"
	ActorTypeSystem ActorType = "System"
	ActorTypeAgent  ActorType = "Agent"
)
