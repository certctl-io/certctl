package domain

import (
	"encoding/json"
	"time"
)

// Issuer represents a certificate authority or ACME provider.
type Issuer struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      IssuerType      `json:"type"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// DeploymentTarget represents a target system where certificates are deployed.
type DeploymentTarget struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      TargetType      `json:"type"`
	AgentID   string          `json:"agent_id"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Agent represents an agent running on a target system.
type Agent struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Hostname        string      `json:"hostname"`
	Status          AgentStatus `json:"status"`
	LastHeartbeatAt *time.Time  `json:"last_heartbeat_at,omitempty"`
	RegisteredAt    time.Time   `json:"registered_at"`
	APIKeyHash      string      `json:"api_key_hash"`
	OS              string      `json:"os"`
	Architecture    string      `json:"architecture"`
	IPAddress       string      `json:"ip_address"`
	Version         string      `json:"version"`
}

// AgentMetadata contains runtime metadata reported by agents via heartbeat.
type AgentMetadata struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	Version      string `json:"version"`
}

// AgentStatus represents the operational status of an agent.
type AgentStatus string

const (
	AgentStatusOnline   AgentStatus = "Online"
	AgentStatusOffline  AgentStatus = "Offline"
	AgentStatusDegraded AgentStatus = "Degraded"
)

// IssuerType represents the type of certificate authority.
type IssuerType string

const (
	IssuerTypeACME      IssuerType = "ACME"
	IssuerTypeGenericCA IssuerType = "GenericCA"
	IssuerTypeStepCA    IssuerType = "StepCA"
	IssuerTypeOpenSSL   IssuerType = "OpenSSL"
)

// TargetType represents the type of deployment target.
type TargetType string

const (
	TargetTypeNGINX   TargetType = "NGINX"
	TargetTypeApache  TargetType = "Apache"
	TargetTypeHAProxy TargetType = "HAProxy"
	TargetTypeF5      TargetType = "F5"
	TargetTypeIIS     TargetType = "IIS"
)
