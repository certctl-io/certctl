package domain

import (
	"encoding/json"
	"time"
)

// Issuer represents a certificate authority or ACME provider.
type Issuer struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Type            IssuerType      `json:"type"`
	Config          json.RawMessage `json:"config"`
	EncryptedConfig []byte          `json:"-"`                         // AES-GCM encrypted full config (never exposed via API)
	Enabled         bool            `json:"enabled"`
	LastTestedAt    *time.Time      `json:"last_tested_at,omitempty"`
	TestStatus      string          `json:"test_status,omitempty"`
	Source          string          `json:"source,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// DeploymentTarget represents a target system where certificates are deployed.
type DeploymentTarget struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Type            TargetType      `json:"type"`
	AgentID         string          `json:"agent_id"`
	Config          json.RawMessage `json:"config"`
	EncryptedConfig []byte          `json:"-"`                         // AES-GCM encrypted full config (never exposed via API)
	Enabled         bool            `json:"enabled"`
	LastTestedAt    *time.Time      `json:"last_tested_at,omitempty"`
	TestStatus      string          `json:"test_status,omitempty"`
	Source          string          `json:"source,omitempty"`
	RetiredAt       *time.Time      `json:"retired_at,omitempty"`      // I-004: soft-retirement timestamp (nil = active)
	RetiredReason   *string         `json:"retired_reason,omitempty"`  // I-004: reason captured at cascade retirement
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
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
	// I-004: soft-retirement fields. An agent with RetiredAt != nil is the
	// canonical "retired" state. The Status column remains as before (Online
	// / Offline / Degraded) and is preserved at retirement time as the
	// last-seen operational status; RetiredAt is the source of truth for
	// "should we filter this row from active listings?".
	RetiredAt     *time.Time `json:"retired_at,omitempty"`
	RetiredReason *string    `json:"retired_reason,omitempty"`
}

// IsRetired returns true when this agent has been soft-retired.
// I-004: callers that iterate active agents (stats dashboard, stale-offline
// sweeper, handler-facing list) must skip retired rows by default.
func (a *Agent) IsRetired() bool { return a != nil && a.RetiredAt != nil }

// AgentDependencyCounts captures the active downstream rows that would be
// affected by retiring an agent. Returned by the preflight pass on
// DELETE /api/v1/agents/{id}. Zero counts mean a clean soft-retire is safe;
// any non-zero count blocks a default retire with HTTP 409 and requires an
// explicit ?force=true&reason=... escape hatch from the operator.
type AgentDependencyCounts struct {
	ActiveTargets     int `json:"active_targets"`     // deployment_targets.agent_id=id AND retired_at IS NULL
	ActiveCertificates int `json:"active_certificates"` // certificates currently deployed via one of this agent's active targets
	PendingJobs       int `json:"pending_jobs"`       // jobs.agent_id=id AND status IN (Pending, AwaitingCSR, AwaitingApproval, Running)
}

// HasDependencies reports whether any preflight counter is non-zero.
func (d AgentDependencyCounts) HasDependencies() bool {
	return d.ActiveTargets > 0 || d.ActiveCertificates > 0 || d.PendingJobs > 0
}

// SentinelAgentIDs enumerates the four reserved agent identities that back
// non-agent discovery subsystems. These rows are created by cmd/server on
// startup and retiring them would orphan their subsystem — the network
// scanner and the three cloud secret-manager sources all key writes to
// these IDs via service.SentinelAgentID / service.SentinelAWSSecretsMgr /
// service.SentinelAzureKeyVault / service.SentinelGCPSecretMgr. The four
// literal IDs below MUST stay in lockstep with those service-package
// constants (see internal/service/network_scan.go line 23 and
// internal/service/cloud_discovery.go lines 14-16).
//
// The retirement service refuses them unconditionally — even with
// ?force=true — via ErrAgentIsSentinel. Living here (and not in the
// service package) lets handler, repository, and scheduler code filter
// them without importing service and creating a cycle.
var SentinelAgentIDs = []string{
	"server-scanner",
	"cloud-aws-sm",
	"cloud-azure-kv",
	"cloud-gcp-sm",
}

// IsSentinelAgent reports whether id matches one of the four reserved
// sentinel agent IDs. A linear scan is fine — the slice is length 4 and
// the check is rare (only on retirement attempts and sweeper filters).
func IsSentinelAgent(id string) bool {
	for _, s := range SentinelAgentIDs {
		if s == id {
			return true
		}
	}
	return false
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
	IssuerTypeVault     IssuerType = "VaultPKI"
	IssuerTypeDigiCert  IssuerType = "DigiCert"
	IssuerTypeSectigo   IssuerType = "Sectigo"
	IssuerTypeGoogleCAS IssuerType = "GoogleCAS"
	IssuerTypeAWSACMPCA  IssuerType = "AWSACMPCA"
	IssuerTypeEntrust    IssuerType = "Entrust"
	IssuerTypeGlobalSign IssuerType = "GlobalSign"
	IssuerTypeEJBCA      IssuerType = "EJBCA"
)

// TargetType represents the type of deployment target.
type TargetType string

const (
	TargetTypeNGINX    TargetType = "NGINX"
	TargetTypeApache   TargetType = "Apache"
	TargetTypeHAProxy  TargetType = "HAProxy"
	TargetTypeF5       TargetType = "F5"
	TargetTypeIIS      TargetType = "IIS"
	TargetTypeTraefik  TargetType = "Traefik"
	TargetTypeCaddy    TargetType = "Caddy"
	TargetTypeEnvoy    TargetType = "Envoy"
	TargetTypePostfix  TargetType = "Postfix"
	TargetTypeDovecot  TargetType = "Dovecot"
	TargetTypeSSH               TargetType = "SSH"
	TargetTypeWinCertStore      TargetType = "WinCertStore"
	TargetTypeJavaKeystore      TargetType = "JavaKeystore"
	TargetTypeKubernetesSecrets TargetType = "KubernetesSecrets"
)
