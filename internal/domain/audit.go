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
	// ActorTypeUser represents a federated human identity. Reserved by
	// Bundle 2 (OIDC + sessions) for OIDC-authenticated humans. Bundle 1
	// continues to set this for legacy callers; new code should use
	// ActorTypeAPIKey for API-key-authenticated requests.
	ActorTypeUser ActorType = "User"

	// ActorTypeSystem represents background workers (scheduler loops, GC
	// sweepers, migrations). System actors don't have a credential; the
	// scheduler / startup code passes them directly to AuditService.
	ActorTypeSystem ActorType = "System"

	// ActorTypeAgent represents a certctl-agent identity. Agents poll the
	// control plane outbound; the matched API key carries this actor type
	// when the operator scopes the key to the agent role (Bundle 1
	// Phase 1 ships the agent role with cert.read + agent.heartbeat +
	// agent.job.* permissions).
	ActorTypeAgent ActorType = "Agent"

	// ActorTypeAPIKey represents an API-key-authenticated request whose
	// scope was not narrowed to agent-only. Bundle 1 Phase 1 introduces
	// this so the audit trail can distinguish a human-operator API key
	// from a federated OIDC user (Bundle 2). System actors and agents
	// keep their existing types.
	ActorTypeAPIKey ActorType = "APIKey"

	// ActorTypeAnonymous represents the synthetic actor used when
	// CERTCTL_AUTH_TYPE=none is configured (the demo path). The audit
	// row records "actor-demo-anon" with this type so operators can
	// filter demo activity from real auth in audit reports.
	ActorTypeAnonymous ActorType = "Anonymous"
)
