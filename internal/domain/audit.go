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

	// EventCategory (Bundle 1 Phase 8) classifies the event into one
	// of "cert_lifecycle", "auth", or "config" so the auditor role
	// can filter to authentication / authorization events without
	// also seeing every cert.issue. The persistence layer treats an
	// empty value as "cert_lifecycle" (the migration default + the
	// DB CHECK constraint).
	EventCategory string `json:"event_category,omitempty"`
}

// Audit event-category constants. Bundle 1 Phase 8 ships exactly
// three; future bundles extend the enum (and the migration's CHECK
// constraint) without reshaping the column.
const (
	// EventCategoryCertLifecycle is the default for cert.* /
	// agent.* / deployment.* / verification.* events.
	EventCategoryCertLifecycle = "cert_lifecycle"

	// EventCategoryAuth covers every auth.role.* / auth.key.* /
	// auth.bootstrap.* event plus the bootstrap.consume action
	// recorded by Phase 6. Auditors filter to this category to
	// review who minted / granted / revoked roles.
	EventCategoryAuth = "auth"

	// EventCategoryConfig covers issuer / target / settings
	// mutations. Distinct from cert_lifecycle so a regulator can
	// review configuration changes separately from cert ops.
	EventCategoryConfig = "config"
)

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
