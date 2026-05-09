package auth

import "time"

// APIKey is the runtime-minted operator API key (Bundle 1 Phase 6).
// Stored in the `api_keys` table with the SHA-256 hash of the key
// value; the plaintext is returned to the operator on creation and
// never persisted. Name is the canonical actor identity that joins
// against actor_roles.actor_id. The Admin flag is a denormalized hint
// replicated from the actor's standing role grant so the auth
// middleware can populate the legacy AdminKey context without joining
// actor_roles on every request; the actor_roles row remains the
// source of truth for authorization.
type APIKey struct {
	ID         string     `json:"id"` // prefix `ak-`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"` // never serialized
	TenantID   string     `json:"tenant_id"`
	Admin      bool       `json:"admin"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}
