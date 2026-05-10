package repository

import (
	"context"
	"errors"
	"time"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
)

// Sentinel errors for the OIDC repositories. Postgres implementations
// translate SQLSTATE codes into these so handler / service code can
// branch via errors.Is.
var (
	// ErrOIDCProviderNotFound: Get / GetByName returned no row. HTTP 404.
	ErrOIDCProviderNotFound = errors.New("oidc: provider not found")

	// ErrOIDCProviderDuplicateName: Create tripped the (tenant_id, name)
	// UNIQUE constraint. HTTP 409.
	ErrOIDCProviderDuplicateName = errors.New("oidc: provider with this name already exists in tenant")

	// ErrOIDCProviderInUse: Delete failed because at least one users row
	// references the provider via oidc_provider_id (FK ON DELETE
	// RESTRICT). HTTP 409.
	ErrOIDCProviderInUse = errors.New("oidc: provider has authenticated users; revoke all sessions before delete")

	// ErrGroupRoleMappingNotFound: Get returned no row. HTTP 404.
	ErrGroupRoleMappingNotFound = errors.New("oidc: group-role mapping not found")

	// ErrGroupRoleMappingDuplicate: Add tripped the
	// (provider_id, group_name, role_id) UNIQUE constraint. HTTP 409.
	ErrGroupRoleMappingDuplicate = errors.New("oidc: group-role mapping already exists")
)

// OIDCProviderRepository wraps the oidc_providers table. Phase 3's
// OIDCService consumes List + Get to look up the IdP for token
// validation; the GUI / CLI wire Create / Update / Delete behind
// auth.oidc.* permission gates per Phase 5.
type OIDCProviderRepository interface {
	// List returns every configured provider in the tenant. Order:
	// created_at ASC for stable GUI rendering.
	List(ctx context.Context, tenantID string) ([]*oidcdomain.OIDCProvider, error)

	// Get returns one provider by id. ErrOIDCProviderNotFound on miss.
	Get(ctx context.Context, id string) (*oidcdomain.OIDCProvider, error)

	// GetByName returns one provider by (tenant_id, name).
	// ErrOIDCProviderNotFound on miss.
	GetByName(ctx context.Context, tenantID, name string) (*oidcdomain.OIDCProvider, error)

	// Create persists a new provider. Caller MUST have already called
	// p.Validate() and encrypted the client_secret_encrypted byte
	// stream via internal/crypto/encryption.go. Returns
	// ErrOIDCProviderDuplicateName when the (tenant_id, name) UNIQUE
	// constraint fires.
	Create(ctx context.Context, p *oidcdomain.OIDCProvider) error

	// Update writes the full mutable field set back to the row.
	// Immutable fields (id, tenant_id, created_at) are read-only;
	// updated_at is set to NOW() by the implementation.
	Update(ctx context.Context, p *oidcdomain.OIDCProvider) error

	// Delete removes a provider by id. Returns ErrOIDCProviderInUse
	// when at least one users row references this provider (FK ON
	// DELETE RESTRICT). Phase 5's handler maps to HTTP 409.
	Delete(ctx context.Context, id string) error
}

// GroupRoleMappingRepository wraps the group_role_mappings table.
// Phase 3's OIDCService.HandleCallback uses Map() to translate IdP
// group claims into role IDs; the GUI / CLI wire ListByProvider /
// Add / Remove for operator configuration.
type GroupRoleMappingRepository interface {
	// ListByProvider returns every mapping for the named provider.
	// Order: group_name ASC for stable GUI rendering.
	ListByProvider(ctx context.Context, providerID string) ([]*oidcdomain.GroupRoleMapping, error)

	// Get returns one mapping by id. ErrGroupRoleMappingNotFound on miss.
	Get(ctx context.Context, id string) (*oidcdomain.GroupRoleMapping, error)

	// Add persists a new mapping. Caller MUST have called m.Validate().
	// Returns ErrGroupRoleMappingDuplicate when the
	// (provider_id, group_name, role_id) UNIQUE constraint fires.
	Add(ctx context.Context, m *oidcdomain.GroupRoleMapping) error

	// Remove deletes a mapping by id.
	Remove(ctx context.Context, id string) error

	// Map resolves an IdP-supplied list of group names against the
	// provider's mappings. Returns the deduplicated set of role IDs
	// the user should hold. Empty result means the user matches no
	// mapping (Phase 3 fail-closed: no session minted, audit row
	// `auth.oidc_login_unmapped_groups`).
	Map(ctx context.Context, providerID string, groupNames []string) ([]string, error)
}

// =============================================================================
// PreLoginRepository — Bundle 2 Phase 5.
//
// Holds short-lived rows that carry OIDC state + nonce + PKCE verifier
// across the IdP redirect. Distinct from the sessions table because
// sessions doesn't carry OIDC-specific columns. 10-minute absolute TTL
// at the schema layer (oidc_pre_login_sessions.absolute_expires_at);
// the GC sweep deletes expired rows.
//
// Cookie wire format `v1.<pl-id>.<sk-id>.<HMAC-SHA256>` matches the
// post-login session cookie format exactly; signing-key id is the
// active SessionSigningKey at handshake time.
// =============================================================================

// PreLoginSession is the row shape for oidc_pre_login_sessions. Held
// here (not in oidc/domain) because it's a Phase-5 storage primitive,
// not a domain concept the wider service layer reasons about.
type PreLoginSession struct {
	ID                string // prefix `pl-`
	TenantID          string
	SigningKeyID      string // FK to session_signing_keys.id
	OIDCProviderID    string // FK to oidc_providers.id
	State             string
	Nonce             string
	PKCEVerifier      string
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
}

// Sentinel errors for PreLoginRepository.
var (
	// ErrPreLoginNotFound: LookupAndConsume found no row with the
	// supplied id. The handler maps to HTTP 400 (replay or forgery).
	ErrPreLoginNotFound = errors.New("oidc: pre-login session not found or already consumed")

	// ErrPreLoginExpired: the row was found but absolute_expires_at is
	// in the past. The handler maps to HTTP 400. The row is also
	// deleted (the consume side of LookupAndConsume).
	ErrPreLoginExpired = errors.New("oidc: pre-login session expired (10-minute TTL exceeded)")
)

// PreLoginRepository wraps the oidc_pre_login_sessions table.
type PreLoginRepository interface {
	// Create persists a new pre-login row. Caller MUST have already
	// generated the random id, state, nonce, and PKCE verifier;
	// CreatedAt + AbsoluteExpiresAt default to NOW() and NOW()+10min
	// at the schema layer when zero.
	Create(ctx context.Context, p *PreLoginSession) error

	// LookupAndConsume reads the row by id AND deletes it atomically
	// (single-use). Returns ErrPreLoginNotFound if no row matches OR
	// if the row was already consumed by a concurrent caller.
	// Returns ErrPreLoginExpired if the row was found but expired
	// (the row is still deleted in this case so retries don't
	// re-trigger the expiry check).
	LookupAndConsume(ctx context.Context, id string) (*PreLoginSession, error)

	// GarbageCollectExpired deletes pre-login rows whose
	// absolute_expires_at is in the past. Returns the count deleted.
	// Wired into the same scheduler sweep as expired post-login sessions.
	GarbageCollectExpired(ctx context.Context) (int, error)
}
