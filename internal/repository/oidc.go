package repository

import (
	"context"
	"errors"

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
