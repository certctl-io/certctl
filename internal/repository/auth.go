package repository

import (
	"context"
	"errors"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// Sentinel errors for the RBAC repositories. Postgres implementations
// translate SQLSTATE codes (23505 unique-violation, 23503 FK-violation,
// no-rows) into these so handler / service code branches via errors.Is.
var (
	// ErrAuthNotFound is returned by Get / GetByName when no row matches.
	// Maps to HTTP 404.
	ErrAuthNotFound = errors.New("auth: row not found")

	// ErrAuthDuplicateName is returned by Create when a UNIQUE constraint
	// fires (e.g. roles.name within a tenant). Maps to HTTP 409.
	ErrAuthDuplicateName = errors.New("auth: duplicate name")

	// ErrAuthRoleInUse is returned by RoleRepository.Delete when active
	// actor_roles still reference the role (FK ON DELETE RESTRICT).
	// Maps to HTTP 409.
	ErrAuthRoleInUse = errors.New("auth: role still has active actor assignments")

	// ErrAuthReservedActor is returned when a mutation targets a system-
	// reserved actor (currently `actor-demo-anon`). Maps to HTTP 409.
	ErrAuthReservedActor = errors.New("auth: reserved system actor cannot be modified")

	// ErrAuthUnknownPermission is returned when a RolePermission grant
	// references a permission name not in the canonical catalog.
	// Maps to HTTP 400.
	ErrAuthUnknownPermission = errors.New("auth: permission not in canonical catalog")
)

// TenantRepository wraps the tenants table. Bundle 1 ships single-tenant
// (one seeded `t-default`); the future managed-service offering activates
// multi-tenant by inserting additional tenants.
type TenantRepository interface {
	Get(ctx context.Context, id string) (*authdomain.Tenant, error)
	List(ctx context.Context) ([]*authdomain.Tenant, error)
	EnsureDefault(ctx context.Context) error
}

// RoleRepository wraps the roles + role_permissions tables.
type RoleRepository interface {
	Get(ctx context.Context, id string) (*authdomain.Role, error)
	GetByName(ctx context.Context, tenantID, name string) (*authdomain.Role, error)
	List(ctx context.Context, tenantID string) ([]*authdomain.Role, error)
	Create(ctx context.Context, role *authdomain.Role) error
	Update(ctx context.Context, role *authdomain.Role) error
	// Delete fails with ErrAuthRoleInUse when active actor_roles still
	// reference the role (FK ON DELETE RESTRICT).
	Delete(ctx context.Context, id string) error

	// ListPermissions returns the (Permission, ScopeType, ScopeID)
	// triples granted to the role.
	ListPermissions(ctx context.Context, roleID string) ([]*authdomain.RolePermission, error)
	// AddPermission creates a row in role_permissions. ON CONFLICT DO
	// NOTHING preserves idempotency for re-applied seeds.
	AddPermission(ctx context.Context, grant *authdomain.RolePermission) error
	// RemovePermission deletes a specific (role, permission, scope) row.
	RemovePermission(ctx context.Context, grant *authdomain.RolePermission) error
}

// PermissionRepository wraps the permissions table.
type PermissionRepository interface {
	List(ctx context.Context) ([]*authdomain.Permission, error)
	GetByName(ctx context.Context, name string) (*authdomain.Permission, error)
	// IsCanonical returns true when name is in
	// authdomain.CanonicalPermissions. The migration seeds the catalog;
	// this is an in-memory check so callers (RoleService.AddPermission)
	// can fail-fast without a DB roundtrip.
	IsCanonical(name string) bool
}

// ActorRoleRepository wraps the actor_roles table.
type ActorRoleRepository interface {
	// ListByActor returns all standing role grants for an actor.
	ListByActor(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, tenantID string) ([]*authdomain.ActorRole, error)
	// ListByRole returns all actors holding a given role. Used by
	// RoleService.Delete to enforce the in-use guard.
	ListByRole(ctx context.Context, roleID string) ([]*authdomain.ActorRole, error)

	// Grant creates an actor_roles row. Idempotent via ON CONFLICT.
	// The reserved actor `actor-demo-anon` admin grant is seeded by
	// the migration; this method will create additional grants for it
	// only if the operator explicitly wires that, which the API
	// layer rejects.
	Grant(ctx context.Context, ar *authdomain.ActorRole) error
	// Revoke deletes an actor_roles row by (actor_id, actor_type,
	// role_id, tenant_id). The API layer must reject revocations
	// targeting `actor-demo-anon` to preserve the demo path.
	Revoke(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, roleID, tenantID string) error

	// EffectivePermissions returns the deduplicated set of
	// (permission_name, scope_type, scope_id) triples granted to the
	// actor across all roles they hold. The middleware-level
	// auth.RequirePermission gate (Phase 3) calls this on every
	// gated request; implementations should cache or use SQL JOINs
	// for performance.
	EffectivePermissions(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, tenantID string) ([]EffectivePermission, error)

	// AdminExists reports whether ANY actor in the tenant currently
	// holds the r-admin role. Bundle 1 Phase 6's bootstrap probe
	// uses this to gate the day-0 endpoint: once the answer flips
	// from false to true the bootstrap path stays closed forever
	// (the seeded actor-demo-anon admin only exists in demo mode;
	// in api-key mode the operator either uses bootstrap or
	// CERTCTL_API_KEYS_NAMED to mint the first admin). The query
	// excludes the synthetic actor-demo-anon so demo-mode deploys
	// can still bootstrap a real admin if/when the operator
	// switches to api-key mode without re-migrating.
	AdminExists(ctx context.Context, tenantID string) (bool, error)

	// ListDistinctActors returns one row per (actor_id, actor_type)
	// pair with at least one actor_roles grant in the tenant.
	// Bundle 1 Phase 7's `auth keys list` + scope-down helper use
	// this to enumerate the actor population without joining
	// against the env-var-loaded namedKeys (whose canonical record
	// is the actor_roles backfill from Phase 1 / C2). The synthetic
	// actor-demo-anon is included so the GUI can render it as
	// "system-managed, scope-down hidden"; Phase 7's interactive
	// flow filters it out of the prompt loop.
	ListDistinctActors(ctx context.Context, tenantID string) ([]ActorWithRoles, error)
}

// ActorWithRoles is the (actor, roles) projection returned by
// ActorRoleRepository.ListDistinctActors. Roles is the slice of role
// IDs the actor holds; the caller can resolve role names via the
// RoleRepository or the CLI's already-cached role list.
type ActorWithRoles struct {
	ActorID   string
	ActorType authdomain.ActorTypeValue
	TenantID  string
	RoleIDs   []string
}

// EffectivePermission is the (permission, scope) pair returned by
// ActorRoleRepository.EffectivePermissions. Multiple actor_roles rows
// may grant the same permission at different scopes; callers receive
// every grant and the matcher handles "global beats specific" semantics.
type EffectivePermission struct {
	PermissionName string
	ScopeType      authdomain.ScopeType
	ScopeID        *string // NULL = global
}

// APIKeyRepository wraps the api_keys table. Bundle 1 Phase 6 ships
// this so the bootstrap endpoint (POST /v1/auth/bootstrap) can mint
// the first admin API key without needing the operator to roundtrip
// through CERTCTL_API_KEYS_NAMED. Operator-tier keys live here;
// agent-tier keys remain on the agents table (`api_key_hash` column).
type APIKeyRepository interface {
	// Create stores a new key row. ID + CreatedAt default if zero.
	// The plaintext key is NOT stored — callers pass only the
	// SHA-256 hex hash. Returns ErrAuthDuplicateName when the
	// (name) UNIQUE constraint fires.
	Create(ctx context.Context, key *authdomain.APIKey) error
	// GetByName returns a single row by operator-visible name.
	// Returns ErrAuthNotFound when no row matches.
	GetByName(ctx context.Context, name string) (*authdomain.APIKey, error)
	// List returns every key row across the tenant. Bundle 1 ships
	// single-tenant so tenantID is typically t-default.
	List(ctx context.Context, tenantID string) ([]*authdomain.APIKey, error)
	// Delete removes a key row by name. Used by the RBAC API's key
	// rotation/revocation paths.
	Delete(ctx context.Context, name string) error
}
