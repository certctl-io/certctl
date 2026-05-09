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
