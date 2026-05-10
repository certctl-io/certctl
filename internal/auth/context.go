// Package auth holds the certctl auth surface: API-key validation, the
// authenticated-actor context keys, and the helpers that consumers across
// the codebase use to read the actor identity (rate limiter, audit
// recorder, handler-level admin gates, GUI affordance hints).
//
// Bundle 1 / Phase 0 split this code out of internal/api/middleware so
// Bundle 2 (OIDC + sessions) and the broader RBAC primitive (roles +
// permissions + scoped grants) have a clean home that doesn't bloat the
// generic-middleware package. Phase 0 is a pure refactor; behaviour
// matches the pre-extract NewAuthWithNamedKeys / NewAuth surface
// byte-for-byte.
package auth

import "context"

// UserKey is the context key for storing the authenticated actor's
// canonical name. Populated by Middleware (a.k.a. NewAuthWithNamedKeys)
// from the matched NamedAPIKey.Name. Read by GetUser.
type UserKey struct{}

// AdminKey is the context key for storing the admin flag. Populated by
// Middleware from the matched NamedAPIKey.Admin. Read by IsAdmin.
//
// Bundle 1 keeps the boolean shape for backwards compatibility with the
// pre-RBAC handler gates. Phase 3 introduces RequirePermission and the
// boolean becomes informational only (admin role membership ↔ this flag).
type AdminKey struct{}

// GetUser extracts the authenticated user from context. Returns the name
// of the matched API key, or "" if the request was not authenticated
// (none mode, missing Bearer, or a misconfigured chain).
func GetUser(ctx context.Context) string {
	user, ok := ctx.Value(UserKey{}).(string)
	if !ok {
		return ""
	}
	return user
}

// IsAdmin extracts the admin flag from context. Returns true only when
// the authenticated actor's NamedAPIKey carried Admin=true.
//
// Bundle 1 maintains the boolean for back-compat. Bundle 1 Phase 3
// introduces auth.RequirePermission as the load-bearing authorization
// gate; legacy IsAdmin callers (5 admin handlers tracked in M-008)
// migrate to RequirePermission in that phase.
func IsAdmin(ctx context.Context) bool {
	admin, ok := ctx.Value(AdminKey{}).(bool)
	return ok && admin
}

// =============================================================================
// Bundle 1 Phase 3: RBAC-aware context keys.
//
// ActorIDKey, ActorTypeKey, and TenantIDKey are populated by the auth
// middleware (NewAuthWithNamedKeys, NewDemoModeAuth, and Bundle 2's
// session middleware) so that downstream RBAC checks have a stable
// identity + tenancy view of the caller.
//
// UserKey + AdminKey continue to be populated for back-compat with
// existing audit / rate-limiter / handler code; the new keys are the
// canonical Phase 3+ identity.
// =============================================================================

// ActorIDKey is the canonical actor identifier (e.g. an API-key name,
// an OIDC user id, or the synthetic `actor-demo-anon`). Phase 3
// middleware populates this; auth.RequirePermission and
// auth.CallerFromContext read it.
type ActorIDKey struct{}

// ActorTypeKey is the typed-string actor type (User, System, Agent,
// APIKey, Anonymous) corresponding to internal/domain.ActorType. Stored
// as a string so the internal/auth package doesn't need to import the
// domain package and create a cycle.
type ActorTypeKey struct{}

// TenantIDKey is the tenant the request executes in. Bundle 1 ships
// single-tenant; every authenticated request gets the seeded
// `t-default` tenant unless the future managed-service offering
// configures a different one.
type TenantIDKey struct{}

// GetActorID returns the canonical actor id from context, or "" when
// no actor is present (anonymous request, missing middleware in test
// harnesses, etc.). Falls back to the legacy UserKey value for
// back-compat with handlers that have not yet adopted the new keys.
func GetActorID(ctx context.Context) string {
	if id, ok := ctx.Value(ActorIDKey{}).(string); ok && id != "" {
		return id
	}
	return GetUser(ctx)
}

// GetActorType returns the actor type string from context, or "" when
// no actor type was set. Phase 3 middleware sets this to "APIKey" for
// validated bearer-token requests and "Anonymous" for the demo-mode
// synthetic actor.
func GetActorType(ctx context.Context) string {
	if t, ok := ctx.Value(ActorTypeKey{}).(string); ok {
		return t
	}
	return ""
}

// GetTenantID returns the tenant id from context, or the seeded
// default tenant when no value was set. Returning the default rather
// than "" keeps RBAC lookups working in deployments that haven't
// configured a tenant explicitly (the Bundle 1 baseline).
func GetTenantID(ctx context.Context) string {
	if t, ok := ctx.Value(TenantIDKey{}).(string); ok && t != "" {
		return t
	}
	return DefaultTenantID
}

// DefaultTenantID is the seeded single tenant. Mirrors
// internal/domain/auth.DefaultTenantID; duplicated here to avoid a
// cross-package import in the hot-path middleware.
const DefaultTenantID = "t-default"

// DemoAnonActorID is the synthetic actor id used by the demo-mode
// auth middleware when CERTCTL_AUTH_TYPE=none. Mirrors
// internal/domain/auth.DemoAnonActorID.
const DemoAnonActorID = "actor-demo-anon"

// ActorTypeAPIKey + ActorTypeAnonymous mirror the corresponding
// domain.ActorType values. Stored as untyped strings here so callers
// don't have to import the domain package.
const (
	ActorTypeAPIKey    = "APIKey"
	ActorTypeAnonymous = "Anonymous"
)
