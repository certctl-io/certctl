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
