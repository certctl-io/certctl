// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// PermissionChecker is the dependency the RequirePermission middleware
// expects. internal/service/auth.Authorizer satisfies this interface;
// tests can supply an in-memory fake.
//
// scopeID is nil for global checks; non-nil for per-resource checks
// (e.g. per-profile or per-issuer scoping). scopeType matches
// internal/domain/auth.ScopeType ("global", "profile", "issuer").
type PermissionChecker interface {
	CheckPermission(
		ctx context.Context,
		actorID string,
		actorType string,
		tenantID string,
		permission string,
		scopeType string,
		scopeID *string,
	) (bool, error)
}

// ScopeFunc extracts the scope (type, id) from the request. A nil
// ScopeFunc means "global scope" (the most common case for admin-class
// gates like bulk revocation, intermediate-CA management, etc.).
type ScopeFunc func(r *http.Request) (scopeType string, scopeID *string)

// RequirePermission returns a middleware that gates the wrapped handler
// behind the named permission. Returns 401 when no actor is in
// context, 403 when the actor exists but lacks the permission, 500 on
// repository errors. Skips the gate entirely for protocol-level
// endpoints in ProtocolEndpointPrefixes (ACME / SCEP / EST / OCSP / CRL).
//
// The permission name MUST exist in
// internal/domain/auth.CanonicalPermissions (enforced indirectly via
// the seed migration; an unknown permission name will simply return
// 403 because no role grant references it).
func RequirePermission(checker PermissionChecker, permission string, scope ScopeFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Protocol endpoints keep their existing protocol-level
			// auth; the RBAC gate doesn't apply.
			if IsProtocolEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			actorID := GetActorID(ctx)
			if actorID == "" {
				writeJSONError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			actorType := GetActorType(ctx)
			if actorType == "" {
				// Legacy callers that only set UserKey: assume APIKey.
				// Bundle 2's OIDC middleware sets the type explicitly
				// to "User"; the demo-mode middleware sets it to
				// "Anonymous"; the API-key middleware (Phase 3
				// extension) sets it to "APIKey".
				actorType = ActorTypeAPIKey
			}

			scopeType := "global"
			var scopeID *string
			if scope != nil {
				scopeType, scopeID = scope(r)
			}

			tenantID := GetTenantID(ctx)
			ok, err := checker.CheckPermission(ctx, actorID, actorType, tenantID, permission, scopeType, scopeID)
			if err != nil {
				slog.ErrorContext(ctx, "RBAC check failed",
					"permission", permission,
					"actor_id", actorID,
					"error", err,
				)
				writeJSONError(w, http.StatusInternalServerError, "Internal error")
				return
			}
			if !ok {
				writeJSONError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HasPermission is a convenience for handlers that need to check a
// permission imperatively (e.g. branch behaviour without 403'ing the
// whole request). Returns (true, nil) when granted, (false, nil) when
// denied, (false, err) on repository failure. Skips the protocol-
// endpoint allowlist.
func HasPermission(ctx context.Context, checker PermissionChecker, permission string, scopeType string, scopeID *string) (bool, error) {
	actorID := GetActorID(ctx)
	if actorID == "" {
		return false, ErrNoActor
	}
	actorType := GetActorType(ctx)
	if actorType == "" {
		actorType = ActorTypeAPIKey
	}
	tenantID := GetTenantID(ctx)
	return checker.CheckPermission(ctx, actorID, actorType, tenantID, permission, scopeType, scopeID)
}

// ErrNoActor is returned by HasPermission when the request context has
// no actor identity. Handler code typically translates this to HTTP
// 401.
var ErrNoActor = errors.New("auth: no actor in context")

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// Match the existing middleware error shape so handler tests that
	// assert on the body text continue to work.
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
