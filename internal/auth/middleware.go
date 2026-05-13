// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// AuthConfig holds configuration for the legacy NewAuth shim.
//
// G-1 (P1): valid Type values are "api-key" or "none" only. "jwt" was
// removed because no JWT middleware ships with certctl (silent auth
// downgrade pre-G-1). The single source of truth for the allowed set
// lives at internal/config.AuthType / config.ValidAuthTypes(); prefer
// those constants over string literals when comparing.
//
// Bundle 2 will extend ValidAuthTypes() with "oidc"; Bundle 1 leaves
// the surface unchanged.
type AuthConfig struct {
	Type   string // "api-key" or "none" (see config.AuthType constants)
	Secret string // The raw API key or comma-separated list of valid API keys
}

// NewAuthWithNamedKeys creates an authentication middleware that validates
// Bearer tokens against a set of named API keys. Each key carries a name
// (propagated as the actor via context) and an admin flag (consulted by
// authorization gates such as bulk revocation).
//
// When namedKeys is empty the returned middleware is a no-op pass-through,
// which is used in demo/development mode (CERTCTL_AUTH_TYPE=none). When one
// or more keys are provided, requests must include a matching Bearer token
// or they are rejected with 401.
//
// Bundle 1 Phase 3 extends Middleware with the RBAC primitive. This
// function continues to exist as the API-key validator; Phase 3 wraps it
// with the role lookup that populates the future ActorIDKey / RolesKey
// context values.
func NewAuthWithNamedKeys(namedKeys []NamedAPIKey) func(http.Handler) http.Handler {
	if len(namedKeys) == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	if len(namedKeys) == 1 {
		slog.Warn("only one API key configured — consider adding a rotation key for zero-downtime rotation")
	}
	return NewAuthWithKeyStore(NewStaticKeyStore(namedKeys))
}

// NewAuthWithKeyStore is the Bundle-1 Phase-6 entry point. It builds a
// Bearer-token middleware whose lookup table is supplied by the caller
// instead of being baked into the closure. Production wiring passes a
// MutableKeyStore so the bootstrap path can mint new admin keys at
// runtime; tests pass a StaticKeyStore for the immutable case. A nil
// store yields the demo-mode pass-through (matches NewAuthWithNamedKeys
// with an empty slice).
func NewAuthWithKeyStore(store KeyStore) func(http.Handler) http.Handler {
	if store == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("WWW-Authenticate", `Bearer realm="certctl"`)
				http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
				return
			}
			if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid Authorization header format, expected: Bearer <token>"}`, http.StatusUnauthorized)
				return
			}

			token := authHeader[7:]
			matched, ok := store.LookupByHash(HashAPIKey(token))
			if !ok {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// Bundle 1 Phase 0 legacy UserKey/AdminKey + Phase 3 RBAC
			// ActorIDKey/ActorTypeKey/TenantIDKey are populated on every
			// authenticated request so downstream RequirePermission +
			// audit-attribution code see a consistent actor.
			ctx := context.WithValue(r.Context(), UserKey{}, matched.Name)
			ctx = context.WithValue(ctx, AdminKey{}, matched.Admin)
			ctx = context.WithValue(ctx, ActorIDKey{}, matched.Name)
			ctx = context.WithValue(ctx, ActorTypeKey{}, ActorTypeAPIKey)
			ctx = context.WithValue(ctx, TenantIDKey{}, DefaultTenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewDemoModeAuth returns a middleware that injects the synthetic
// `actor-demo-anon` identity into every request context. Used when
// CERTCTL_AUTH_TYPE=none is configured (the demo path) so that
// RBAC-gated handlers see an admin-equivalent caller without operator
// configuration.
//
// The synthetic actor is seeded by migration 000029_rbac.up.sql with
// the admin role at global scope, so RequirePermission resolves
// every gated request as an admin. The reserved-actor guard in the
// service layer prevents the API from accidentally mutating this
// actor's role assignments.
//
// Production deployments MUST NOT use this middleware. The cmd/server
// startup wires it only when CERTCTL_AUTH_TYPE=none is explicitly
// configured.
func NewDemoModeAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserKey{}, DemoAnonActorID)
			ctx = context.WithValue(ctx, AdminKey{}, true)
			ctx = context.WithValue(ctx, ActorIDKey{}, DemoAnonActorID)
			ctx = context.WithValue(ctx, ActorTypeKey{}, ActorTypeAnonymous)
			ctx = context.WithValue(ctx, TenantIDKey{}, DefaultTenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewAuth is a legacy shim that converts a comma-separated Secret list into
// synthesized legacy-key-N named entries and delegates to NewAuthWithNamedKeys.
// It preserves the pre-M-002 behavior for callers that still pass raw AuthConfig
// (primarily cmd/server/main_test.go). The synthesized actor is "legacy-key-N"
// rather than the old hardcoded "api-key-user" so audit events carry
// meaningful identity even on the legacy path.
//
// Deprecated: Use NewAuthWithNamedKeys with explicit NamedAPIKey entries.
func NewAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	if cfg.Type == "none" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	var namedKeys []NamedAPIKey
	idx := 0
	for _, k := range strings.Split(cfg.Secret, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		namedKeys = append(namedKeys, NamedAPIKey{
			Name:  fmt.Sprintf("legacy-key-%d", idx),
			Key:   k,
			Admin: false,
		})
		idx++
	}
	return NewAuthWithNamedKeys(namedKeys)
}
