package auth

import (
	"context"
	"crypto/subtle"
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

	// Pre-compute hashes of all valid keys for constant-time comparison.
	type keyEntry struct {
		hash  string
		name  string
		admin bool
	}
	var entries []keyEntry
	for _, nk := range namedKeys {
		entries = append(entries, keyEntry{
			hash:  HashAPIKey(nk.Key),
			name:  nk.Name,
			admin: nk.Admin,
		})
	}

	// Warn if only one key is configured in production mode
	if len(entries) == 1 {
		slog.Warn("only one API key configured — consider adding a rotation key for zero-downtime rotation")
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

			// Extract Bearer token
			if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid Authorization header format, expected: Bearer <token>"}`, http.StatusUnauthorized)
				return
			}

			token := authHeader[7:]
			tokenHash := HashAPIKey(token)

			// Check against all valid keys using constant-time comparison
			var matched *keyEntry
			for i := range entries {
				if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(entries[i].hash)) == 1 {
					matched = &entries[i]
					break
				}
			}

			if matched == nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// Store the authenticated identity and admin flag in context
			ctx := context.WithValue(r.Context(), UserKey{}, matched.name)
			ctx = context.WithValue(ctx, AdminKey{}, matched.admin)
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
