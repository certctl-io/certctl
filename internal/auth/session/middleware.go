// Package session — Auth Bundle 2 Phase 6 / session + CSRF middleware.
//
// This file ships the HTTP middleware that wires the post-login session
// machinery into the request path. Three middlewares + one combinator:
//
//  1. SessionMiddleware — reads `certctl_session` cookie, validates
//     via SessionService.Validate, populates the actor/role context
//     keys (same keys as the API-key path) so downstream handlers
//     and RBAC gates see a consistent caller.
//
//  2. CSRFMiddleware — for state-changing methods (POST/PUT/DELETE/
//     PATCH), checks `X-CSRF-Token` header against the session row's
//     stored hash. API-key actors are EXEMPT (they're not browser-
//     driven; CSRF doesn't apply). Returns 403 on mismatch.
//
//  3. ChainAuthSessionThenBearer — the load-bearing chained-auth
//     combinator: tries the session cookie first; on miss/invalid,
//     falls back to the Bearer-token middleware; if neither
//     authenticates, returns 401. Wired in cmd/server/main.go in the
//     documented chain position (#6 — Auth, between RateLimit and CSRF).
//
// Bypass list (Category E): the existing public-route allowlist in
// internal/api/router/router.go::AuthExemptRouterRoutes (/health,
// /ready, /api/v1/auth/info, /api/v1/version, /api/v1/auth/bootstrap,
// /auth/oidc/login + callback + back-channel-logout, /auth/logout) is
// preserved by virtue of those routes registering via direct
// r.mux.Handle (they bypass the entire middleware chain). The
// protocol-endpoint allowlist (ACME / SCEP / EST / OCSP / CRL) bypasses
// via the cmd/server/main.go::buildFinalHandler URL-prefix dispatch —
// those routes never reach the auth middleware at all.
package session

import (
	"context"
	"net/http"

	"github.com/certctl-io/certctl/internal/auth"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// =============================================================================
// SessionMiddleware.
// =============================================================================

// SessionValidator is the slice of *Service the SessionMiddleware
// consumes. Defining the projection here keeps the middleware
// decoupled from the wider service surface (and lets tests stub
// validation without spinning up a full SessionService).
type SessionValidator interface {
	Validate(ctx context.Context, in ValidateInput) (*sessiondomain.Session, error)
	UpdateLastSeen(ctx context.Context, sessionID string) error
}

// NewSessionMiddleware returns the Phase 6 session-cookie middleware.
//
// Behavior on each request:
//
//  1. Read `certctl_session` cookie. Missing -> defer to next middleware
//     (the chained-auth combinator falls back to Bearer).
//  2. Validate via SessionService.Validate. On failure, defer to next
//     middleware (likewise falls back to Bearer).
//  3. On success, populate the legacy UserKey / AdminKey + the Phase 3
//     RBAC context keys (ActorIDKey / ActorTypeKey / TenantIDKey) so
//     downstream RequirePermission + audit-attribution code see a
//     consistent actor regardless of how they authenticated.
//  4. Best-effort UpdateLastSeen so the idle-expiry sliding window
//     stays fresh (errors swallowed; the session is already validated).
//  5. Defer to the next handler.
//
// The middleware does NOT 401 on session-validate failure; instead it
// passes through, letting the chained-auth combinator try Bearer. The
// combinator 401s when neither authenticates.
func NewSessionMiddleware(svc SessionValidator) func(http.Handler) http.Handler {
	if svc == nil {
		// No session service wired (pre-Phase-5 deployments) — pass-through.
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessiondomain.PostLoginCookieName)
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, verr := svc.Validate(r.Context(), ValidateInput{
				CookieValue: cookie.Value,
				ClientIP:    clientIPFromRequest(r),
				UserAgent:   r.UserAgent(),
			})
			if verr != nil {
				// Cookie present but invalid (expired / tampered /
				// retired-key / IP-bind / UA-bind / revoked). Defer to
				// the next middleware so a valid Bearer can still
				// authenticate. The auth combinator 401s if neither
				// works.
				next.ServeHTTP(w, r)
				return
			}

			// Best-effort sliding-window update. The session is already
			// validated; an UpdateLastSeen error doesn't change the
			// auth outcome (the row stays valid until idle / absolute
			// expiry; this just keeps the idle window fresh).
			_ = svc.UpdateLastSeen(r.Context(), sess.ID)

			ctx := r.Context()
			ctx = context.WithValue(ctx, auth.UserKey{}, sess.ActorID)
			ctx = context.WithValue(ctx, auth.AdminKey{}, false) // RBAC takes over from the legacy admin-flag heuristic
			ctx = context.WithValue(ctx, auth.ActorIDKey{}, sess.ActorID)
			ctx = context.WithValue(ctx, auth.ActorTypeKey{}, sess.ActorType)
			ctx = context.WithValue(ctx, auth.TenantIDKey{}, sess.TenantID)
			// Stash the session row itself so the CSRF middleware can
			// look up the stored CSRF hash without re-validating.
			ctx = context.WithValue(ctx, sessionContextKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// =============================================================================
// CSRFMiddleware.
// =============================================================================

// CSRFValidator is the slice of *Service the CSRFMiddleware uses.
type CSRFValidator interface {
	ValidateCSRF(headerValue string, sess *sessiondomain.Session) error
}

// NewCSRFMiddleware returns the Phase 6 CSRF middleware.
//
// Behavior:
//
//   - Safe methods (GET / HEAD / OPTIONS / TRACE) pass through unchecked.
//   - Requests authenticated via Bearer (API-key actors) pass through
//     unchecked: CSRF is a browser-driven attack vector that doesn't
//     apply to programmatic API clients. The middleware detects API-key
//     actors via the absence of a session row in context (the
//     SessionMiddleware populates it; the API-key middleware doesn't).
//   - Requests authenticated via session cookie + state-changing method
//     are gated by SessionService.ValidateCSRF (constant-time-compare
//     of SHA-256(X-CSRF-Token header) against the session row's
//     stored hash). Mismatch returns 403.
func NewCSRFMiddleware(svc CSRFValidator) func(http.Handler) http.Handler {
	if svc == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isStateChangingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			// Find the session row populated by SessionMiddleware.
			// Absence => either (a) caller authenticated via Bearer
			// (API-key path; CSRF exempt by design), or (b) caller is
			// unauthenticated (the auth combinator already 401'd
			// before we got here, so this branch is unreachable in
			// production; defensive code keeps the test surface tidy).
			sess, ok := r.Context().Value(sessionContextKey{}).(*sessiondomain.Session)
			if !ok || sess == nil {
				next.ServeHTTP(w, r)
				return
			}
			header := r.Header.Get("X-CSRF-Token")
			if err := svc.ValidateCSRF(header, sess); err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"CSRF token missing or invalid"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// ChainAuthSessionThenBearer — the load-bearing combinator.
// =============================================================================

// ChainAuthSessionThenBearer composes the session middleware with the
// API-key middleware so a single chain entry tries both paths.
//
// The composition order is critical:
//
//  1. SessionMiddleware runs first. On a valid session cookie it
//     populates the actor context keys + sets the session-row stash
//     and calls next.
//  2. The Bearer-only inner middleware runs second. If the session
//     middleware already populated ActorIDKey, the Bearer middleware
//     is a pass-through (the request is already authenticated). If
//     ActorIDKey is empty, it runs the standard Bearer-token check
//     and either populates the context (200) or 401s.
//
// This means a request with BOTH a valid session AND a valid Bearer
// uses the session (cookie wins; the Bundle 2 contract). A request
// with only one works regardless of which one. A request with neither
// 401s.
//
// The bearer parameter is the existing API-key middleware
// (auth.NewAuthWithKeyStore or similar); when nil the chain degrades
// to session-only.
func ChainAuthSessionThenBearer(
	sessionMW func(http.Handler) http.Handler,
	bearerMW func(http.Handler) http.Handler,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Build the inner: a Bearer middleware that short-circuits when
		// SessionMiddleware already populated ActorIDKey.
		inner := bearerSkipIfAuthenticated(bearerMW)(next)
		// Then wrap with SessionMiddleware so it runs first.
		return sessionMW(inner)
	}
}

// bearerSkipIfAuthenticated wraps the Bearer-token middleware with a
// short-circuit: if ActorIDKey is already populated (the session
// middleware authenticated the request), pass through to next without
// running the Bearer check. Otherwise run Bearer.
func bearerSkipIfAuthenticated(bearerMW func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if bearerMW == nil {
		// No Bearer auth wired (test deployments / session-only). Just
		// require ActorIDKey from the session middleware; 401 if missing.
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if actorID, _ := r.Context().Value(auth.ActorIDKey{}).(string); actorID != "" {
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Authentication required"}`, http.StatusUnauthorized)
			})
		}
	}
	return func(next http.Handler) http.Handler {
		bearerInner := bearerMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if actorID, _ := r.Context().Value(auth.ActorIDKey{}).(string); actorID != "" {
				// Session middleware already authenticated. Skip Bearer.
				next.ServeHTTP(w, r)
				return
			}
			// Defer to Bearer.
			bearerInner.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Helpers.
// =============================================================================

// sessionContextKey is the context key under which SessionMiddleware
// stashes the validated *sessiondomain.Session so CSRFMiddleware can
// reach it without re-validating the cookie.
type sessionContextKey struct{}

// SessionFromContext returns the validated session row populated by
// SessionMiddleware. Returns nil when the request was authenticated via
// Bearer (no session) OR is unauthenticated.
func SessionFromContext(ctx context.Context) *sessiondomain.Session {
	if v, ok := ctx.Value(sessionContextKey{}).(*sessiondomain.Session); ok {
		return v
	}
	return nil
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// clientIPFromRequest pulls the request's client IP — X-Forwarded-For
// first hop wins when present; otherwise RemoteAddr (host:port) with
// the port stripped. Mirrors the helper in
// internal/api/handler/auth_session_oidc.go for the same reason: the
// handler + middleware both need to derive the canonical client IP
// from the same request shape, and duplicating the 6-line helper is
// preferable to introducing an internal/util package for it.
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return trimSpace(xff[:i])
			}
		}
		return trimSpace(xff)
	}
	if i := lastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
