// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package handler — Auth Bundle 2 Phase 5 / OIDC + session HTTP surface.
//
// 13 endpoints split into three logical groups:
//
//  1. Public OIDC handshake (auth-exempt, no certctl-issued credentials):
//     GET  /auth/oidc/login?provider=<id>          -> 302 to IdP
//     GET  /auth/oidc/callback?code=...&state=...  -> consume + mint session
//     POST /auth/oidc/back-channel-logout          -> IdP-initiated revoke
//     POST /auth/logout                            -> revoke caller's session
//
//  2. Session management (RBAC-gated):
//     GET    /api/v1/auth/sessions                 -> list (own / all-actors)
//     DELETE /api/v1/auth/sessions/{id}            -> revoke (own / any)
//
//  3. OIDC provider + group-mapping CRUD (RBAC-gated):
//     GET    /api/v1/auth/oidc/providers            -> auth.oidc.list
//     POST   /api/v1/auth/oidc/providers            -> auth.oidc.create
//     PUT    /api/v1/auth/oidc/providers/{id}       -> auth.oidc.edit
//     DELETE /api/v1/auth/oidc/providers/{id}       -> auth.oidc.delete
//     POST   /api/v1/auth/oidc/providers/{id}/refresh -> auth.oidc.edit
//     GET    /api/v1/auth/oidc/group-mappings       -> auth.oidc.list
//     POST   /api/v1/auth/oidc/group-mappings       -> auth.oidc.edit
//     DELETE /api/v1/auth/oidc/group-mappings/{id}  -> auth.oidc.edit
//
// Audit logging on every mutating operation; event_category="auth".
package handler

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	sessionsvc "github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Service-layer projections.
// =============================================================================

// OIDCAuthHandshaker is the slice of *oidc.Service the OIDC HTTP path
// consumes. Phase 3's *oidc.Service satisfies this directly.
type OIDCAuthHandshaker interface {
	// Audit 2026-05-10 MED-16 — clientIP + userAgent persist into the
	// pre-login row so HandleCallback can reject mismatches at consume
	// time (RFC 9700 §4.7.1 binding).
	HandleAuthRequest(ctx context.Context, providerID, clientIP, userAgent string) (authURL, cookieValue, preLoginID string, err error)
	// Audit 2026-05-10 MED-17 — callbackIss carries the value of the
	// RFC 9207 `iss` query parameter on /auth/oidc/callback (empty
	// string when the IdP doesn't send it). The service enforces the
	// check only when the provider's discovery doc advertised support.
	HandleCallback(ctx context.Context, preLoginCookie, code, callbackState, callbackIss, ip, userAgent string) (*oidcsvc.CallbackResult, error)
	RefreshKeys(ctx context.Context, providerID string) error
}

// SessionMinter is the slice of *session.Service the OIDC handler uses.
//
// Audit 2026-05-11 Fix 13 closure — adds RotateCSRFTokenForActor so the
// Logout handler can fire the HIGH-2 fourth call site. The HIGH-2 spec
// at cowork/auth-bundles-fixes-2026-05-10/06-high-1-2-revoke-and-rotate.md
// enumerated four CSRF-rotation triggers; three were wired (login mints
// fresh by construction, AssignRoleToKey + RevokeRoleFromKey rotate
// post-success), but Logout was missing. A token captured pre-logout
// (browser DevTools, malicious extension) was reusable on the actor's
// sibling sessions until those sessions hit their own idle/absolute
// expiry. Rotation on logout defeats this. Nil-safe: when the wired
// implementation isn't the production *session.Service (e.g. a future
// minimal-config deployment), the Logout handler skips the rotation
// instead of panic-ing.
type SessionMinter interface {
	Create(ctx context.Context, actorID, actorType, ip, userAgent string) (*sessionsvc.CreateResult, error)
	Validate(ctx context.Context, in sessionsvc.ValidateInput) (*sessiondomain.Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAllForActor(ctx context.Context, actorID, actorType string) error
	// RotateCSRFTokenForActor mints a fresh CSRF token across every
	// active session for the (actorID, actorType) pair. Returns the
	// count rotated. NEVER errors — rotation is defense-in-depth and
	// must not block the surrounding mutation that triggered it.
	// Matches the signature on *session.Service so the production
	// wiring satisfies the interface without an adapter.
	RotateCSRFTokenForActor(ctx context.Context, actorID, actorType string) int
}

// BackChannelLogoutVerifier validates an OpenID Connect Back-Channel
// Logout 1.0 logout_token JWT against the IdP's JWKS using the same
// alg allow-list as Phase 3. Phase 5 ships a default implementation
// keyed off the OIDCService's per-provider verifier; a stub satisfies
// this in tests.
type BackChannelLogoutVerifier interface {
	// Verify returns the logout subject (iss + (sub OR sid)) on a
	// valid logout token; an error mapped to HTTP 400 otherwise. Spec
	// references: §2.4 nonce-MUST-be-absent, §2.5 events-MUST-contain-
	// the-back-channel-logout URI, §2.6 fail-400-on-any-validation-fail.
	//
	// Audit 2026-05-10 HIGH-3 closure — the iat+jti return values let
	// the handler enforce the iat-skew window + the jti consumed-set.
	// Pre-fix the verifier only checked iat != 0 and jti != ""; it
	// never enforced freshness nor replay. The verifier itself now
	// enforces the iat-window per its configured max-age; the handler
	// owns the jti consumed-set (so the audit-row outcome category
	// can distinguish first-receive from replay).
	Verify(ctx context.Context, logoutTokenJWT string) (issuer, sub, sid, jti string, iat int64, err error)
}

// =============================================================================
// Config knobs the handler honors.
// =============================================================================

// SessionCookieAttrs bundles the operator-configured cookie attributes
// applied to certctl_session and certctl_csrf cookies. Pulled from
// internal/config Phase 4 SessionConfig.
type SessionCookieAttrs struct {
	SameSite http.SameSite
	Secure   bool // hard-coded true in production via config Validate
}

// =============================================================================
// AuthSessionOIDCHandler.
// =============================================================================

// AuthSessionOIDCHandler ships the Phase 5 surface.
type AuthSessionOIDCHandler struct {
	oidcSvc       OIDCAuthHandshaker
	sessionSvc    SessionMinter
	bclVerifier   BackChannelLogoutVerifier
	providerRepo  repository.OIDCProviderRepository
	mappingRepo   repository.GroupRoleMappingRepository
	sessionRepo   repository.SessionRepository
	userRepo      repository.UserRepository // CRIT-2: BCL sub→actor_id lookup
	bclReplay     BCLReplayConsumer         // HIGH-3: BCL jti consumed-set
	bclMaxAge     time.Duration             // HIGH-3: matches verifier window for TTL
	audit         AuditRecorder
	encryptionKey string
	cookieAttrs   SessionCookieAttrs
	tenantID      string
	postLoginURL  string // 302 target after successful callback (default: /)

	// checker is the optional PermissionChecker projection used for
	// query-parameter-conditional gates that the router-level rbacGate
	// can't express. Audit 2026-05-10 MED-2: ListSessions allows the
	// caller to query their own sessions with auth.session.list, but
	// `?actor_id=<other>` requires the narrower auth.session.list.all.
	// Nil-safe: handlers that don't need conditional gating leave it
	// unset (existing tests).
	checker permissionChecker
}

// permissionChecker is the projection of auth.PermissionChecker the
// session handler uses for query-conditional gates (MED-2). Defined
// locally to avoid importing internal/auth from the handler package
// just for this single use.
type permissionChecker interface {
	CheckPermission(ctx context.Context, actorID, actorType, tenantID, permission, scopeType string, scopeID *string) (bool, error)
}

// WithPermissionChecker installs a PermissionChecker projection on the
// handler. Audit 2026-05-10 MED-2 closure — used by ListSessions to
// gate `?actor_id=<other>` on auth.session.list.all.
func (h *AuthSessionOIDCHandler) WithPermissionChecker(c permissionChecker) *AuthSessionOIDCHandler {
	h.checker = c
	return h
}

// BCLReplayConsumer is the projection of repository.BCLReplayRepository
// the handler uses to record consumed (jti, iss) pairs. Audit 2026-05-10
// HIGH-3 closure. Nil-safe: when unset the handler skips the consume
// step (back-compat for pre-Bundle-2 tests).
type BCLReplayConsumer interface {
	ConsumeJTI(ctx context.Context, jti, issuerURL string, ttl time.Duration) error
}

// AuditRecorder is the slice of *service.AuditService used here.
type AuditRecorder interface {
	RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, category, resourceType, resourceID string, details map[string]interface{}) error
}

// WithBCLReplayConsumer installs the BCL jti consumed-set + TTL on the
// handler. Audit 2026-05-10 HIGH-3 closure. Pre-fix the handler accepted
// any logout_token whose iat + jti were syntactically present;
// captured tokens were replayable indefinitely. Pass nil maxAge to use
// the verifier default (DefaultBCLVerifierMaxAge); the consumed-set
// TTL is set to max(24h, 2 * maxAge) so the replay window covers
// reasonable IdP retry semantics.
func (h *AuthSessionOIDCHandler) WithBCLReplayConsumer(c BCLReplayConsumer, maxAge time.Duration) *AuthSessionOIDCHandler {
	h.bclReplay = c
	if maxAge <= 0 {
		maxAge = DefaultBCLVerifierMaxAge
	}
	h.bclMaxAge = maxAge
	return h
}

// NewAuthSessionOIDCHandler constructs the handler.
//
// userRepo is load-bearing for the BCL sub→actor_id resolution
// (CRIT-2 of the 2026-05-10 audit). Passing nil here is only valid in
// tests that exercise non-BCL paths; production wiring in
// cmd/server/main.go MUST inject a non-nil repository.
func NewAuthSessionOIDCHandler(
	oidcSvc OIDCAuthHandshaker,
	sessionSvc SessionMinter,
	bclVerifier BackChannelLogoutVerifier,
	providerRepo repository.OIDCProviderRepository,
	mappingRepo repository.GroupRoleMappingRepository,
	sessionRepo repository.SessionRepository,
	userRepo repository.UserRepository,
	audit AuditRecorder,
	encryptionKey, tenantID, postLoginURL string,
	cookieAttrs SessionCookieAttrs,
) *AuthSessionOIDCHandler {
	if postLoginURL == "" {
		postLoginURL = "/"
	}
	return &AuthSessionOIDCHandler{
		oidcSvc:       oidcSvc,
		sessionSvc:    sessionSvc,
		bclVerifier:   bclVerifier,
		providerRepo:  providerRepo,
		mappingRepo:   mappingRepo,
		sessionRepo:   sessionRepo,
		userRepo:      userRepo,
		audit:         audit,
		encryptionKey: encryptionKey,
		cookieAttrs:   cookieAttrs,
		tenantID:      tenantID,
		postLoginURL:  postLoginURL,
	}
}

// =============================================================================
// Helpers.
// =============================================================================

// encryptClientSecret wraps internal/crypto.EncryptIfKeySet but with
// empty-passphrase passthrough. Production deployments MUST set
// CERTCTL_CONFIG_ENCRYPTION_KEY (validated at boot in
// internal/config/config.go) so the empty case only fires in tests
// and local-dev builds — the same pattern session.go uses for its
// HMAC-key blob path.
func (h *AuthSessionOIDCHandler) encryptClientSecret(plaintext []byte) ([]byte, error) {
	if h.encryptionKey == "" {
		return plaintext, nil
	}
	blob, _, err := cryptopkg.EncryptIfKeySet(plaintext, h.encryptionKey)
	return blob, err
}

// recordAudit is a thin wrapper that swallows audit-layer errors (the
// audit row is best-effort; a failed audit must not block a successful
// auth operation). Phase 8 contract: every row event_category="auth".
func (h *AuthSessionOIDCHandler) recordAudit(ctx context.Context, action, actor string, actorType domain.ActorType, resourceID string, details map[string]interface{}) {
	if h.audit == nil {
		return
	}
	// Audit 2026-05-10 HIGH-6 partial closure — emit WARN on audit-write
	// failure so the silent row-miss is observable. The transactional-
	// leg WithinTx refactor is a v3 follow-on.
	if err := h.audit.RecordEventWithCategory(ctx, actor, actorType, action,
		domain.EventCategoryAuth, "session", resourceID, details); err != nil {
		slog.WarnContext(ctx, "oidc handler audit write failed (action committed; audit row may be missing)",
			"action", action,
			"actor_id", actor,
			"resource_id", resourceID,
			"err", err)
	}
}

func (h *AuthSessionOIDCHandler) clearPreLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessiondomain.PreLoginCookieName,
		Value: "",
		// Audit 2026-05-10 MED-14 — Path=/ matches the write site
		// post-`__Host-` rename. The browser only clears cookies that
		// match the original Set-Cookie's Name+Path+Domain triple.
		Path:     "/",
		MaxAge:   -1,
		Secure:   h.cookieAttrs.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthSessionOIDCHandler) clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{sessiondomain.PostLoginCookieName, sessiondomain.CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   h.cookieAttrs.Secure,
			HttpOnly: name == sessiondomain.PostLoginCookieName,
			SameSite: h.cookieAttrs.SameSite,
		})
	}
}

func clientIPFromRequest(r *http.Request) string {
	// X-Forwarded-For first hop wins when present.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// RemoteAddr is host:port; strip the port.
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// classifyOIDCFailure maps an OIDC service error to a stable audit
// category string. Used for the failure_category audit detail; the
// wire stays uniform 400.
//
// Audit 2026-05-10 MED-17 — the three iss-related sentinel errors are
// dispatched via errors.Is BEFORE the substring fall-through so they
// stay distinguishable in the audit row:
//   - ErrIssParamMissing  → iss_param_missing
//   - ErrIssParamMismatch → iss_param_mismatch
//   - ErrIssuerMismatch   → id_token_iss_mismatch
//
// errors.Is is used for the iss family because all three error
// strings contain "iss" and substring matching would either collapse
// them or order-dependently mis-classify.
func classifyOIDCFailure(err error) string {
	if err == nil {
		return "ok"
	}
	// Audit 2026-05-10 MED-17 — typed dispatch for the iss family.
	// Audit 2026-05-10 MED-16 — typed dispatch for the UA/IP binding
	// family (no substring guarantees because UA strings are operator
	// data and could match anything).
	switch {
	case errors.Is(err, oidcsvc.ErrIssParamMissing):
		return "iss_param_missing"
	case errors.Is(err, oidcsvc.ErrIssParamMismatch):
		return "iss_param_mismatch"
	case errors.Is(err, oidcsvc.ErrIssuerMismatch):
		return "id_token_iss_mismatch"
	case errors.Is(err, oidcsvc.ErrPreLoginUAMismatch):
		return "prelogin_ua_mismatch"
	case errors.Is(err, oidcsvc.ErrPreLoginIPMismatch):
		return "prelogin_ip_mismatch"
	// Audit 2026-05-11 A-2 — surface deactivated-user rejection as its
	// own audit category so SOC / SIEM can alert on attempted logins by
	// federated users that the admin has soft-deleted. Typed dispatch
	// (not substring) because the sentinel is the only authoritative
	// test for this condition; the message string is implementation
	// detail subject to change.
	case errors.Is(err, oidcsvc.ErrUserDeactivated):
		return "user_deactivated"
	// Audit 2026-05-11 A-6 — strict-when-stored. Distinguishes the
	// new "request omitted the bound header" reject path from the
	// existing "header was supplied but didn't match" path so SIEM
	// rules can alert specifically on attempted bypasses.
	case errors.Is(err, oidcsvc.ErrPreLoginUAMissing):
		return "prelogin_ua_missing"
	case errors.Is(err, oidcsvc.ErrPreLoginIPMissing):
		return "prelogin_ip_missing"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "pre-login"):
		return "pre_login_consume_failed"
	case strings.Contains(msg, "state"):
		return "state_mismatch"
	case strings.Contains(msg, "nonce"):
		return "nonce_mismatch"
	case strings.Contains(msg, "audience"), strings.Contains(msg, "aud"):
		return "audience_mismatch"
	case strings.Contains(msg, "expired"):
		return "token_expired"
	case strings.Contains(msg, "azp"):
		return "azp_mismatch"
	case strings.Contains(msg, "at_hash"):
		return "at_hash_mismatch"
	case strings.Contains(msg, "iat"):
		return "iat_window"
	case strings.Contains(msg, "alg"):
		return "alg_rejected"
	case strings.Contains(msg, "groups did not match"), strings.Contains(msg, "unmapped"):
		return "unmapped_groups"
	case strings.Contains(msg, "groups missing"), strings.Contains(msg, "missing or malformed"):
		return "groups_missing"
	case strings.Contains(msg, "jwks"):
		return "jwks_unreachable"
	// Audit 2026-05-10 HIGH-7 — surface CRIT-5 email-domain rejection
	// + PKCE invalidation distinctly so the LoginPage can render an
	// operator-friendly reason. The sentinel errors live in
	// internal/auth/oidc/service.go (ErrEmailDomainNotAllowed,
	// ErrEmailMissingButRequired, ErrPKCEPlainRejected).
	case strings.Contains(msg, "email domain not in allowlist"):
		return "email_domain_not_allowed"
	case strings.Contains(msg, "requires email but token has none"):
		return "email_missing_but_required"
	case strings.Contains(msg, "pkce"):
		return "pkce_invalid"
	default:
		return "unspecified"
	}
}

func randomB64URLForHandler(n int) string {
	// Audit 2026-05-10 LOW-3 closure — was a time-nano-shifted buffer
	// (two providers created in the same nanosecond would collide). Now
	// crypto/rand: provider/mapping IDs aren't security tokens, but
	// collision-freedom matters for primary keys and entropy is free.
	buf := make([]byte, n)
	if _, err := cryptorand.Read(buf); err != nil {
		// Fall back to time-nano if crypto/rand is broken (extremely
		// unlikely; logged at WARN by the caller's audit row if the ID
		// turns out to clash).
		now := time.Now().UnixNano()
		for i := 0; i < n; i++ {
			buf[i] = byte(now >> (uint(i) * 8))
		}
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func defaultIfBlank(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func defaultIntIfZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
