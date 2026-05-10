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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
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
	HandleAuthRequest(ctx context.Context, providerID string) (authURL, cookieValue, preLoginID string, err error)
	HandleCallback(ctx context.Context, preLoginCookie, code, callbackState, ip, userAgent string) (*oidcsvc.CallbackResult, error)
	RefreshKeys(ctx context.Context, providerID string) error
}

// SessionMinter is the slice of *session.Service the OIDC handler uses.
type SessionMinter interface {
	Create(ctx context.Context, actorID, actorType, ip, userAgent string) (*sessionsvc.CreateResult, error)
	Validate(ctx context.Context, in sessionsvc.ValidateInput) (*sessiondomain.Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAllForActor(ctx context.Context, actorID, actorType string) error
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
// 1. Public OIDC handshake handlers.
// =============================================================================

// LoginInitiate handles GET /auth/oidc/login?provider=<id>.
//
// Generates state + nonce + PKCE-S256 verifier (in OIDCService),
// persists the pre-login row, sets the certctl_oidc_pending cookie,
// 302-redirects to the IdP authorization URL.
func (h *AuthSessionOIDCHandler) LoginInitiate(w http.ResponseWriter, r *http.Request) {
	providerID := strings.TrimSpace(r.URL.Query().Get("provider"))
	if providerID == "" {
		Error(w, http.StatusBadRequest, "missing required query parameter `provider`")
		return
	}
	authURL, cookieValue, _, err := h.oidcSvc.HandleAuthRequest(r.Context(), providerID)
	if err != nil {
		// Provider not found is the most common case; map to 404.
		if errors.Is(err, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		// Other errors (disco fetch failure / IdP downgrade defense /
		// crypto failure) are server-side; surface as 500 without
		// leaking details.
		Error(w, http.StatusInternalServerError, "could not initiate OIDC login")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessiondomain.PreLoginCookieName,
		Value:    cookieValue,
		Path:     "/auth/oidc/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		Secure:   h.cookieAttrs.Secure,
		HttpOnly: true,
		// Pre-login cookie MUST be SameSite=Lax (cannot be Strict
		// because the IdP-initiated callback is a top-level navigation
		// from a different origin per Phase 5 spec).
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// LoginCallback handles GET /auth/oidc/callback?code=...&state=....
//
// Reads the certctl_oidc_pending cookie, drives OIDCService.HandleCallback
// (which parses + HMAC-verifies the cookie, runs the 11-step token
// validation, group-claim resolution, role-mapping, user-upsert),
// mints a post-login session via SessionService.Create, deletes the
// pre-login cookie, sets the post-login cookie + CSRF token cookie,
// and 302's to the dashboard.
func (h *AuthSessionOIDCHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := strings.TrimSpace(q.Get("code"))
	state := strings.TrimSpace(q.Get("state"))
	if code == "" || state == "" {
		Error(w, http.StatusBadRequest, "missing code or state query parameter")
		return
	}
	preLoginCookie, err := r.Cookie(sessiondomain.PreLoginCookieName)
	if err != nil || preLoginCookie.Value == "" {
		Error(w, http.StatusBadRequest, "missing pre-login cookie")
		h.recordAudit(r.Context(), "auth.oidc_login_failed", "anonymous", domain.ActorTypeSystem, "",
			map[string]interface{}{"failure_category": "missing_pre_login_cookie"})
		return
	}
	clientIP := clientIPFromRequest(r)
	userAgent := r.UserAgent()

	res, err := h.oidcSvc.HandleCallback(r.Context(), preLoginCookie.Value, code, state, clientIP, userAgent)
	if err != nil {
		// Audit 2026-05-10 HIGH-7 — instead of a blank 400, redirect
		// to /login?error=oidc_failed&reason=<category>. The LoginPage
		// reads the query params and renders an operator-friendly
		// alert. The audit row still carries the specific
		// failure_category so server-side observability is unchanged.
		category := classifyOIDCFailure(err)
		h.recordAudit(r.Context(), "auth.oidc_login_failed", "anonymous", domain.ActorTypeSystem, "",
			map[string]interface{}{"failure_category": category})
		// Special-case unmapped groups so the audit row name distinguishes
		// it from generic failures (operator-policy decision).
		if category == "unmapped_groups" {
			h.recordAudit(r.Context(), "auth.oidc_login_unmapped_groups", "anonymous", domain.ActorTypeSystem, "",
				map[string]interface{}{})
		}
		// Always clear the pre-login cookie on failure.
		h.clearPreLoginCookie(w)
		// 302 to the login page; the reason categorizes the failure for
		// the GUI to render. Keep the redirect target relative — the
		// SPA serves /login.
		http.Redirect(w, r, "/login?error=oidc_failed&reason="+category, http.StatusFound)
		return
	}

	// res from the OIDC service already carries cookieValue + CSRFToken
	// (the OIDC service wraps SessionService internally per Phase 3).
	// We re-emit them via the standard Set-Cookie helper here so cookie
	// attributes stay handler-controlled.
	now := time.Now().UTC()
	expires := now.Add(8 * time.Hour) // matches default SessionConfig.AbsoluteTimeout
	http.SetCookie(w, &http.Cookie{
		Name:     sessiondomain.PostLoginCookieName,
		Value:    res.CookieValue,
		Path:     "/",
		Expires:  expires,
		Secure:   h.cookieAttrs.Secure,
		HttpOnly: true,
		SameSite: h.cookieAttrs.SameSite,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sessiondomain.CSRFCookieName,
		Value:    res.CSRFToken,
		Path:     "/",
		Expires:  expires,
		Secure:   h.cookieAttrs.Secure,
		HttpOnly: false, // intentional — GUI must read this to echo header
		SameSite: h.cookieAttrs.SameSite,
	})
	h.clearPreLoginCookie(w)

	userID := ""
	if res.User != nil {
		userID = res.User.ID
	}
	h.recordAudit(r.Context(), "auth.oidc_login_succeeded", userID, domain.ActorTypeUser, userID,
		map[string]interface{}{
			"user_id":  userID,
			"role_ids": res.RoleIDs,
		})
	h.recordAudit(r.Context(), "auth.session_created", userID, domain.ActorTypeUser, userID,
		map[string]interface{}{"user_id": userID})

	http.Redirect(w, r, h.postLoginURL, http.StatusFound)
}

// BackChannelLogout handles POST /auth/oidc/back-channel-logout.
//
// OpenID Connect Back-Channel Logout 1.0. The IdP POSTs a logout_token
// JWT in the body (form-encoded `logout_token=<jwt>`); certctl validates
// signature against the IdP's JWKS, validates required claims (iss, aud,
// iat, jti, events; exactly one of sub or sid; nonce ABSENT), revokes
// matching sessions, returns 200 with Cache-Control: no-store. Failure
// modes return 400 per spec §2.6.
func (h *AuthSessionOIDCHandler) BackChannelLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		Error(w, http.StatusBadRequest, "could not parse form body")
		return
	}
	logoutToken := strings.TrimSpace(r.FormValue("logout_token"))
	if logoutToken == "" {
		Error(w, http.StatusBadRequest, "missing logout_token in form body")
		return
	}
	issuer, sub, sid, jti, _, err := h.bclVerifier.Verify(r.Context(), logoutToken)
	if err != nil {
		// Per spec §2.6 — uniform 400 on any validation failure. The
		// audit row carries the specific reason; the wire stays uniform.
		// iat-skew rejections (Audit 2026-05-10 HIGH-3 iat-window check)
		// land here too — the reason string distinguishes them.
		h.recordAudit(r.Context(), "auth.oidc_back_channel_logout_failed", "anonymous", domain.ActorTypeSystem, "",
			map[string]interface{}{"failure_reason": err.Error()})
		Error(w, http.StatusBadRequest, "logout_token validation failed")
		return
	}

	// Audit 2026-05-10 HIGH-3 — jti consumed-set. Atomic single-use
	// semantics via the postgres ON CONFLICT DO NOTHING path. On
	// replay return 200 + audit outcome=jti_replayed (RFC 9700 §2.7).
	// On transient repo error return 503 so the IdP follows its retry
	// semantics. When the consumer is nil (test path / pre-fix
	// deployments) the consume step is skipped.
	if h.bclReplay != nil && jti != "" {
		ttl := h.bclMaxAge * 2
		if ttl < 24*time.Hour {
			ttl = 24 * time.Hour
		}
		if cerr := h.bclReplay.ConsumeJTI(r.Context(), jti, issuer, ttl); cerr != nil {
			if errors.Is(cerr, repository.ErrBCLJTIAlreadyConsumed) {
				h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sub,
					map[string]interface{}{"issuer": issuer, "subject": sub, "jti": jti, "outcome": "jti_replayed"})
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				return
			}
			// Transient — let the IdP retry.
			h.recordAudit(r.Context(), "auth.oidc_back_channel_logout_failed", "anonymous", domain.ActorTypeSystem, sub,
				map[string]interface{}{"issuer": issuer, "subject": sub, "jti": jti, "outcome": "jti_consume_failed", "err": cerr.Error()})
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
	}

	// Resolve target sessions:
	//   - sub set: revoke ALL sessions for the actor (oidc_subject lookup).
	//   - sid set: revoke the specific session_id.
	if sid != "" {
		if rerr := h.sessionSvc.Revoke(r.Context(), sid); rerr != nil {
			// Idempotent at the repo layer; rerr is unlikely. Audit
			// regardless and return 200 (the IdP shouldn't retry on
			// our errors).
			_ = rerr
		}
		h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sid,
			map[string]interface{}{"sub_or_sid": "sid", "issuer": issuer, "session_id": sid})
	} else if sub != "" {
		// CRIT-2 closure of the 2026-05-10 audit. Pre-fix this branch called
		// RevokeAllForActor(sub, "User") under the false assumption that
		// the OIDC subject was used as the actor_id stem. In reality,
		// internal/auth/oidc/service.go::upsertUser mints
		// u.ID = "u-" + randomB64URL(16) and stores the OIDC subject in
		// a separate column, so the pre-fix lookup never found a session
		// row and the error was silently swallowed. BCL silently revoked
		// nothing — CWE-613.
		//
		// The fix resolves the IdP-signed `iss` claim back to a provider
		// row via providerRepo.List + IssuerURL filter, then resolves
		// sub → user.ID via userRepo.GetByOIDCSubject, then revokes all
		// sessions for that actor. Outcome categories audited:
		//   - revoked            (happy path)
		//   - issuer_unknown     (iss doesn't match any configured provider)
		//   - user_unknown       (provider matched, but no user.id seeded for this subject)
		//   - revoke_failed      (DB hiccup at the revoke step)
		//   - provider_lookup_failed / user_lookup_failed → 503 (transient; IdP retries)
		// All success-shaped outcomes return 200 + Cache-Control: no-store
		// per OIDC BCL 1.0 §2.7. Transient errors return 503 so the IdP
		// follows its own retry semantics.
		providers, plerr := h.providerRepo.List(r.Context(), h.tenantID)
		if plerr != nil {
			h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sub,
				map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "provider_lookup_failed"})
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		var matched *oidcdomain.OIDCProvider
		for _, p := range providers {
			if p.IssuerURL == issuer {
				matched = p
				break
			}
		}
		if matched == nil {
			h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sub,
				map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "issuer_unknown"})
			// Idempotent — return 200 per spec.
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			return
		}

		user, uerr := h.userRepo.GetByOIDCSubject(r.Context(), matched.ID, sub)
		if uerr != nil {
			if errors.Is(uerr, repository.ErrUserNotFound) {
				// Idempotent: nothing to revoke. IdP may BCL a user we
				// never logged in. RFC compliance: still 200.
				h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sub,
					map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "user_unknown"})
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				return
			}
			// Transient — let the IdP retry.
			h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", "anonymous", domain.ActorTypeSystem, sub,
				map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "user_lookup_failed"})
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}

		if rerr := h.sessionSvc.RevokeAllForActor(r.Context(), user.ID, string(domain.ActorTypeUser)); rerr != nil {
			// Revoke failed — BCL is best-effort per §2.8; still 200,
			// audit the failure.
			h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", user.ID, domain.ActorTypeUser, sub,
				map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "revoke_failed"})
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			return
		}

		h.recordAudit(r.Context(), "auth.oidc_back_channel_logout", user.ID, domain.ActorTypeUser, sub,
			map[string]interface{}{"sub_or_sid": "sub", "issuer": issuer, "subject": sub, "outcome": "revoked"})
	}
	// Per spec §2.7 — Cache-Control: no-store on success.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// Logout handles POST /auth/logout. Revokes the caller's current
// session. Permission: own session (any authenticated caller).
func (h *AuthSessionOIDCHandler) Logout(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	// Resolve the caller's session via the cookie -> Validate path.
	sessionCookie, cerr := r.Cookie(sessiondomain.PostLoginCookieName)
	if cerr != nil || sessionCookie.Value == "" {
		// No cookie => nothing to revoke; treat as success (idempotent).
		h.clearSessionCookies(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sess, verr := h.sessionSvc.Validate(r.Context(), sessionsvc.ValidateInput{
		CookieValue: sessionCookie.Value,
		ClientIP:    clientIPFromRequest(r),
		UserAgent:   r.UserAgent(),
	})
	if verr != nil {
		// Cookie is invalid; clear + 204 (idempotent).
		h.clearSessionCookies(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if rerr := h.sessionSvc.Revoke(r.Context(), sess.ID); rerr != nil {
		Error(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	h.recordAudit(r.Context(), "auth.session_revoked", caller.ActorID, caller.ActorType, sess.ID,
		map[string]interface{}{"session_id": sess.ID, "self_initiated": true})
	h.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// 2. Session management handlers (RBAC-gated).
// =============================================================================

type sessionResponse struct {
	ID                string `json:"id"`
	ActorID           string `json:"actor_id"`
	ActorType         string `json:"actor_type"`
	IPAddress         string `json:"ip_address,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	CreatedAt         string `json:"created_at"`
	LastSeenAt        string `json:"last_seen_at"`
	IdleExpiresAt     string `json:"idle_expires_at"`
	AbsoluteExpiresAt string `json:"absolute_expires_at"`
	Revoked           bool   `json:"revoked"`
}

func sessionToResponse(s *sessiondomain.Session) sessionResponse {
	return sessionResponse{
		ID:                s.ID,
		ActorID:           s.ActorID,
		ActorType:         s.ActorType,
		IPAddress:         s.IPAddress,
		UserAgent:         s.UserAgent,
		CreatedAt:         s.CreatedAt.UTC().Format(time.RFC3339),
		LastSeenAt:        s.LastSeenAt.UTC().Format(time.RFC3339),
		IdleExpiresAt:     s.IdleExpiresAt.UTC().Format(time.RFC3339),
		AbsoluteExpiresAt: s.AbsoluteExpiresAt.UTC().Format(time.RFC3339),
		Revoked:           s.RevokedAt != nil,
	}
}

// ListSessions handles GET /api/v1/auth/sessions.
//
// Default behavior: list current actor's sessions. With
// ?actor_id=<other> + auth.session.list.all permission: list that
// actor's sessions. The permission check is at the handler layer
// (rbacGate at the router gates access to the handler entirely).
func (h *AuthSessionOIDCHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	// Default to the caller's own sessions.
	actorID := caller.ActorID
	actorType := string(caller.ActorType)
	if q := r.URL.Query().Get("actor_id"); q != "" && q != actorID {
		// Audit 2026-05-10 MED-2 closure — listing a different
		// actor's sessions requires the narrower auth.session.list.all
		// permission. The router gate already enforced
		// auth.session.list (the floor for any session-list call),
		// but the all-actors variant is an admin-class capability and
		// must be checked separately because the rbacGate can't see
		// the query param. When the handler is wired with
		// WithPermissionChecker (production), we re-check inline; when
		// it isn't (legacy tests), the router gate's auth.session.list
		// floor is the only check.
		if h.checker != nil {
			ok, perr := h.checker.CheckPermission(r.Context(),
				caller.ActorID, string(caller.ActorType), h.tenantID,
				"auth.session.list.all", "global", nil)
			if perr != nil {
				Error(w, http.StatusInternalServerError, "permission check failed")
				return
			}
			if !ok {
				Error(w, http.StatusForbidden, "auth.session.list.all required to list another actor's sessions")
				return
			}
		}
		actorID = q
		if at := r.URL.Query().Get("actor_type"); at != "" {
			actorType = at
		}
	}
	sessions, lerr := h.sessionRepo.ListByActor(r.Context(), actorID, actorType, h.tenantID)
	if lerr != nil {
		Error(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	out := make([]sessionResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionToResponse(s))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": out})
}

// RevokeSession handles DELETE /api/v1/auth/sessions/{id}.
func (h *AuthSessionOIDCHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	sessionID := r.PathValue("id")
	if sessionID == "" {
		Error(w, http.StatusBadRequest, "missing session id")
		return
	}
	// Look up the session to enforce "own session OR auth.session.revoke".
	sess, gerr := h.sessionRepo.Get(r.Context(), sessionID)
	if gerr != nil {
		if errors.Is(gerr, repository.ErrSessionNotFound) {
			Error(w, http.StatusNotFound, "session not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not load session")
		return
	}
	// Revoking your own session is always allowed (any authenticated
	// caller). Revoking someone else's session requires the
	// auth.session.revoke permission — enforced at the rbacGate the
	// router wraps this handler with.
	if sess.ActorID == caller.ActorID && sess.ActorType == string(caller.ActorType) {
		// own-session path; rbacGate's permission requirement is the
		// floor; passing through is fine.
	}
	if rerr := h.sessionSvc.Revoke(r.Context(), sessionID); rerr != nil {
		Error(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	h.recordAudit(r.Context(), "auth.session_revoked", caller.ActorID, caller.ActorType, sessionID,
		map[string]interface{}{"session_id": sessionID, "target_actor_id": sess.ActorID})
	w.WriteHeader(http.StatusNoContent)
}

// RevokeAllExceptCurrent handles DELETE /api/v1/auth/sessions?except=current.
//
// Audit 2026-05-10 MED-3 closure — backs the "Sign out all other
// sessions" SessionsPage button. Revokes every active session for the
// caller EXCEPT the session that issued the current request (so the
// user doesn't get logged out by the action they just took).
//
// The current session ID is read from the request's session cookie via
// the SessionMiddleware's actor context — for Bearer-mode callers this
// is the empty string and ALL the actor's sessions are revoked (matches
// the "log me out everywhere" semantic for API-key-mode users).
//
// Audit row records the count for compliance (one summary row per
// invocation; per-session detail is implicit in the count + actor).
func (h *AuthSessionOIDCHandler) RevokeAllExceptCurrent(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if r.URL.Query().Get("except") != "current" {
		Error(w, http.StatusBadRequest, "only ?except=current is supported")
		return
	}
	// Current session ID — empty for Bearer/API-key callers (acceptable;
	// the repo's RevokeAllExceptForActor handles "" by revoking
	// literally every active session). Read from the session middleware's
	// SessionFromContext helper which populates the validated session
	// on the request context for cookie-mode callers.
	currentSessionID := ""
	if sess := sessionsvc.SessionFromContext(r.Context()); sess != nil {
		currentSessionID = sess.ID
	}

	count, rerr := h.sessionRepo.RevokeAllExceptForActor(r.Context(),
		caller.ActorID, string(caller.ActorType), h.tenantID, currentSessionID)
	if rerr != nil {
		Error(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	h.recordAudit(r.Context(), "auth.sessions_revoked_all_except_current",
		caller.ActorID, caller.ActorType, currentSessionID,
		map[string]interface{}{
			"count":              count,
			"current_session_id": currentSessionID,
		})
	writeJSON(w, http.StatusOK, map[string]interface{}{"revoked_count": count})
}

// =============================================================================
// 3. OIDC provider + group-mapping CRUD.
// =============================================================================

type oidcProviderResponse struct {
	ID                  string   `json:"id"`
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	IssuerURL           string   `json:"issuer_url"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	GroupsClaimPath     string   `json:"groups_claim_path"`
	GroupsClaimFormat   string   `json:"groups_claim_format"`
	FetchUserinfo       bool     `json:"fetch_userinfo"`
	Scopes              []string `json:"scopes"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	IATWindowSeconds    int      `json:"iat_window_seconds"`
	JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

func providerToResponse(p *oidcdomain.OIDCProvider) oidcProviderResponse {
	return oidcProviderResponse{
		ID: p.ID, TenantID: p.TenantID, Name: p.Name,
		IssuerURL: p.IssuerURL, ClientID: p.ClientID, RedirectURI: p.RedirectURI,
		GroupsClaimPath: p.GroupsClaimPath, GroupsClaimFormat: p.GroupsClaimFormat,
		FetchUserinfo: p.FetchUserinfo, Scopes: p.Scopes, AllowedEmailDomains: p.AllowedEmailDomains,
		IATWindowSeconds: p.IATWindowSeconds, JWKSCacheTTLSeconds: p.JWKSCacheTTLSeconds,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

type oidcProviderRequest struct {
	Name                string   `json:"name"`
	IssuerURL           string   `json:"issuer_url"`
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"` // plaintext on the wire ONLY at create/update; encrypted at rest
	RedirectURI         string   `json:"redirect_uri"`
	GroupsClaimPath     string   `json:"groups_claim_path"`
	GroupsClaimFormat   string   `json:"groups_claim_format"`
	FetchUserinfo       bool     `json:"fetch_userinfo"`
	Scopes              []string `json:"scopes"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	IATWindowSeconds    int      `json:"iat_window_seconds"`
	JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds"`
}

// ListProviders handles GET /api/v1/auth/oidc/providers.
func (h *AuthSessionOIDCHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	if _, err := callerFromRequest(r); err != nil {
		writeAuthError(w, err)
		return
	}
	provs, err := h.providerRepo.List(r.Context(), h.tenantID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "could not list providers")
		return
	}
	out := make([]oidcProviderResponse, 0, len(provs))
	for _, p := range provs {
		out = append(out, providerToResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"providers": out})
}

// CreateProvider handles POST /api/v1/auth/oidc/providers.
func (h *AuthSessionOIDCHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req oidcProviderRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		Error(w, http.StatusBadRequest, "client_secret is required")
		return
	}
	encrypted, eerr := h.encryptClientSecret([]byte(req.ClientSecret))
	if eerr != nil {
		Error(w, http.StatusInternalServerError, "could not encrypt client secret")
		return
	}
	prov := &oidcdomain.OIDCProvider{
		ID:                    "op-" + randomB64URLForHandler(16),
		TenantID:              h.tenantID,
		Name:                  req.Name,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecretEncrypted: encrypted,
		RedirectURI:           req.RedirectURI,
		GroupsClaimPath:       defaultIfBlank(req.GroupsClaimPath, oidcdomain.DefaultGroupsClaimPath),
		GroupsClaimFormat:     defaultIfBlank(req.GroupsClaimFormat, oidcdomain.GroupsClaimFormatStringArray),
		FetchUserinfo:         req.FetchUserinfo,
		Scopes:                req.Scopes,
		AllowedEmailDomains:   req.AllowedEmailDomains,
		IATWindowSeconds:      defaultIntIfZero(req.IATWindowSeconds, oidcdomain.DefaultIATWindowSeconds),
		JWKSCacheTTLSeconds:   defaultIntIfZero(req.JWKSCacheTTLSeconds, oidcdomain.DefaultJWKSCacheTTLSeconds),
	}
	if verr := prov.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if cerr := h.providerRepo.Create(r.Context(), prov); cerr != nil {
		if errors.Is(cerr, repository.ErrOIDCProviderDuplicateName) {
			Error(w, http.StatusConflict, "provider name already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "could not create provider")
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_created", caller.ActorID, caller.ActorType, prov.ID,
		map[string]interface{}{"provider_id": prov.ID, "name": prov.Name, "issuer_url": prov.IssuerURL})
	writeJSON(w, http.StatusCreated, providerToResponse(prov))
}

// UpdateProvider handles PUT /api/v1/auth/oidc/providers/{id}.
func (h *AuthSessionOIDCHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	existing, gerr := h.providerRepo.Get(r.Context(), id)
	if gerr != nil {
		if errors.Is(gerr, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not load provider")
		return
	}
	var req oidcProviderRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Mutable fields only (id / tenant_id / created_at preserved).
	existing.Name = req.Name
	existing.IssuerURL = req.IssuerURL
	existing.ClientID = req.ClientID
	existing.RedirectURI = req.RedirectURI
	existing.GroupsClaimPath = defaultIfBlank(req.GroupsClaimPath, existing.GroupsClaimPath)
	existing.GroupsClaimFormat = defaultIfBlank(req.GroupsClaimFormat, existing.GroupsClaimFormat)
	existing.FetchUserinfo = req.FetchUserinfo
	existing.Scopes = req.Scopes
	existing.AllowedEmailDomains = req.AllowedEmailDomains
	if req.IATWindowSeconds != 0 {
		existing.IATWindowSeconds = req.IATWindowSeconds
	}
	if req.JWKSCacheTTLSeconds != 0 {
		existing.JWKSCacheTTLSeconds = req.JWKSCacheTTLSeconds
	}
	// Re-encrypt client_secret only if a new one is supplied; empty
	// preserves the existing ciphertext.
	if strings.TrimSpace(req.ClientSecret) != "" {
		encrypted, eerr := h.encryptClientSecret([]byte(req.ClientSecret))
		if eerr != nil {
			Error(w, http.StatusInternalServerError, "could not encrypt client secret")
			return
		}
		existing.ClientSecretEncrypted = encrypted
	}
	if verr := existing.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if uerr := h.providerRepo.Update(r.Context(), existing); uerr != nil {
		Error(w, http.StatusInternalServerError, "could not update provider")
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_updated", caller.ActorID, caller.ActorType, existing.ID,
		map[string]interface{}{"provider_id": existing.ID, "name": existing.Name})
	writeJSON(w, http.StatusOK, providerToResponse(existing))
}

// DeleteProvider handles DELETE /api/v1/auth/oidc/providers/{id}.
// Refused when at least one user has authenticated via this provider.
func (h *AuthSessionOIDCHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	if derr := h.providerRepo.Delete(r.Context(), id); derr != nil {
		switch {
		case errors.Is(derr, repository.ErrOIDCProviderNotFound):
			Error(w, http.StatusNotFound, "provider not found")
		case errors.Is(derr, repository.ErrOIDCProviderInUse):
			Error(w, http.StatusConflict, "provider has authenticated users; revoke all sessions before delete")
		default:
			Error(w, http.StatusInternalServerError, "could not delete provider")
		}
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_deleted", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"provider_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// RefreshProvider handles POST /api/v1/auth/oidc/providers/{id}/refresh.
// Forces re-fetch of the IdP discovery doc + JWKS, re-runs the IdP
// downgrade-attack defense.
func (h *AuthSessionOIDCHandler) RefreshProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	if rerr := h.oidcSvc.RefreshKeys(r.Context(), id); rerr != nil {
		if errors.Is(rerr, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		Error(w, http.StatusBadRequest, "refresh failed: "+rerr.Error())
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_refreshed", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"provider_id": id})
	writeJSON(w, http.StatusOK, map[string]interface{}{"refreshed": true})
}

type groupMappingResponse struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	GroupName  string `json:"group_name"`
	RoleID     string `json:"role_id"`
	TenantID   string `json:"tenant_id"`
	CreatedAt  string `json:"created_at"`
}

func mappingToResponse(m *oidcdomain.GroupRoleMapping) groupMappingResponse {
	return groupMappingResponse{
		ID: m.ID, ProviderID: m.ProviderID, GroupName: m.GroupName,
		RoleID: m.RoleID, TenantID: m.TenantID,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type groupMappingRequest struct {
	ProviderID string `json:"provider_id"`
	GroupName  string `json:"group_name"`
	RoleID     string `json:"role_id"`
}

// ListGroupMappings handles GET /api/v1/auth/oidc/group-mappings?provider_id=<id>.
func (h *AuthSessionOIDCHandler) ListGroupMappings(w http.ResponseWriter, r *http.Request) {
	if _, err := callerFromRequest(r); err != nil {
		writeAuthError(w, err)
		return
	}
	providerID := strings.TrimSpace(r.URL.Query().Get("provider_id"))
	if providerID == "" {
		Error(w, http.StatusBadRequest, "missing required query parameter `provider_id`")
		return
	}
	mappings, lerr := h.mappingRepo.ListByProvider(r.Context(), providerID)
	if lerr != nil {
		Error(w, http.StatusInternalServerError, "could not list mappings")
		return
	}
	out := make([]groupMappingResponse, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, mappingToResponse(m))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"mappings": out})
}

// AddGroupMapping handles POST /api/v1/auth/oidc/group-mappings.
func (h *AuthSessionOIDCHandler) AddGroupMapping(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req groupMappingRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	mapping := &oidcdomain.GroupRoleMapping{
		ID:         "grm-" + randomB64URLForHandler(16),
		ProviderID: req.ProviderID,
		GroupName:  req.GroupName,
		RoleID:     req.RoleID,
		TenantID:   h.tenantID,
	}
	if verr := mapping.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if aerr := h.mappingRepo.Add(r.Context(), mapping); aerr != nil {
		if errors.Is(aerr, repository.ErrGroupRoleMappingDuplicate) {
			Error(w, http.StatusConflict, "mapping already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "could not add mapping")
		return
	}
	h.recordAudit(r.Context(), "auth.group_mapping_added", caller.ActorID, caller.ActorType, mapping.ID,
		map[string]interface{}{
			"mapping_id": mapping.ID, "provider_id": mapping.ProviderID,
			"group_name": mapping.GroupName, "role_id": mapping.RoleID,
		})
	writeJSON(w, http.StatusCreated, mappingToResponse(mapping))
}

// RemoveGroupMapping handles DELETE /api/v1/auth/oidc/group-mappings/{id}.
func (h *AuthSessionOIDCHandler) RemoveGroupMapping(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing mapping id")
		return
	}
	if rerr := h.mappingRepo.Remove(r.Context(), id); rerr != nil {
		if errors.Is(rerr, repository.ErrGroupRoleMappingNotFound) {
			Error(w, http.StatusNotFound, "mapping not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not remove mapping")
		return
	}
	h.recordAudit(r.Context(), "auth.group_mapping_removed", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"mapping_id": id})
	w.WriteHeader(http.StatusNoContent)
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
		Name:     sessiondomain.PreLoginCookieName,
		Value:    "",
		Path:     "/auth/oidc/",
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
func classifyOIDCFailure(err error) string {
	if err == nil {
		return "ok"
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

// =============================================================================
// Default BackChannelLogoutVerifier — wraps go-oidc/v3.
// =============================================================================

// DefaultBCLVerifier is the production BackChannelLogoutVerifier. It
// resolves the IdP by issuer (matched against the OIDCProviderRepository),
// fetches the IdP's JWKS via gooidc.Provider, and validates the
// logout_token JWT signature + required claims.
// DefaultBCLVerifierMaxAge is the default iat-freshness skew window
// (60 seconds; tokens older or newer than this are rejected). Override
// per-server via CERTCTL_OIDC_BCL_MAX_AGE_SECONDS. Audit 2026-05-10
// HIGH-3 closure.
const DefaultBCLVerifierMaxAge = 60 * time.Second

type DefaultBCLVerifier struct {
	providerRepo repository.OIDCProviderRepository
	tenantID     string
	allowedAlgs  []string
	// maxAge is the iat-freshness skew window. Tokens with iat in the
	// past beyond this OR in the future beyond this are rejected. Set
	// via WithMaxAge; defaults to DefaultBCLVerifierMaxAge.
	maxAge time.Duration
	// nowFn is the clock seam (test injection).
	nowFn func() time.Time

	// Injectable for tests so unit tests don't hit a real IdP.
	verifyOverride func(ctx context.Context, providerIssuer, rawIDToken string) (*gooidc.IDToken, error)
}

// NewDefaultBCLVerifier constructs a verifier wired against the given
// provider repo + tenant.
func NewDefaultBCLVerifier(providerRepo repository.OIDCProviderRepository, tenantID string, allowedAlgs []string) *DefaultBCLVerifier {
	if len(allowedAlgs) == 0 {
		allowedAlgs = []string{
			gooidc.RS256, gooidc.RS512, gooidc.ES256, gooidc.ES384, gooidc.EdDSA,
		}
	}
	return &DefaultBCLVerifier{
		providerRepo: providerRepo,
		tenantID:     tenantID,
		allowedAlgs:  allowedAlgs,
		maxAge:       DefaultBCLVerifierMaxAge,
		nowFn:        time.Now,
	}
}

// WithMaxAge returns a copy of the verifier with the iat-skew window
// overridden. Audit 2026-05-10 HIGH-3 — operator-configurable via
// CERTCTL_OIDC_BCL_MAX_AGE_SECONDS at cmd/server/main.go.
func (v *DefaultBCLVerifier) WithMaxAge(d time.Duration) *DefaultBCLVerifier {
	v.maxAge = d
	return v
}

// Verify implements BackChannelLogoutVerifier.
func (v *DefaultBCLVerifier) Verify(ctx context.Context, logoutToken string) (issuer, sub, sid, jti string, iat int64, err error) {
	// We don't know which provider the logout_token came from until we
	// peek at the iss claim. Parse-without-verify, look up the matching
	// provider, then verify against that provider's JWKS.
	iss, peekErr := peekIssuer(logoutToken)
	if peekErr != nil {
		return "", "", "", "", 0, fmt.Errorf("peek issuer: %w", peekErr)
	}
	provs, lerr := v.providerRepo.List(ctx, v.tenantID)
	if lerr != nil {
		return "", "", "", "", 0, fmt.Errorf("list providers: %w", lerr)
	}
	var matched *oidcdomain.OIDCProvider
	for _, p := range provs {
		if p.IssuerURL == iss {
			matched = p
			break
		}
	}
	if matched == nil {
		return "", "", "", "", 0, fmt.Errorf("no provider configured for issuer %q", iss)
	}

	var idToken *gooidc.IDToken
	if v.verifyOverride != nil {
		idToken, err = v.verifyOverride(ctx, matched.IssuerURL, logoutToken)
	} else {
		provider, perr := gooidc.NewProvider(ctx, matched.IssuerURL)
		if perr != nil {
			return "", "", "", "", 0, fmt.Errorf("provider discovery: %w", perr)
		}
		verifier := provider.Verifier(&gooidc.Config{
			ClientID:             matched.ClientID,
			SupportedSigningAlgs: v.allowedAlgs,
			SkipExpiryCheck:      true, // OIDC BCL §2.4 — no exp claim required
		})
		idToken, err = verifier.Verify(ctx, logoutToken)
	}
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("verify: %w", err)
	}

	// Required claims per spec §2.4.
	var claims struct {
		Iss    string                 `json:"iss"`
		Aud    interface{}            `json:"aud"`
		Iat    int64                  `json:"iat"`
		Jti    string                 `json:"jti"`
		Events map[string]interface{} `json:"events"`
		Sub    string                 `json:"sub"`
		Sid    string                 `json:"sid"`
		Nonce  string                 `json:"nonce"`
	}
	if cerr := idToken.Claims(&claims); cerr != nil {
		return "", "", "", "", 0, fmt.Errorf("claims unmarshal: %w", cerr)
	}
	if claims.Iat == 0 {
		return "", "", "", "", 0, errors.New("missing iat claim")
	}
	// Audit 2026-05-10 HIGH-3 — iat freshness check. Reject tokens
	// whose iat is outside the skew window. RFC 9700 §2.7 + the
	// existing ID-token-path skew tolerance (oidc/service.go:463).
	maxAge := v.maxAge
	if maxAge <= 0 {
		maxAge = DefaultBCLVerifierMaxAge
	}
	now := v.nowFn().UTC()
	iatTime := time.Unix(claims.Iat, 0).UTC()
	if iatTime.After(now.Add(maxAge)) {
		return "", "", "", "", 0, fmt.Errorf("iat is in the future beyond max-age %s", maxAge)
	}
	if now.Sub(iatTime) > maxAge {
		return "", "", "", "", 0, fmt.Errorf("iat is stale (age %s > max-age %s)", now.Sub(iatTime), maxAge)
	}
	if claims.Jti == "" {
		return "", "", "", "", 0, errors.New("missing jti claim")
	}
	if claims.Events == nil {
		return "", "", "", "", 0, errors.New("missing events claim")
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return "", "", "", "", 0, errors.New("events claim missing back-channel-logout URI")
	}
	if claims.Nonce != "" {
		// Spec §2.4: nonce MUST NOT be present.
		return "", "", "", "", 0, errors.New("nonce claim must be absent in logout_token")
	}
	if claims.Sub == "" && claims.Sid == "" {
		return "", "", "", "", 0, errors.New("logout_token must carry sub or sid")
	}
	return claims.Iss, claims.Sub, claims.Sid, claims.Jti, claims.Iat, nil
}

// peekIssuer base64-decodes the JWT payload (segment 1 after the `.`)
// and pulls the `iss` claim out without verifying the signature. Used
// to find the matching provider before we know which JWKS to use.
// peekIssuer extracts the `iss` claim from an unsigned JWT payload —
// used by the BCL handler to route the logout_token to the right
// provider for verification.
//
// Audit 2026-05-10 Nit-3 — peekIssuer is INTENTIONALLY unsigned-permissive.
// The returned issuer is used ONLY to select the verifier; the full
// signature + claim verification happens in DefaultBCLVerifier.Verify
// (which re-checks the `iss` claim against the matched provider's
// IssuerURL after JWS signature validation). Callers MUST NOT trust
// peekIssuer output for any access-control decision before the verify
// step completes; the pin is encoded in the BCL handler's call shape
// (peek → match provider → verify-against-provider → consume).
func peekIssuer(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("expected 3 JWT segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload base64: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if jerr := json.Unmarshal(payload, &c); jerr != nil {
		return "", fmt.Errorf("payload json: %w", jerr)
	}
	if c.Iss == "" {
		return "", errors.New("missing iss claim in payload")
	}
	return c.Iss, nil
}
