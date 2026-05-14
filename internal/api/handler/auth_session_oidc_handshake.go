// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	sessionsvc "github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 11 (2026-05-14): extracted from
// internal/api/handler/auth_session_oidc.go via the Option B
// sibling-file pattern. Package stays `handler`; every external
// caller of `handler.AuthSessionOIDCHandler.{LoginInitiate,
// LoginCallback, BackChannelLogout, Logout}` resolves the same
// way — pure mechanical relocation. The router wiring in
// internal/api/router/router.go is unaffected.
//
// This file holds Section 1 of the original file's three-section
// layout (per its own package doc-comment): the PUBLIC OIDC
// HANDSHAKE handlers. These four endpoints are auth-exempt — they
// run before the caller has a certctl-issued credential:
//
//   GET  /auth/oidc/login?provider=<id>          -> 302 to IdP
//   GET  /auth/oidc/callback?code=...&state=...  -> consume + mint
//   POST /auth/oidc/back-channel-logout          -> IdP-initiated
//   POST /auth/logout                            -> revoke caller's
//
// Helpers (h.clearPreLoginCookie / h.clearSessionCookies /
// h.recordAudit / clientIPFromRequest / classifyOIDCFailure) stay
// in auth_session_oidc.go alongside the AuthSessionOIDCHandler
// struct + constructor — same-package resolution makes the calls
// reach across the file boundary at zero compile-time cost.

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
	// Audit 2026-05-10 MED-16 — capture clientIP + UA at /auth/oidc/login
	// so HandleCallback can reject a stolen pre-login cookie replayed
	// from a different browser/source. clientIPFromRequest already
	// honours the LOW-5 trusted-proxy gating; r.UserAgent() reads the
	// header verbatim.
	loginIP := clientIPFromRequest(r)
	loginUA := r.UserAgent()
	authURL, cookieValue, _, err := h.oidcSvc.HandleAuthRequest(r.Context(), providerID, loginIP, loginUA)
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
		Name:  sessiondomain.PreLoginCookieName,
		Value: cookieValue,
		// Audit 2026-05-10 MED-14 — `__Host-` prefix requires Path=/.
		// The cookie lives 10 minutes and is only ever consumed by the
		// callback handler; the wider path scope is harmless.
		Path:     "/",
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
	// Audit 2026-05-10 MED-17 — RFC 9207 iss URL parameter. NOT
	// trimmed; preserved exactly as sent so the service-layer compare
	// against the matched provider's IssuerURL is byte-strict. The IdP
	// emits this only when advertised in its discovery doc; the
	// service-layer check is a no-op otherwise.
	callbackIss := q.Get("iss")
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

	res, err := h.oidcSvc.HandleCallback(r.Context(), preLoginCookie.Value, code, state, callbackIss, clientIP, userAgent)
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
	// Audit 2026-05-11 Fix 13 — HIGH-2 fourth call site. Rotate the CSRF
	// token on the actor's remaining sessions so a token captured in
	// this device's browser pre-logout (DevTools, malicious extension,
	// session-storage leak) can't be replayed against a sibling session
	// (other browser, other device) after the user logged out here.
	// The just-revoked session also rotates but its CSRF lookup will
	// fail at the sessions table's revoked_at IS NOT NULL filter
	// anyway; rotation on the revoked row is harmless. RotateCSRFTokenForActor
	// returns the count rotated and NEVER errors — rotation is defense
	// in depth and must not block the logout success.
	rotated := h.sessionSvc.RotateCSRFTokenForActor(r.Context(), caller.ActorID, string(caller.ActorType))
	h.recordAudit(r.Context(), "auth.session_revoked", caller.ActorID, caller.ActorType, sess.ID,
		map[string]interface{}{"session_id": sess.ID, "self_initiated": true, "csrf_rotated": rotated})
	h.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}
