// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package handler — Auth Bundle 2 Phase 7.5 / break-glass admin HTTP surface.
//
// 4 endpoints across two access levels:
//
//  1. Public (auth-bypass; the whole point is to log in WITHOUT
//     existing creds):
//     POST /auth/breakglass/login
//     Rate-limited at 5/minute per source IP via the existing
//     rate limiter middleware. When CERTCTL_BREAKGLASS_ENABLED=false,
//     returns 404 (NOT 403) so the surface is invisible to scanners.
//
//  2. RBAC-gated (auth.breakglass.admin):
//     POST   /api/v1/auth/breakglass/credentials
//     POST   /api/v1/auth/breakglass/credentials/{actor_id}/unlock
//     DELETE /api/v1/auth/breakglass/credentials/{actor_id}
//
// The handler delegates to internal/auth/breakglass.Service for the
// load-bearing logic (Argon2id hashing, lockout state machine,
// constant-time-compare, identical-shape errors). This file is purely
// HTTP shape — request-binding, status-code mapping, audit attribution
// for the caller-actor-id wire-up.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/auth/breakglass"
	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/ratelimit"
)

// =============================================================================
// AuthBreakglassHandler.
// =============================================================================

// BreakglassService is the projection of *breakglass.Service the
// handler consumes. Defining the projection here keeps the handler
// stub-friendly + decoupled from the wider service surface.
type BreakglassService interface {
	Enabled() bool
	SetPassword(ctx context.Context, callerActorID, targetActorID, plaintext string) (*breakglass.SetPasswordResult, error)
	Authenticate(ctx context.Context, actorID, plaintext, ip, userAgent string) (*breakglass.AuthenticateResult, error)
	Unlock(ctx context.Context, callerActorID, targetActorID string) error
	RemoveCredential(ctx context.Context, callerActorID, targetActorID string) error
	List(ctx context.Context) ([]*bgdomain.BreakglassCredential, error)
}

// AuthBreakglassHandler ships the Phase 7.5 surface.
//
// Bundle 5 closure (S1): the docstring at the top of this file claimed
// the login endpoint was "Rate-limited at 5/minute per source IP via
// the existing rate limiter middleware" but no per-route limiter was
// wired — `/auth/breakglass/login` is registered via `r.mux.Handle`
// in router.go::AuthExemptRouterRoutes and bypasses the global RPS
// middleware that wraps `r.Register`-mounted routes. The login handler
// now owns its own SlidingWindowLimiter (5 attempts / minute / source
// IP, 50 000 key cap) so the documented behavior actually ships.
//
// Wired at startup via SetLoginRateLimiter (called from cmd/server/main.go
// alongside the other per-handler rate limiters that close audit
// findings H-9 / H-12 / Bundle 3 D7 / etc.). Defense-in-depth: even
// when the limiter is nil (legacy / test), the service-layer Argon2id
// lockout state machine still protects against brute force — but a
// nil limiter is a misconfiguration the integration test catches.
type AuthBreakglassHandler struct {
	svc         BreakglassService
	cookieAttrs SessionCookieAttrs
	// loginLimiter rate-limits POST /auth/breakglass/login by source IP.
	// nil-safe: when unset, the handler skips the limiter check and
	// relies on the service-layer Argon2id lockout. Production deploys
	// MUST set this via SetLoginRateLimiter.
	loginLimiter *ratelimit.SlidingWindowLimiter
}

// NewAuthBreakglassHandler constructs the handler.
func NewAuthBreakglassHandler(svc BreakglassService, cookieAttrs SessionCookieAttrs) *AuthBreakglassHandler {
	return &AuthBreakglassHandler{svc: svc, cookieAttrs: cookieAttrs}
}

// SetLoginRateLimiter wires the per-source-IP rate limiter the Login
// handler enforces. Bundle 5 closure (S1) — see the AuthBreakglassHandler
// type docstring for the full rationale.
func (h *AuthBreakglassHandler) SetLoginRateLimiter(l *ratelimit.SlidingWindowLimiter) {
	h.loginLimiter = l
}

// =============================================================================
// 1. Public login endpoint.
// =============================================================================

type breakglassLoginRequest struct {
	ActorID  string `json:"actor_id"`
	Password string `json:"password"`
}

// Login handles POST /auth/breakglass/login.
//
// Auth-bypass — the whole point is to log in WITHOUT existing creds.
// When Service.Enabled() == false, returns 404 (NOT 403) so the surface
// is invisible to scanners. On success, sets the post-login session
// cookie + CSRF cookie + 204 No Content. On any failure (wrong password,
// locked account, no credential, unknown actor): uniform 401 + identical
// timing.
func (h *AuthBreakglassHandler) Login(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Enabled() {
		// Surface invisibility — 404 (NOT 403) per Phase 7.5 spec.
		http.NotFound(w, r)
		return
	}
	var req breakglassLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Even invalid JSON returns 401 (identical to wrong-password) —
		// no scanner-friendly 400 that distinguishes "wrong shape" vs
		// "wrong password".
		Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if strings.TrimSpace(req.ActorID) == "" || req.Password == "" {
		Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ip := clientIPFromRequest(r)

	// Bundle 5 closure (S1): per-source-IP rate limit. 5 attempts /
	// minute / IP (default; configurable via the constructor at
	// cmd/server/main.go). Returns 429 with no body so the response
	// shape matches the rest of the auth surface (scanner-unfriendly).
	// Audited by the service layer on the next attempt — we don't
	// audit the rate-limit hit itself here because that would let an
	// attacker flood the audit table with rate-limit rows from a
	// single IP.
	if h.loginLimiter != nil {
		if err := h.loginLimiter.Allow(ip, time.Now()); err != nil {
			Error(w, http.StatusTooManyRequests, "too many requests")
			return
		}
	}

	res, err := h.svc.Authenticate(r.Context(), req.ActorID, req.Password, ip, r.UserAgent())
	if err != nil {
		// All authenticate errors map to the SAME 401 + same body.
		// The service has already audited the specific failure category.
		Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Set the post-login session cookie + CSRF cookie. Same attributes
	// as the OIDC callback handler in auth_session_oidc.go; we
	// duplicate the 8-line cookie-set block here so the break-glass
	// handler doesn't import the OIDC handler package.
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
		HttpOnly: false, // intentional — GUI must read it
		SameSite: h.cookieAttrs.SameSite,
	})
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// 2. Admin endpoints.
// =============================================================================

type breakglassSetPasswordRequest struct {
	ActorID  string `json:"actor_id"`
	Password string `json:"password"`
}

// SetPassword handles POST /api/v1/auth/breakglass/credentials.
// Permission: auth.breakglass.admin (gated at the router via rbacGate).
//
// When Service.Enabled() == false, returns 404 — admin endpoints share
// the surface-invisibility property with the login endpoint so an
// attacker probing for break-glass via the admin surface gets the same
// signal as probing the login endpoint.
func (h *AuthBreakglassHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Enabled() {
		http.NotFound(w, r)
		return
	}
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req breakglassSetPasswordRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, serr := h.svc.SetPassword(r.Context(), caller.ActorID, req.ActorID, req.Password)
	if serr != nil {
		switch {
		case errors.Is(serr, breakglass.ErrWeakPassword):
			Error(w, http.StatusBadRequest, "password fails strength requirements (min 12 bytes, max 256 bytes)")
		case errors.Is(serr, breakglass.ErrUnauthenticated):
			Error(w, http.StatusUnauthorized, "Authentication required")
		case errors.Is(serr, breakglass.ErrDisabled):
			http.NotFound(w, r)
		default:
			Error(w, http.StatusInternalServerError, "could not set password")
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"actor_id":   res.ActorID,
		"created_at": res.CreatedAt.Format(time.RFC3339),
	})
}

// Unlock handles POST /api/v1/auth/breakglass/credentials/{actor_id}/unlock.
// Permission: auth.breakglass.admin.
func (h *AuthBreakglassHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Enabled() {
		http.NotFound(w, r)
		return
	}
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	targetID := r.PathValue("actor_id")
	if targetID == "" {
		Error(w, http.StatusBadRequest, "missing actor_id path param")
		return
	}
	if uerr := h.svc.Unlock(r.Context(), caller.ActorID, targetID); uerr != nil {
		switch {
		case errors.Is(uerr, breakglass.ErrDisabled):
			http.NotFound(w, r)
		case errors.Is(uerr, breakglass.ErrUnauthenticated):
			Error(w, http.StatusUnauthorized, "Authentication required")
		default:
			// repository.ErrBreakglassNotFound surfaces as a wrapped
			// error here; we map to 404 via string match to avoid
			// importing repository.
			if strings.Contains(uerr.Error(), "not found") {
				Error(w, http.StatusNotFound, "credential not found")
			} else {
				Error(w, http.StatusInternalServerError, "could not unlock credential")
			}
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Remove handles DELETE /api/v1/auth/breakglass/credentials/{actor_id}.
// Permission: auth.breakglass.admin.
func (h *AuthBreakglassHandler) Remove(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Enabled() {
		http.NotFound(w, r)
		return
	}
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	targetID := r.PathValue("actor_id")
	if targetID == "" {
		Error(w, http.StatusBadRequest, "missing actor_id path param")
		return
	}
	if rerr := h.svc.RemoveCredential(r.Context(), caller.ActorID, targetID); rerr != nil {
		switch {
		case errors.Is(rerr, breakglass.ErrDisabled):
			http.NotFound(w, r)
		case errors.Is(rerr, breakglass.ErrUnauthenticated):
			Error(w, http.StatusUnauthorized, "Authentication required")
		default:
			if strings.Contains(rerr.Error(), "not found") {
				Error(w, http.StatusNotFound, "credential not found")
			} else {
				Error(w, http.StatusInternalServerError, "could not remove credential")
			}
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// breakglassCredentialResponse is the wire shape returned by ListCredentials.
// Intentionally omits PasswordHash — the admin GUI only needs metadata to
// render the credentialed-actor table.
type breakglassCredentialResponse struct {
	ActorID              string  `json:"actor_id"`
	CreatedAt            string  `json:"created_at"`
	LastPasswordChangeAt string  `json:"last_password_change_at"`
	FailureCount         int     `json:"failure_count"`
	LockedUntil          *string `json:"locked_until,omitempty"`
	LastFailureAt        *string `json:"last_failure_at,omitempty"`
}

type listBreakglassCredentialsResponse struct {
	Credentials []breakglassCredentialResponse `json:"credentials"`
}

// ListCredentials handles GET /api/v1/auth/breakglass/credentials.
// Permission: auth.breakglass.admin.
//
// Audit 2026-05-10 CRIT-4 closure — backs the admin GUI Break-glass
// page. Returns 404 when CERTCTL_BREAKGLASS_ENABLED=false (surface
// invisibility, consistent with the other break-glass admin endpoints).
// The password hash is NEVER serialized to the wire.
func (h *AuthBreakglassHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Enabled() {
		http.NotFound(w, r)
		return
	}
	creds, err := h.svc.List(r.Context())
	if err != nil {
		if errors.Is(err, breakglass.ErrDisabled) {
			http.NotFound(w, r)
			return
		}
		Error(w, http.StatusInternalServerError, "could not list break-glass credentials")
		return
	}
	resp := listBreakglassCredentialsResponse{Credentials: make([]breakglassCredentialResponse, 0, len(creds))}
	for _, c := range creds {
		row := breakglassCredentialResponse{
			ActorID:              c.ActorID,
			CreatedAt:            c.CreatedAt.UTC().Format(time.RFC3339),
			LastPasswordChangeAt: c.LastPasswordChangeAt.UTC().Format(time.RFC3339),
			FailureCount:         c.FailureCount,
		}
		if c.LockedUntil != nil {
			s := c.LockedUntil.UTC().Format(time.RFC3339)
			row.LockedUntil = &s
		}
		if c.LastFailureAt != nil {
			s := c.LastFailureAt.UTC().Format(time.RFC3339)
			row.LastFailureAt = &s
		}
		resp.Credentials = append(resp.Credentials, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
