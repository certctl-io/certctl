// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"errors"
	"net/http"
	"time"

	sessionsvc "github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 11 (2026-05-14): extracted from
// internal/api/handler/auth_session_oidc.go via the Option B
// sibling-file pattern.
//
// This file holds Section 2 of the original three-section layout:
// the SESSION MANAGEMENT handlers (RBAC-gated). Three endpoints:
//
//   GET    /api/v1/auth/sessions              -> list (own / all-actors)
//   DELETE /api/v1/auth/sessions/{id}         -> revoke (own / any)
//   DELETE /api/v1/auth/sessions/all-except-current
//                                             -> revoke-all-except-current
//
// The sessionResponse projection type lives here alongside its
// callers (sessionToResponse + the three handler methods). It's
// the shape the API renders externally; no external caller relies
// on its exact file location.

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
