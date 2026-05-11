package handler

// Audit 2026-05-10 MED-11 closure — federated-user admin surface.
//
// GET    /api/v1/auth/users          → gated auth.user.read
// DELETE /api/v1/auth/users/{id}     → gated auth.user.deactivate
//
// The DELETE path is SOFT-DELETE — it sets users.deactivated_at and
// cascade-revokes the user's active sessions in the same operation.
// The row is the OIDC binding (tuple of (oidc_provider_id, oidc_subject));
// destroying it would re-mint a fresh user on the next IdP login under
// the same subject, losing the audit trail.

import (
	"context"
	"errors"
	"net/http"
	"time"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// AuthUsersHandler exposes the federated-user admin surface.
type AuthUsersHandler struct {
	users    repository.UserRepository
	sessions UserSessionsRevoker
	audit    AuditRecorder
	tenantID string
}

// UserSessionsRevoker is the slice of *session.Service the user-handler
// uses to cascade-revoke a deactivated user's active sessions in the
// same operation. Nil-safe: when unset (tests without session wiring),
// Deactivate logs an audit row but skips the revoke step.
type UserSessionsRevoker interface {
	RevokeAllForActor(ctx context.Context, actorID, actorType string) error
}

// NewAuthUsersHandler constructs a federated-user admin handler.
func NewAuthUsersHandler(users repository.UserRepository, sessions UserSessionsRevoker, audit AuditRecorder, tenantID string) *AuthUsersHandler {
	return &AuthUsersHandler{users: users, sessions: sessions, audit: audit, tenantID: tenantID}
}

type userResponse struct {
	ID             string  `json:"id"`
	TenantID       string  `json:"tenant_id"`
	Email          string  `json:"email"`
	DisplayName    string  `json:"display_name"`
	OIDCSubject    string  `json:"oidc_subject"`
	OIDCProviderID string  `json:"oidc_provider_id"`
	LastLoginAt    string  `json:"last_login_at"`
	CreatedAt      string  `json:"created_at"`
	DeactivatedAt  *string `json:"deactivated_at,omitempty"`
}

func userToResponse(u *userdomain.User) userResponse {
	r := userResponse{
		ID:             u.ID,
		TenantID:       u.TenantID,
		Email:          u.Email,
		DisplayName:    u.DisplayName,
		OIDCSubject:    u.OIDCSubject,
		OIDCProviderID: u.OIDCProviderID,
		LastLoginAt:    u.LastLoginAt.UTC().Format(time.RFC3339),
		CreatedAt:      u.CreatedAt.UTC().Format(time.RFC3339),
	}
	if u.DeactivatedAt != nil {
		s := u.DeactivatedAt.UTC().Format(time.RFC3339)
		r.DeactivatedAt = &s
	}
	return r
}

// List returns every user in the active tenant. Pagination + filter
// are accepted as query parameters; the repository's ListAll returns
// every row and we filter client-side for simplicity.
func (h *AuthUsersHandler) List(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	users, lerr := h.users.ListAll(r.Context(), h.tenantID)
	if lerr != nil {
		Error(w, http.StatusInternalServerError, "could not list users")
		return
	}
	providerFilter := r.URL.Query().Get("oidc_provider_id")
	out := make([]userResponse, 0, len(users))
	for _, u := range users {
		if providerFilter != "" && u.OIDCProviderID != providerFilter {
			continue
		}
		out = append(out, userToResponse(u))
	}
	_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.user_list",
		domain.EventCategoryAuth, "user", "",
		map[string]interface{}{"count": len(out), "provider_filter": providerFilter})
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": out})
}

// Deactivate sets deactivated_at on the user and cascade-revokes
// active sessions. Returns 204 on success.
func (h *AuthUsersHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing user id")
		return
	}
	// Audit 2026-05-11 A-2 — self-deactivate guard. An admin that
	// deactivates their own User row immediately invalidates their next
	// login (upsertUser at internal/auth/oidc/service.go rejects with
	// ErrUserDeactivated); the cascade-revoke then kicks them out of the
	// active session, leaving the tenant without an admin able to
	// reactivate themselves. Break-glass credentials (Bundle 2 Phase 7.5)
	// remain the recovery path, but the operator should not be able to
	// trip the foot-gun through the standard handler. 409 (not 403) —
	// the request is well-formed and authenticated; the conflict is
	// between the action and the actor's own identity. Audit row records
	// the rejection so an upstream SIEM can spot accidental triggers.
	if caller.ActorType == domain.ActorTypeUser && caller.ActorID == id {
		_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.user_deactivate_self_rejected",
			domain.EventCategoryAuth, "user", id,
			map[string]interface{}{"user_id": id, "reason": "self_deactivate_blocked"})
		Error(w, http.StatusConflict, "cannot deactivate your own account; use break-glass recovery or have another admin act")
		return
	}
	u, gerr := h.users.Get(r.Context(), id)
	if gerr != nil {
		if errors.Is(gerr, repository.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not load user")
		return
	}
	// Idempotent: deactivating an already-deactivated user is a no-op
	// from the wire's perspective.
	if u.DeactivatedAt != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := time.Now().UTC()
	u.DeactivatedAt = &now
	if uerr := h.users.Update(r.Context(), u); uerr != nil {
		Error(w, http.StatusInternalServerError, "could not deactivate user")
		return
	}
	// Cascade-revoke active sessions. Best-effort: revoke failures do
	// NOT roll back the deactivation (the user is already marked
	// deactivated; a leftover session expires at the absolute-TTL anyway).
	revokeStatus := "skipped_no_revoker"
	if h.sessions != nil {
		if rerr := h.sessions.RevokeAllForActor(r.Context(), u.ID, string(domain.ActorTypeUser)); rerr != nil {
			revokeStatus = "failed"
		} else {
			revokeStatus = "ok"
		}
	}
	_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.user_deactivated",
		domain.EventCategoryAuth, "user", u.ID,
		map[string]interface{}{
			"user_id":               u.ID,
			"oidc_provider_id":      u.OIDCProviderID,
			"session_revoke_status": revokeStatus,
		})
	w.WriteHeader(http.StatusNoContent)
}

// Reactivate clears users.deactivated_at, allowing the federated user
// to log in again via their OIDC provider. The next OIDC callback for
// the (provider_id, subject) tuple goes through upsertUser, which now
// passes the DeactivatedAt == nil gate, and the user's account
// information (email, display_name, last_login_at) updates normally.
//
// Audit 2026-05-11 A-2 — Reactivate is the inverse of Deactivate. The
// original MED-11 closure only shipped Deactivate; with A-2 closure the
// DeactivatedAt field now actually gates login, so the operator needs a
// supported way to undo a soft-delete without hand-editing the database.
//
// Gate: same auth.user.deactivate permission. Reactivation is the
// inverse op, not a separate privilege — anyone who can deactivate must
// be able to undo their own mistake.
//
// Idempotent: reactivating an already-active user returns 204 with no
// row write.
//
// No session-side-effect: reactivation does NOT mint a session. The
// user must complete a fresh OIDC login through their provider; sessions
// from before the deactivation stay revoked (the cascade-revoke in
// Deactivate is irreversible by design).
func (h *AuthUsersHandler) Reactivate(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing user id")
		return
	}
	u, gerr := h.users.Get(r.Context(), id)
	if gerr != nil {
		if errors.Is(gerr, repository.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not load user")
		return
	}
	// Idempotent: reactivating an already-active user is a no-op.
	if u.DeactivatedAt == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	u.DeactivatedAt = nil
	if uerr := h.users.Update(r.Context(), u); uerr != nil {
		Error(w, http.StatusInternalServerError, "could not reactivate user")
		return
	}
	_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.user_reactivated",
		domain.EventCategoryAuth, "user", u.ID,
		map[string]interface{}{
			"user_id":          u.ID,
			"oidc_provider_id": u.OIDCProviderID,
		})
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// MED-12 — Auth runtime config read endpoint.
// =============================================================================

// AuthRuntimeConfigHandler exposes a flat-map view of the auth-related
// CERTCTL_* env vars so operators can verify the deployed
// configuration matches their intent from the GUI. Read-only — no
// mutation surface (config changes require a restart + env-var edit
// by design).
type AuthRuntimeConfigHandler struct {
	cfg   func() map[string]string
	audit AuditRecorder
}

// NewAuthRuntimeConfigHandler constructs the runtime-config handler.
// `cfg` is a closure so wires can be lazily evaluated against the
// running config without snapshot drift.
func NewAuthRuntimeConfigHandler(cfg func() map[string]string, audit AuditRecorder) *AuthRuntimeConfigHandler {
	return &AuthRuntimeConfigHandler{cfg: cfg, audit: audit}
}

func (h *AuthRuntimeConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	m := h.cfg()
	if m == nil {
		m = map[string]string{}
	}
	_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.runtime_config_read",
		domain.EventCategoryAuth, "config", "",
		map[string]interface{}{"key_count": len(m)})
	writeJSON(w, http.StatusOK, map[string]interface{}{"runtime_config": m})
}

// =============================================================================
// MED-7 — JWKS health endpoint.
// =============================================================================

// JWKSStatusProbe is the projection of *oidc.Service the JWKS-status
// handler uses to read the per-provider verifier counters. Production
// *oidc.Service satisfies this directly via the JWKSStatus method.
type JWKSStatusProbe interface {
	JWKSStatus(ctx context.Context, providerID string) (*oidcsvc.JWKSStatusSnapshot, error)
}

// AuthOIDCJWKSStatusHandler exposes per-provider JWKS health.
type AuthOIDCJWKSStatusHandler struct {
	probe JWKSStatusProbe
	audit AuditRecorder
}

// NewAuthOIDCJWKSStatusHandler constructs the JWKS-status handler.
func NewAuthOIDCJWKSStatusHandler(probe JWKSStatusProbe, audit AuditRecorder) *AuthOIDCJWKSStatusHandler {
	return &AuthOIDCJWKSStatusHandler{probe: probe, audit: audit}
}

func (h *AuthOIDCJWKSStatusHandler) Status(w http.ResponseWriter, r *http.Request) {
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
	snap, perr := h.probe.JWKSStatus(r.Context(), id)
	if perr != nil {
		if errors.Is(perr, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not read JWKS status")
		return
	}
	_ = h.audit.RecordEventWithCategory(r.Context(), caller.ActorID, caller.ActorType, "auth.oidc_jwks_status_read",
		domain.EventCategoryAuth, "oidc_provider", id,
		map[string]interface{}{"provider_id": id})
	writeJSON(w, http.StatusOK, snap)
}

// AuditRecorder is reused from auth_session_oidc.go — same package.
