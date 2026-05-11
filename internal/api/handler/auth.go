package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
	authsvc "github.com/certctl-io/certctl/internal/service/auth"
)

// AuthHandler exposes the RBAC primitive over HTTP. Bundle 1 Phase 4 wires
// the routes registered by HandlerRegistry under /v1/auth/*.
//
// Every mutating endpoint runs through the service layer, which enforces
// the privilege-escalation guard (callers need auth.role.assign for
// Grant/Revoke, auth.role.create/edit/delete for the role lifecycle,
// auth.key.* for key management). Read endpoints require auth.role.list.
//
// The /v1/auth/me endpoint has no permission requirement (every
// authenticated caller can read their own permissions); this is the
// query the GUI uses to gate affordance rendering.
type AuthHandler struct {
	roles   AuthRoleService
	perms   AuthPermissionService
	actors  AuthActorRoleService
	checker auth.PermissionChecker
	// csrfRotator is the optional session-CSRF-rotation hook called
	// post-role-mutation. Audit 2026-05-10 HIGH-2 closure — when an
	// actor's role set changes, every active session's CSRF token is
	// rotated as defense-in-depth against token leak preceding the
	// privilege change. Nil-safe: when unset (pre-Bundle-2 wiring,
	// tests that don't care about CSRF), the wires are no-ops.
	csrfRotator CSRFRotator
}

// CSRFRotator is the projection of *session.Service used by AuthHandler
// to rotate CSRF tokens across an actor's active sessions after a role
// mutation. RotateCSRFTokenForActor returns the count of rotated rows
// and NEVER errors out — rotation is defense-in-depth and must not
// block the role mutation that triggered it.
type CSRFRotator interface {
	RotateCSRFTokenForActor(ctx context.Context, actorID, actorType string) int
}

// AuthRoleService is the service-layer dependency the AuthHandler uses
// for role + role-permission lifecycle. Mirrors internal/service/auth.
type AuthRoleService interface {
	List(ctx context.Context, caller *authsvc.Caller) ([]*authdomain.Role, error)
	Get(ctx context.Context, caller *authsvc.Caller, id string) (*authdomain.Role, error)
	Create(ctx context.Context, caller *authsvc.Caller, role *authdomain.Role) error
	Update(ctx context.Context, caller *authsvc.Caller, role *authdomain.Role) error
	Delete(ctx context.Context, caller *authsvc.Caller, id string) error
	ListPermissions(ctx context.Context, caller *authsvc.Caller, roleID string) ([]*authdomain.RolePermission, error)
	AddPermission(ctx context.Context, caller *authsvc.Caller, roleID, permName string, scopeType authdomain.ScopeType, scopeID *string) error
	RemovePermission(ctx context.Context, caller *authsvc.Caller, roleID, permName string, scopeType authdomain.ScopeType, scopeID *string) error
}

// AuthPermissionService exposes the canonical permission catalogue.
type AuthPermissionService interface {
	List(ctx context.Context) ([]*authdomain.Permission, error)
	IsRegistered(name string) bool
}

// AuthActorRoleService manages role grants on actors and surfaces the
// effective-permissions query the GUI's /v1/auth/me handler uses.
type AuthActorRoleService interface {
	Grant(ctx context.Context, caller *authsvc.Caller, ar *authdomain.ActorRole) error
	// Audit 2026-05-11 A-4 — Revoke takes optional scope filtering so
	// callers that hold multiple scoped variants of the same role can
	// drop one variant selectively. opts.ScopeType == "" preserves the
	// legacy "revoke all" semantic.
	Revoke(ctx context.Context, caller *authsvc.Caller, actorID string, actorType domain.ActorType, roleID string, opts repository.ActorRoleRevokeOptions) error
	ListForActor(ctx context.Context, caller *authsvc.Caller, actorID string, actorType domain.ActorType) ([]*authdomain.ActorRole, error)
	EffectivePermissions(ctx context.Context, caller *authsvc.Caller, actorID string, actorType domain.ActorType) ([]repository.EffectivePermission, error)
	// ListKeys (Bundle 1 Phase 7) returns every actor in the tenant
	// with at least one role grant. The CLI's `auth keys list` and
	// scope-down helper consume this. The synthetic actor-demo-anon
	// row is included; the CLI filters it out of the interactive
	// prompt loop.
	ListKeys(ctx context.Context, caller *authsvc.Caller) ([]repository.ActorWithRoles, error)
}

// NewAuthHandler constructs an AuthHandler with the service-layer
// dependencies wired in cmd/server/main.go.
func NewAuthHandler(
	roles AuthRoleService,
	perms AuthPermissionService,
	actors AuthActorRoleService,
	checker auth.PermissionChecker,
) AuthHandler {
	return AuthHandler{
		roles:   roles,
		perms:   perms,
		actors:  actors,
		checker: checker,
	}
}

// WithCSRFRotator returns a copy of the handler with the CSRF-rotation
// hook installed. Audit 2026-05-10 HIGH-2 closure — production wiring
// in cmd/server/main.go calls this with the post-Bundle-2
// session.Service; pre-Bundle-2 deployments + tests can leave the
// rotator nil and the role-mutation handlers simply skip rotation.
func (h AuthHandler) WithCSRFRotator(r CSRFRotator) AuthHandler {
	h.csrfRotator = r
	return h
}

// =============================================================================
// JSON request / response shapes
// =============================================================================

type roleResponse struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func roleToResponse(r *authdomain.Role) roleResponse {
	return roleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		CreatedAt:   r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

type permissionResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func permToResponse(p *authdomain.Permission) permissionResponse {
	return permissionResponse{ID: p.ID, Name: p.Name, Namespace: p.Namespace}
}

type rolePermissionResponse struct {
	RoleID       string  `json:"role_id"`
	PermissionID string  `json:"permission_id"`
	ScopeType    string  `json:"scope_type"`
	ScopeID      *string `json:"scope_id,omitempty"`
}

func rolePermToResponse(g *authdomain.RolePermission) rolePermissionResponse {
	return rolePermissionResponse{
		RoleID:       g.RoleID,
		PermissionID: g.PermissionID,
		ScopeType:    string(g.ScopeType),
		ScopeID:      g.ScopeID,
	}
}

type createRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type addPermissionRequest struct {
	Permission string  `json:"permission"`
	ScopeType  string  `json:"scope_type,omitempty"` // defaults to "global"
	ScopeID    *string `json:"scope_id,omitempty"`
}

// assignRoleRequest is the POST /api/v1/auth/keys/{id}/roles body.
//
// Audit 2026-05-10 HIGH-10 closure — extended with scope_type /
// scope_id / expires_at so per-actor scoped + time-bound grants are
// expressible via the API. Pre-fix, the only path was creating a
// scoped role and granting that; now operators can scope a standing
// role to a specific resource on a per-actor basis.
//
// Validation rules:
//   - role_id is required.
//   - scope_type defaults to "global"; allowed values are global /
//     profile / issuer.
//   - scope_id is required when scope_type != "global"; rejected
//     (must be empty) when scope_type == "global".
//   - expires_at must be in the future when present; nil = standing.
type assignRoleRequest struct {
	RoleID    string     `json:"role_id"`
	ScopeType string     `json:"scope_type,omitempty"`
	ScopeID   *string    `json:"scope_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type meResponse struct {
	ActorID              string                       `json:"actor_id"`
	ActorType            string                       `json:"actor_type"`
	TenantID             string                       `json:"tenant_id"`
	Admin                bool                         `json:"admin"` // back-compat with /v1/auth/check
	Roles                []string                     `json:"roles"`
	EffectivePermissions []effectivePermissionPayload `json:"effective_permissions"`
}

type effectivePermissionPayload struct {
	Permission string  `json:"permission"`
	ScopeType  string  `json:"scope_type"`
	ScopeID    *string `json:"scope_id,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// ListRoles handles GET /api/v1/auth/roles.
// Permission: auth.role.list (enforced at the service layer).
func (h AuthHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	roles, err := h.roles.List(r.Context(), caller)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	out := make([]roleResponse, 0, len(roles))
	for _, role := range roles {
		out = append(out, roleToResponse(role))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roles": out})
}

// GetRole handles GET /api/v1/auth/roles/{id}.
func (h AuthHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	role, err := h.roles.Get(r.Context(), caller, id)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	perms, err := h.roles.ListPermissions(r.Context(), caller, id)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	permResponses := make([]rolePermissionResponse, 0, len(perms))
	for _, p := range perms {
		permResponses = append(permResponses, rolePermToResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"role":        roleToResponse(role),
		"permissions": permResponses,
	})
}

// CreateRole handles POST /api/v1/auth/roles.
func (h AuthHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		Error(w, http.StatusBadRequest, "role name is required")
		return
	}
	role := &authdomain.Role{Name: req.Name, Description: req.Description}
	if err := h.roles.Create(r.Context(), caller, role); err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, roleToResponse(role))
}

// UpdateRole handles PUT /api/v1/auth/roles/{id}.
func (h AuthHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	var req updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	role := &authdomain.Role{ID: id, Name: req.Name, Description: req.Description}
	if err := h.roles.Update(r.Context(), caller, role); err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, roleToResponse(role))
}

// DeleteRole handles DELETE /api/v1/auth/roles/{id}.
func (h AuthHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if err := h.roles.Delete(r.Context(), caller, id); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListPermissions handles GET /api/v1/auth/permissions.
func (h AuthHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	if _, err := callerFromRequest(r); err != nil {
		writeAuthError(w, err)
		return
	}
	perms, err := h.perms.List(r.Context())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	out := make([]permissionResponse, 0, len(perms))
	for _, p := range perms {
		out = append(out, permToResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"permissions": out})
}

// ListKeys handles GET /api/v1/auth/keys (Bundle 1 Phase 7).
// Permission: auth.role.list. Returns every distinct actor in the
// tenant with at least one role grant — the CLI's `auth keys list`
// and scope-down flow consume this.
func (h AuthHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	keys, err := h.actors.ListKeys(r.Context(), caller)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	type keyEntry struct {
		ActorID   string   `json:"actor_id"`
		ActorType string   `json:"actor_type"`
		TenantID  string   `json:"tenant_id"`
		RoleIDs   []string `json:"role_ids"`
	}
	out := make([]keyEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyEntry{
			ActorID:   k.ActorID,
			ActorType: string(k.ActorType),
			TenantID:  k.TenantID,
			RoleIDs:   k.RoleIDs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": out})
}

// AddRolePermission handles POST /api/v1/auth/roles/{id}/permissions.
func (h AuthHandler) AddRolePermission(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	roleID := r.PathValue("id")
	var req addPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Permission == "" {
		Error(w, http.StatusBadRequest, "permission is required")
		return
	}
	scopeType := authdomain.ScopeType(req.ScopeType)
	if scopeType == "" {
		scopeType = authdomain.ScopeTypeGlobal
	}
	if err := h.roles.AddPermission(r.Context(), caller, roleID, req.Permission, scopeType, req.ScopeID); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveRolePermission handles DELETE /api/v1/auth/roles/{id}/permissions/{perm}.
func (h AuthHandler) RemoveRolePermission(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	roleID := r.PathValue("id")
	permName := r.PathValue("perm")
	scopeType := authdomain.ScopeType(r.URL.Query().Get("scope_type"))
	if scopeType == "" {
		scopeType = authdomain.ScopeTypeGlobal
	}
	var scopeID *string
	if v := r.URL.Query().Get("scope_id"); v != "" {
		scopeID = &v
	}
	if err := h.roles.RemovePermission(r.Context(), caller, roleID, permName, scopeType, scopeID); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssignRoleToKey handles POST /api/v1/auth/keys/{id}/roles.
// {id} is the API-key actor name (e.g. "alice", "ops-admin"); the
// service layer resolves to the actor_roles row.
func (h AuthHandler) AssignRoleToKey(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	keyID := r.PathValue("id")
	var req assignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.RoleID == "" {
		Error(w, http.StatusBadRequest, "role_id is required")
		return
	}

	// Audit 2026-05-10 HIGH-10 validation.
	scopeType := authdomain.ScopeType(req.ScopeType)
	if scopeType == "" {
		scopeType = authdomain.ScopeTypeGlobal
	}
	switch scopeType {
	case authdomain.ScopeTypeGlobal:
		if req.ScopeID != nil && *req.ScopeID != "" {
			Error(w, http.StatusBadRequest, "scope_id must be empty when scope_type=global")
			return
		}
	case authdomain.ScopeTypeProfile, authdomain.ScopeTypeIssuer:
		if req.ScopeID == nil || strings.TrimSpace(*req.ScopeID) == "" {
			Error(w, http.StatusBadRequest, "scope_id is required when scope_type is profile or issuer")
			return
		}
	default:
		Error(w, http.StatusBadRequest, "invalid scope_type — must be global, profile, or issuer")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now().UTC()) {
		Error(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}

	ar := &authdomain.ActorRole{
		ActorID:   keyID,
		ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey),
		RoleID:    req.RoleID,
		ScopeType: scopeType,
		ScopeID:   req.ScopeID,
		ExpiresAt: req.ExpiresAt,
	}
	if err := h.actors.Grant(r.Context(), caller, ar); err != nil {
		writeAuthError(w, err)
		return
	}
	// Audit 2026-05-10 HIGH-2 closure — rotate CSRF across every
	// active session of the target actor. Non-blocking (per-row
	// failures are logged inside RotateCSRFTokenForActor but the
	// return value isn't an error). API-key actors typically have no
	// sessions (Bearer-only) so this is a no-op for them.
	if h.csrfRotator != nil {
		_ = h.csrfRotator.RotateCSRFTokenForActor(r.Context(), keyID, string(domain.ActorTypeAPIKey))
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeRoleFromKey handles DELETE /api/v1/auth/keys/{id}/roles/{role_id}.
//
// Audit 2026-05-11 A-4 — two operating modes selected by presence of
// the optional `?scope_type=` / `?scope_id=` query parameters:
//
//   - No query params: legacy "revoke every scope variant of this role
//     from this actor" semantic. Preserves pre-A-4 GUI behaviour
//     (KeysPage before Fix 12 fires plain DELETE with no scope; one
//     button per role row).
//
//   - `scope_type=global` (no scope_id) or
//     `scope_type=profile&scope_id=<id>` /
//     `scope_type=issuer&scope_id=<id>`: drop ONLY the matching variant.
//     Returns HTTP 404 when no row matches the scope (operator
//     feedback for typos). Validation mirrors AssignRoleToKey:
//     `scope_id` MUST be empty with `scope_type=global`, MUST be
//     present with `profile` / `issuer`, anything else → 400.
func (h AuthHandler) RevokeRoleFromKey(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	keyID := r.PathValue("id")
	roleID := r.PathValue("role_id")

	// Parse + validate optional scope filter. Empty query string is
	// the legacy path; mismatched filter is rejected before the call
	// reaches the service.
	scopeTypeRaw := r.URL.Query().Get("scope_type")
	scopeIDRaw := r.URL.Query().Get("scope_id")
	opts, derr := parseRevokeScope(scopeTypeRaw, scopeIDRaw)
	if derr != nil {
		Error(w, http.StatusBadRequest, derr.Error())
		return
	}

	if err := h.actors.Revoke(r.Context(), caller, keyID, domain.ActorTypeAPIKey, roleID, opts); err != nil {
		writeAuthError(w, err)
		return
	}
	// Audit 2026-05-10 HIGH-2 closure — rotate CSRF post-revoke.
	if h.csrfRotator != nil {
		_ = h.csrfRotator.RotateCSRFTokenForActor(r.Context(), keyID, string(domain.ActorTypeAPIKey))
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseRevokeScope translates the (scope_type, scope_id) query string
// into an ActorRoleRevokeOptions. Empty inputs → legacy "revoke all"
// option (zero value); any combination missing required halves →
// validation error. Audit 2026-05-11 A-4 — mirrors AssignRoleToKey's
// scope validation so the assign / revoke pair stays symmetric.
func parseRevokeScope(scopeType, scopeID string) (repository.ActorRoleRevokeOptions, error) {
	scopeType = strings.TrimSpace(scopeType)
	scopeID = strings.TrimSpace(scopeID)
	if scopeType == "" {
		if scopeID != "" {
			return repository.ActorRoleRevokeOptions{}, fmt.Errorf("scope_id requires scope_type")
		}
		return repository.ActorRoleRevokeOptions{}, nil
	}
	switch authdomain.ScopeType(scopeType) {
	case authdomain.ScopeTypeGlobal:
		if scopeID != "" {
			return repository.ActorRoleRevokeOptions{}, fmt.Errorf("scope_id must be empty when scope_type=global")
		}
		return repository.ActorRoleRevokeOptions{ScopeType: authdomain.ScopeTypeGlobal}, nil
	case authdomain.ScopeTypeProfile, authdomain.ScopeTypeIssuer:
		if scopeID == "" {
			return repository.ActorRoleRevokeOptions{}, fmt.Errorf("scope_id is required when scope_type is profile or issuer")
		}
		sid := scopeID
		return repository.ActorRoleRevokeOptions{
			ScopeType: authdomain.ScopeType(scopeType),
			ScopeID:   &sid,
		}, nil
	default:
		return repository.ActorRoleRevokeOptions{}, fmt.Errorf("invalid scope_type — must be global, profile, or issuer")
	}
}

// Me handles GET /api/v1/auth/me. Returns the current actor's effective
// permissions plus admin flag (back-compat with /v1/auth/check). No
// permission required: every authenticated caller can read their own.
func (h AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	roles, err := h.actors.ListForActor(r.Context(), caller, caller.ActorID, caller.ActorType)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	roleIDs := make([]string, 0, len(roles))
	hasAdmin := false
	for _, role := range roles {
		roleIDs = append(roleIDs, role.RoleID)
		if role.RoleID == authdomain.RoleIDAdmin {
			hasAdmin = true
		}
	}
	effective, err := h.actors.EffectivePermissions(r.Context(), caller, caller.ActorID, caller.ActorType)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	payload := make([]effectivePermissionPayload, 0, len(effective))
	for _, p := range effective {
		payload = append(payload, effectivePermissionPayload{
			Permission: p.PermissionName,
			ScopeType:  string(p.ScopeType),
			ScopeID:    p.ScopeID,
		})
	}
	writeJSON(w, http.StatusOK, meResponse{
		ActorID:              caller.ActorID,
		ActorType:            string(caller.ActorType),
		TenantID:             caller.TenantID,
		Admin:                hasAdmin,
		Roles:                roleIDs,
		EffectivePermissions: payload,
	})
}

// =============================================================================
// Helpers
// =============================================================================

// callerFromRequest builds an authsvc.Caller from request context. The
// auth middleware (Phase 3) populates ActorIDKey / ActorTypeKey /
// TenantIDKey on every authenticated request. Returns auth.ErrNoActor
// when no actor is in context (handler returns 401).
func callerFromRequest(r *http.Request) (*authsvc.Caller, error) {
	ctx := r.Context()
	actorID := auth.GetActorID(ctx)
	if actorID == "" {
		return nil, auth.ErrNoActor
	}
	actorType := auth.GetActorType(ctx)
	if actorType == "" {
		actorType = auth.ActorTypeAPIKey
	}
	tenantID := auth.GetTenantID(ctx)
	return &authsvc.Caller{
		ActorID:   actorID,
		ActorType: domain.ActorType(actorType),
		TenantID:  tenantID,
	}, nil
}

// writeAuthError translates service-layer + repository sentinel errors
// into HTTP status codes. Any non-mapped error is 500.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrNoActor), errors.Is(err, authsvc.ErrUnauthenticated):
		Error(w, http.StatusUnauthorized, "Authentication required")
	case errors.Is(err, authsvc.ErrForbidden), errors.Is(err, authsvc.ErrSelfRoleAssignment):
		Error(w, http.StatusForbidden, err.Error())
	case errors.Is(err, authsvc.ErrInvalidPermission):
		Error(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, repository.ErrAuthNotFound), errors.Is(err, repository.ErrActorRoleNotFound):
		Error(w, http.StatusNotFound, "Not found")
	case errors.Is(err, repository.ErrAuthDuplicateName), errors.Is(err, repository.ErrAuthRoleInUse), errors.Is(err, repository.ErrAuthReservedActor):
		Error(w, http.StatusConflict, err.Error())
	case errors.Is(err, repository.ErrAuthUnknownPermission):
		Error(w, http.StatusBadRequest, err.Error())
	default:
		Error(w, http.StatusInternalServerError, "Internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
