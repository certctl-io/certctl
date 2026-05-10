package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
	authsvc "github.com/certctl-io/certctl/internal/service/auth"
)

// =============================================================================
// In-memory fakes — sufficient for handler-level translation tests. The
// service-layer privilege guards live in internal/service/auth and are
// covered there; these tests pin HTTP shape (status code, JSON envelope,
// error mapping).
// =============================================================================

type fakeAuthRoleSvc struct {
	roles      map[string]*authdomain.Role
	rolePerms  map[string][]*authdomain.RolePermission
	listErr    error
	createErr  error
	deleteErr  error
	addPermErr error
}

func newFakeAuthRoleSvc() *fakeAuthRoleSvc {
	return &fakeAuthRoleSvc{
		roles:     map[string]*authdomain.Role{},
		rolePerms: map[string][]*authdomain.RolePermission{},
	}
}
func (f *fakeAuthRoleSvc) List(_ context.Context, _ *authsvc.Caller) ([]*authdomain.Role, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*authdomain.Role, 0, len(f.roles))
	for _, r := range f.roles {
		out = append(out, r)
	}
	return out, nil
}
func (f *fakeAuthRoleSvc) Get(_ context.Context, _ *authsvc.Caller, id string) (*authdomain.Role, error) {
	r, ok := f.roles[id]
	if !ok {
		return nil, repository.ErrAuthNotFound
	}
	return r, nil
}
func (f *fakeAuthRoleSvc) Create(_ context.Context, _ *authsvc.Caller, role *authdomain.Role) error {
	if f.createErr != nil {
		return f.createErr
	}
	if role.ID == "" {
		role.ID = "r-" + role.Name
	}
	f.roles[role.ID] = role
	return nil
}
func (f *fakeAuthRoleSvc) Update(_ context.Context, _ *authsvc.Caller, role *authdomain.Role) error {
	f.roles[role.ID] = role
	return nil
}
func (f *fakeAuthRoleSvc) Delete(_ context.Context, _ *authsvc.Caller, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.roles, id)
	return nil
}
func (f *fakeAuthRoleSvc) ListPermissions(_ context.Context, _ *authsvc.Caller, roleID string) ([]*authdomain.RolePermission, error) {
	return f.rolePerms[roleID], nil
}
func (f *fakeAuthRoleSvc) AddPermission(_ context.Context, _ *authsvc.Caller, roleID, permName string, scopeType authdomain.ScopeType, scopeID *string) error {
	if f.addPermErr != nil {
		return f.addPermErr
	}
	f.rolePerms[roleID] = append(f.rolePerms[roleID], &authdomain.RolePermission{
		RoleID: roleID, PermissionID: "p-" + permName, ScopeType: scopeType, ScopeID: scopeID,
	})
	return nil
}
func (f *fakeAuthRoleSvc) RemovePermission(_ context.Context, _ *authsvc.Caller, _ string, _ string, _ authdomain.ScopeType, _ *string) error {
	return nil
}

type fakeAuthPermSvc struct {
	perms []*authdomain.Permission
}

func newFakeAuthPermSvc() *fakeAuthPermSvc {
	out := make([]*authdomain.Permission, 0, len(authdomain.CanonicalPermissions))
	for _, p := range authdomain.CanonicalPermissions {
		out = append(out, &authdomain.Permission{ID: "p-" + p, Name: p, Namespace: p})
	}
	return &fakeAuthPermSvc{perms: out}
}
func (f *fakeAuthPermSvc) List(_ context.Context) ([]*authdomain.Permission, error) {
	return f.perms, nil
}
func (f *fakeAuthPermSvc) IsRegistered(name string) bool {
	for _, p := range f.perms {
		if p.Name == name {
			return true
		}
	}
	return false
}

type fakeAuthActorSvc struct {
	grantErr  error
	revokeErr error
	roles     []*authdomain.ActorRole
	effective []repository.EffectivePermission
}

func newFakeAuthActorSvc() *fakeAuthActorSvc {
	return &fakeAuthActorSvc{}
}
func (f *fakeAuthActorSvc) Grant(_ context.Context, _ *authsvc.Caller, ar *authdomain.ActorRole) error {
	if f.grantErr != nil {
		return f.grantErr
	}
	f.roles = append(f.roles, ar)
	return nil
}
func (f *fakeAuthActorSvc) Revoke(_ context.Context, _ *authsvc.Caller, _ string, _ domain.ActorType, _ string) error {
	return f.revokeErr
}
func (f *fakeAuthActorSvc) ListForActor(_ context.Context, _ *authsvc.Caller, _ string, _ domain.ActorType) ([]*authdomain.ActorRole, error) {
	return f.roles, nil
}
func (f *fakeAuthActorSvc) EffectivePermissions(_ context.Context, _ *authsvc.Caller, _ string, _ domain.ActorType) ([]repository.EffectivePermission, error) {
	return f.effective, nil
}
func (f *fakeAuthActorSvc) ListKeys(_ context.Context, _ *authsvc.Caller) ([]repository.ActorWithRoles, error) {
	out := make([]repository.ActorWithRoles, 0, len(f.roles))
	for _, ar := range f.roles {
		out = append(out, repository.ActorWithRoles{
			ActorID:   ar.ActorID,
			ActorType: ar.ActorType,
			TenantID:  ar.TenantID,
			RoleIDs:   []string{ar.RoleID},
		})
	}
	return out, nil
}

type fakePermChecker struct {
	check func(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error)
}

func (f *fakePermChecker) CheckPermission(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error) {
	if f.check == nil {
		return true, nil
	}
	return f.check(ctx, actorID, actorType, tenantID, perm, scopeType, scopeID)
}

func newAuthHandlerWithFakes() (AuthHandler, *fakeAuthRoleSvc, *fakeAuthPermSvc, *fakeAuthActorSvc) {
	roles := newFakeAuthRoleSvc()
	perms := newFakeAuthPermSvc()
	actors := newFakeAuthActorSvc()
	checker := &fakePermChecker{}
	return NewAuthHandler(roles, perms, actors, checker), roles, perms, actors
}

// withAuthCtx populates the Phase 3 actor context keys on a request.
func withAuthCtx(req *http.Request, actorID, actorType string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, auth.ActorIDKey{}, actorID)
	ctx = context.WithValue(ctx, auth.ActorTypeKey{}, actorType)
	return req.WithContext(ctx)
}

// =============================================================================
// Tests
// =============================================================================

func TestAuthHandler_NoActorReturns401(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil)
	rec := httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("ListRoles without actor should yield 401; got %d", rec.Code)
	}
}

func TestAuthHandler_ListRolesReturnsAllRoles(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.roles["r-admin"] = &authdomain.Role{ID: "r-admin", Name: "admin"}
	roleSvc.roles["r-viewer"] = &authdomain.Role{ID: "r-viewer", Name: "viewer"}
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Roles []roleResponse `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Roles) != 2 {
		t.Errorf("expected 2 roles; got %d", len(resp.Roles))
	}
}

func TestAuthHandler_CreateRoleReturns201(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	body, _ := json.Marshal(createRoleRequest{Name: "custom", Description: "Test role"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles", bytes.NewReader(body)), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.CreateRole(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201; got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_CreateRoleRejectsEmptyName(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	body, _ := json.Marshal(createRoleRequest{Name: "  ", Description: "blank"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles", bytes.NewReader(body)), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.CreateRole(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("blank name should be 400; got %d", rec.Code)
	}
}

func TestAuthHandler_DeleteRoleReturns204(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.roles["r-x"] = &authdomain.Role{ID: "r-x", Name: "x"}
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/r-x", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.DeleteRole(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete should be 204; got %d", rec.Code)
	}
}

func TestAuthHandler_DeleteRoleInUseReturns409(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.deleteErr = repository.ErrAuthRoleInUse
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/r-x", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.DeleteRole(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("ErrAuthRoleInUse should be 409; got %d", rec.Code)
	}
}

func TestAuthHandler_DeleteRoleNotFoundReturns404(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.deleteErr = repository.ErrAuthNotFound
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/missing", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "missing")
	rec := httptest.NewRecorder()
	h.DeleteRole(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("ErrAuthNotFound should be 404; got %d", rec.Code)
	}
}

func TestAuthHandler_ForbiddenMappedTo403(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.listErr = authsvc.ErrForbidden
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil), "bob", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ErrForbidden should be 403; got %d", rec.Code)
	}
}

func TestAuthHandler_AssignRoleToKey(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	body, _ := json.Marshal(assignRoleRequest{RoleID: "r-viewer"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204; got %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(actorSvc.roles) != 1 {
		t.Errorf("expected 1 grant recorded; got %d", len(actorSvc.roles))
	}
	if actorSvc.roles[0].RoleID != "r-viewer" || actorSvc.roles[0].ActorID != "alice" {
		t.Errorf("grant fields wrong; got %+v", actorSvc.roles[0])
	}
}

// Audit 2026-05-10 HIGH-10 regression matrix — pin the new
// scope_type / scope_id / expires_at fields on assignRoleRequest.
// Pre-fix, the request body accepted only `{role_id}` so per-actor
// scope-bound grants and time-bound grants weren't expressible via
// the API even though the schema reserved the columns. Post-fix,
// validation rules:
//
//   - scope_type ∈ {global, profile, issuer}; defaults to global.
//   - scope_id required when scope_type != global; rejected when
//     scope_type == global.
//   - expires_at must be in the future when present.
func TestAssignRoleToKey_HIGH10_ProfileScopeBoundGrantPersists(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	scopeID := "p-finance"
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ScopeType: "profile",
		ScopeID:   &scopeID,
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if len(actorSvc.roles) != 1 {
		t.Fatalf("expected 1 grant; got %d", len(actorSvc.roles))
	}
	if got := string(actorSvc.roles[0].ScopeType); got != "profile" {
		t.Errorf("ScopeType = %q; want profile", got)
	}
	if actorSvc.roles[0].ScopeID == nil || *actorSvc.roles[0].ScopeID != "p-finance" {
		t.Errorf("ScopeID = %v; want p-finance", actorSvc.roles[0].ScopeID)
	}
}

func TestAssignRoleToKey_HIGH10_TimeBoundGrantPersists(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	future := time.Now().Add(24 * time.Hour).UTC()
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ExpiresAt: &future,
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if len(actorSvc.roles) != 1 || actorSvc.roles[0].ExpiresAt == nil {
		t.Fatalf("expected 1 grant with ExpiresAt; got %+v", actorSvc.roles)
	}
}

func TestAssignRoleToKey_HIGH10_RejectsScopeIDWithGlobalScope(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	bad := "p-finance"
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ScopeType: "global",
		ScopeID:   &bad,
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("scope_id with scope_type=global should be 400; got %d", rec.Code)
	}
}

func TestAssignRoleToKey_HIGH10_RejectsMissingScopeIDOnProfile(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ScopeType: "profile",
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing scope_id on scope_type=profile should be 400; got %d", rec.Code)
	}
}

func TestAssignRoleToKey_HIGH10_RejectsPastExpiry(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	past := time.Now().Add(-1 * time.Hour).UTC()
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ExpiresAt: &past,
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("past expires_at should be 400; got %d", rec.Code)
	}
}

func TestAssignRoleToKey_HIGH10_RejectsInvalidScopeType(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	body, _ := json.Marshal(assignRoleRequest{
		RoleID:    "r-operator",
		ScopeType: "tenant", // not a valid scope_type
	})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid scope_type should be 400; got %d", rec.Code)
	}
}

func TestAuthHandler_AssignRoleSelfRoleAssignReturns403(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	actorSvc.grantErr = errors.New("auth.role.assign required: " + authsvc.ErrSelfRoleAssignment.Error())
	// Force the wrapped sentinel:
	actorSvc.grantErr = authsvc.ErrSelfRoleAssignment
	body, _ := json.Marshal(assignRoleRequest{RoleID: "r-admin"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/keys/alice/roles", bytes.NewReader(body)), "bob", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	rec := httptest.NewRecorder()
	h.AssignRoleToKey(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ErrSelfRoleAssignment should be 403; got %d", rec.Code)
	}
}

func TestAuthHandler_RevokeRoleFromKey(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/keys/alice/roles/r-viewer", nil), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "alice")
	req.SetPathValue("role_id", "r-viewer")
	rec := httptest.NewRecorder()
	h.RevokeRoleFromKey(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("revoke should be 204; got %d", rec.Code)
	}
}

func TestAuthHandler_RevokeReservedActorReturns409(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	actorSvc.revokeErr = repository.ErrAuthReservedActor
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/keys/actor-demo-anon/roles/r-admin", nil), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "actor-demo-anon")
	req.SetPathValue("role_id", "r-admin")
	rec := httptest.NewRecorder()
	h.RevokeRoleFromKey(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("ErrAuthReservedActor should be 409; got %d", rec.Code)
	}
}

func TestAuthHandler_AddRolePermissionInvalidJSON(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles/r-admin/permissions", strings.NewReader("not json")), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	rec := httptest.NewRecorder()
	h.AddRolePermission(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON should be 400; got %d", rec.Code)
	}
}

func TestAuthHandler_AddRolePermissionDefaultScopeGlobal(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	body, _ := json.Marshal(addPermissionRequest{Permission: "cert.read"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles/r-admin/permissions", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	rec := httptest.NewRecorder()
	h.AddRolePermission(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204; got %d, body=%s", rec.Code, rec.Body.String())
	}
	grants := roleSvc.rolePerms["r-admin"]
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant; got %d", len(grants))
	}
	if grants[0].ScopeType != authdomain.ScopeTypeGlobal {
		t.Errorf("default scope should be global; got %q", grants[0].ScopeType)
	}
}

func TestAuthHandler_AddRolePermissionInvalidPermission(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.addPermErr = authsvc.ErrInvalidPermission
	body, _ := json.Marshal(addPermissionRequest{Permission: "fake"})
	req := withAuthCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles/r-admin/permissions", bytes.NewReader(body)), "admin", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	rec := httptest.NewRecorder()
	h.AddRolePermission(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ErrInvalidPermission should be 400; got %d", rec.Code)
	}
}

func TestAuthHandler_ListPermissionsReturnsCanonical(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/permissions", nil), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.ListPermissions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var resp struct {
		Permissions []permissionResponse `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Permissions) != len(authdomain.CanonicalPermissions) {
		t.Errorf("permission count: got %d, want %d (canonical catalogue size)", len(resp.Permissions), len(authdomain.CanonicalPermissions))
	}
}

func TestAuthHandler_MeReturnsActorIdentity(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	actorSvc.roles = []*authdomain.ActorRole{
		{RoleID: "r-admin", ActorID: "alice"},
	}
	actorSvc.effective = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.Me(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ActorID != "alice" {
		t.Errorf("actor id = %q, want alice", resp.ActorID)
	}
	if !resp.Admin {
		t.Errorf("alice has r-admin; admin flag should be true (back-compat)")
	}
	if len(resp.EffectivePermissions) != 1 || resp.EffectivePermissions[0].Permission != "cert.read" {
		t.Errorf("effective_permissions wrong; got %+v", resp.EffectivePermissions)
	}
}

// =============================================================================
// Coverage-floor closure (post-Bundle-1 follow-on, 2026-05-09).
//
// CI run #486 caught internal/api/handler at 74.7% — 0.3pp below the
// 75 floor. The auth handlers added in Bundle 1 had several 0%-covered
// methods: GetRole, UpdateRole, ListKeys, RemoveRolePermission. The
// tests below close the gap.
// =============================================================================

func TestAuthHandler_GetRoleReturnsRoleAndPermissions(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.roles["r-admin"] = &authdomain.Role{ID: "r-admin", Name: "admin", Description: "the admin role"}
	scope := "p-corp"
	roleSvc.rolePerms["r-admin"] = []*authdomain.RolePermission{
		{RoleID: "r-admin", PermissionID: "p-cert.read", ScopeType: authdomain.ScopeTypeGlobal},
		{RoleID: "r-admin", PermissionID: "p-profile.edit", ScopeType: authdomain.ScopeTypeProfile, ScopeID: &scope},
	}
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles/r-admin", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	rec := httptest.NewRecorder()
	h.GetRole(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetRole code = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Role        roleResponse             `json:"role"`
		Permissions []rolePermissionResponse `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Role.ID != "r-admin" || resp.Role.Name != "admin" {
		t.Errorf("Role envelope wrong: %+v", resp.Role)
	}
	if len(resp.Permissions) != 2 {
		t.Errorf("permissions length = %d; want 2", len(resp.Permissions))
	}
}

func TestAuthHandler_GetRoleNotFoundReturns404(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles/r-missing", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-missing")
	rec := httptest.NewRecorder()
	h.GetRole(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GetRole(missing) code = %d; want 404", rec.Code)
	}
}

func TestAuthHandler_GetRoleNoActorReturns401(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles/r-admin", nil)
	req.SetPathValue("id", "r-admin")
	rec := httptest.NewRecorder()
	h.GetRole(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GetRole no-actor code = %d; want 401", rec.Code)
	}
}

func TestAuthHandler_UpdateRoleReturns200(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.roles["r-x"] = &authdomain.Role{ID: "r-x", Name: "old", Description: ""}
	body := bytes.NewBufferString(`{"name":"new","description":"updated"}`)
	req := withAuthCtx(httptest.NewRequest(http.MethodPut, "/api/v1/auth/roles/r-x", body), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.UpdateRole(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("UpdateRole code = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp roleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "new" || resp.Description != "updated" {
		t.Errorf("UpdateRole returned %+v; want Name=new, Description=updated", resp)
	}
}

func TestAuthHandler_UpdateRoleInvalidJSONReturns400(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	body := strings.NewReader(`{"name":`) // truncated
	req := withAuthCtx(httptest.NewRequest(http.MethodPut, "/api/v1/auth/roles/r-x", body), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.UpdateRole(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("UpdateRole invalid JSON code = %d; want 400", rec.Code)
	}
}

func TestAuthHandler_UpdateRoleNoActorReturns401(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/roles/r-x", bytes.NewBufferString(`{"name":"new"}`))
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.UpdateRole(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("UpdateRole no-actor code = %d; want 401", rec.Code)
	}
}

func TestAuthHandler_ListKeysReturnsActorList(t *testing.T) {
	h, _, _, actorSvc := newAuthHandlerWithFakes()
	actorSvc.roles = []*authdomain.ActorRole{
		{ID: "ar-1", ActorID: "alice", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), TenantID: authdomain.DefaultTenantID, RoleID: "r-admin"},
		{ID: "ar-2", ActorID: "carol", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), TenantID: authdomain.DefaultTenantID, RoleID: "r-viewer"},
	}
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/keys", nil), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	h.ListKeys(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListKeys code = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Keys []struct {
			ActorID   string   `json:"actor_id"`
			ActorType string   `json:"actor_type"`
			TenantID  string   `json:"tenant_id"`
			RoleIDs   []string `json:"role_ids"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Keys) != 2 {
		t.Errorf("ListKeys returned %d keys; want 2", len(resp.Keys))
	}
}

func TestAuthHandler_ListKeysNoActorReturns401(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/keys", nil)
	rec := httptest.NewRecorder()
	h.ListKeys(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("ListKeys no-actor code = %d; want 401", rec.Code)
	}
}

func TestAuthHandler_RemoveRolePermissionReturns204(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/r-admin/permissions/cert.read", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	req.SetPathValue("perm", "cert.read")
	rec := httptest.NewRecorder()
	h.RemoveRolePermission(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("RemoveRolePermission code = %d; want 204", rec.Code)
	}
}

func TestAuthHandler_RemoveRolePermissionScopedReturns204(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := withAuthCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/r-admin/permissions/profile.edit?scope_type=profile&scope_id=p-corp", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-admin")
	req.SetPathValue("perm", "profile.edit")
	rec := httptest.NewRecorder()
	h.RemoveRolePermission(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("RemoveRolePermission(scoped) code = %d; want 204", rec.Code)
	}
}

func TestAuthHandler_RemoveRolePermissionNoActorReturns401(t *testing.T) {
	h, _, _, _ := newAuthHandlerWithFakes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/roles/r-admin/permissions/cert.read", nil)
	req.SetPathValue("id", "r-admin")
	req.SetPathValue("perm", "cert.read")
	rec := httptest.NewRecorder()
	h.RemoveRolePermission(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("RemoveRolePermission no-actor code = %d; want 401", rec.Code)
	}
}

// Pin the rolePermToResponse helper indirectly via GetRole; the test
// above already exercises both global + scoped permission encoding.
// Add an explicit assertion here so the helper's nil-scope branch is
// readable in coverage output.
func TestAuthHandler_GetRoleRolePermResponseEncodesScope(t *testing.T) {
	h, roleSvc, _, _ := newAuthHandlerWithFakes()
	roleSvc.roles["r-x"] = &authdomain.Role{ID: "r-x", Name: "x"}
	scope := "iss-corp"
	roleSvc.rolePerms["r-x"] = []*authdomain.RolePermission{
		{RoleID: "r-x", PermissionID: "p-cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
		{RoleID: "r-x", PermissionID: "p-issuer.edit", ScopeType: authdomain.ScopeTypeIssuer, ScopeID: &scope},
	}
	req := withAuthCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles/r-x", nil), "alice", auth.ActorTypeAPIKey)
	req.SetPathValue("id", "r-x")
	rec := httptest.NewRecorder()
	h.GetRole(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetRole code = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"scope_type":"issuer"`)) {
		t.Errorf("body should include scope_type=issuer; got %s", rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"scope_id":"iss-corp"`)) {
		t.Errorf("body should include scope_id=iss-corp; got %s", rec.Body.String())
	}
}

// ensure 'errors' import stays used after edits.
var _ = errors.Is
