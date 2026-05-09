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
