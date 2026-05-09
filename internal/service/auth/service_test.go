package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// In-memory fakes. These exist solely to make the service-layer unit tests
// feasible without testcontainers. Phase 12 wires the live-Postgres
// integration suite that exercises the same code paths against the real
// schema; this file pins the privilege-escalation invariants that don't
// need a database.
// =============================================================================

type fakeRoleRepo struct {
	roles      map[string]*authdomain.Role
	rolePerms  map[string][]*authdomain.RolePermission
	deleteFail error
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{
		roles:     map[string]*authdomain.Role{},
		rolePerms: map[string][]*authdomain.RolePermission{},
	}
}

func (f *fakeRoleRepo) Get(_ context.Context, id string) (*authdomain.Role, error) {
	r, ok := f.roles[id]
	if !ok {
		return nil, repository.ErrAuthNotFound
	}
	return r, nil
}
func (f *fakeRoleRepo) GetByName(_ context.Context, _, name string) (*authdomain.Role, error) {
	for _, r := range f.roles {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, repository.ErrAuthNotFound
}
func (f *fakeRoleRepo) List(_ context.Context, _ string) ([]*authdomain.Role, error) {
	out := make([]*authdomain.Role, 0, len(f.roles))
	for _, r := range f.roles {
		out = append(out, r)
	}
	return out, nil
}
func (f *fakeRoleRepo) Create(_ context.Context, r *authdomain.Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *fakeRoleRepo) Update(_ context.Context, r *authdomain.Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *fakeRoleRepo) Delete(_ context.Context, id string) error {
	if f.deleteFail != nil {
		return f.deleteFail
	}
	delete(f.roles, id)
	return nil
}
func (f *fakeRoleRepo) ListPermissions(_ context.Context, roleID string) ([]*authdomain.RolePermission, error) {
	return f.rolePerms[roleID], nil
}
func (f *fakeRoleRepo) AddPermission(_ context.Context, g *authdomain.RolePermission) error {
	f.rolePerms[g.RoleID] = append(f.rolePerms[g.RoleID], g)
	return nil
}
func (f *fakeRoleRepo) RemovePermission(_ context.Context, g *authdomain.RolePermission) error {
	out := f.rolePerms[g.RoleID][:0]
	for _, x := range f.rolePerms[g.RoleID] {
		if x.PermissionID != g.PermissionID || x.ScopeType != g.ScopeType {
			out = append(out, x)
		}
	}
	f.rolePerms[g.RoleID] = out
	return nil
}

type fakePermissionRepo struct {
	byName map[string]*authdomain.Permission
}

func newFakePermissionRepo() *fakePermissionRepo {
	r := &fakePermissionRepo{byName: map[string]*authdomain.Permission{}}
	for _, p := range authdomain.CanonicalPermissions {
		r.byName[p] = &authdomain.Permission{
			ID:        "p-" + p,
			Name:      p,
			Namespace: p,
		}
	}
	return r
}

func (f *fakePermissionRepo) List(_ context.Context) ([]*authdomain.Permission, error) {
	out := make([]*authdomain.Permission, 0, len(f.byName))
	for _, p := range f.byName {
		out = append(out, p)
	}
	return out, nil
}
func (f *fakePermissionRepo) GetByName(_ context.Context, name string) (*authdomain.Permission, error) {
	p, ok := f.byName[name]
	if !ok {
		return nil, repository.ErrAuthNotFound
	}
	return p, nil
}
func (f *fakePermissionRepo) IsCanonical(name string) bool {
	_, ok := f.byName[name]
	return ok
}

// fakeActorRoleRepo mocks the actor_roles repository plus the
// EffectivePermissions JOIN. Tests configure perms[(actorID,actorType)]
// to return a specific permission set.
type fakeActorRoleRepo struct {
	grants []*authdomain.ActorRole
	perms  map[string][]repository.EffectivePermission
}

func newFakeActorRoleRepo() *fakeActorRoleRepo {
	return &fakeActorRoleRepo{
		perms: map[string][]repository.EffectivePermission{},
	}
}
func actorKey(id string, t authdomain.ActorTypeValue) string {
	return string(t) + ":" + id
}
func (f *fakeActorRoleRepo) ListByActor(_ context.Context, actorID string, actorType authdomain.ActorTypeValue, _ string) ([]*authdomain.ActorRole, error) {
	var out []*authdomain.ActorRole
	for _, g := range f.grants {
		if g.ActorID == actorID && g.ActorType == actorType {
			out = append(out, g)
		}
	}
	return out, nil
}
func (f *fakeActorRoleRepo) ListByRole(_ context.Context, roleID string) ([]*authdomain.ActorRole, error) {
	var out []*authdomain.ActorRole
	for _, g := range f.grants {
		if g.RoleID == roleID {
			out = append(out, g)
		}
	}
	return out, nil
}
func (f *fakeActorRoleRepo) Grant(_ context.Context, ar *authdomain.ActorRole) error {
	f.grants = append(f.grants, ar)
	return nil
}
func (f *fakeActorRoleRepo) Revoke(_ context.Context, actorID string, actorType authdomain.ActorTypeValue, roleID, _ string) error {
	out := f.grants[:0]
	for _, g := range f.grants {
		if g.ActorID == actorID && g.ActorType == actorType && g.RoleID == roleID {
			continue
		}
		out = append(out, g)
	}
	f.grants = out
	return nil
}
func (f *fakeActorRoleRepo) AdminExists(_ context.Context, _ string) (bool, error) {
	for _, g := range f.grants {
		if g.RoleID == authdomain.RoleIDAdmin && g.ActorID != authdomain.DemoAnonActorID {
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeActorRoleRepo) ListDistinctActors(_ context.Context, _ string) ([]repository.ActorWithRoles, error) {
	seen := map[string]*repository.ActorWithRoles{}
	for _, g := range f.grants {
		k := string(g.ActorType) + ":" + g.ActorID
		if seen[k] == nil {
			seen[k] = &repository.ActorWithRoles{
				ActorID:   g.ActorID,
				ActorType: g.ActorType,
				TenantID:  g.TenantID,
			}
		}
		seen[k].RoleIDs = append(seen[k].RoleIDs, g.RoleID)
	}
	out := make([]repository.ActorWithRoles, 0, len(seen))
	for _, v := range seen {
		out = append(out, *v)
	}
	return out, nil
}
func (f *fakeActorRoleRepo) EffectivePermissions(_ context.Context, actorID string, actorType authdomain.ActorTypeValue, _ string) ([]repository.EffectivePermission, error) {
	return f.perms[actorKey(actorID, actorType)], nil
}

type fakeAudit struct {
	calls []struct {
		Actor, ActorType, Action, Category, ResourceID string
	}
}

func (f *fakeAudit) RecordEvent(_ context.Context, actor string, actorType domain.ActorType, action, resourceType, resourceID string, _ map[string]interface{}) error {
	f.calls = append(f.calls, struct{ Actor, ActorType, Action, Category, ResourceID string }{
		actor, string(actorType), action, "", resourceID,
	})
	return nil
}

func (f *fakeAudit) RecordEventWithCategory(_ context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, _ map[string]interface{}) error {
	f.calls = append(f.calls, struct{ Actor, ActorType, Action, Category, ResourceID string }{
		actor, string(actorType), action, eventCategory, resourceID,
	})
	return nil
}

// =============================================================================
// Authorizer tests
// =============================================================================

func TestAuthorizer_GlobalGrantBeatsSpecificScope(t *testing.T) {
	r := newFakeActorRoleRepo()
	r.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	az := NewAuthorizer(r)
	scopeID := "iss-foo"
	ok, err := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", authdomain.ScopeTypeIssuer, &scopeID)
	if err != nil {
		t.Fatalf("CheckPermission err: %v", err)
	}
	if !ok {
		t.Errorf("global cert.read grant should match scoped request; got false")
	}
}

func TestAuthorizer_NoGrantReturnsFalse(t *testing.T) {
	r := newFakeActorRoleRepo()
	az := NewAuthorizer(r)
	ok, err := az.CheckPermission(context.Background(), "bob", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.delete", authdomain.ScopeTypeGlobal, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("actor with no grants should not pass any permission check")
	}
}

func TestAuthorizer_SpecificScopeMatchesExactID(t *testing.T) {
	r := newFakeActorRoleRepo()
	scope := "p-corp"
	r.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "profile.edit", ScopeType: authdomain.ScopeTypeProfile, ScopeID: &scope},
	}
	az := NewAuthorizer(r)
	matchID := "p-corp"
	wrongID := "p-other"
	ok, _ := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "profile.edit", authdomain.ScopeTypeProfile, &matchID)
	if !ok {
		t.Errorf("scoped grant on p-corp should match request for p-corp")
	}
	ok, _ = az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "profile.edit", authdomain.ScopeTypeProfile, &wrongID)
	if ok {
		t.Errorf("scoped grant on p-corp should NOT match request for p-other")
	}
}

// =============================================================================
// RoleService tests
// =============================================================================

func newRoleServiceWithFakes() (*RoleService, *fakeAudit, *fakeActorRoleRepo) {
	roleRepo := newFakeRoleRepo()
	permRepo := newFakePermissionRepo()
	actorRepo := newFakeActorRoleRepo()
	audit := &fakeAudit{}
	az := NewAuthorizer(actorRepo)
	return NewRoleService(roleRepo, permRepo, az, audit), audit, actorRepo
}

func TestRoleService_NoCallerReturnsUnauthenticated(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	_, err := rs.List(context.Background(), nil)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("nil caller should return ErrUnauthenticated, got %v", err)
	}
}

func TestRoleService_CallerWithoutPermissionForbidden(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	_, err := rs.List(context.Background(), caller)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("caller without auth.role.list should be forbidden; got %v", err)
	}
}

func TestRoleService_SystemCallerBypassesGate(t *testing.T) {
	rs, audit, _ := newRoleServiceWithFakes()
	role := &authdomain.Role{ID: "r-x", Name: "x", Description: "test"}
	if err := rs.Create(context.Background(), AsSystemCaller(), role); err != nil {
		t.Fatalf("system caller should bypass auth.role.create gate; got %v", err)
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "role.create" {
		t.Errorf("expected one role.create audit row, got %+v", audit.calls)
	}
}

func TestRoleService_AddPermissionRejectsNonCanonical(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	err := rs.AddPermission(context.Background(), AsSystemCaller(), "r-admin", "fake.permission", authdomain.ScopeTypeGlobal, nil)
	if !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("non-canonical permission should be rejected; got %v", err)
	}
}

// =============================================================================
// ActorRoleService tests — privilege-escalation guard
// =============================================================================

func newActorRoleServiceWithFakes() (*ActorRoleService, *fakeActorRoleRepo, *fakeAudit) {
	roleRepo := newFakeRoleRepo()
	actorRepo := newFakeActorRoleRepo()
	audit := &fakeAudit{}
	az := NewAuthorizer(actorRepo)
	return NewActorRoleService(actorRepo, roleRepo, az, audit), actorRepo, audit
}

func TestActorRoleService_GrantRequiresAuthRoleAssign(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	// Caller bob has cert.read but NOT auth.role.assign.
	repo.perms[actorKey("bob", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	err := svc.Grant(context.Background(), caller, &authdomain.ActorRole{
		ActorID: "carol", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-admin",
	})
	if !errors.Is(err, ErrSelfRoleAssignment) {
		t.Errorf("Grant without auth.role.assign should fail with ErrSelfRoleAssignment; got %v", err)
	}
}

func TestActorRoleService_GrantSucceedsWithAuthRoleAssign(t *testing.T) {
	svc, repo, audit := newActorRoleServiceWithFakes()
	// Caller alice holds auth.role.assign globally.
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "auth.role.assign", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	err := svc.Grant(context.Background(), caller, &authdomain.ActorRole{
		ActorID: "carol", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer",
	})
	if err != nil {
		t.Fatalf("Grant should succeed when caller holds auth.role.assign; got %v", err)
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "actor_role.grant" {
		t.Errorf("expected one actor_role.grant audit row; got %+v", audit.calls)
	}
}

func TestActorRoleService_GrantRejectsReservedDemoActor(t *testing.T) {
	svc, _, _ := newActorRoleServiceWithFakes()
	err := svc.Grant(context.Background(), AsSystemCaller(), &authdomain.ActorRole{
		ActorID: authdomain.DemoAnonActorID,
		RoleID:  "r-viewer",
	})
	if !errors.Is(err, repository.ErrAuthReservedActor) {
		t.Errorf("Grant against actor-demo-anon should be rejected; got %v", err)
	}
}

func TestActorRoleService_RevokeRejectsReservedDemoActor(t *testing.T) {
	svc, _, _ := newActorRoleServiceWithFakes()
	err := svc.Revoke(context.Background(), AsSystemCaller(), authdomain.DemoAnonActorID, domain.ActorTypeAnonymous, "r-admin")
	if !errors.Is(err, repository.ErrAuthReservedActor) {
		t.Errorf("Revoke against actor-demo-anon should be rejected; got %v", err)
	}
}

// =============================================================================
// PermissionService tests
// =============================================================================

func TestPermissionService_IsRegistered(t *testing.T) {
	repo := newFakePermissionRepo()
	ps := NewPermissionService(repo)
	if !ps.IsRegistered("cert.read") {
		t.Errorf("cert.read should be in canonical catalogue")
	}
	if ps.IsRegistered("not.a.real.permission") {
		t.Errorf("non-canonical permission should NOT be registered")
	}
}

// =============================================================================
// CallerFromContext returns ErrUnauthenticated until Phase 3 wires the
// middleware; pin the contract here so the upgrade is observable.
// =============================================================================

func TestCallerFromContext_Phase2ReturnsUnauthenticated(t *testing.T) {
	_, err := CallerFromContext(context.Background())
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Phase 2 stub should return ErrUnauthenticated; got %v. Phase 3 wires the middleware-context bridge.", err)
	}
}

// =============================================================================
// Bundle 1 Phase 12 — additional negative-test paths from the prompt list:
//   #9: role delete with actors assigned → ErrAuthRoleInUse (HTTP 409).
// The Authorizer wrong-scope path is already covered by
// TestAuthorizer_SpecificScopeMatchesExactID (the wrongID arm asserts
// false). The ErrInvalidPermission path is covered by
// TestRoleService_AddPermissionRejectsNonCanonical.
// =============================================================================

// TestRoleService_DeleteWithActorsAssignedReturns409 pins the
// repository sentinel pass-through: when the FK ON DELETE RESTRICT
// trips at the postgres layer, the repo returns
// repository.ErrAuthRoleInUse; the service surfaces that verbatim so
// the handler can map to HTTP 409.
func TestRoleService_DeleteWithActorsAssignedReturns409(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	// Pin the repo to surface ErrAuthRoleInUse on Delete (simulates
	// the FK guard tripping in postgres).
	rs.repo.(*fakeRoleRepo).deleteFail = repository.ErrAuthRoleInUse
	err := rs.Delete(context.Background(), AsSystemCaller(), "r-operator")
	if !errors.Is(err, repository.ErrAuthRoleInUse) {
		t.Errorf("Delete err = %v, want repository.ErrAuthRoleInUse (handler maps to 409)", err)
	}
}
