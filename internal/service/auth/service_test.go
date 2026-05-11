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

// RecordEventWithCategoryWithTx satisfies the Audit 2026-05-10 HIGH-6
// interface extension. The test stub stores into the same calls slice;
// no transactional semantics needed because the fake doesn't have a DB.
func (f *fakeAudit) RecordEventWithCategoryWithTx(_ context.Context, _ repository.Querier, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, _ map[string]interface{}) error {
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

// Audit 2026-05-11 A-1 — pin that when the SQL narrowed effective set
// reflects an actor-role-scope-narrowed permission, CheckPermission
// authorizes only the narrowed scope. This is the unit-level
// counterpart to TestEffectivePermissions_ActorRoleProfile_RolePermGlobal_A1Closure
// in internal/repository/postgres/auth_scope_test.go which exercises
// the actual SQL.
//
// Pre-fix, the SQL ignored ar.scope_*, so a profile-scoped grant
// produced a row with rp.scope (global), and CheckPermission would
// pass for ANY profile. Post-fix, the SQL narrows the row to
// (profile, p-prod), and CheckPermission only passes when the
// request scope matches.
func TestAuthorizer_ActorRoleProfileScope_OnlyNarrowedScopeAuthorizes_A1(t *testing.T) {
	r := newFakeActorRoleRepo()
	scope := "p-prod"
	// Simulate the post-A-1 SQL emission: actor-role scoped to
	// profile=p-prod + role-permission scoped global → narrowed
	// effective row at profile=p-prod.
	r.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeProfile, ScopeID: &scope},
	}
	az := NewAuthorizer(r)

	// Request scope matches narrowed grant → authorize.
	matchID := "p-prod"
	ok, err := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", authdomain.ScopeTypeProfile, &matchID)
	if err != nil {
		t.Fatalf("CheckPermission (matching scope): %v", err)
	}
	if !ok {
		t.Error("A-1: profile-scoped grant must authorize matching profile request")
	}

	// Different profile → reject (the load-bearing post-fix
	// behavior). Pre-fix this would have returned true silently.
	wrongID := "p-acme"
	ok, _ = az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", authdomain.ScopeTypeProfile, &wrongID)
	if ok {
		t.Error("A-1 regression: profile-scoped grant must NOT authorize a different profile (the canonical CRIT-5 shape)")
	}

	// Global request → also reject. A profile-scoped actor-role
	// grant doesn't elevate to global; same shape as RFC 9700
	// least-privilege.
	ok, _ = az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", authdomain.ScopeTypeGlobal, nil)
	if ok {
		t.Error("A-1: profile-scoped grant must NOT authorize a global request")
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

// =============================================================================
// Coverage-floor closure (post-Bundle-1 follow-on, 2026-05-09).
//
// The Phase 12 gate file claimed every read-side + Update path was
// covered. CI run #486 caught the discrepancy: internal/service/auth
// landed at 42.9% per-package, far below the 85 floor. The tests below
// fill the gaps without relaxing the gate. Each function listed had 0%
// or partial coverage at the time of the closure:
//
//   PermissionService.List           0%
//   PermissionService.GetByName      0%
//   RoleService.Get                  0%
//   RoleService.Update               0%
//   RoleService.ListPermissions      0%
//   RoleService.RemovePermission     0%
//   ActorRoleService.ListForActor    0%
//   ActorRoleService.EffectivePermissions 0%
//   ActorRoleService.ListKeys        0%
//   RoleService.List                 33.3%
//   RoleService.Delete               50%
//   RoleService.AddPermission        20%
//   ActorRoleService.Revoke          26.7%
// =============================================================================

// PermissionService.List returns the catalogue.
func TestPermissionService_ListReturnsCatalogue(t *testing.T) {
	ps := NewPermissionService(newFakePermissionRepo())
	out, err := ps.List(context.Background())
	if err != nil {
		t.Fatalf("List err: %v", err)
	}
	if len(out) != len(authdomain.CanonicalPermissions) {
		t.Errorf("List returned %d perms; want %d (one per canonical entry)", len(out), len(authdomain.CanonicalPermissions))
	}
}

// PermissionService.GetByName returns a hit + ErrAuthNotFound on miss.
func TestPermissionService_GetByName(t *testing.T) {
	ps := NewPermissionService(newFakePermissionRepo())
	p, err := ps.GetByName(context.Background(), "cert.read")
	if err != nil {
		t.Fatalf("GetByName(cert.read) err: %v", err)
	}
	if p == nil || p.Name != "cert.read" {
		t.Errorf("GetByName(cert.read) returned %+v; want Name=cert.read", p)
	}
	_, err = ps.GetByName(context.Background(), "fake.perm")
	if !errors.Is(err, repository.ErrAuthNotFound) {
		t.Errorf("GetByName(fake.perm) err = %v; want ErrAuthNotFound", err)
	}
}

// RoleService.Get gates on auth.role.list and surfaces repo errors.
func TestRoleService_GetGatesOnPermissionAndSurfaces(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	// nil caller -> ErrUnauthenticated
	if _, err := rs.Get(context.Background(), nil, "r-admin"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Get(nil) err = %v; want ErrUnauthenticated", err)
	}
	// caller without auth.role.list -> ErrForbidden
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if _, err := rs.Get(context.Background(), caller, "r-admin"); !errors.Is(err, ErrForbidden) {
		t.Errorf("Get(no perm) err = %v; want ErrForbidden", err)
	}
	// system caller, missing role -> ErrAuthNotFound from repo
	if _, err := rs.Get(context.Background(), AsSystemCaller(), "r-missing"); !errors.Is(err, repository.ErrAuthNotFound) {
		t.Errorf("Get(missing) err = %v; want ErrAuthNotFound", err)
	}
	// system caller, present role -> success
	rs.repo.(*fakeRoleRepo).roles["r-x"] = &authdomain.Role{ID: "r-x", Name: "x"}
	got, err := rs.Get(context.Background(), AsSystemCaller(), "r-x")
	if err != nil || got == nil || got.ID != "r-x" {
		t.Errorf("Get(r-x) = %+v, %v; want ID=r-x and nil err", got, err)
	}
}

// RoleService.List returns the role set + emits no audit row.
func TestRoleService_ListSucceedsForSystemCaller(t *testing.T) {
	rs, audit, _ := newRoleServiceWithFakes()
	rs.repo.(*fakeRoleRepo).roles["r-a"] = &authdomain.Role{ID: "r-a", Name: "a"}
	rs.repo.(*fakeRoleRepo).roles["r-b"] = &authdomain.Role{ID: "r-b", Name: "b"}
	out, err := rs.List(context.Background(), AsSystemCaller())
	if err != nil {
		t.Fatalf("List err: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("List returned %d; want 2", len(out))
	}
	if len(audit.calls) != 0 {
		t.Errorf("List should not emit audit rows; got %+v", audit.calls)
	}
}

// RoleService.Update gates + records audit.
func TestRoleService_UpdateGatesAndAudits(t *testing.T) {
	rs, audit, _ := newRoleServiceWithFakes()
	// nil caller
	if err := rs.Update(context.Background(), nil, &authdomain.Role{ID: "r-x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Update(nil) err = %v; want ErrUnauthenticated", err)
	}
	// no permission
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if err := rs.Update(context.Background(), caller, &authdomain.Role{ID: "r-x"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("Update(no perm) err = %v; want ErrForbidden", err)
	}
	// system caller succeeds + audit emitted
	role := &authdomain.Role{ID: "r-x", Name: "x"}
	if err := rs.Update(context.Background(), AsSystemCaller(), role); err != nil {
		t.Fatalf("Update(system) err: %v", err)
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "role.update" {
		t.Errorf("expected one role.update audit row; got %+v", audit.calls)
	}
}

// RoleService.ListPermissions returns rows + gates on auth.role.list.
func TestRoleService_ListPermissionsGatesAndReturns(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if _, err := rs.ListPermissions(context.Background(), caller, "r-admin"); !errors.Is(err, ErrForbidden) {
		t.Errorf("ListPermissions(no perm) err = %v; want ErrForbidden", err)
	}
	if _, err := rs.ListPermissions(context.Background(), nil, "r-admin"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("ListPermissions(nil) err = %v; want ErrUnauthenticated", err)
	}
	// seed grants then list
	rs.repo.(*fakeRoleRepo).rolePerms["r-admin"] = []*authdomain.RolePermission{
		{RoleID: "r-admin", PermissionID: "p-cert.read", ScopeType: authdomain.ScopeTypeGlobal},
	}
	out, err := rs.ListPermissions(context.Background(), AsSystemCaller(), "r-admin")
	if err != nil {
		t.Fatalf("ListPermissions(system) err: %v", err)
	}
	if len(out) != 1 || out[0].PermissionID != "p-cert.read" {
		t.Errorf("ListPermissions returned %+v; want one entry for p-cert.read", out)
	}
}

// RoleService.AddPermission happy path + RemovePermission round-trip.
func TestRoleService_AddRemovePermissionRoundTrip(t *testing.T) {
	rs, audit, _ := newRoleServiceWithFakes()
	scope := "p-corp"
	if err := rs.AddPermission(context.Background(), AsSystemCaller(), "r-admin", "profile.edit", authdomain.ScopeTypeProfile, &scope); err != nil {
		t.Fatalf("AddPermission err: %v", err)
	}
	if len(rs.repo.(*fakeRoleRepo).rolePerms["r-admin"]) != 1 {
		t.Errorf("AddPermission should have added one row; got %d", len(rs.repo.(*fakeRoleRepo).rolePerms["r-admin"]))
	}
	// audit row carries scope_id when scope is bounded
	if len(audit.calls) != 1 || audit.calls[0].Action != "role.permission.add" {
		t.Errorf("expected one role.permission.add audit row; got %+v", audit.calls)
	}
	// Remove it
	if err := rs.RemovePermission(context.Background(), AsSystemCaller(), "r-admin", "profile.edit", authdomain.ScopeTypeProfile, &scope); err != nil {
		t.Fatalf("RemovePermission err: %v", err)
	}
	if len(rs.repo.(*fakeRoleRepo).rolePerms["r-admin"]) != 0 {
		t.Errorf("RemovePermission should have removed the grant; %d remain", len(rs.repo.(*fakeRoleRepo).rolePerms["r-admin"]))
	}
	if len(audit.calls) != 2 || audit.calls[1].Action != "role.permission.remove" {
		t.Errorf("expected role.permission.remove second audit row; got %+v", audit.calls)
	}
}

// RoleService.AddPermission fails on nil caller / no perm / unknown perm.
func TestRoleService_AddPermissionGates(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	if err := rs.AddPermission(context.Background(), nil, "r-admin", "cert.read", authdomain.ScopeTypeGlobal, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("AddPermission(nil) err = %v; want ErrUnauthenticated", err)
	}
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if err := rs.AddPermission(context.Background(), caller, "r-admin", "cert.read", authdomain.ScopeTypeGlobal, nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("AddPermission(no perm) err = %v; want ErrForbidden", err)
	}
}

// RoleService.RemovePermission gates on caller.
func TestRoleService_RemovePermissionGates(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	if err := rs.RemovePermission(context.Background(), nil, "r-admin", "cert.read", authdomain.ScopeTypeGlobal, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("RemovePermission(nil) err = %v; want ErrUnauthenticated", err)
	}
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if err := rs.RemovePermission(context.Background(), caller, "r-admin", "cert.read", authdomain.ScopeTypeGlobal, nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("RemovePermission(no perm) err = %v; want ErrForbidden", err)
	}
}

// RoleService.Delete success path + audit emission.
func TestRoleService_DeleteSuccessEmitsAudit(t *testing.T) {
	rs, audit, _ := newRoleServiceWithFakes()
	rs.repo.(*fakeRoleRepo).roles["r-x"] = &authdomain.Role{ID: "r-x", Name: "x"}
	if err := rs.Delete(context.Background(), AsSystemCaller(), "r-x"); err != nil {
		t.Fatalf("Delete err: %v", err)
	}
	if _, exists := rs.repo.(*fakeRoleRepo).roles["r-x"]; exists {
		t.Errorf("Delete should have removed r-x from the fake repo")
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "role.delete" {
		t.Errorf("expected one role.delete audit row; got %+v", audit.calls)
	}
}

// RoleService.Delete nil caller / no permission.
func TestRoleService_DeleteGatesOnCaller(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	if err := rs.Delete(context.Background(), nil, "r-x"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Delete(nil) err = %v; want ErrUnauthenticated", err)
	}
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if err := rs.Delete(context.Background(), caller, "r-x"); !errors.Is(err, ErrForbidden) {
		t.Errorf("Delete(no perm) err = %v; want ErrForbidden", err)
	}
}

// RoleService.Create with an unauthenticated caller.
func TestRoleService_CreateNilCallerUnauthenticated(t *testing.T) {
	rs, _, _ := newRoleServiceWithFakes()
	if err := rs.Create(context.Background(), nil, &authdomain.Role{ID: "r-x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Create(nil) err = %v; want ErrUnauthenticated", err)
	}
}

// ActorRoleService.ListForActor: self-lookup bypasses the auth.role.list
// gate; cross-actor lookup requires it.
func TestActorRoleService_ListForActorSelfBypassAndPermissionGate(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	// alice has no perms but can look up her own roles.
	repo.grants = []*authdomain.ActorRole{{ID: "ar-1", ActorID: "alice", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer"}}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	got, err := svc.ListForActor(context.Background(), caller, "alice", domain.ActorTypeAPIKey)
	if err != nil {
		t.Fatalf("self-lookup err: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("self-lookup returned %d roles; want 1", len(got))
	}
	// alice can NOT look up bob without auth.role.list.
	if _, err := svc.ListForActor(context.Background(), caller, "bob", domain.ActorTypeAPIKey); !errors.Is(err, ErrForbidden) {
		t.Errorf("cross-actor lookup without perm err = %v; want ErrForbidden", err)
	}
	// nil caller -> Unauthenticated
	if _, err := svc.ListForActor(context.Background(), nil, "alice", domain.ActorTypeAPIKey); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("ListForActor(nil) err = %v; want ErrUnauthenticated", err)
	}
	// system caller succeeds for anyone.
	if _, err := svc.ListForActor(context.Background(), AsSystemCaller(), "bob", domain.ActorTypeAPIKey); err != nil {
		t.Errorf("system caller cross-actor lookup err: %v", err)
	}
}

// ActorRoleService.ListForActor: cross-actor lookup with auth.role.list grant.
func TestActorRoleService_ListForActorCrossActorWithPerm(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "auth.role.list", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	repo.grants = []*authdomain.ActorRole{{ID: "ar-1", ActorID: "bob", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer"}}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	got, err := svc.ListForActor(context.Background(), caller, "bob", domain.ActorTypeAPIKey)
	if err != nil {
		t.Fatalf("cross-actor with perm err: %v", err)
	}
	if len(got) != 1 || got[0].ActorID != "bob" {
		t.Errorf("cross-actor lookup returned %+v; want bob's roles", got)
	}
}

// ActorRoleService.EffectivePermissions: same self/cross/system pattern.
func TestActorRoleService_EffectivePermissionsGates(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	// self-lookup bypasses gate
	got, err := svc.EffectivePermissions(context.Background(), caller, "alice", domain.ActorTypeAPIKey)
	if err != nil {
		t.Fatalf("self-lookup err: %v", err)
	}
	if len(got) != 1 || got[0].PermissionName != "cert.read" {
		t.Errorf("self-lookup returned %+v; want one cert.read entry", got)
	}
	// cross-actor without perm -> Forbidden
	if _, err := svc.EffectivePermissions(context.Background(), caller, "bob", domain.ActorTypeAPIKey); !errors.Is(err, ErrForbidden) {
		t.Errorf("cross-actor without perm err = %v; want ErrForbidden", err)
	}
	// nil caller -> Unauthenticated
	if _, err := svc.EffectivePermissions(context.Background(), nil, "alice", domain.ActorTypeAPIKey); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("EffectivePermissions(nil) err = %v; want ErrUnauthenticated", err)
	}
	// system caller cross-actor -> succeeds (with empty result for bob)
	if _, err := svc.EffectivePermissions(context.Background(), AsSystemCaller(), "bob", domain.ActorTypeAPIKey); err != nil {
		t.Errorf("system caller cross-actor err: %v", err)
	}
}

// ActorRoleService.EffectivePermissions: cross-actor with auth.role.list grant.
func TestActorRoleService_EffectivePermissionsCrossActorWithPerm(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "auth.role.list", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	repo.perms[actorKey("bob", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	got, err := svc.EffectivePermissions(context.Background(), caller, "bob", domain.ActorTypeAPIKey)
	if err != nil {
		t.Fatalf("cross-actor with perm err: %v", err)
	}
	if len(got) != 1 || got[0].PermissionName != "cert.read" {
		t.Errorf("cross-actor returned %+v; want bob's cert.read", got)
	}
}

// ActorRoleService.ListKeys: requires auth.role.list (or system).
func TestActorRoleService_ListKeysGates(t *testing.T) {
	svc, repo, _ := newActorRoleServiceWithFakes()
	if _, err := svc.ListKeys(context.Background(), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("ListKeys(nil) err = %v; want ErrUnauthenticated", err)
	}
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if _, err := svc.ListKeys(context.Background(), caller); !errors.Is(err, ErrForbidden) {
		t.Errorf("ListKeys(no perm) err = %v; want ErrForbidden", err)
	}
	// caller with auth.role.list succeeds
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "auth.role.list", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	repo.grants = []*authdomain.ActorRole{
		{ID: "ar-a", ActorID: "alice", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-admin"},
		{ID: "ar-b", ActorID: "carol", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer"},
	}
	got, err := svc.ListKeys(context.Background(), &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey})
	if err != nil {
		t.Fatalf("ListKeys(perm) err: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListKeys returned %d actors; want 2 (alice + carol)", len(got))
	}
	// system caller succeeds without grants
	if _, err := svc.ListKeys(context.Background(), AsSystemCaller()); err != nil {
		t.Errorf("ListKeys(system) err: %v", err)
	}
}

// ActorRoleService.Revoke: nil caller / system success / no-perm forbidden.
func TestActorRoleService_RevokeGatesAndSucceeds(t *testing.T) {
	svc, repo, audit := newActorRoleServiceWithFakes()
	// nil caller
	if err := svc.Revoke(context.Background(), nil, "alice", domain.ActorTypeAPIKey, "r-admin"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Revoke(nil) err = %v; want ErrUnauthenticated", err)
	}
	// caller without auth.role.assign
	caller := &Caller{ActorID: "bob", ActorType: domain.ActorTypeAPIKey}
	if err := svc.Revoke(context.Background(), caller, "alice", domain.ActorTypeAPIKey, "r-admin"); !errors.Is(err, ErrSelfRoleAssignment) {
		t.Errorf("Revoke(no perm) err = %v; want ErrSelfRoleAssignment", err)
	}
	// system caller success
	repo.grants = []*authdomain.ActorRole{
		{ID: "ar-1", ActorID: "alice", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-admin", TenantID: authdomain.DefaultTenantID},
	}
	if err := svc.Revoke(context.Background(), AsSystemCaller(), "alice", domain.ActorTypeAPIKey, "r-admin"); err != nil {
		t.Fatalf("Revoke(system) err: %v", err)
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "actor_role.revoke" {
		t.Errorf("expected one actor_role.revoke audit row; got %+v", audit.calls)
	}
}

// ActorRoleService.Revoke success when caller holds auth.role.assign.
func TestActorRoleService_RevokeSucceedsWithAuthRoleAssign(t *testing.T) {
	svc, repo, audit := newActorRoleServiceWithFakes()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "auth.role.assign", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	repo.grants = []*authdomain.ActorRole{
		{ID: "ar-1", ActorID: "carol", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer", TenantID: authdomain.DefaultTenantID},
	}
	caller := &Caller{ActorID: "alice", ActorType: domain.ActorTypeAPIKey}
	if err := svc.Revoke(context.Background(), caller, "carol", domain.ActorTypeAPIKey, "r-viewer"); err != nil {
		t.Fatalf("Revoke(perm) err: %v", err)
	}
	if len(audit.calls) != 1 || audit.calls[0].Action != "actor_role.revoke" {
		t.Errorf("expected one actor_role.revoke audit row; got %+v", audit.calls)
	}
}

// AsSystemCaller produces a Caller flagged IsSystem so the gates skip
// the authorizer round-trip. Pin the contract.
func TestAsSystemCallerIsSystemFlagged(t *testing.T) {
	c := AsSystemCaller()
	if !c.IsSystem {
		t.Errorf("AsSystemCaller().IsSystem = false; want true")
	}
}

// Authorizer edge cases: empty actorID short-circuits to false; empty
// tenantID defaults to authdomain.DefaultTenantID; scoped grant without
// scope_id never matches.
func TestAuthorizer_EmptyActorIDReturnsFalse(t *testing.T) {
	az := NewAuthorizer(newFakeActorRoleRepo())
	ok, err := az.CheckPermission(context.Background(), "", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), "", "cert.read", authdomain.ScopeTypeGlobal, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("empty actorID should always return false")
	}
}

func TestAuthorizer_EmptyTenantIDDefaultsAndStillResolves(t *testing.T) {
	repo := newFakeActorRoleRepo()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	az := NewAuthorizer(repo)
	ok, err := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), "", "cert.read", authdomain.ScopeTypeGlobal, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Errorf("empty tenantID should default to DefaultTenantID and still resolve global grants")
	}
}

func TestAuthorizer_ScopedGrantWithoutScopeIDNeverMatches(t *testing.T) {
	repo := newFakeActorRoleRepo()
	// Grant scope_type=profile but scope_id=nil — represents a
	// malformed row that pre-Phase-12 could have leaked through.
	// The matcher must NOT treat nil-scope as a wildcard.
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "profile.edit", ScopeType: authdomain.ScopeTypeProfile, ScopeID: nil},
	}
	az := NewAuthorizer(repo)
	matchID := "p-corp"
	ok, _ := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "profile.edit", authdomain.ScopeTypeProfile, &matchID)
	if ok {
		t.Errorf("scope_type=profile + scope_id=nil should NOT match scoped request — would be a wildcard escape")
	}
}

// errorActorRoleRepo wraps fakeActorRoleRepo and injects errors on the
// EffectivePermissions read so we can pin the wrap-then-return path.
type errorActorRoleRepo struct {
	fakeActorRoleRepo
	effErr error
}

func (e *errorActorRoleRepo) EffectivePermissions(_ context.Context, _ string, _ authdomain.ActorTypeValue, _ string) ([]repository.EffectivePermission, error) {
	return nil, e.effErr
}

func TestAuthorizer_RepoErrorIsWrappedAndReturned(t *testing.T) {
	sentinel := errors.New("postgres: connection refused")
	repo := &errorActorRoleRepo{
		fakeActorRoleRepo: *newFakeActorRoleRepo(),
		effErr:            sentinel,
	}
	az := NewAuthorizer(repo)
	_, err := az.CheckPermission(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", authdomain.ScopeTypeGlobal, nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("CheckPermission should wrap the repo error verbatim; got %v", err)
	}
}

// Authorizer.HoldsAnyOf early-exits on first match.
func TestAuthorizer_HoldsAnyOfEarlyExitsOnFirstMatch(t *testing.T) {
	repo := newFakeActorRoleRepo()
	repo.perms[actorKey("alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey))] = []repository.EffectivePermission{
		{PermissionName: "cert.read", ScopeType: authdomain.ScopeTypeGlobal, ScopeID: nil},
	}
	az := NewAuthorizer(repo)
	// alice has cert.read but neither auth.role.assign nor cert.delete.
	ok, err := az.HoldsAnyOf(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.read", "cert.delete")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Errorf("HoldsAnyOf with one matching permission should return true")
	}
	// neither of these matches
	ok, err = az.HoldsAnyOf(context.Background(), "alice", authdomain.ActorTypeValue(domain.ActorTypeAPIKey), authdomain.DefaultTenantID, "cert.delete", "auth.role.assign")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("HoldsAnyOf with no matching permission should return false")
	}
}

// recordAudit short-circuits on nil audit + nil caller. Pin both arms
// so the no-op branches are exercised.
func TestRoleService_RecordAuditNilArmsAreNoOps(t *testing.T) {
	// Build a service with audit=nil; Create should still succeed.
	roleRepo := newFakeRoleRepo()
	permRepo := newFakePermissionRepo()
	az := NewAuthorizer(newFakeActorRoleRepo())
	rs := NewRoleService(roleRepo, permRepo, az, nil)
	if err := rs.Create(context.Background(), AsSystemCaller(), &authdomain.Role{ID: "r-x", Name: "x"}); err != nil {
		t.Errorf("Create with nil audit should still succeed; got %v", err)
	}
}

func TestActorRoleService_RecordAuditNilArmsAreNoOps(t *testing.T) {
	// Build a service with audit=nil; Grant should still succeed.
	roleRepo := newFakeRoleRepo()
	actorRepo := newFakeActorRoleRepo()
	az := NewAuthorizer(actorRepo)
	svc := NewActorRoleService(actorRepo, roleRepo, az, nil)
	if err := svc.Grant(context.Background(), AsSystemCaller(), &authdomain.ActorRole{
		ActorID: "alice", ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey), RoleID: "r-viewer",
	}); err != nil {
		t.Errorf("Grant with nil audit should still succeed; got %v", err)
	}
}
