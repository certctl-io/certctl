package postgres_test

// Audit 2026-05-11 A-1 closure — EffectivePermissions scope-intersection
// regression matrix. Pre-fix, the SQL only narrowed by role-permission
// scope (rp.scope_*); actor-role scope (ar.scope_*) was ignored. An
// operator who scope-granted Alice `r-operator` to `profile=p-prod`
// silently elevated Alice to `r-operator` globally. Same shape as the
// original CRIT-5 lying field, replicated in the load-bearing auth
// check path.
//
// These tests exercise the SQL change in isolation against a real
// Postgres container. They cover the six effective-scope cases the
// fix encodes (see the EffectivePermissions SQL comment block):
//
//   ar.scope    rp.scope    expected_effective
//   ─────────   ─────────   ──────────────────────────
//   global      global      global / NULL
//   global      profile=X   profile=X      (rp narrows)
//   profile=X   global      profile=X      (ar narrows)
//   profile=X   profile=X   profile=X      (both agree)
//   profile=X   profile=Y   ROW DROPPED    (disjoint)
//   profile=X   issuer=*    ROW DROPPED    (scope-type mismatch)

import (
	"context"
	"testing"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// seedRoleWithPerm creates a role with one permission grant at the
// supplied scope and returns the role ID. Helper for the test matrix.
func seedRoleWithPerm(t *testing.T, ctx context.Context, roleRepo *postgres.RoleRepository, permRepo *postgres.PermissionRepository, roleSuffix, permName string, rpScopeType authdomain.ScopeType, rpScopeID *string) string {
	t.Helper()
	roleID := "r-" + roleSuffix
	role := &authdomain.Role{
		ID: roleID, Name: "Test " + roleSuffix, Description: "scope-test role", TenantID: authdomain.DefaultTenantID,
	}
	if err := roleRepo.Create(ctx, role); err != nil {
		t.Fatalf("seed role %s: %v", roleSuffix, err)
	}
	// Look up the permission ID (the catalogue is seeded by migrations,
	// but for net-new test perms we'd need to Create — for this test
	// we use a perm name from the existing default catalogue).
	perm, err := permRepo.GetByName(ctx, permName)
	if err != nil {
		t.Fatalf("seed perm GetByName %s: %v", permName, err)
	}
	rp := &authdomain.RolePermission{
		RoleID: roleID, PermissionID: perm.ID, ScopeType: rpScopeType, ScopeID: rpScopeID,
	}
	if err := roleRepo.AddPermission(ctx, rp); err != nil {
		t.Fatalf("seed AddPermission %s/%s: %v", roleSuffix, permName, err)
	}
	return roleID
}

// grantActorRoleAtScope inserts an actor_roles row at the supplied
// scope. ScopeID nil = global.
func grantActorRoleAtScope(t *testing.T, ctx context.Context, repo *postgres.ActorRoleRepository, actorID, roleID string, scopeType authdomain.ScopeType, scopeID *string) {
	t.Helper()
	ar := &authdomain.ActorRole{
		ActorID: actorID, ActorType: authdomain.ActorTypeValue("APIKey"), RoleID: roleID,
		TenantID: authdomain.DefaultTenantID, ScopeType: scopeType, ScopeID: scopeID,
	}
	if err := repo.Grant(ctx, ar); err != nil {
		t.Fatalf("Grant %s -> %s@%s: %v", actorID, roleID, scopeType, err)
	}
}

func ptrStr(s string) *string { return &s }

// effectivePermFor returns the single EffectivePermission for
// (actor, perm) or nil. Asserts at most one row matches the perm name —
// the SQL DISTINCT should fold duplicates.
func effectivePermFor(t *testing.T, ctx context.Context, repo *postgres.ActorRoleRepository, actorID, permName string) (authdomain.ScopeType, *string, bool) {
	t.Helper()
	rows, err := repo.EffectivePermissions(ctx, actorID, authdomain.ActorTypeValue("APIKey"), authdomain.DefaultTenantID)
	if err != nil {
		t.Fatalf("EffectivePermissions for %s: %v", actorID, err)
	}
	for _, r := range rows {
		if r.PermissionName == permName {
			return r.ScopeType, r.ScopeID, true
		}
	}
	return "", nil, false
}

// TestEffectivePermissions_ActorRoleGlobal_RolePermGlobal pins the
// trivial happy path — both global → effective global.
func TestEffectivePermissions_ActorRoleGlobal_RolePermGlobal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-globglob", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-globglob", rid, authdomain.ScopeTypeGlobal, nil)

	st, sid, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-globglob", "cert.read")
	if !ok {
		t.Fatal("expected cert.read in effective permissions")
	}
	if st != authdomain.ScopeTypeGlobal {
		t.Errorf("effective scope_type = %q; want global", st)
	}
	if sid != nil {
		t.Errorf("effective scope_id = %v; want nil", sid)
	}
}

// TestEffectivePermissions_ActorRoleGlobal_RolePermProfile pins that
// rp.scope narrows when ar is global — the permission flows through
// at the rp scope.
func TestEffectivePermissions_ActorRoleGlobal_RolePermProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-globprof", "cert.read", authdomain.ScopeTypeProfile, ptrStr("p-prod"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-globprof", rid, authdomain.ScopeTypeGlobal, nil)

	st, sid, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-globprof", "cert.read")
	if !ok {
		t.Fatal("expected cert.read in effective permissions")
	}
	if st != authdomain.ScopeTypeProfile {
		t.Errorf("effective scope_type = %q; want profile", st)
	}
	if sid == nil || *sid != "p-prod" {
		t.Errorf("effective scope_id = %v; want p-prod", sid)
	}
}

// TestEffectivePermissions_ActorRoleProfile_RolePermGlobal is the
// load-bearing case the A-1 fix closes: pre-fix, ar.scope was ignored
// and Alice scoped to profile=p-prod silently got the rp global
// permission AT GLOBAL SCOPE (i.e. on profile=p-acme too). Post-fix,
// the effective scope must narrow to ar.scope (profile=p-prod).
func TestEffectivePermissions_ActorRoleProfile_RolePermGlobal_A1Closure(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-profglob", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-profglob", rid, authdomain.ScopeTypeProfile, ptrStr("p-prod"))

	st, sid, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-profglob", "cert.read")
	if !ok {
		t.Fatal("expected cert.read in effective permissions")
	}
	if st != authdomain.ScopeTypeProfile {
		t.Errorf("A-1 closure regression: effective scope_type = %q; want profile (narrowed to ar.scope)", st)
	}
	if sid == nil || *sid != "p-prod" {
		t.Errorf("A-1 closure regression: effective scope_id = %v; want p-prod (narrowed to ar.scope_id)", sid)
	}
}

// TestEffectivePermissions_BothScopedSameTuple_Matches pins that
// (ar=profile=p-prod, rp=profile=p-prod) collapses to a single
// matching effective row at profile=p-prod.
func TestEffectivePermissions_BothScopedSameTuple_Matches(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-bothsame", "cert.read", authdomain.ScopeTypeProfile, ptrStr("p-prod"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-bothsame", rid, authdomain.ScopeTypeProfile, ptrStr("p-prod"))

	st, sid, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-bothsame", "cert.read")
	if !ok {
		t.Fatal("expected cert.read in effective permissions")
	}
	if st != authdomain.ScopeTypeProfile || sid == nil || *sid != "p-prod" {
		t.Errorf("matching tuple did not produce profile=p-prod effective row; got (%q, %v)", st, sid)
	}
}

// TestEffectivePermissions_BothScopedDifferentIDs_RowDropped pins the
// disjoint-scope case: ar.profile=p-prod, rp.profile=p-acme → no
// permission row should appear in the effective set. Pre-A1 fix, the
// permission flowed through at rp.scope (p-acme) silently.
func TestEffectivePermissions_BothScopedDifferentIDs_RowDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-bothdiff", "cert.read", authdomain.ScopeTypeProfile, ptrStr("p-acme"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-bothdiff", rid, authdomain.ScopeTypeProfile, ptrStr("p-prod"))

	_, _, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-bothdiff", "cert.read")
	if ok {
		t.Error("A-1 closure regression: disjoint scopes (ar=p-prod, rp=p-acme) should NOT produce an effective permission row")
	}
}

// TestEffectivePermissions_ScopeTypeMismatch_RowDropped pins the
// scope-type-disagreement case: ar.profile=p-prod, rp.issuer=iss-x →
// no permission. Cross-type narrowing is undefined.
func TestEffectivePermissions_ScopeTypeMismatch_RowDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-typemis", "cert.read", authdomain.ScopeTypeIssuer, ptrStr("iss-x"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-typemis", rid, authdomain.ScopeTypeProfile, ptrStr("p-prod"))

	_, _, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-typemis", "cert.read")
	if ok {
		t.Error("A-1 closure regression: scope-type mismatch (ar=profile, rp=issuer) should NOT produce an effective permission row")
	}
}

// TestEffectivePermissions_ExpiredGrant_Excluded pins that
// ar.expires_at < NOW() excludes the grant from the effective set.
// This worked pre-A1; the test pins it stays correct under the new
// subquery shape.
func TestEffectivePermissions_ExpiredGrant_Excluded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-expired", "cert.read", authdomain.ScopeTypeGlobal, nil)
	// Set an expired grant by post-hoc UPDATE since Grant doesn't accept
	// past expires_at via the API — we mimic the "grant was made,
	// expired since" steady state.
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-expired", rid, authdomain.ScopeTypeGlobal, nil)
	if _, err := db.ExecContext(ctx, `UPDATE actor_roles SET expires_at = NOW() - INTERVAL '1 hour' WHERE actor_id = $1`, "alice-a1-expired"); err != nil {
		t.Fatalf("expire grant: %v", err)
	}

	_, _, ok := effectivePermFor(t, ctx, actorRepo, "alice-a1-expired", "cert.read")
	if ok {
		t.Error("expired grant should not contribute to effective permissions")
	}
}

// TestListByActor_ReturnsScopeColumns pins that ar.scope_type / scope_id
// surface on the read-side ListByActor path. Pre-A1 fix, scanActorRoles
// didn't read these columns even when the row carried non-default
// values — operators couldn't see what they configured.
func TestListByActor_ReturnsScopeColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	rid := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "ar-a1-listscope", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice-a1-listscope", rid, authdomain.ScopeTypeProfile, ptrStr("p-staging"))

	grants, err := actorRepo.ListByActor(ctx, "alice-a1-listscope", authdomain.ActorTypeValue("APIKey"), authdomain.DefaultTenantID)
	if err != nil {
		t.Fatalf("ListByActor: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants; want 1", len(grants))
	}
	if grants[0].ScopeType != authdomain.ScopeTypeProfile {
		t.Errorf("ListByActor scope_type = %q; want profile", grants[0].ScopeType)
	}
	if grants[0].ScopeID == nil || *grants[0].ScopeID != "p-staging" {
		t.Errorf("ListByActor scope_id = %v; want p-staging", grants[0].ScopeID)
	}
}
