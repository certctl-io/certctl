package postgres_test

// Audit 2026-05-11 A-4 closure — scope-aware ActorRoleRepository.Revoke
// regression matrix. Pre-fix, Revoke deleted every (actor,role,tenant)
// row regardless of (scope_type, scope_id), so an operator who held
// the same role at two different profile scopes could only nuke them
// both — selective revoke was unrepresentable. The new semantic:
//
//   opts.ScopeType == ""        → legacy "revoke all variants"
//   opts.ScopeType == global    → drop only the (global, NULL) row
//   opts.ScopeType == profile|issuer + scope_id → drop only that variant
//   no match for a scoped revoke → ErrActorRoleNotFound (HTTP 404)
//
// Helpers (seedRoleWithPerm, grantActorRoleAtScope, ptrStr) live in
// auth_scope_test.go in this same _test package.

import (
	"context"
	"errors"
	"testing"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// listActorRoleScopes returns every (scope_type, scope_id-or-empty)
// tuple held by the actor for the role. Lets tests assert which
// variants are still standing after a Revoke.
func listActorRoleScopes(t *testing.T, ctx context.Context, repo *postgres.ActorRoleRepository, actorID, roleID string) []string {
	t.Helper()
	rows, err := repo.ListByActor(ctx, actorID, authdomain.ActorTypeValue("APIKey"), authdomain.DefaultTenantID)
	if err != nil {
		t.Fatalf("ListByActor: %v", err)
	}
	var out []string
	for _, r := range rows {
		if r.RoleID != roleID {
			continue
		}
		st := string(r.ScopeType)
		sid := ""
		if r.ScopeID != nil {
			sid = *r.ScopeID
		}
		out = append(out, st+"|"+sid)
	}
	return out
}

// TestRevokeActorRole_NoOpts_RemovesAllVariants — pre-A-4 legacy
// semantic. Actor holds the same role at two profile scopes; Revoke
// with zero-value opts must wipe both.
func TestRevokeActorRole_NoOpts_RemovesAllVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	roleID := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-noopts", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-acme"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-globex"))

	got := listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 2 {
		t.Fatalf("pre-revoke variants = %v; want 2", got)
	}

	if err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), roleID, authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{}); err != nil {
		t.Fatalf("Revoke (no-opts): %v", err)
	}
	got = listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 0 {
		t.Errorf("legacy revoke left variants: %v; want []", got)
	}
}

// TestRevokeActorRole_WithScope_RemovesOnlyMatching — the A-4
// selective-revoke happy path. Two scoped grants; revoke one by
// (profile=p-acme); the other (profile=p-globex) stays.
func TestRevokeActorRole_WithScope_RemovesOnlyMatching(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	roleID := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-scoped", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-acme"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-globex"))

	err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), roleID, authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{
		ScopeType: authdomain.ScopeTypeProfile,
		ScopeID:   ptrStr("p-acme"),
	})
	if err != nil {
		t.Fatalf("scoped Revoke: %v", err)
	}
	got := listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 1 || got[0] != "profile|p-globex" {
		t.Errorf("post-revoke variants = %v; want [profile|p-globex]", got)
	}
}

// TestRevokeActorRole_WithGlobalScope_RemovesOnlyGlobal — pin the
// `scope_id IS NOT DISTINCT FROM $6` branch. Actor holds global +
// profile-scoped grants of the same role; revoke `scope_type=global`
// drops only the global row.
func TestRevokeActorRole_WithGlobalScope_RemovesOnlyGlobal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	roleID := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-global", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-acme"))

	err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), roleID, authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{
		ScopeType: authdomain.ScopeTypeGlobal,
		ScopeID:   nil,
	})
	if err != nil {
		t.Fatalf("global-scope Revoke: %v", err)
	}
	got := listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 1 || got[0] != "profile|p-acme" {
		t.Errorf("post-revoke variants = %v; want [profile|p-acme]", got)
	}
}

// TestRevokeActorRole_NoMatch_ReturnsNotFound — operator passes a
// (scope_type, scope_id) the actor doesn't actually hold for this
// role. Selective revoke must return ErrActorRoleNotFound; existing
// rows must be untouched.
func TestRevokeActorRole_NoMatch_ReturnsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	roleID := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-nomatch", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-acme"))

	err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), roleID, authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{
		ScopeType: authdomain.ScopeTypeProfile,
		ScopeID:   ptrStr("p-globex"),
	})
	if !errors.Is(err, repository.ErrActorRoleNotFound) {
		t.Errorf("err = %v; want ErrActorRoleNotFound", err)
	}
	got := listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 1 || got[0] != "profile|p-acme" {
		t.Errorf("untargeted revoke mutated existing rows: %v", got)
	}
}

// TestRevokeActorRole_NoOpts_NoMatch_IsNoOp — pin the legacy
// idempotence contract. Empty opts + zero matching rows must NOT
// return an error (the GUI's pre-A-4 revoke button fires this when
// the operator clicks "remove" on a stale row).
func TestRevokeActorRole_NoOpts_NoMatch_IsNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	// Seed an unrelated role + grant so the table isn't completely
	// empty (more realistic baseline).
	otherRole := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-noop-other", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "bob", otherRole, authdomain.ScopeTypeGlobal, nil)

	if err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), "r-nonexistent", authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{}); err != nil {
		t.Errorf("no-match no-opts Revoke should be nil; got %v", err)
	}
	// Sanity: the unrelated grant is untouched.
	got := listActorRoleScopes(t, ctx, actorRepo, "bob", otherRole)
	if len(got) != 1 || got[0] != "global|" {
		t.Errorf("unrelated grant mutated: %v", got)
	}
}

// TestRevokeActorRole_IssuerScope_RemovesOnlyMatching — pin the
// issuer-scope variant (the other half of the {profile, issuer}
// scope-type pair). Actor holds the same role across profile + issuer
// scopes; revoke `issuer=iss-x` drops only the issuer row.
func TestRevokeActorRole_IssuerScope_RemovesOnlyMatching(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	ctx := context.Background()
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	actorRepo := postgres.NewActorRoleRepository(db)

	roleID := seedRoleWithPerm(t, ctx, roleRepo, permRepo, "rev-issuer", "cert.read", authdomain.ScopeTypeGlobal, nil)
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeProfile, ptrStr("p-acme"))
	grantActorRoleAtScope(t, ctx, actorRepo, "alice", roleID, authdomain.ScopeTypeIssuer, ptrStr("iss-x"))

	err := actorRepo.Revoke(ctx, "alice", authdomain.ActorTypeValue("APIKey"), roleID, authdomain.DefaultTenantID, repository.ActorRoleRevokeOptions{
		ScopeType: authdomain.ScopeTypeIssuer,
		ScopeID:   ptrStr("iss-x"),
	})
	if err != nil {
		t.Fatalf("issuer-scope Revoke: %v", err)
	}
	got := listActorRoleScopes(t, ctx, actorRepo, "alice", roleID)
	if len(got) != 1 || got[0] != "profile|p-acme" {
		t.Errorf("post-revoke variants = %v; want [profile|p-acme]", got)
	}
}
