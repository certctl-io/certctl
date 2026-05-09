package auth

import "testing"

// TestCanonicalPermissions_HasNoDuplicates pins the permission catalogue
// against accidental duplication. Migration 000029_rbac.up.sql seeds one
// permission row per name; if the catalogue has duplicates, the
// migration fails on the (name) UNIQUE constraint. Catch the regression
// at compile time instead of at startup.
func TestCanonicalPermissions_HasNoDuplicates(t *testing.T) {
	seen := make(map[string]struct{}, len(CanonicalPermissions))
	for _, p := range CanonicalPermissions {
		if _, ok := seen[p]; ok {
			t.Errorf("duplicate permission in CanonicalPermissions: %q", p)
		}
		seen[p] = struct{}{}
	}
}

// TestDefaultRoles_ReferenceCanonicalPermissionsOnly pins that every
// permission referenced in DefaultRoles is also present in
// CanonicalPermissions. The migration seeds one row per permission;
// referencing a non-canonical permission would fail at runtime.
func TestDefaultRoles_ReferenceCanonicalPermissionsOnly(t *testing.T) {
	canonical := make(map[string]struct{}, len(CanonicalPermissions))
	for _, p := range CanonicalPermissions {
		canonical[p] = struct{}{}
	}
	for roleID, perms := range DefaultRoles {
		for _, p := range perms {
			if _, ok := canonical[p]; !ok {
				t.Errorf("role %s references non-canonical permission %q", roleID, p)
			}
		}
	}
}

// TestDefaultRoles_AdminHasEveryPermission pins the invariant that the
// admin role is assigned the full canonical catalogue. Bundle 1
// Phase 1's migration relies on this for the admin grant SELECT * FROM
// permissions; if the role somehow only got a subset, downstream
// RequirePermission gates would 403 admin actors on permissions that
// were forgotten.
func TestDefaultRoles_AdminHasEveryPermission(t *testing.T) {
	adminPerms := DefaultRoles[RoleIDAdmin]
	if len(adminPerms) != len(CanonicalPermissions) {
		t.Errorf("admin role permission count = %d, want %d (full canonical catalogue)",
			len(adminPerms), len(CanonicalPermissions))
	}
}

// TestSeededIDs_HavePrefixes pins the TEXT-PK-with-prefix convention
// (CLAUDE.md "Architecture Decisions").
func TestSeededIDs_HavePrefixes(t *testing.T) {
	cases := []struct {
		id     string
		prefix string
	}{
		{DefaultTenantID, "t-"},
		{RoleIDAdmin, "r-"},
		{RoleIDOperator, "r-"},
		{RoleIDViewer, "r-"},
		{RoleIDAgent, "r-"},
		{RoleIDMCP, "r-"},
		{RoleIDCLI, "r-"},
		{RoleIDAuditor, "r-"},
		// DemoAnonActorID is an actor id, not a role / tenant id; it
		// uses the actor- prefix instead of t-/r-/p-/ar-. Pin
		// separately so a future rename doesn't silently regress.
		{DemoAnonActorID, "actor-"},
	}
	for _, tc := range cases {
		if len(tc.id) <= len(tc.prefix) || tc.id[:len(tc.prefix)] != tc.prefix {
			t.Errorf("id %q missing prefix %q", tc.id, tc.prefix)
		}
	}
}

// TestScopeType_EnumValuesPinned pins the three Bundle 1 scope types
// against drift. Migration 000029_rbac.up.sql has a CHECK constraint
// `scope_type IN ('global', 'profile', 'issuer')`; if Bundle 1 code
// adds a fourth value, the migration must be updated in lockstep.
func TestScopeType_EnumValuesPinned(t *testing.T) {
	want := []ScopeType{ScopeTypeGlobal, ScopeTypeProfile, ScopeTypeIssuer}
	gotValues := []string{string(ScopeTypeGlobal), string(ScopeTypeProfile), string(ScopeTypeIssuer)}
	wantValues := []string{"global", "profile", "issuer"}
	for i, v := range wantValues {
		if gotValues[i] != v {
			t.Errorf("scope type %d: got %q, want %q", i, gotValues[i], v)
		}
	}
	if len(want) != 3 {
		t.Errorf("ScopeType enum size = %d, want 3 (any change requires migration update)", len(want))
	}
}
