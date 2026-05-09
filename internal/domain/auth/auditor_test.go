package auth

import "testing"

// =============================================================================
// Bundle 1 Phase 8 — auditor role invariants. Pin the seeded permission
// set so a future refactor that accidentally widens it gets caught.
// =============================================================================

// TestAuditorRoleHoldsExactlyAuditReadAndExport pins the load-bearing
// invariant that the auditor role has read-only audit access AND
// nothing else. Any drift here breaks the SOC 2 / FedRAMP separation
// the prompt requires.
func TestAuditorRoleHoldsExactlyAuditReadAndExport(t *testing.T) {
	got, ok := DefaultRoles[RoleIDAuditor]
	if !ok {
		t.Fatalf("auditor role missing from DefaultRoles")
	}
	want := map[string]bool{
		"audit.read":   true,
		"audit.export": true,
	}
	if len(got) != len(want) {
		t.Errorf("auditor permission count = %d, want %d (auditor role widened?)", len(got), len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("auditor holds %q but should not — auditor must be read-only", p)
		}
	}
	for w := range want {
		found := false
		for _, p := range got {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("auditor role missing %q", w)
		}
	}
}

// TestAuditorRoleDoesNotHoldMutatingOrReadingNonAuditPerms pins that
// the auditor role grants ZERO mutating perms (cert.*, profile.*,
// issuer.*, target.*, agent.*) AND zero non-audit read perms. The
// auditor is "audit-only", not "read-only across everything".
func TestAuditorRoleDoesNotHoldMutatingOrReadingNonAuditPerms(t *testing.T) {
	got := DefaultRoles[RoleIDAuditor]
	for _, p := range got {
		switch p {
		case "audit.read", "audit.export":
			// allowed
		default:
			t.Errorf("auditor holds non-audit permission %q — should be audit-only", p)
		}
	}
}

// TestAuditorRoleSeparateFromViewer pins that auditor and viewer
// permission sets are disjoint EXCEPT for nothing — viewer gets
// resource-read perms (cert/profile/issuer/target/agent) which auditor
// must NOT inherit. Closes the "auditor sees customer cert data" leg.
func TestAuditorRoleSeparateFromViewer(t *testing.T) {
	auditorSet := map[string]bool{}
	for _, p := range DefaultRoles[RoleIDAuditor] {
		auditorSet[p] = true
	}
	viewerSet := map[string]bool{}
	for _, p := range DefaultRoles[RoleIDViewer] {
		viewerSet[p] = true
	}
	for v := range viewerSet {
		if v == "audit.read" {
			// shared by design (viewer can read audit)
			continue
		}
		if auditorSet[v] {
			t.Errorf("auditor inherits viewer permission %q — must be disjoint except audit.read", v)
		}
	}
}
