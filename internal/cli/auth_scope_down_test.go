package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// TestSuggestRoleFromAuditEvents_TablePins the audit-event analyser
// classification rules. Pure function; no I/O. Adding a new role
// pattern means adding a row here.
func TestSuggestRoleFromAuditEvents_Table(t *testing.T) {
	cases := []struct {
		name       string
		events     []AuditEventLite
		wantRole   string
		reasonHint string
	}{
		{
			name:       "empty history → viewer",
			events:     nil,
			wantRole:   "viewer",
			reasonHint: "no audit history",
		},
		{
			name: "only cert.read → viewer",
			events: []AuditEventLite{
				{Action: "cert.read"},
				{Action: "cert.read"},
				{Action: "issuer.read"},
			},
			wantRole:   "viewer",
			reasonHint: "read-only",
		},
		{
			name: "agent + cert.issue → agent",
			events: []AuditEventLite{
				{Action: "agent.heartbeat"},
				{Action: "agent.job.poll"},
				{Action: "cert.issue"},
				{Action: "cert.read"},
			},
			wantRole:   "agent",
			reasonHint: "agent",
		},
		{
			name: "cert lifecycle without admin → operator",
			events: []AuditEventLite{
				{Action: "cert.issue"},
				{Action: "cert.revoke"},
				{Action: "profile.edit"},
				{Action: "target.edit"},
			},
			wantRole:   "operator",
			reasonHint: "lifecycle",
		},
		{
			name: "any auth.role.assign → admin",
			events: []AuditEventLite{
				{Action: "auth.role.assign"},
			},
			wantRole:   "admin",
			reasonHint: "admin-only",
		},
		{
			name: "any cert.bulk_revoke → admin",
			events: []AuditEventLite{
				{Action: "cert.bulk_revoke"},
			},
			wantRole:   "admin",
			reasonHint: "admin-only",
		},
		{
			name: "ca.hierarchy.* → admin",
			events: []AuditEventLite{
				{Action: "ca.hierarchy.add_child"},
			},
			wantRole:   "admin",
			reasonHint: "admin-only",
		},
		{
			name: "MCP-only history → mcp",
			events: []AuditEventLite{
				{Action: "mcp.list_certificates"},
				{Action: "mcp.get_issuer"},
			},
			wantRole:   "mcp",
			reasonHint: "MCP",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role, reason := SuggestRoleFromAuditEvents(tc.events)
			if role != tc.wantRole {
				t.Errorf("role = %q, want %q (reason=%q)", role, tc.wantRole, reason)
			}
			if !strings.Contains(strings.ToLower(reason), strings.ToLower(tc.reasonHint)) {
				t.Errorf("reason %q does not contain hint %q", reason, tc.reasonHint)
			}
		})
	}
}

// TestFilterScopeDownCandidates_HidesDemoAnon pins the invariant that
// the synthetic actor-demo-anon row never reaches the prompt loop.
func TestFilterScopeDownCandidates_HidesDemoAnon(t *testing.T) {
	in := []AuthKeyEntry{
		{ActorID: "alice", RoleIDs: []string{"r-admin"}},
		{ActorID: DemoAnonActorID, RoleIDs: []string{"r-admin"}},
		{ActorID: "bob", RoleIDs: []string{"r-viewer"}},
	}
	got := filterScopeDownCandidates(in)
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	for _, k := range got {
		if k.ActorID == DemoAnonActorID {
			t.Errorf("filter let actor-demo-anon through")
		}
	}
}

// TestBuildScopeDownPlan_KeepEmptyAndUnknown pins the prompt-loop
// behaviour: empty input or "keep" leaves the row alone; unknown role
// names also fall through (operator can re-run the flow).
func TestBuildScopeDownPlan_KeepEmptyAndUnknown(t *testing.T) {
	keys := []AuthKeyEntry{
		{ActorID: "alice", RoleIDs: []string{"r-admin"}},
		{ActorID: "bob", RoleIDs: []string{"r-admin"}},
		{ActorID: "carol", RoleIDs: []string{"r-admin"}},
	}
	// alice keeps; bob → operator; carol → bogus role (no change).
	in := bufio.NewReader(strings.NewReader("\noperator\nbogus\n"))
	var out bytes.Buffer
	plan, err := buildScopeDownPlan(keys, in, &out)
	if err != nil {
		t.Fatalf("plan err = %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("plan size = %d, want 1 (only bob changes)", len(plan))
	}
	if plan[0].ActorID != "bob" || plan[0].TargetRole != "r-operator" {
		t.Errorf("plan[0] = %+v, want bob → r-operator", plan[0])
	}
}

// TestBuildScopeDownPlan_ApplyRolePrefix pins that the "operator"
// input becomes "r-operator" downstream — the API accepts the
// prefixed role IDs and the plan-builder normalizes.
func TestBuildScopeDownPlan_ApplyRolePrefix(t *testing.T) {
	keys := []AuthKeyEntry{{ActorID: "alice", RoleIDs: []string{"r-admin"}}}
	for _, role := range []string{"admin", "operator", "viewer", "agent", "mcp", "cli", "auditor"} {
		in := bufio.NewReader(strings.NewReader(role + "\n"))
		var out bytes.Buffer
		plan, err := buildScopeDownPlan(keys, in, &out)
		if err != nil {
			t.Fatalf("role=%s: %v", role, err)
		}
		if len(plan) != 1 || plan[0].TargetRole != "r-"+role {
			t.Errorf("role=%s: plan[0].TargetRole = %q, want r-%s", role, plan[0].TargetRole, role)
		}
	}
}
