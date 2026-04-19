package domain

import (
	"testing"
	"time"
)

// TestAgent_IsRetired covers the I-004 soft-retirement predicate that gates
// which callers hide an agent row from active listings.
func TestAgent_IsRetired(t *testing.T) {
	t.Run("nil receiver is not retired", func(t *testing.T) {
		var a *Agent
		if a.IsRetired() {
			t.Fatalf("nil *Agent should not be retired")
		}
	})

	t.Run("zero value is not retired", func(t *testing.T) {
		a := &Agent{}
		if a.IsRetired() {
			t.Fatalf("zero Agent should not be retired")
		}
	})

	t.Run("RetiredAt set is retired", func(t *testing.T) {
		now := time.Now()
		a := &Agent{RetiredAt: &now}
		if !a.IsRetired() {
			t.Fatalf("Agent with RetiredAt != nil must be retired")
		}
	})
}

// TestAgentDependencyCounts_HasDependencies verifies the preflight
// aggregation helper used by the 409 block path of DELETE /agents/{id}.
func TestAgentDependencyCounts_HasDependencies(t *testing.T) {
	cases := []struct {
		name   string
		counts AgentDependencyCounts
		want   bool
	}{
		{"all zero", AgentDependencyCounts{}, false},
		{"active target", AgentDependencyCounts{ActiveTargets: 1}, true},
		{"active cert", AgentDependencyCounts{ActiveCertificates: 1}, true},
		{"pending job", AgentDependencyCounts{PendingJobs: 1}, true},
		{"mixed", AgentDependencyCounts{ActiveTargets: 3, PendingJobs: 2}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.counts.HasDependencies(); got != tc.want {
				t.Fatalf("HasDependencies()=%v want=%v counts=%+v", got, tc.want, tc.counts)
			}
		})
	}
}
