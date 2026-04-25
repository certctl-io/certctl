package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// jsonMarshalDirect / jsonUnmarshalDirect are thin aliases for the
// stdlib encoding/json calls. They exist only to make the G-2 redaction
// tests below grep-friendly: any future test author searching for "how
// is APIKeyHash redaction tested" will land on these and the call sites,
// rather than having to grep through dozens of unrelated json.Marshal
// usages.
func jsonMarshalDirect(v interface{}) ([]byte, error)      { return json.Marshal(v) }
func jsonUnmarshalDirect(data []byte, v interface{}) error { return json.Unmarshal(data, v) }
func containsSubstr(haystack, needle string) bool          { return strings.Contains(haystack, needle) }

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

// G-2 (P1): the cat-s5-apikey_leak audit closure tests. Pre-G-2,
// Agent.APIKeyHash was tagged `json:"api_key_hash"` and shipped on
// every /api/v1/agents response — credential-derivative leak that gave
// offline brute-force targets to every authenticated client. Post-G-2
// the tag is "-" AND Agent.MarshalJSON zeroes the field on a marshal-
// time copy. These tests pin both layers of the defense:
//
//   1. A populated APIKeyHash is never present in the marshaled JSON.
//   2. The redaction holds on *Agent, on slice elements, and on a
//      sentinel literal-value check (so even a future field that
//      happens to contain the same hash string would not appear).
//   3. The marshal-time copy does not mutate the caller's original —
//      receiver is by-value, but pin it explicitly so a future refactor
//      that switches to pointer-receiver gets caught.
//   4. Round-trip preserves every other field (hash dropped on encode,
//      cannot reappear on decode because the wire never carries it).

const g2LeakSentinel = "sha256:LEAKED-CREDENTIAL-DERIVATIVE-SENTINEL"

// TestAgent_MarshalJSON_RedactsAPIKeyHash is the marshal-boundary
// contract test: a single Agent value with a populated APIKeyHash must
// not emit the field name nor the sentinel value.
func TestAgent_MarshalJSON_RedactsAPIKeyHash(t *testing.T) {
	t.Parallel()
	a := Agent{
		ID:           "agent-test",
		Name:         "test-agent",
		Hostname:     "host.example",
		Status:       AgentStatusOnline,
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		APIKeyHash:   g2LeakSentinel,
		OS:           "linux",
		Architecture: "amd64",
		IPAddress:    "10.0.0.1",
		Version:      "v2.0.49",
	}
	out, err := jsonMarshalDirect(a)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	body := string(out)
	if containsSubstr(body, "api_key_hash") {
		t.Errorf("marshaled body contains \"api_key_hash\" key — G-2 leak regressed:\n%s", body)
	}
	if containsSubstr(body, "APIKeyHash") {
		t.Errorf("marshaled body contains \"APIKeyHash\" — type-alias redaction broke:\n%s", body)
	}
	if containsSubstr(body, g2LeakSentinel) {
		t.Errorf("marshaled body contains the leak sentinel %q — value redaction broke:\n%s", g2LeakSentinel, body)
	}
	// Sanity: every OTHER non-zero field IS present (this guards against
	// the type-alias trick accidentally dropping siblings).
	for _, want := range []string{"agent-test", "test-agent", "host.example", "Online", "linux", "amd64", "10.0.0.1", "v2.0.49"} {
		if !containsSubstr(body, want) {
			t.Errorf("marshaled body missing expected field value %q:\n%s", want, body)
		}
	}
}

// TestAgent_MarshalJSON_RedactsViaPointer covers the *Agent path that
// handlers hit when calling JSON(w, http.StatusOK, agent) with a *Agent
// from svc.GetAgent. A value-receiver MarshalJSON is reachable from
// pointer values via reflect; this test pins that contract.
func TestAgent_MarshalJSON_RedactsViaPointer(t *testing.T) {
	t.Parallel()
	a := &Agent{ID: "agent-x", APIKeyHash: g2LeakSentinel}
	out, err := jsonMarshalDirect(a)
	if err != nil {
		t.Fatalf("Marshal *Agent returned error: %v", err)
	}
	if containsSubstr(string(out), g2LeakSentinel) {
		t.Errorf("*Agent marshal leaked sentinel:\n%s", string(out))
	}
	if containsSubstr(string(out), "api_key_hash") {
		t.Errorf("*Agent marshal contains \"api_key_hash\" key:\n%s", string(out))
	}
}

// TestAgent_MarshalJSON_RedactsInSlice covers the []domain.Agent path
// the ListAgents handler emits via PagedResponse{Data: agents}. Each
// element must be redacted independently.
func TestAgent_MarshalJSON_RedactsInSlice(t *testing.T) {
	t.Parallel()
	agents := []Agent{
		{ID: "agent-1", APIKeyHash: g2LeakSentinel + "-1"},
		{ID: "agent-2", APIKeyHash: g2LeakSentinel + "-2"},
		{ID: "agent-3", APIKeyHash: g2LeakSentinel + "-3"},
	}
	out, err := jsonMarshalDirect(agents)
	if err != nil {
		t.Fatalf("Marshal []Agent returned error: %v", err)
	}
	body := string(out)
	if containsSubstr(body, "api_key_hash") {
		t.Errorf("[]Agent marshal contains \"api_key_hash\" key:\n%s", body)
	}
	for i := 1; i <= 3; i++ {
		sentinel := g2LeakSentinel + "-" + string(rune('0'+i))
		if containsSubstr(body, sentinel) {
			t.Errorf("[]Agent marshal leaked sentinel %q:\n%s", sentinel, body)
		}
	}
	// Every agent ID is present — the redaction didn't accidentally
	// strip the entire element.
	for _, id := range []string{"agent-1", "agent-2", "agent-3"} {
		if !containsSubstr(body, id) {
			t.Errorf("[]Agent marshal missing element ID %q:\n%s", id, body)
		}
	}
}

// TestAgent_MarshalJSON_DoesNotMutateReceiver pins the by-value-receiver
// contract: marshaling must not zero APIKeyHash on the caller's struct,
// only on the marshal-time copy. This guards against a future refactor
// that switches to pointer receiver and breaks every code path that
// marshals an Agent and then re-uses it (e.g., audit-event payload
// construction immediately after returning the agent in a handler).
func TestAgent_MarshalJSON_DoesNotMutateReceiver(t *testing.T) {
	t.Parallel()
	a := Agent{ID: "agent-keep", APIKeyHash: g2LeakSentinel}
	if _, err := jsonMarshalDirect(a); err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if a.APIKeyHash != g2LeakSentinel {
		t.Errorf("MarshalJSON mutated caller's APIKeyHash: got %q want %q", a.APIKeyHash, g2LeakSentinel)
	}
}

// TestAgent_MarshalJSON_RoundTrip pins the wire-shape contract: an
// Agent marshaled to JSON and unmarshaled back into a fresh Agent has
// every field preserved EXCEPT APIKeyHash, which the wire never carries.
// This double-confirms the redaction is a one-way guarantee at the
// serialization boundary, not an accidental on-decode behavior.
func TestAgent_MarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	hb := now.Add(-5 * time.Minute)
	original := Agent{
		ID:              "agent-rt",
		Name:            "rt",
		Hostname:        "rt.host",
		Status:          AgentStatusOnline,
		LastHeartbeatAt: &hb,
		RegisteredAt:    now,
		APIKeyHash:      g2LeakSentinel,
		OS:              "linux",
		Architecture:    "arm64",
		IPAddress:       "10.0.0.99",
		Version:         "v2.0.49",
	}
	out, err := jsonMarshalDirect(original)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var got Agent
	if err := jsonUnmarshalDirect(out, &got); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if got.APIKeyHash != "" {
		t.Errorf("APIKeyHash survived round-trip: got %q want empty (the wire must not carry it)", got.APIKeyHash)
	}
	if got.ID != original.ID || got.Name != original.Name || got.Hostname != original.Hostname {
		t.Errorf("identity fields lost in round-trip: got %+v want %+v", got, original)
	}
	if got.OS != original.OS || got.Architecture != original.Architecture || got.IPAddress != original.IPAddress {
		t.Errorf("metadata fields lost in round-trip: got %+v want %+v", got, original)
	}
}
