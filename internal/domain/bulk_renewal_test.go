package domain

import (
	"encoding/json"
	"testing"
)

// TestBulkRenewalCriteria_IsEmpty pins the validate-and-reject contract:
// empty criteria → service rejects with 400. Mirrors
// TestBulkRevocationCriteria_IsEmpty exactly so the cross-bulk-endpoint
// behaviour is uniform.
func TestBulkRenewalCriteria_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		c    BulkRenewalCriteria
		want bool
	}{
		{"all-zero", BulkRenewalCriteria{}, true},
		{"profile-id-set", BulkRenewalCriteria{ProfileID: "cp-x"}, false},
		{"owner-id-set", BulkRenewalCriteria{OwnerID: "o-alice"}, false},
		{"agent-id-set", BulkRenewalCriteria{AgentID: "ag-1"}, false},
		{"issuer-id-set", BulkRenewalCriteria{IssuerID: "iss-x"}, false},
		{"team-id-set", BulkRenewalCriteria{TeamID: "t-x"}, false},
		{"ids-set", BulkRenewalCriteria{CertificateIDs: []string{"mc-1"}}, false},
		{"ids-empty-slice", BulkRenewalCriteria{CertificateIDs: []string{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBulkRenewalResult_JSONShape pins the wire contract. Operator
// tooling (k8s rollouts, blackbox probes, the `certctl-cli bulk-renew`
// JSON consumer) parses these field names; renaming any of them is a
// breaking change.
func TestBulkRenewalResult_JSONShape(t *testing.T) {
	t.Parallel()

	r := &BulkRenewalResult{
		TotalMatched:  5,
		TotalEnqueued: 4,
		TotalSkipped:  1,
		TotalFailed:   0,
		EnqueuedJobs: []BulkEnqueuedJob{
			{CertificateID: "mc-1", JobID: "job-a"},
		},
		Errors: nil,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for _, k := range []string{"total_matched", "total_enqueued", "total_skipped", "total_failed", "enqueued_jobs"} {
		if _, ok := round[k]; !ok {
			t.Errorf("missing JSON field %q in %s", k, string(b))
		}
	}
	// errors omitempty when nil — must NOT appear
	if _, ok := round["errors"]; ok {
		t.Errorf("nil Errors should be omitempty; got: %s", string(b))
	}

	// EnqueuedJobs nested shape
	jobs := round["enqueued_jobs"].([]interface{})
	if len(jobs) != 1 {
		t.Fatalf("enqueued_jobs len = %d, want 1", len(jobs))
	}
	first := jobs[0].(map[string]interface{})
	if first["certificate_id"] != "mc-1" || first["job_id"] != "job-a" {
		t.Errorf("BulkEnqueuedJob field names drifted: %v", first)
	}
}
