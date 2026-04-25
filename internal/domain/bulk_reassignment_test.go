package domain

import (
	"encoding/json"
	"testing"
)

func TestBulkReassignmentRequest_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    BulkReassignmentRequest
		want bool
	}{
		{"all-zero", BulkReassignmentRequest{}, true},
		{"empty-ids-slice", BulkReassignmentRequest{CertificateIDs: []string{}}, true},
		{"ids-set-but-no-owner", BulkReassignmentRequest{CertificateIDs: []string{"mc-1"}}, false},
		// IsEmpty is a pure ID-presence check; OwnerID/TeamID are
		// validated separately in the service layer (OwnerID required;
		// TeamID optional). This split mirrors how BulkRevocationCriteria
		// + reason are validated in two distinct steps.
		{"owner-set-but-no-ids", BulkReassignmentRequest{OwnerID: "o-alice"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBulkReassignmentResult_JSONShape(t *testing.T) {
	t.Parallel()

	r := &BulkReassignmentResult{
		TotalMatched:    10,
		TotalReassigned: 7,
		TotalSkipped:    3, // already-owned-by-target — silent no-op
		TotalFailed:     0,
		Errors:          nil,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	for _, k := range []string{"total_matched", "total_reassigned", "total_skipped", "total_failed"} {
		if _, ok := round[k]; !ok {
			t.Errorf("missing JSON field %q in %s", k, string(b))
		}
	}
	if _, ok := round["errors"]; ok {
		t.Errorf("nil Errors should be omitempty; got: %s", string(b))
	}
}

func TestBulkOperationError_JSONShape(t *testing.T) {
	t.Parallel()

	e := BulkOperationError{
		CertificateID: "mc-1",
		Error:         "renewal already in progress",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	want := `{"certificate_id":"mc-1","error":"renewal already in progress"}`
	if string(b) != want {
		t.Errorf("JSON shape drift:\n  got:  %s\n  want: %s", string(b), want)
	}
}
