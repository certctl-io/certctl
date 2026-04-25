package domain

// BulkReassignmentRequest is the input to POST /api/v1/certificates/bulk-reassign.
//
// L-2 closure (cat-l-8a1fb258a38a): the GUI used to loop
// `await updateCertificate(id, { owner_id: ownerId })` over the selection
// at `web/src/pages/CertificatesPage.tsx::handleReassign`. Post-L-2 it
// POSTs once.
//
// Narrower than BulkRenewalCriteria — the operator workflow is "I have N
// certs selected and I want them all owned by Alice now". Criteria-mode
// reassignment doesn't have a strong use case (operators query first,
// then reassign by ID), so the request is IDs-only. OwnerID is required;
// TeamID is optional and the cert's team_id is updated only when TeamID
// is non-empty (matches the existing per-cert PUT behaviour where empty
// fields leave the existing value unchanged).
type BulkReassignmentRequest struct {
	CertificateIDs []string `json:"certificate_ids"`
	OwnerID        string   `json:"owner_id"`
	TeamID         string   `json:"team_id,omitempty"`
}

// IsEmpty returns true if no IDs are provided. The service layer rejects
// empty IDs with a 400 — explicit-IDs is the only selection mode for
// reassignment (no criteria-mode). Naming mirrors BulkRevocationCriteria
// + BulkRenewalCriteria.IsEmpty so the validate-and-reject pattern is
// the same across all three bulk endpoints.
func (r BulkReassignmentRequest) IsEmpty() bool {
	return len(r.CertificateIDs) == 0
}

// BulkReassignmentResult mirrors BulkRevocationResult / BulkRenewalResult
// envelope shape so the frontend's bulk-result rendering is one helper.
//
// Counters semantics:
//   - TotalMatched: number of certs resolved from CertificateIDs
//   - TotalReassigned: number where owner_id (and optionally team_id)
//     was actually mutated
//   - TotalSkipped: certs already owned by the target OwnerID — no-op
//     skip rather than a fake "succeeded" count, so operators see "5 of
//     your 10 selections were no-ops" without triaging fake errors
//   - TotalFailed: certs where the per-cert update returned an error
//     (e.g., the cert no longer exists, the repo update failed)
//   - Errors: per-cert error details for the failure path
type BulkReassignmentResult struct {
	TotalMatched    int                  `json:"total_matched"`
	TotalReassigned int                  `json:"total_reassigned"`
	TotalSkipped    int                  `json:"total_skipped"`
	TotalFailed     int                  `json:"total_failed"`
	Errors          []BulkOperationError `json:"errors,omitempty"`
}
