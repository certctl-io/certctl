package domain

// BulkRenewalCriteria selects a set of managed certificates to renew. At
// least one selector must be non-empty (IsEmpty() guards this in the
// service layer; same shape and rule as BulkRevocationCriteria so
// operators who already know the bulk-revoke contract have zero new
// surface to learn).
//
// L-1 master closure (cat-l-fa0c1ac07ab5): the GUI used to loop
// `await triggerRenewal(id)` over the selection at
// `web/src/pages/CertificatesPage.tsx::handleBulkRenewal`. 100 certs =
// 100 sequential HTTP round-trips × Auth → audit → handler → service →
// repo → DB → audit. Post-L-1 the GUI POSTs once; the server resolves
// the criteria, applies status filters, and enqueues N renewal jobs.
//
// The "renew all certs of profile X before its CA changes" use case is
// the canonical reason to support criteria-mode in addition to explicit
// IDs. Mirrors `BulkRevocationCriteria` field-for-field.
type BulkRenewalCriteria struct {
	ProfileID      string   `json:"profile_id,omitempty"`
	OwnerID        string   `json:"owner_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	IssuerID       string   `json:"issuer_id,omitempty"`
	TeamID         string   `json:"team_id,omitempty"`
	CertificateIDs []string `json:"certificate_ids,omitempty"`
}

// IsEmpty returns true if no filter criteria are set. The service layer
// rejects empty criteria with a 400 (mirrors BulkRevocationCriteria.IsEmpty).
func (c BulkRenewalCriteria) IsEmpty() bool {
	return c.ProfileID == "" && c.OwnerID == "" && c.AgentID == "" &&
		c.IssuerID == "" && c.TeamID == "" && len(c.CertificateIDs) == 0
}

// BulkRenewalResult is the envelope returned to the caller. Distinct
// from BulkRevocationResult because the action verb differs: renewal
// ENQUEUES a job per matched cert (asynchronous) rather than performing
// the mutation synchronously like revocation. The EnqueuedJobs slice
// gives the caller the job IDs so the GUI can poll
// /api/v1/jobs?status=Running for progress without re-querying the
// certificate list.
//
// Counters semantics (mirror BulkRevocationResult conventions):
//   - TotalMatched: number of certs the criteria/IDs resolved to
//   - TotalEnqueued: number of renewal jobs successfully created
//   - TotalSkipped: certs in a status that disallows renewal (already
//     RenewalInProgress, Revoked, or Archived); silent no-op, NOT an error
//   - TotalFailed: certs where the enqueue path returned an error
//   - EnqueuedJobs: per-cert {certificate_id, job_id} pairs for the
//     successful enqueue path (omitempty so an all-skipped batch
//     produces a clean response)
//   - Errors: per-cert error details for the failure path
type BulkRenewalResult struct {
	TotalMatched  int                  `json:"total_matched"`
	TotalEnqueued int                  `json:"total_enqueued"`
	TotalSkipped  int                  `json:"total_skipped"`
	TotalFailed   int                  `json:"total_failed"`
	EnqueuedJobs  []BulkEnqueuedJob    `json:"enqueued_jobs,omitempty"`
	Errors        []BulkOperationError `json:"errors,omitempty"`
}

// BulkEnqueuedJob pairs a certificate ID with the renewal job ID that was
// just created for it. Lets the GUI link directly into the job-detail
// page without an extra round-trip to query "what job did this cert
// just get assigned?".
type BulkEnqueuedJob struct {
	CertificateID string `json:"certificate_id"`
	JobID         string `json:"job_id"`
}

// BulkOperationError records a per-certificate failure for any bulk
// operation (renew, reassign — and revoke, which uses the older
// BulkRevocationError shape kept for backwards compatibility on the
// /bulk-revoke wire format). Same shape as BulkRevocationError so the
// frontend's bulk-result rendering is one helper.
type BulkOperationError struct {
	CertificateID string `json:"certificate_id"`
	Error         string `json:"error"`
}
