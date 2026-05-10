package domain

import "time"

// ApprovalRequest represents a pending issuance / renewal that requires
// human approval before the issuer connector is dispatched. One row per
// (CertificateID, JobID) pair; the JobID points at the blocked Job whose
// Status is JobStatusAwaitingApproval.
//
// Lifecycle:
//
//	pending  → approved   (Approve called by a non-requester)
//	pending  → rejected   (Reject called)
//	pending  → expired    (scheduler reaper at approvalCutoff)
//
// Once terminal, the row is immutable; the audit_events table is the
// durable record of who approved + why.
//
// Rank 7 of the 2026-05-03 Infisical deep-research deliverable
// (the project's deep-research deliverable, Part 5). Closes the
// "two-person integrity / four-eyes principle" procurement gap for
// PCI-DSS Level 1, FedRAMP Moderate / High, and SOC 2 Type II
// customers.
type ApprovalRequest struct {
	ID            string            `json:"id"`                       // ar-<slug>
	Kind          ApprovalKind      `json:"kind"`                     // cert_issuance | profile_edit (Phase 9)
	CertificateID string            `json:"certificate_id,omitempty"` // FK managed_certificates.id (nullable for profile_edit)
	JobID         string            `json:"job_id,omitempty"`         // FK jobs.id (nullable for profile_edit)
	ProfileID     string            `json:"profile_id"`               // CertificateProfile that triggered the gate
	RequestedBy   string            `json:"requested_by"`             // actor that triggered the renewal
	State         ApprovalState     `json:"state"`                    // pending / approved / rejected / expired
	DecidedBy     *string           `json:"decided_by,omitempty"`     // null while state=pending
	DecidedAt     *time.Time        `json:"decided_at,omitempty"`     // null while state=pending
	DecisionNote  *string           `json:"decision_note,omitempty"`  // operator's reason text
	Metadata      map[string]string `json:"metadata,omitempty"`       // common_name, sans, issuer_id, severity_tier
	// Payload (Phase 9) carries the pending profile diff for
	// approval_kind=profile_edit rows. Empty for cert_issuance.
	// Stored as a raw JSON byte slice so the service layer
	// serializes/deserializes the *domain.CertificateProfile
	// without the repository needing to know the inner shape.
	Payload   []byte    `json:"payload,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ApprovalKind classifies the row into one of the supported approval
// workflows. Bundle 1 Phase 9 ships exactly two kinds. Bundle 2 will
// extend the enum (and the migration's CHECK constraint) without
// reshaping the column.
type ApprovalKind string

const (
	// ApprovalKindCertIssuance is the original Rank-7 workflow:
	// cert/renewal blocked at JobStatusAwaitingApproval until a
	// non-requester decides. cert_id + job_id are required.
	ApprovalKindCertIssuance ApprovalKind = "cert_issuance"

	// ApprovalKindProfileEdit (Phase 9) closes the flip-flop loophole:
	// a profile with RequiresApproval=true cannot be mutated until a
	// non-requester decides. The pending diff lives in Payload until
	// the approver's POST /v1/approvals/{id}/approve triggers the
	// apply path. cert_id / job_id are NULL for these rows.
	ApprovalKindProfileEdit ApprovalKind = "profile_edit"
)

// IsValidApprovalKind reports whether k is a closed-enum value.
func IsValidApprovalKind(k ApprovalKind) bool {
	switch k {
	case ApprovalKindCertIssuance, ApprovalKindProfileEdit:
		return true
	}
	return false
}

// ApprovalState is the closed enum of approval lifecycle states.
type ApprovalState string

const (
	// ApprovalStatePending is the initial state — created by RequestApproval,
	// blocking the linked Job at JobStatusAwaitingApproval. The scheduler does
	// NOT dispatch the job until the approval transitions to approved.
	ApprovalStatePending ApprovalState = "pending"

	// ApprovalStateApproved is the success terminal state. Approve sets
	// DecidedBy / DecidedAt / DecisionNote and transitions the linked Job
	// from AwaitingApproval to Pending so the job processor picks it up.
	ApprovalStateApproved ApprovalState = "approved"

	// ApprovalStateRejected is the human-rejected terminal state. The
	// linked Job transitions from AwaitingApproval to Cancelled.
	ApprovalStateRejected ApprovalState = "rejected"

	// ApprovalStateExpired is the timeout terminal state. The scheduler's
	// reaper transitions stale pending requests to expired after the
	// CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT cutoff (default 168h = 7 days).
	ApprovalStateExpired ApprovalState = "expired"
)

// IsValidApprovalState reports whether s is a closed-enum value. Used by
// repository validation + handler request-body parsing to defend against
// off-enum typos at write time.
func IsValidApprovalState(s ApprovalState) bool {
	switch s {
	case ApprovalStatePending, ApprovalStateApproved,
		ApprovalStateRejected, ApprovalStateExpired:
		return true
	}
	return false
}

// IsTerminal reports whether s is one of the immutable terminal states
// (approved / rejected / expired). Once terminal, an ApprovalRequest's
// row cannot be mutated; subsequent Approve / Reject calls return
// ErrApprovalAlreadyDecided.
func (s ApprovalState) IsTerminal() bool {
	switch s {
	case ApprovalStateApproved, ApprovalStateRejected, ApprovalStateExpired:
		return true
	}
	return false
}

// Approval-decision outcome strings used by the metrics counter
// (certctl_approval_decisions_total{outcome,profile_id}). Matches the
// Prometheus convention: lower-case, snake_case, bounded cardinality.
const (
	ApprovalOutcomeApproved = "approved"
	ApprovalOutcomeRejected = "rejected"
	ApprovalOutcomeExpired  = "expired"
	ApprovalOutcomeBypassed = "bypassed"
)

// ApprovalActorSystemBypass is the synthetic actor identity stamped on
// audit rows + DecidedBy when CERTCTL_APPROVAL_BYPASS=true short-circuits
// the workflow for dev/CI. Production deploys MUST leave the bypass
// unset; compliance auditors run `SELECT FROM audit_events WHERE
// actor='system-bypass'` to confirm zero rows.
const ApprovalActorSystemBypass = "system-bypass"
