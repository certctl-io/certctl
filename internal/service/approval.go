package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// ApprovalService manages the issuance approval-workflow primitive.
// Rank 7 of the 2026-05-03 deep-research deliverable.
//
// Lifecycle: a profile with RequiresApproval=true causes the renewal
// entry points (TriggerRenewal + CheckExpiringCertificates) to call
// RequestApproval; the resulting Job is created at
// JobStatusAwaitingApproval; the scheduler does NOT dispatch until
// Approve transitions the job to Pending.
//
// RBAC contract: the requester cannot approve their own request.
// Approve checks decidedBy != request.RequestedBy and rejects with
// ErrApproveBySameActor otherwise. This is the load-bearing two-
// person integrity check; compliance auditors pattern-match against
// it.
//
// Bypass mode: if CERTCTL_APPROVAL_BYPASS=true at boot, every
// RequestApproval call immediately auto-approves with
// decidedBy="system-bypass". Used by dev / CI to keep renewal-
// scheduler tests fast without standing up an approver. Production
// deploys MUST leave this unset; the bypass emits an audit row with
// ActorType=System so a downstream auditor can grep for
// "system-bypass" approvals and confirm none happened in production.
type ApprovalService struct {
	approvalRepo repository.ApprovalRepository
	jobRepo      JobStatusUpdater
	auditService *AuditService
	metrics      *ApprovalMetrics

	bypassEnabled bool
}

// JobStatusUpdater is the narrow interface ApprovalService depends on
// from JobRepository. Accepting the small interface (rather than the
// full repository.JobRepository) keeps the test mock surface tiny —
// real JobRepository implementations (postgres + any future) satisfy
// it implicitly because they implement UpdateStatus already.
type JobStatusUpdater interface {
	UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error
}

// NewApprovalService constructs an ApprovalService. metrics may be nil
// for tests that don't need Prometheus integration; auditService should
// not be nil in production but is tolerated for unit tests that don't
// care about audit-row emission.
func NewApprovalService(
	approvalRepo repository.ApprovalRepository,
	jobRepo JobStatusUpdater,
	auditService *AuditService,
	metrics *ApprovalMetrics,
	bypassEnabled bool,
) *ApprovalService {
	return &ApprovalService{
		approvalRepo:  approvalRepo,
		jobRepo:       jobRepo,
		auditService:  auditService,
		metrics:       metrics,
		bypassEnabled: bypassEnabled,
	}
}

// Sentinels for handler-side dispatch via errors.Is.
var (
	// ErrApprovalNotFound is returned when the request ID does not exist.
	// Handlers map to HTTP 404.
	ErrApprovalNotFound = errors.New("approval request not found")

	// ErrApprovalAlreadyDecided is returned when Approve / Reject is called
	// on a request whose State is already terminal. Handlers map to HTTP 409.
	ErrApprovalAlreadyDecided = errors.New("approval request already decided")

	// ErrApproveBySameActor is the load-bearing two-person integrity check.
	// Returned when the supplied decidedBy equals request.RequestedBy.
	// Handlers map to HTTP 403.
	ErrApproveBySameActor = errors.New("approver cannot be the same as requester (two-person integrity)")
)

// RequestApproval creates a pending ApprovalRequest row and is invoked
// from the renewal entry points after they have created the Job at
// Status=AwaitingApproval. Returns the request ID for handler /
// caller use.
//
// If bypassEnabled is true, this method synchronously calls Approve
// internally with decidedBy=ApprovalActorSystemBypass and returns the
// resulting (now-approved) request ID. The audit row records
// ActorType=System so a downstream auditor can confirm bypass-mode
// was off in production via a single SQL query.
func (s *ApprovalService) RequestApproval(
	ctx context.Context,
	cert *domain.ManagedCertificate,
	jobID, profileID, requestedBy string,
	metadata map[string]string,
) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("approval: nil certificate")
	}
	if jobID == "" || profileID == "" || requestedBy == "" {
		return "", fmt.Errorf("approval: jobID, profileID, requestedBy required")
	}

	now := time.Now().UTC()
	req := &domain.ApprovalRequest{
		CertificateID: cert.ID,
		JobID:         jobID,
		ProfileID:     profileID,
		RequestedBy:   requestedBy,
		State:         domain.ApprovalStatePending,
		Metadata:      metadata,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.approvalRepo.Create(ctx, req); err != nil {
		return "", fmt.Errorf("approval: create request: %w", err)
	}

	// Audit the request creation. Bypass-mode logs both the request and
	// the auto-approval as separate rows so the timeline is honest.
	s.recordAudit(ctx, requestedBy, domain.ActorTypeUser, "approval_requested", req, nil)

	if s.bypassEnabled {
		if err := s.approveInternal(ctx, req.ID, domain.ApprovalActorSystemBypass,
			"auto-approved by CERTCTL_APPROVAL_BYPASS — dev/CI mode",
			domain.ApprovalOutcomeBypassed, domain.ActorTypeSystem); err != nil {
			return req.ID, fmt.Errorf("approval: bypass auto-approve: %w", err)
		}
	}

	return req.ID, nil
}

// Approve transitions a pending request to approved AND the linked Job
// from AwaitingApproval to Pending so the job processor picks it up.
// RBAC: rejects if decidedBy == request.RequestedBy.
func (s *ApprovalService) Approve(ctx context.Context, requestID, decidedBy, note string) error {
	req, err := s.approvalRepo.Get(ctx, requestID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrApprovalNotFound
		}
		return fmt.Errorf("approval: get for approve: %w", err)
	}
	if req.State.IsTerminal() {
		return ErrApprovalAlreadyDecided
	}
	if decidedBy == req.RequestedBy {
		return ErrApproveBySameActor
	}
	return s.approveInternal(ctx, requestID, decidedBy, note,
		domain.ApprovalOutcomeApproved, domain.ActorTypeUser)
}

// approveInternal is the shared transition path for both human-Approve
// and bypass-mode auto-approve. Same DB transition + audit + metric
// recording, but the outcome label + actorType differ.
func (s *ApprovalService) approveInternal(
	ctx context.Context, requestID, decidedBy, note, outcome string,
	actorType domain.ActorType,
) error {
	now := time.Now().UTC()

	// Re-fetch the request after the state-transition guards in Approve so
	// we can stamp the metric's pending-age + transition the job. For the
	// bypass path, this is the first read.
	req, err := s.approvalRepo.Get(ctx, requestID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrApprovalNotFound
		}
		return fmt.Errorf("approval: get for transition: %w", err)
	}
	if req.State.IsTerminal() {
		return ErrApprovalAlreadyDecided
	}

	if err := s.approvalRepo.UpdateState(ctx, requestID,
		domain.ApprovalStateApproved, decidedBy, now, note); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrApprovalNotFound
		}
		if errors.Is(err, repository.ErrAlreadyExists) {
			return ErrApprovalAlreadyDecided
		}
		return fmt.Errorf("approval: update state to approved: %w", err)
	}

	// Transition the linked Job from AwaitingApproval to Pending so the
	// scheduler picks it up. Best-effort — if the Job has already been
	// cancelled or otherwise mutated externally, log via audit and move on.
	if err := s.jobRepo.UpdateStatus(ctx, req.JobID, domain.JobStatusPending, ""); err != nil {
		s.recordAudit(ctx, decidedBy, actorType, "approval_job_transition_failed", req,
			map[string]interface{}{"target_status": string(domain.JobStatusPending), "error": err.Error()})
		return fmt.Errorf("approval: transition job to Pending: %w", err)
	}

	s.recordAudit(ctx, decidedBy, actorType, "approval_"+outcome, req,
		map[string]interface{}{"note": note, "outcome": outcome})
	if s.metrics != nil {
		s.metrics.RecordDecision(outcome, req.ProfileID)
		s.metrics.ObservePendingAge(now.Sub(req.CreatedAt).Seconds())
	}
	return nil
}

// Reject transitions a pending request to rejected AND the linked Job
// from AwaitingApproval to Cancelled. RBAC: same-actor check applies.
func (s *ApprovalService) Reject(ctx context.Context, requestID, decidedBy, note string) error {
	req, err := s.approvalRepo.Get(ctx, requestID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrApprovalNotFound
		}
		return fmt.Errorf("approval: get for reject: %w", err)
	}
	if req.State.IsTerminal() {
		return ErrApprovalAlreadyDecided
	}
	if decidedBy == req.RequestedBy {
		return ErrApproveBySameActor
	}

	now := time.Now().UTC()
	if err := s.approvalRepo.UpdateState(ctx, requestID,
		domain.ApprovalStateRejected, decidedBy, now, note); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrApprovalNotFound
		}
		if errors.Is(err, repository.ErrAlreadyExists) {
			return ErrApprovalAlreadyDecided
		}
		return fmt.Errorf("approval: update state to rejected: %w", err)
	}

	if err := s.jobRepo.UpdateStatus(ctx, req.JobID, domain.JobStatusCancelled,
		"approval rejected: "+note); err != nil {
		s.recordAudit(ctx, decidedBy, domain.ActorTypeUser, "approval_job_transition_failed", req,
			map[string]interface{}{"target_status": string(domain.JobStatusCancelled), "error": err.Error()})
		return fmt.Errorf("approval: transition job to Cancelled: %w", err)
	}

	s.recordAudit(ctx, decidedBy, domain.ActorTypeUser, "approval_rejected", req,
		map[string]interface{}{"note": note, "outcome": domain.ApprovalOutcomeRejected})
	if s.metrics != nil {
		s.metrics.RecordDecision(domain.ApprovalOutcomeRejected, req.ProfileID)
		s.metrics.ObservePendingAge(now.Sub(req.CreatedAt).Seconds())
	}
	return nil
}

// ListPending returns approval requests in state=pending, paginated.
// Operators reading the dashboard call this on every page load.
func (s *ApprovalService) ListPending(ctx context.Context, page, perPage int) ([]*domain.ApprovalRequest, error) {
	return s.approvalRepo.List(ctx, &repository.ApprovalFilter{
		State:   string(domain.ApprovalStatePending),
		Page:    page,
		PerPage: perPage,
	})
}

// List returns approval requests filtered by the supplied filter. Used
// by handler GET /api/v1/approvals with arbitrary state.
func (s *ApprovalService) List(ctx context.Context, filter *repository.ApprovalFilter) ([]*domain.ApprovalRequest, error) {
	return s.approvalRepo.List(ctx, filter)
}

// Get returns a single approval request by ID, or ErrApprovalNotFound.
func (s *ApprovalService) Get(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	req, err := s.approvalRepo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrApprovalNotFound
		}
		return nil, err
	}
	return req, nil
}

// ExpireStale runs from the scheduler's reaper loop. Calls the
// repository's ExpireStale (bulk pending→expired transition) +
// transitions matching jobs from AwaitingApproval to Cancelled.
// Records one audit row per expiry. Returns the count expired.
//
// Operators alert when this is non-zero — it means an approval
// request timed out without human review.
func (s *ApprovalService) ExpireStale(ctx context.Context, before time.Time) (int, error) {
	// Find pending requests older than `before` so we can record the
	// audit + metric per expiry. ExpireStale on the repo bulk-mutates
	// the rows; we read first to capture the per-row metadata for
	// auditing, then call the repo's bulk update.
	pending, err := s.approvalRepo.List(ctx, &repository.ApprovalFilter{
		State:   string(domain.ApprovalStatePending),
		PerPage: 500,
	})
	if err != nil {
		return 0, fmt.Errorf("approval: list pending for expiry: %w", err)
	}

	var stale []*domain.ApprovalRequest
	for _, req := range pending {
		if req.CreatedAt.Before(before) || req.CreatedAt.Equal(before) {
			stale = append(stale, req)
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}

	count, err := s.approvalRepo.ExpireStale(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("approval: bulk expire: %w", err)
	}

	now := time.Now().UTC()
	for _, req := range stale {
		// Cancel the linked job — best-effort. The scheduler's existing
		// ReapTimedOutJobs already handles AwaitingApproval timeouts on
		// the job side; this is a defensive double-cancel that's
		// idempotent if the scheduler already ran.
		if err := s.jobRepo.UpdateStatus(ctx, req.JobID, domain.JobStatusCancelled,
			"approval expired: timed out without review"); err != nil {
			// Log via audit and continue — don't fail the whole sweep on
			// one bad job.
			s.recordAudit(ctx, "system-reaper", domain.ActorTypeSystem, "approval_job_transition_failed", req,
				map[string]interface{}{"target_status": string(domain.JobStatusCancelled), "error": err.Error()})
		}

		s.recordAudit(ctx, "system-reaper", domain.ActorTypeSystem, "approval_expired", req,
			map[string]interface{}{"outcome": domain.ApprovalOutcomeExpired, "before_cutoff": before.Format(time.RFC3339)})
		if s.metrics != nil {
			s.metrics.RecordDecision(domain.ApprovalOutcomeExpired, req.ProfileID)
			s.metrics.ObservePendingAge(now.Sub(req.CreatedAt).Seconds())
		}
	}

	return count, nil
}

// recordAudit is the shared audit-emission helper. Tolerates a nil
// AuditService (unit tests that don't wire it) and discards errors —
// audit failures must not block the primary state transition.
func (s *ApprovalService) recordAudit(ctx context.Context, actor string, actorType domain.ActorType,
	action string, req *domain.ApprovalRequest, extra map[string]interface{}) {
	if s.auditService == nil || req == nil {
		return
	}
	details := map[string]interface{}{
		"approval_id":    req.ID,
		"certificate_id": req.CertificateID,
		"job_id":         req.JobID,
		"profile_id":     req.ProfileID,
		"requested_by":   req.RequestedBy,
		"state":          string(req.State),
	}
	for k, v := range req.Metadata {
		details["metadata_"+k] = v
	}
	for k, v := range extra {
		details[k] = v
	}
	_ = s.auditService.RecordEvent(ctx, actor, actorType, action,
		"approval_request", req.ID, details)
}
