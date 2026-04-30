package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ErrSelfApproval is returned by ApproveJob when the actor attempting to
// approve a renewal job is the same person listed as the owner of the
// underlying certificate. M-003 enforces separation of duties: the owner who
// requested (or benefits from) the renewal must not be the same identity that
// approves it. Handlers map this sentinel to HTTP 403 Forbidden.
var ErrSelfApproval = errors.New("self-approval forbidden: actor is the owner of the certificate")

// JobService manages job processing and status tracking.
// It coordinates between the scheduler and various job-specific services.
type JobService struct {
	jobRepo           repository.JobRepository
	certRepo          repository.CertificateRepository
	ownerRepo         repository.OwnerRepository
	renewalService    *RenewalService
	deploymentService *DeploymentService
	auditService      *AuditService
	logger            *slog.Logger
}

// NewJobService creates a new job service.
//
// certRepo and ownerRepo are required for the M-003 not-self-approval check
// in ApproveJob. Callers may pass nil for either to disable the check
// (useful for tests that don't exercise the approval path); when nil, the
// service logs a warning on the first approval attempt and permits the
// transition. Production wiring must supply both.
func NewJobService(
	jobRepo repository.JobRepository,
	certRepo repository.CertificateRepository,
	ownerRepo repository.OwnerRepository,
	renewalService *RenewalService,
	deploymentService *DeploymentService,
	logger *slog.Logger,
) *JobService {
	return &JobService{
		jobRepo:           jobRepo,
		certRepo:          certRepo,
		ownerRepo:         ownerRepo,
		renewalService:    renewalService,
		deploymentService: deploymentService,
		logger:            logger,
	}
}

// SetAuditService wires an optional audit service for emitting lifecycle
// events (e.g., scheduler-driven job_retry transitions recorded by
// RetryFailedJobs). Construction keeps the audit dependency optional so
// bootstrap/test wiring that doesn't exercise the retry path can omit it;
// production wiring in cmd/server/main.go should always call this.
func (s *JobService) SetAuditService(a *AuditService) {
	s.auditService = a
}

// ProcessPendingJobs fetches and processes all pending jobs.
// It routes jobs to the appropriate service based on job type and handles errors gracefully.
//
// Concurrency (H-6 CWE-362): jobs are claimed via ClaimPendingJobs which uses
// SELECT ... FOR UPDATE SKIP LOCKED and flips Pending → Running atomically. Concurrent
// scheduler replicas in HA deployments will therefore never observe the same Pending row,
// and the subsequent UpdateStatus(Running) calls inside the downstream service methods are
// idempotent against the pre-flipped state.
func (s *JobService) ProcessPendingJobs(ctx context.Context) error {
	// Claim pending jobs atomically (H-6 remediation: was ListByStatus which had no row lock).
	// Empty jobType matches all types; zero limit means unlimited (preserves prior semantics).
	pendingJobs, err := s.jobRepo.ClaimPendingJobs(ctx, "", 0)
	if err != nil {
		return fmt.Errorf("failed to claim pending jobs: %w", err)
	}

	if len(pendingJobs) == 0 {
		s.logger.Debug("no pending jobs to process")
		return nil
	}

	s.logger.Info("processing pending jobs", "count", len(pendingJobs))

	var processedCount int
	var failedCount int

	// Process each job
	for _, job := range pendingJobs {
		// Skip deployment jobs that have an agent_id — those are meant for agent
		// pickup via GetPendingWork(), not server-side processing. The server should
		// only process deployment jobs without an agent (legacy/serverless targets).
		if job.Type == domain.JobTypeDeployment && job.AgentID != nil && *job.AgentID != "" {
			s.logger.Debug("skipping agent-routed deployment job",
				"job_id", job.ID,
				"agent_id", *job.AgentID)
			continue
		}

		if err := s.processJob(ctx, job); err != nil {
			s.logger.Error("failed to process job",
				"job_id", job.ID,
				"job_type", job.Type,
				"error", err)
			failedCount++
			continue
		}
		processedCount++
	}

	s.logger.Info("job processing completed",
		"processed", processedCount,
		"failed", failedCount,
		"total", len(pendingJobs))

	return nil
}

// processJob routes a single job to the appropriate service based on type.
func (s *JobService) processJob(ctx context.Context, job *domain.Job) error {
	s.logger.Debug("processing job",
		"job_id", job.ID,
		"job_type", job.Type,
		"certificate_id", job.CertificateID)

	switch job.Type {
	case domain.JobTypeRenewal:
		return s.renewalService.ProcessRenewalJob(ctx, job)
	case domain.JobTypeDeployment:
		return s.deploymentService.ProcessDeploymentJob(ctx, job)
	case domain.JobTypeIssuance:
		return s.processIssuanceJob(ctx, job)
	case domain.JobTypeValidation:
		return s.processValidationJob(ctx, job)
	default:
		return fmt.Errorf("unknown job type: %s", job.Type)
	}
}

// processIssuanceJob handles a certificate issuance job.
// It reuses the renewal service's ProcessRenewalJob since the flow is identical:
// generate key → create CSR → call issuer → store version → create deployment jobs.
// The only difference is semantics (new cert vs renewed cert), not mechanics.
func (s *JobService) processIssuanceJob(ctx context.Context, job *domain.Job) error {
	s.logger.Debug("processing issuance job", "job_id", job.ID)

	// Issuance follows the same code path as renewal for the Local CA:
	// generate server-side key + CSR → sign via issuer → store cert version → deploy
	return s.renewalService.ProcessRenewalJob(ctx, job)
}

// processValidationJob handles a certificate validation job.
// This is a placeholder that documents the flow.
// TODO: Implement actual validation job processing if needed.
func (s *JobService) processValidationJob(ctx context.Context, job *domain.Job) error {
	s.logger.Debug("processing validation job", "job_id", job.ID)

	// TODO: Implement validation job processing
	// In production:
	//   1. Fetch the certificate
	//   2. For each target, call target connector ValidateDeployment
	//   3. Aggregate results
	//   4. Update job status based on results
	//   5. Send notification if any validation fails

	return fmt.Errorf("validation job processing not yet implemented")
}

// RetryFailedJobs finds failed jobs and resets them for retry.
// It only retries jobs that haven't exceeded max attempts.
//
// Audit trail (I-001): each successful Failed → Pending transition emits a
// "job_retry" audit event with actor "system" (ActorTypeSystem), capturing
// the old→new state and attempt counters so operators can reconstruct
// scheduler-driven retry activity. The audit service is optional — callers
// that haven't wired it via SetAuditService simply skip emission.
//
// maxRetries is retained for interface compatibility with
// scheduler.JobServicer but is advisory: per-job eligibility is governed by
// each job's own Attempts vs. MaxAttempts, not this parameter.
func (s *JobService) RetryFailedJobs(ctx context.Context, maxRetries int) error {
	s.logger.Debug("retrying failed jobs", "max_retries", maxRetries)

	failedJobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusFailed)
	if err != nil {
		return fmt.Errorf("failed to fetch failed jobs: %w", err)
	}

	var retriedCount int

	for _, job := range failedJobs {
		// Check if we can retry (Attempts < MaxAttempts)
		if job.Attempts >= job.MaxAttempts {
			s.logger.Debug("job exceeded max retries",
				"job_id", job.ID,
				"attempts", job.Attempts,
				"max_attempts", job.MaxAttempts)
			continue
		}

		// Reset status to pending for retry
		if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusPending, ""); err != nil {
			s.logger.Error("failed to reset job status for retry",
				"job_id", job.ID,
				"error", err)
			continue
		}

		if s.auditService != nil {
			if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
				"job_retry", "job", job.ID,
				map[string]interface{}{
					"old_status":   string(domain.JobStatusFailed),
					"new_status":   string(domain.JobStatusPending),
					"attempts":     job.Attempts,
					"max_attempts": job.MaxAttempts,
				}); auditErr != nil {
				s.logger.Error("failed to record job retry audit event",
					"job_id", job.ID,
					"error", auditErr)
			}
		}

		retriedCount++
	}

	s.logger.Info("failed jobs retry completed",
		"retried", retriedCount,
		"total_failed", len(failedJobs))

	return nil
}

// ReapJobsWithOfflineAgents transitions jobs in Running status whose
// owning agent has been silent longer than agentTTL to Failed with
// reason "agent_offline". Bundle C / Audit M-016 (CWE-754): closes the
// gap left by ReapTimedOutJobs (which only handles AwaitingCSR /
// AwaitingApproval). I-001's retry loop then auto-promotes eligible
// Failed jobs back to Pending so a healthy agent can claim them.
func (s *JobService) ReapJobsWithOfflineAgents(ctx context.Context, agentTTL time.Duration) error {
	if agentTTL <= 0 {
		return fmt.Errorf("ReapJobsWithOfflineAgents: agentTTL must be positive, got %s", agentTTL)
	}
	cutoff := time.Now().Add(-agentTTL)

	staleJobs, err := s.jobRepo.ListJobsWithOfflineAgents(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("list jobs with offline agents: %w", err)
	}

	var reaped int
	for _, job := range staleJobs {
		oldStatus := job.Status
		errMsg := fmt.Sprintf("agent offline (no heartbeat for >%s)", agentTTL)

		job.Status = domain.JobStatusFailed
		job.LastError = &errMsg

		if err := s.jobRepo.Update(ctx, job); err != nil {
			s.logger.Error("failed to transition offline-agent job",
				"job_id", job.ID, "agent_id", job.AgentID, "error", err)
			continue
		}

		if s.auditService != nil {
			if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
				"job_offline_agent_reap", "job", job.ID,
				map[string]interface{}{
					"old_status":     string(oldStatus),
					"new_status":     string(domain.JobStatusFailed),
					"timeout_reason": "agent_offline",
					"agent_id":       job.AgentID,
				}); auditErr != nil {
				s.logger.Error("failed to record offline-agent reap audit event",
					"job_id", job.ID, "error", auditErr)
			}
		}
		reaped++
	}

	s.logger.Info("offline-agent job reaper completed",
		"reaped", reaped, "total_stale", len(staleJobs))
	return nil
}

// ReapTimedOutJobs transitions jobs stuck in AwaitingCSR or AwaitingApproval
// to Failed if they've exceeded their TTL. I-001's retry loop then auto-promotes
// eligible Failed jobs back to Pending (closes coverage gap I-003).
func (s *JobService) ReapTimedOutJobs(ctx context.Context, csrTTL, approvalTTL time.Duration) error {
	s.logger.Debug("reaping timed-out jobs", "csr_ttl", csrTTL, "approval_ttl", approvalTTL)

	now := time.Now()
	csrCutoff := now.Add(-csrTTL)
	approvalCutoff := now.Add(-approvalTTL)

	timedOutJobs, err := s.jobRepo.ListTimedOutAwaitingJobs(ctx, csrCutoff, approvalCutoff)
	if err != nil {
		return fmt.Errorf("failed to fetch timed-out jobs: %w", err)
	}

	var reaped int

	for _, job := range timedOutJobs {
		oldStatus := job.Status
		var (
			newErrMsg string
			reason    string
			ttl       time.Duration
		)
		switch job.Status {
		case domain.JobStatusAwaitingCSR:
			ttl = csrTTL
			reason = "csr_timeout"
			newErrMsg = fmt.Sprintf("timed out in %s after %s", oldStatus, csrTTL)
		case domain.JobStatusAwaitingApproval:
			ttl = approvalTTL
			reason = "approval_timeout"
			newErrMsg = fmt.Sprintf("timed out in %s after %s", oldStatus, approvalTTL)
		default:
			continue
		}
		_ = ttl

		job.Status = domain.JobStatusFailed
		job.LastError = &newErrMsg

		if err := s.jobRepo.Update(ctx, job); err != nil {
			s.logger.Error("failed to transition timed-out job",
				"job_id", job.ID,
				"old_status", oldStatus,
				"error", err)
			continue
		}

		if s.auditService != nil {
			ageHours := time.Since(job.CreatedAt).Hours()
			if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
				"job_timeout", "job", job.ID,
				map[string]interface{}{
					"old_status":     string(oldStatus),
					"new_status":     string(domain.JobStatusFailed),
					"timeout_reason": reason,
					"age_hours":      ageHours,
				}); auditErr != nil {
				s.logger.Error("failed to record job timeout audit event",
					"job_id", job.ID,
					"error", auditErr)
			}
		}

		reaped++
	}

	s.logger.Info("job timeout reaper completed",
		"reaped", reaped,
		"total_timed_out", len(timedOutJobs))

	return nil
}

// GetJobStatus returns the current status of a job.
func (s *JobService) GetJobStatus(ctx context.Context, jobID string) (*domain.Job, error) {
	job, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job: %w", err)
	}
	return job, nil
}

// CancelJob cancels a pending or running job (handler interface method).
func (s *JobService) CancelJob(ctx context.Context, jobID string) error {
	job, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to fetch job: %w", err)
	}

	if job.Status != domain.JobStatusPending && job.Status != domain.JobStatusRunning {
		return fmt.Errorf("cannot cancel job with status %s", job.Status)
	}

	if err := s.jobRepo.UpdateStatus(ctx, jobID, domain.JobStatusCancelled, "cancelled by user"); err != nil {
		return fmt.Errorf("failed to cancel job: %w", err)
	}

	s.logger.Info("job cancelled", "job_id", jobID)
	return nil
}

// ListJobs returns paginated jobs with optional filtering (handler interface method).
func (s *JobService) ListJobs(ctx context.Context, status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	allJobs, err := s.jobRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list jobs: %w", err)
	}

	// Filter jobs in memory based on status and jobType
	var filtered []*domain.Job
	for _, job := range allJobs {
		if job == nil {
			continue
		}
		if status != "" && string(job.Status) != status {
			continue
		}
		if jobType != "" && string(job.Type) != jobType {
			continue
		}
		filtered = append(filtered, job)
	}

	total := int64(len(filtered))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	var result []domain.Job
	for _, job := range filtered[start:end] {
		if job != nil {
			result = append(result, *job)
		}
	}

	return result, total, nil
}

// GetJob returns a single job (handler interface method).
func (s *JobService) GetJob(ctx context.Context, id string) (*domain.Job, error) {
	return s.jobRepo.Get(ctx, id)
}

// ApproveJob approves a renewal job that is awaiting approval.
// Transitions the job from AwaitingApproval to Pending so the scheduler picks it up.
//
// actor is the named-key identity of the approver (from the auth middleware
// via resolveActor). M-003: if actor matches the certificate owner's Name or
// Email (case-insensitive), returns ErrSelfApproval to enforce separation of
// duties. Callers must pass a non-empty actor; empty actor is treated as an
// anonymous system caller and permitted (internal/system paths).
func (s *JobService) ApproveJob(ctx context.Context, id, actor string) error {
	job, err := s.jobRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	if job.Status != domain.JobStatusAwaitingApproval {
		return fmt.Errorf("cannot approve job with status %s (must be AwaitingApproval)", job.Status)
	}

	if err := s.checkNotSelf(ctx, job, actor); err != nil {
		return err
	}

	if err := s.jobRepo.UpdateStatus(ctx, id, domain.JobStatusPending, ""); err != nil {
		return fmt.Errorf("failed to approve job: %w", err)
	}

	s.logger.Info("renewal job approved",
		"job_id", id,
		"certificate_id", job.CertificateID,
		"actor", actor)
	return nil
}

// RejectJob rejects a renewal job that is awaiting approval.
// Transitions the job to Cancelled with a rejection reason.
//
// actor is the named-key identity of the rejector (from the auth middleware
// via resolveActor). Rejection is NOT subject to the not-self check — an
// owner is permitted to cancel their own pending renewal. actor is recorded
// on the log line for audit attribution.
func (s *JobService) RejectJob(ctx context.Context, id, reason, actor string) error {
	job, err := s.jobRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	if job.Status != domain.JobStatusAwaitingApproval {
		return fmt.Errorf("cannot reject job with status %s (must be AwaitingApproval)", job.Status)
	}

	msg := "rejected by user"
	if reason != "" {
		msg = "rejected: " + reason
	}

	if err := s.jobRepo.UpdateStatus(ctx, id, domain.JobStatusCancelled, msg); err != nil {
		return fmt.Errorf("failed to reject job: %w", err)
	}

	s.logger.Info("renewal job rejected",
		"job_id", id,
		"certificate_id", job.CertificateID,
		"reason", reason,
		"actor", actor)
	return nil
}

// checkNotSelf enforces the M-003 separation-of-duties rule for renewal
// approval: the actor approving a job may not be the owner of the underlying
// certificate.
//
// Resolution rules:
//   - Empty actor → permitted (internal/system caller; auth middleware already
//     short-circuits anonymous users at the handler layer).
//   - certRepo or ownerRepo nil → warn once, permit (test/bootstrap wiring).
//   - Job has no certificate or certificate has no OwnerID → permitted (no
//     owner to collide with).
//   - Owner record not found → warn, permit (defensive: stale FK should not
//     block operations).
//   - Case-insensitive match against owner.Name OR owner.Email → returns
//     ErrSelfApproval.
func (s *JobService) checkNotSelf(ctx context.Context, job *domain.Job, actor string) error {
	if actor == "" {
		return nil
	}
	if s.certRepo == nil || s.ownerRepo == nil {
		s.logger.Warn("not-self approval check skipped: cert/owner repo not wired",
			"job_id", job.ID, "actor", actor)
		return nil
	}
	if job.CertificateID == "" {
		return nil
	}

	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		s.logger.Warn("not-self approval check: certificate lookup failed",
			"job_id", job.ID, "certificate_id", job.CertificateID, "error", err)
		return nil
	}
	if cert == nil || cert.OwnerID == "" {
		return nil
	}

	owner, err := s.ownerRepo.Get(ctx, cert.OwnerID)
	if err != nil || owner == nil {
		s.logger.Warn("not-self approval check: owner lookup failed",
			"job_id", job.ID, "owner_id", cert.OwnerID, "error", err)
		return nil
	}

	actorLower := strings.ToLower(actor)
	if strings.ToLower(owner.Name) == actorLower || strings.ToLower(owner.Email) == actorLower {
		s.logger.Warn("self-approval blocked",
			"job_id", job.ID,
			"certificate_id", job.CertificateID,
			"owner_id", owner.ID,
			"actor", actor)
		return ErrSelfApproval
	}

	return nil
}
