package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// JobService manages job processing and status tracking.
// It coordinates between the scheduler and various job-specific services.
type JobService struct {
	jobRepo           repository.JobRepository
	renewalService    *RenewalService
	deploymentService *DeploymentService
	logger            *slog.Logger
}

// NewJobService creates a new job service.
func NewJobService(
	jobRepo repository.JobRepository,
	renewalService *RenewalService,
	deploymentService *DeploymentService,
	logger *slog.Logger,
) *JobService {
	return &JobService{
		jobRepo:           jobRepo,
		renewalService:    renewalService,
		deploymentService: deploymentService,
		logger:            logger,
	}
}

// ProcessPendingJobs fetches and processes all pending jobs.
// It routes jobs to the appropriate service based on job type and handles errors gracefully.
func (s *JobService) ProcessPendingJobs(ctx context.Context) error {
	// Fetch pending jobs
	pendingJobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusPending)
	if err != nil {
		return fmt.Errorf("failed to list pending jobs: %w", err)
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

		retriedCount++
	}

	s.logger.Info("failed jobs retry completed",
		"retried", retriedCount,
		"total_failed", len(failedJobs))

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

// CancelJobWithContext cancels a pending or running job.
func (s *JobService) CancelJobWithContext(ctx context.Context, jobID string) error {
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

// CancelJob cancels a job (handler interface method).
func (s *JobService) CancelJob(id string) error {
	return s.CancelJobWithContext(context.Background(), id)
}

// ListJobs returns paginated jobs with optional filtering (handler interface method).
func (s *JobService) ListJobs(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	allJobs, err := s.jobRepo.List(context.Background())
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
func (s *JobService) GetJob(id string) (*domain.Job, error) {
	return s.jobRepo.Get(context.Background(), id)
}

// ApproveJob approves a renewal job that is awaiting approval.
// Transitions the job from AwaitingApproval to Pending so the scheduler picks it up.
func (s *JobService) ApproveJob(id string) error {
	ctx := context.Background()
	job, err := s.jobRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	if job.Status != domain.JobStatusAwaitingApproval {
		return fmt.Errorf("cannot approve job with status %s (must be AwaitingApproval)", job.Status)
	}

	if err := s.jobRepo.UpdateStatus(ctx, id, domain.JobStatusPending, ""); err != nil {
		return fmt.Errorf("failed to approve job: %w", err)
	}

	s.logger.Info("renewal job approved", "job_id", id, "certificate_id", job.CertificateID)
	return nil
}

// RejectJob rejects a renewal job that is awaiting approval.
// Transitions the job to Cancelled with a rejection reason.
func (s *JobService) RejectJob(id string, reason string) error {
	ctx := context.Background()
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

	s.logger.Info("renewal job rejected", "job_id", id, "certificate_id", job.CertificateID, "reason", reason)
	return nil
}
