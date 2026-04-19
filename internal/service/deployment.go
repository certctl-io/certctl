package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// DeploymentService manages certificate deployment to targets via agents.
type DeploymentService struct {
	jobRepo         repository.JobRepository
	targetRepo      repository.TargetRepository
	agentRepo       repository.AgentRepository
	certRepo        repository.CertificateRepository
	auditService    *AuditService
	notificationSvc *NotificationService
}

// NewDeploymentService creates a new deployment service.
func NewDeploymentService(
	jobRepo repository.JobRepository,
	targetRepo repository.TargetRepository,
	agentRepo repository.AgentRepository,
	certRepo repository.CertificateRepository,
	auditService *AuditService,
	notificationSvc *NotificationService,
) *DeploymentService {
	return &DeploymentService{
		jobRepo:         jobRepo,
		targetRepo:      targetRepo,
		agentRepo:       agentRepo,
		certRepo:        certRepo,
		auditService:    auditService,
		notificationSvc: notificationSvc,
	}
}

// CreateDeploymentJobs creates a job for each target of a certificate.
func (s *DeploymentService) CreateDeploymentJobs(ctx context.Context, certID string) ([]string, error) {
	// Fetch all targets for this certificate
	targets, err := s.targetRepo.ListByCertificate(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list targets: %w", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found for certificate %s", certID)
	}

	var jobIDs []string

	// Create a deployment job for each target
	for _, target := range targets {
		job := &domain.Job{
			ID:            generateID("job"),
			CertificateID: certID,
			Type:          domain.JobTypeDeployment,
			Status:        domain.JobStatusPending,
			ScheduledAt:   time.Now(),
			CreatedAt:     time.Now(),
		}
		// Store target info in TargetID field
		if target.ID != "" {
			job.TargetID = &target.ID
		}
		// Route job to the target's assigned agent
		if target.AgentID != "" {
			agentID := target.AgentID
			job.AgentID = &agentID
		}

		if err := s.jobRepo.Create(ctx, job); err != nil {
			slog.Error("failed to create deployment job for target", "target_id", target.ID, "error", err)
			continue
		}

		jobIDs = append(jobIDs, job.ID)
	}

	if len(jobIDs) == 0 {
		return nil, fmt.Errorf("failed to create any deployment jobs")
	}

	// Record audit event
	if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"deployment_jobs_created", "certificate", certID,
		map[string]interface{}{"target_count": len(targets), "job_count": len(jobIDs)}); auditErr != nil {
		slog.Error("failed to record audit event", "error", auditErr)
	}

	return jobIDs, nil
}

// ProcessDeploymentJob handles a deployment job by coordinating with an agent.
func (s *DeploymentService) ProcessDeploymentJob(ctx context.Context, job *domain.Job) error {
	// Update job status to in-progress
	if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusRunning, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Fetch certificate
	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("certificate fetch failed: %v", err))
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	// Fetch target
	var targetID string
	if job.TargetID != nil {
		targetID = *job.TargetID
	}
	if targetID == "" {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, "target_id not found in job")
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}
		return fmt.Errorf("target_id not found in job")
	}

	target, err := s.targetRepo.Get(ctx, targetID)
	if err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("target fetch failed: %v", err))
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}
		return fmt.Errorf("failed to fetch target: %w", err)
	}

	// Verify agent is available
	agentID := target.AgentID
	agent, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("agent fetch failed: %v", err))
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	// I-004: AgentRepository.Get surfaces retired rows by design (for the GUI
	// banner + 410 Gone heartbeat path). Deployments must never dispatch to a
	// retired agent — it will never heartbeat again and the target row should
	// itself have been cascade-retired when the agent was force-retired. A job
	// slipping through here would otherwise hit the heartbeat-staleness branch
	// below with the misleading reason "agent is offline"; we want operators to
	// see the real cause. Fail the job with an explicit reason, send a
	// deployment notification so the owner is alerted, and record an audit
	// event. Falls through the same notify+audit shape as the offline branch.
	if agent.IsRetired() {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, "assigned agent is retired")
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}
		if notifErr := s.notificationSvc.SendDeploymentNotification(ctx, cert, target, false, fmt.Errorf("agent retired")); notifErr != nil {
			slog.Error("failed to send deployment notification", "error", notifErr)
		}
		if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"deployment_job_failed", "certificate", job.CertificateID,
			map[string]interface{}{"job_id": job.ID, "reason": "agent retired", "target_id": targetID, "agent_id": agentID}); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
		return fmt.Errorf("agent %s is retired", agentID)
	}

	// Check agent heartbeat (must be within last 5 minutes)
	if agent.LastHeartbeatAt != nil && time.Since(*agent.LastHeartbeatAt) > 5*time.Minute {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, "agent is offline")
		if updateErr != nil {
			slog.Error("failed to update job status", "job_id", job.ID, "error", updateErr)
		}

		if notifErr := s.notificationSvc.SendDeploymentNotification(ctx, cert, target, false, fmt.Errorf("agent offline")); notifErr != nil {
			slog.Error("failed to send deployment notification", "error", notifErr)
		}
		if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"deployment_job_failed", "certificate", job.CertificateID,
			map[string]interface{}{"job_id": job.ID, "reason": "agent offline", "target_id": targetID}); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}

		return fmt.Errorf("agent %s is offline", agentID)
	}

	// In a real implementation, the agent would poll GetPendingWork() to fetch this job.
	// The control plane would wait for the agent to complete the work asynchronously.
	// For now, we mark it as pending and rely on agent polling.

	// Record audit event
	if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"deployment_job_dispatched", "certificate", job.CertificateID,
		map[string]interface{}{"job_id": job.ID, "target_id": targetID, "agent_id": agentID}); auditErr != nil {
		slog.Error("failed to record audit event", "error", auditErr)
	}

	return nil
}

// ValidateDeployment checks the deployment status of a certificate on a target.
func (s *DeploymentService) ValidateDeployment(ctx context.Context, certID string, targetID string) (bool, error) {
	// List deployment jobs for this certificate and target
	jobs, err := s.jobRepo.ListByCertificate(ctx, certID)
	if err != nil {
		return false, fmt.Errorf("failed to list jobs: %w", err)
	}

	for _, job := range jobs {
		if job.Type != domain.JobTypeDeployment {
			continue
		}

		// Check if this job is for the target
		if job.TargetID == nil || *job.TargetID != targetID {
			continue
		}

		// Check if the most recent job for this target succeeded
		if job.Status == domain.JobStatusCompleted {
			return true, nil
		}

		if job.Status == domain.JobStatusFailed {
			if job.LastError != nil {
				return false, fmt.Errorf("deployment failed: %s", *job.LastError)
			}
			return false, fmt.Errorf("deployment failed")
		}

		// Still in progress
		return false, fmt.Errorf("deployment in progress")
	}

	// No deployment job found
	return false, fmt.Errorf("no deployment job found for target %s", targetID)
}

// MarkDeploymentComplete marks a deployment job as successfully completed.
// This is called by agents after they finish deploying a certificate.
func (s *DeploymentService) MarkDeploymentComplete(ctx context.Context, jobID string) error {
	job, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to fetch job: %w", err)
	}

	if err := s.jobRepo.UpdateStatus(ctx, jobID, domain.JobStatusCompleted, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Fetch certificate and target for notification
	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		slog.Error("failed to fetch certificate for notification", "error", err)
		return nil
	}

	var targetID string
	if job.TargetID != nil {
		targetID = *job.TargetID
	}

	if targetID != "" {
		target, err := s.targetRepo.Get(ctx, targetID)
		if err != nil {
			slog.Error("failed to fetch target for notification", "error", err)
			return nil
		}

		// Send deployment success notification
		if err := s.notificationSvc.SendDeploymentNotification(ctx, cert, target, true, nil); err != nil {
			slog.Error("failed to send deployment notification", "error", err)
		}
	}

	// Record audit event
	if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"deployment_job_completed", "certificate", job.CertificateID,
		map[string]interface{}{"job_id": jobID, "target_id": targetID}); auditErr != nil {
		slog.Error("failed to record audit event", "error", auditErr)
	}

	return nil
}

// MarkDeploymentFailed marks a deployment job as failed.
// Called by agents when deployment fails.
func (s *DeploymentService) MarkDeploymentFailed(ctx context.Context, jobID string, errMsg string) error {
	job, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to fetch job: %w", err)
	}

	if err := s.jobRepo.UpdateStatus(ctx, jobID, domain.JobStatusFailed, errMsg); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Fetch certificate and target for notification
	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		slog.Error("failed to fetch certificate for notification", "error", err)
		return nil
	}

	var targetID string
	if job.TargetID != nil {
		targetID = *job.TargetID
	}

	if targetID != "" {
		target, err := s.targetRepo.Get(ctx, targetID)
		if err != nil {
			slog.Error("failed to fetch target for notification", "error", err)
			return nil
		}

		// Send deployment failure notification
		if err := s.notificationSvc.SendDeploymentNotification(ctx, cert, target, false, fmt.Errorf("%s", errMsg)); err != nil {
			slog.Error("failed to send deployment notification", "error", err)
		}
	}

	// Record audit event
	if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"deployment_job_failed", "certificate", job.CertificateID,
		map[string]interface{}{"job_id": jobID, "target_id": targetID, "error": errMsg}); auditErr != nil {
		slog.Error("failed to record audit event", "error", auditErr)
	}

	return nil
}
