package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// VerificationService handles recording and querying certificate deployment verification results.
type VerificationService struct {
	jobRepo       repository.JobRepository
	auditService  *AuditService
	logger        *slog.Logger
}

// NewVerificationService creates a new verification service.
func NewVerificationService(
	jobRepo repository.JobRepository,
	auditService *AuditService,
	logger *slog.Logger,
) *VerificationService {
	return &VerificationService{
		jobRepo:       jobRepo,
		auditService:  auditService,
		logger:        logger,
	}
}

// RecordVerificationResult updates a job with the results of TLS endpoint verification.
// This records both success and failure results, along with timestamp and fingerprint comparison.
// An audit event is recorded for every verification result.
func (s *VerificationService) RecordVerificationResult(ctx context.Context, result *domain.VerificationResult) error {
	if result == nil {
		return fmt.Errorf("verification result is required")
	}
	if result.JobID == "" {
		return fmt.Errorf("job ID is required")
	}

	// Get the current job to update it
	job, err := s.jobRepo.Get(ctx, result.JobID)
	if err != nil {
		return fmt.Errorf("failed to fetch job for verification: %w", err)
	}

	// Determine verification status
	var status domain.VerificationStatus
	if result.Error != "" {
		status = domain.VerificationFailed
	} else if result.Verified {
		status = domain.VerificationSuccess
	} else {
		status = domain.VerificationFailed
	}

	// Update job with verification results
	job.VerificationStatus = status
	job.VerifiedAt = &result.VerifiedAt
	job.VerificationFp = &result.ActualFingerprint
	if result.Error != "" {
		job.VerificationError = &result.Error
	}

	if err := s.jobRepo.Update(ctx, job); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to record verification result",
				"job_id", result.JobID,
				"error", err)
		}
		return fmt.Errorf("failed to update job with verification result: %w", err)
	}

	// Record audit event
	auditEvent := "job_verification_success"
	auditDetails := map[string]interface{}{
		"job_id":                  result.JobID,
		"target_id":               result.TargetID,
		"expected_fingerprint":    result.ExpectedFingerprint,
		"actual_fingerprint":      result.ActualFingerprint,
		"verified":                result.Verified,
	}

	if result.Error != "" {
		auditEvent = "job_verification_failed"
		auditDetails["error"] = result.Error
	}

	s.auditService.RecordEvent(ctx, "agent", domain.ActorTypeAgent,
		auditEvent, "job", result.JobID,
		auditDetails)

	if s.logger != nil {
		s.logger.Info("recorded verification result",
			"job_id", result.JobID,
			"status", status,
			"verified", result.Verified)
	}

	return nil
}

// GetVerificationResult retrieves the verification status and details for a job.
func (s *VerificationService) GetVerificationResult(ctx context.Context, jobID string) (*domain.VerificationResult, error) {
	if jobID == "" {
		return nil, fmt.Errorf("job ID is required")
	}

	job, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job: %w", err)
	}

	result := &domain.VerificationResult{
		JobID:  job.ID,
		Verified: job.VerificationStatus == domain.VerificationSuccess,
	}

	// If target ID is set, populate it
	if job.TargetID != nil {
		result.TargetID = *job.TargetID
	}

	// Populate fingerprints if available
	if job.VerificationFp != nil {
		result.ActualFingerprint = *job.VerificationFp
	}
	if job.VerificationError != nil {
		result.Error = *job.VerificationError
	}
	if job.VerifiedAt != nil {
		result.VerifiedAt = *job.VerifiedAt
	}

	return result, nil
}
