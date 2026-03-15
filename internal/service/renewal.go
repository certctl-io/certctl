package service

import (
	"context"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// RenewalService manages certificate renewal workflows.
type RenewalService struct {
	certRepo         repository.CertificateRepository
	jobRepo          repository.JobRepository
	auditService     *AuditService
	notificationSvc  *NotificationService
	issuerRegistry   map[string]IssuerConnector
}

// IssuerConnector defines the interface for interacting with certificate issuers.
type IssuerConnector interface {
	// RenewCertificate renews a certificate and returns the new certificate PEM.
	RenewCertificate(ctx context.Context, csr []byte) ([]byte, error)
	// GetCertificateChain returns the issuer's certificate chain.
	GetCertificateChain(ctx context.Context) ([]byte, error)
}

// NewRenewalService creates a new renewal service.
func NewRenewalService(
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	auditService *AuditService,
	notificationSvc *NotificationService,
	issuerRegistry map[string]IssuerConnector,
) *RenewalService {
	return &RenewalService{
		certRepo:        certRepo,
		jobRepo:         jobRepo,
		auditService:    auditService,
		notificationSvc: notificationSvc,
		issuerRegistry:  issuerRegistry,
	}
}

// CheckExpiringCertificates identifies certificates needing renewal based on policy windows.
func (s *RenewalService) CheckExpiringCertificates(ctx context.Context) error {
	// Default renewal window: 30 days before expiry
	renewalWindow := time.Now().AddDate(0, 0, 30)

	expiring, err := s.certRepo.GetExpiringCertificates(ctx, renewalWindow)
	if err != nil {
		return fmt.Errorf("failed to fetch expiring certificates: %w", err)
	}

	for _, cert := range expiring {
		// Skip if already renewing or archived
		if cert.Status == domain.CertificateStatusRenewalInProgress || cert.Status == domain.CertificateStatusArchived {
			continue
		}

		// Calculate days until expiry
		daysUntil := time.Until(cert.ExpiresAt).Hours() / 24

		// Send expiration warning notification (always, regardless of issuer availability)
		if err := s.notificationSvc.SendExpirationWarning(ctx, cert, int(daysUntil)); err != nil {
			fmt.Printf("failed to send expiration warning for cert %s: %v\n", cert.ID, err)
		}

		// Only create renewal job if an issuer connector is registered for this cert's issuer
		if _, hasIssuer := s.issuerRegistry[cert.IssuerID]; !hasIssuer {
			continue
		}

		// Create renewal job
		job := &domain.Job{
			ID:            generateID("job"),
			CertificateID: cert.ID,
			Type:          domain.JobTypeRenewal,
			Status:        domain.JobStatusPending,
			ScheduledAt:   time.Now(),
			CreatedAt:     time.Now(),
		}

		if err := s.jobRepo.Create(ctx, job); err != nil {
			fmt.Printf("failed to create renewal job for cert %s: %v\n", cert.ID, err)
			continue
		}

		// Record audit event
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"renewal_job_created", "certificate", cert.ID,
			map[string]interface{}{"days_until_expiry": daysUntil, "job_id": job.ID})
	}

	return nil
}

// ProcessRenewalJob executes a renewal job: call issuer, store new version, update cert status.
func (s *RenewalService) ProcessRenewalJob(ctx context.Context, job *domain.Job) error {
	// Update job status to in-progress
	if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusRunning, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Fetch certificate
	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("certificate fetch failed: %v", err))
		if updateErr != nil {
			fmt.Printf("failed to update job status: %v\n", updateErr)
		}
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	// Get issuer connector
	issuerID := cert.IssuerID
	if issuerID == "" {
		return fmt.Errorf("certificate has no issuer assigned")
	}

	connector, ok := s.issuerRegistry[issuerID]
	if !ok {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed,
			fmt.Sprintf("issuer connector not found for %s", issuerID))
		if updateErr != nil {
			fmt.Printf("failed to update job status: %v\n", updateErr)
		}
		return fmt.Errorf("issuer connector not found for %s", issuerID)
	}

	// TODO: In production, fetch CSR from agent or generate new CSR
	// For now, we'd use cert.CSR or generate a new one from the private key
	csr := []byte{} // placeholder

	// Call issuer to renew
	certPEM, err := connector.RenewCertificate(ctx, csr)
	if err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("issuer renewal failed: %v", err))
		if updateErr != nil {
			fmt.Printf("failed to update job status: %v\n", updateErr)
		}

		// Send failure notification
		_ = s.notificationSvc.SendRenewalNotification(ctx, cert, false, err)

		// Record audit event
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"renewal_job_failed", "certificate", job.CertificateID,
			map[string]interface{}{"job_id": job.ID, "error": err.Error()})

		return fmt.Errorf("issuer renewal failed: %w", err)
	}

	// Create new certificate version
	version := &domain.CertificateVersion{
		ID:            generateID("certver"),
		CertificateID: job.CertificateID,
		SerialNumber:  fmt.Sprintf("renewed-%d", time.Now().Unix()),
		PEMChain:      string(certPEM),
		CreatedAt:     time.Now(),
	}

	if err := s.certRepo.CreateVersion(ctx, version); err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("version creation failed: %v", err))
		if updateErr != nil {
			fmt.Printf("failed to update job status: %v\n", updateErr)
		}
		return fmt.Errorf("failed to create certificate version: %w", err)
	}

	// Update certificate status
	cert.Status = domain.CertificateStatusActive
	if err := s.certRepo.Update(ctx, cert); err != nil {
		updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, fmt.Sprintf("cert update failed: %v", err))
		if updateErr != nil {
			fmt.Printf("failed to update job status: %v\n", updateErr)
		}
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	// Mark job as completed
	if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusCompleted, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Send success notification
	if err := s.notificationSvc.SendRenewalNotification(ctx, cert, true, nil); err != nil {
		fmt.Printf("failed to send renewal notification: %v\n", err)
	}

	// Record audit event
	_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"renewal_job_completed", "certificate", job.CertificateID,
		map[string]interface{}{"job_id": job.ID, "serial": version.SerialNumber})

	return nil
}

// Retry attempts to reprocess failed renewal jobs with exponential backoff.
func (s *RenewalService) RetryFailedJobs(ctx context.Context, maxRetries int) error {
	failedJobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusFailed)
	if err != nil {
		return fmt.Errorf("failed to fetch failed jobs: %w", err)
	}

	for _, job := range failedJobs {
		if job.Type != domain.JobTypeRenewal {
			continue
		}

		// Check if we've exceeded max attempts
		if job.Attempts >= job.MaxAttempts {
			continue
		}

		// Reset status to pending for retry
		if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusPending, ""); err != nil {
			fmt.Printf("failed to reset job status for retry: %v\n", err)
			continue
		}
	}

	return nil
}

// generateID is a helper to generate unique IDs. In production, use a proper ID generator.
func generateID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
