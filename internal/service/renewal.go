package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// RenewalService manages certificate renewal workflows.
type RenewalService struct {
	certRepo          repository.CertificateRepository
	jobRepo           repository.JobRepository
	renewalPolicyRepo repository.RenewalPolicyRepository
	auditService      *AuditService
	notificationSvc   *NotificationService
	issuerRegistry    map[string]IssuerConnector
}

// IssuerConnector defines the service-layer interface for interacting with certificate issuers.
// This is distinct from the connector-layer issuer.Connector interface to maintain dependency
// inversion. Use IssuerConnectorAdapter to bridge between the two.
type IssuerConnector interface {
	// IssueCertificate issues a new certificate using the provided CSR PEM.
	IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string) (*IssuanceResult, error)
	// RenewCertificate renews a certificate using the provided CSR PEM.
	RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string) (*IssuanceResult, error)
}

// IssuanceResult holds the result of a certificate issuance or renewal operation.
type IssuanceResult struct {
	CertPEM   string
	ChainPEM  string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

// NewRenewalService creates a new renewal service.
func NewRenewalService(
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	auditService *AuditService,
	notificationSvc *NotificationService,
	issuerRegistry map[string]IssuerConnector,
) *RenewalService {
	return &RenewalService{
		certRepo:          certRepo,
		jobRepo:           jobRepo,
		renewalPolicyRepo: renewalPolicyRepo,
		auditService:      auditService,
		notificationSvc:   notificationSvc,
		issuerRegistry:    issuerRegistry,
	}
}

// CheckExpiringCertificates identifies certificates needing renewal and sends threshold-based
// expiration alerts. For each certificate, it looks up the renewal policy's configured alert
// thresholds (default: 30, 14, 7, 0 days) and sends deduplicated notifications at each threshold.
// Certificates are also transitioned to Expiring/Expired status as appropriate.
func (s *RenewalService) CheckExpiringCertificates(ctx context.Context) error {
	// Use the maximum possible threshold window (30 days) plus buffer for query
	renewalWindow := time.Now().AddDate(0, 0, 31)

	expiring, err := s.certRepo.GetExpiringCertificates(ctx, renewalWindow)
	if err != nil {
		return fmt.Errorf("failed to fetch expiring certificates: %w", err)
	}

	// Cache renewal policies to avoid repeated lookups
	policyCache := make(map[string]*domain.RenewalPolicy)

	for _, cert := range expiring {
		// Skip if already renewing or archived
		if cert.Status == domain.CertificateStatusRenewalInProgress || cert.Status == domain.CertificateStatusArchived {
			continue
		}

		// Calculate days until expiry
		daysUntil := time.Until(cert.ExpiresAt).Hours() / 24

		// Look up renewal policy for alert thresholds
		thresholds := domain.DefaultAlertThresholds()
		if cert.RenewalPolicyID != "" {
			policy, ok := policyCache[cert.RenewalPolicyID]
			if !ok {
				policy, err = s.renewalPolicyRepo.Get(ctx, cert.RenewalPolicyID)
				if err != nil {
					// Log but continue with defaults
					fmt.Printf("failed to fetch renewal policy %s for cert %s, using defaults: %v\n",
						cert.RenewalPolicyID, cert.ID, err)
				} else {
					policyCache[cert.RenewalPolicyID] = policy
				}
			}
			if policy != nil {
				thresholds = policy.EffectiveAlertThresholds()
			}
		}

		// Update certificate status based on expiry
		s.updateCertExpiryStatus(ctx, cert, daysUntil)

		// Send threshold-based alerts with deduplication
		s.sendThresholdAlerts(ctx, cert, int(daysUntil), thresholds)

		// Only create renewal job if an issuer connector is registered for this cert's issuer
		if _, hasIssuer := s.issuerRegistry[cert.IssuerID]; !hasIssuer {
			continue
		}

		// Check for existing pending/running renewal jobs to avoid duplicates
		existingJobs, err := s.jobRepo.ListByCertificate(ctx, cert.ID)
		if err == nil {
			hasActiveRenewal := false
			for _, j := range existingJobs {
				if j.Type == domain.JobTypeRenewal &&
					(j.Status == domain.JobStatusPending || j.Status == domain.JobStatusRunning) {
					hasActiveRenewal = true
					break
				}
			}
			if hasActiveRenewal {
				continue
			}
		}

		// Create renewal job
		job := &domain.Job{
			ID:            generateID("job"),
			CertificateID: cert.ID,
			Type:          domain.JobTypeRenewal,
			Status:        domain.JobStatusPending,
			MaxAttempts:   3,
			ScheduledAt:   time.Now(),
			CreatedAt:     time.Now(),
		}

		if err := s.jobRepo.Create(ctx, job); err != nil {
			fmt.Printf("failed to create renewal job for cert %s: %v\n", cert.ID, err)
			continue
		}

		// Update certificate status to RenewalInProgress
		cert.Status = domain.CertificateStatusRenewalInProgress
		if err := s.certRepo.Update(ctx, cert); err != nil {
			fmt.Printf("failed to update cert status for %s: %v\n", cert.ID, err)
		}

		// Record audit event
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"renewal_job_created", "certificate", cert.ID,
			map[string]interface{}{"days_until_expiry": daysUntil, "job_id": job.ID})
	}

	return nil
}

// sendThresholdAlerts sends deduplicated expiration notifications based on configured thresholds.
// For each threshold that the certificate has crossed (e.g., ≤30 days, ≤14 days), it checks
// whether a notification for that threshold was already sent. Only new threshold crossings
// trigger notifications.
func (s *RenewalService) sendThresholdAlerts(ctx context.Context, cert *domain.ManagedCertificate, daysUntil int, thresholds []int) {
	for _, threshold := range thresholds {
		// Only alert if the cert has crossed this threshold (days remaining ≤ threshold)
		if daysUntil > threshold {
			continue
		}

		// Check if we already sent a notification for this threshold (deduplication)
		alreadySent, err := s.notificationSvc.HasThresholdNotification(ctx, cert.ID, threshold)
		if err != nil {
			fmt.Printf("failed to check notification dedup for cert %s threshold %d: %v\n",
				cert.ID, threshold, err)
			continue
		}
		if alreadySent {
			continue
		}

		// Send the threshold alert
		if err := s.notificationSvc.SendThresholdAlert(ctx, cert, daysUntil, threshold); err != nil {
			fmt.Printf("failed to send threshold alert for cert %s at %d days: %v\n",
				cert.ID, threshold, err)
		}

		// Record audit event for the alert
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"expiration_alert_sent", "certificate", cert.ID,
			map[string]interface{}{
				"threshold_days":  threshold,
				"days_until_expiry": daysUntil,
			})
	}
}

// updateCertExpiryStatus transitions a certificate to Expiring or Expired status based on
// how many days remain before expiry. Expired = 0 or fewer days, Expiring = within 30 days.
func (s *RenewalService) updateCertExpiryStatus(ctx context.Context, cert *domain.ManagedCertificate, daysUntil float64) {
	var newStatus domain.CertificateStatus

	if daysUntil <= 0 {
		newStatus = domain.CertificateStatusExpired
	} else {
		newStatus = domain.CertificateStatusExpiring
	}

	// Only update if status is changing and cert isn't already in a terminal/active renewal state
	if cert.Status == newStatus {
		return
	}
	if cert.Status == domain.CertificateStatusRenewalInProgress ||
		cert.Status == domain.CertificateStatusArchived ||
		cert.Status == domain.CertificateStatusRevoked {
		return
	}

	cert.Status = newStatus
	cert.UpdatedAt = time.Now()
	if err := s.certRepo.Update(ctx, cert); err != nil {
		fmt.Printf("failed to update cert %s status to %s: %v\n", cert.ID, newStatus, err)
	}
}

// ProcessRenewalJob executes a renewal job: generate CSR, call issuer, store new version,
// update cert status, and create deployment jobs for targets.
//
// V1 Architecture Note: For the Local CA issuer, the control plane generates a server-side
// ephemeral key + CSR. The private key is stored in the CertificateVersion.CSRPEM field
// so agents can retrieve it for deployment. In V2+ with ACME/external CAs, agents will
// generate keys locally and submit CSRs, so private keys never leave the target infrastructure.
func (s *RenewalService) ProcessRenewalJob(ctx context.Context, job *domain.Job) error {
	// Update job status to in-progress
	if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusRunning, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Fetch certificate
	cert, err := s.certRepo.Get(ctx, job.CertificateID)
	if err != nil {
		s.failJob(ctx, job, fmt.Sprintf("certificate fetch failed: %v", err))
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	// Get issuer connector
	issuerID := cert.IssuerID
	if issuerID == "" {
		s.failJob(ctx, job, "certificate has no issuer assigned")
		return fmt.Errorf("certificate has no issuer assigned")
	}

	connector, ok := s.issuerRegistry[issuerID]
	if !ok {
		s.failJob(ctx, job, fmt.Sprintf("issuer connector not found for %s", issuerID))
		return fmt.Errorf("issuer connector not found for %s", issuerID)
	}

	// Generate server-side RSA key + CSR for this renewal
	// V1: server generates ephemeral key for Local CA. V2+: agent generates key locally.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.failJob(ctx, job, fmt.Sprintf("key generation failed: %v", err))
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cert.CommonName,
		},
		DNSNames: cert.SANs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		s.failJob(ctx, job, fmt.Sprintf("CSR generation failed: %v", err))
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// Encode private key to PEM for storage (V1: stored so agent can retrieve for deployment)
	privKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}))

	// Call issuer connector to renew
	result, err := connector.RenewCertificate(ctx, cert.CommonName, cert.SANs, csrPEM)
	if err != nil {
		s.failJob(ctx, job, fmt.Sprintf("issuer renewal failed: %v", err))

		// Send failure notification
		_ = s.notificationSvc.SendRenewalNotification(ctx, cert, false, err)

		// Record audit event
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"renewal_job_failed", "certificate", job.CertificateID,
			map[string]interface{}{"job_id": job.ID, "error": err.Error()})

		return fmt.Errorf("issuer renewal failed: %w", err)
	}

	// Compute SHA-256 fingerprint of the issued certificate
	fingerprint := computeCertFingerprint(result.CertPEM)

	// Create new certificate version
	version := &domain.CertificateVersion{
		ID:                generateID("certver"),
		CertificateID:    job.CertificateID,
		SerialNumber:     result.Serial,
		NotBefore:        result.NotBefore,
		NotAfter:         result.NotAfter,
		FingerprintSHA256: fingerprint,
		PEMChain:         result.CertPEM + "\n" + result.ChainPEM,
		CSRPEM:           privKeyPEM, // V1: stores private key for agent deployment
		CreatedAt:        time.Now(),
	}

	if err := s.certRepo.CreateVersion(ctx, version); err != nil {
		s.failJob(ctx, job, fmt.Sprintf("version creation failed: %v", err))
		return fmt.Errorf("failed to create certificate version: %w", err)
	}

	// Update certificate status and expiry
	cert.Status = domain.CertificateStatusActive
	cert.ExpiresAt = result.NotAfter
	now := time.Now()
	cert.LastRenewalAt = &now
	cert.UpdatedAt = now
	if err := s.certRepo.Update(ctx, cert); err != nil {
		s.failJob(ctx, job, fmt.Sprintf("cert update failed: %v", err))
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	// Mark renewal job as completed
	if err := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusCompleted, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Create deployment jobs for each target
	if len(cert.TargetIDs) > 0 {
		for _, targetID := range cert.TargetIDs {
			tid := targetID // capture loop variable
			deployJob := &domain.Job{
				ID:            generateID("job"),
				CertificateID: cert.ID,
				Type:          domain.JobTypeDeployment,
				Status:        domain.JobStatusPending,
				TargetID:      &tid,
				MaxAttempts:   3,
				ScheduledAt:   time.Now(),
				CreatedAt:     time.Now(),
			}
			if err := s.jobRepo.Create(ctx, deployJob); err != nil {
				fmt.Printf("failed to create deployment job for target %s: %v\n", targetID, err)
			}
		}
	}

	// Send success notification
	if err := s.notificationSvc.SendRenewalNotification(ctx, cert, true, nil); err != nil {
		fmt.Printf("failed to send renewal notification: %v\n", err)
	}

	// Record audit event
	_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"renewal_job_completed", "certificate", job.CertificateID,
		map[string]interface{}{
			"job_id":    job.ID,
			"serial":    result.Serial,
			"not_after": result.NotAfter,
		})

	return nil
}

// failJob is a helper to mark a job as failed with an error message.
func (s *RenewalService) failJob(ctx context.Context, job *domain.Job, errMsg string) {
	if updateErr := s.jobRepo.UpdateStatus(ctx, job.ID, domain.JobStatusFailed, errMsg); updateErr != nil {
		fmt.Printf("failed to update job status: %v\n", updateErr)
	}
}

// computeCertFingerprint computes the SHA-256 fingerprint of a PEM-encoded certificate.
func computeCertFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

// RetryFailedJobs resets failed renewal jobs for retry if they haven't exceeded max attempts.
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
