package service

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// CertificateService provides business logic for certificate management.
type CertificateService struct {
	certRepo        repository.CertificateRepository
	targetRepo      repository.TargetRepository
	revocationRepo  repository.RevocationRepository
	profileRepo     repository.CertificateProfileRepository
	policyService   *PolicyService
	auditService    *AuditService
	notificationSvc *NotificationService
	issuerRegistry  map[string]IssuerConnector
}

// NewCertificateService creates a new certificate service.
func NewCertificateService(
	certRepo repository.CertificateRepository,
	policyService *PolicyService,
	auditService *AuditService,
) *CertificateService {
	return &CertificateService{
		certRepo:      certRepo,
		policyService: policyService,
		auditService:  auditService,
	}
}

// SetRevocationRepo sets the revocation repository (called after construction to avoid init order issues).
func (s *CertificateService) SetRevocationRepo(repo repository.RevocationRepository) {
	s.revocationRepo = repo
}

// SetNotificationService sets the notification service for revocation alerts.
func (s *CertificateService) SetNotificationService(svc *NotificationService) {
	s.notificationSvc = svc
}

// SetIssuerRegistry sets the issuer registry for issuer-level revocation.
func (s *CertificateService) SetIssuerRegistry(registry map[string]IssuerConnector) {
	s.issuerRegistry = registry
}

// SetProfileRepo sets the profile repository for short-lived cert exemption in CRL/OCSP.
func (s *CertificateService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// SetTargetRepo sets the target repository for deployment queries.
func (s *CertificateService) SetTargetRepo(repo repository.TargetRepository) {
	s.targetRepo = repo
}

// List returns a paginated list of certificates matching the filter.
func (s *CertificateService) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	certs, total, err := s.certRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificates: %w", err)
	}
	return certs, total, nil
}

// ListCertificatesWithFilter returns a list of certificates with advanced filtering (M20).
// This method supports the new M20 filters and returns domain.ManagedCertificate (not pointers).
func (s *CertificateService) ListCertificatesWithFilter(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
	certs, total, err := s.certRepo.List(context.Background(), filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificates with filter: %w", err)
	}

	// Convert pointers to values for handler compatibility
	result := make([]domain.ManagedCertificate, len(certs))
	for i, cert := range certs {
		result[i] = *cert
	}
	return result, total, nil
}

// Get retrieves a certificate by ID.
func (s *CertificateService) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	cert, err := s.certRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate %s: %w", id, err)
	}
	return cert, nil
}

// Create validates and stores a new certificate.
func (s *CertificateService) Create(ctx context.Context, cert *domain.ManagedCertificate, actor string) error {
	// Validate certificate structure
	if cert.ID == "" || cert.CommonName == "" || cert.IssuerID == "" {
		return fmt.Errorf("invalid certificate: missing required fields")
	}

	// Run policy validation
	violations, err := s.policyService.ValidateCertificate(ctx, cert)
	if err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}
	if len(violations) > 0 {
		// Record violations but do not block creation
		for _, v := range violations {
			if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
				"policy_violation_detected", "certificate", cert.ID,
				map[string]interface{}{"rule_id": v.RuleID, "message": v.Message}); auditErr != nil {
				slog.Error("failed to record audit event", "error", auditErr)
			}
		}
	}

	// Store certificate
	if err := s.certRepo.Create(ctx, cert); err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"certificate_created", "certificate", cert.ID,
		map[string]interface{}{"common_name": cert.CommonName}); err != nil {
		// Log but don't fail the operation
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// Update modifies an existing certificate.
func (s *CertificateService) Update(ctx context.Context, cert *domain.ManagedCertificate, actor string) error {
	existing, err := s.certRepo.Get(ctx, cert.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch existing certificate: %w", err)
	}

	// Run policy validation on updated cert
	violations, err := s.policyService.ValidateCertificate(ctx, cert)
	if err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}
	if len(violations) > 0 {
		for _, v := range violations {
			if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
				"policy_violation_detected", "certificate", cert.ID,
				map[string]interface{}{"rule_id": v.RuleID, "message": v.Message}); auditErr != nil {
				slog.Error("failed to record audit event", "error", auditErr)
			}
		}
	}

	// Store updated certificate
	if err := s.certRepo.Update(ctx, cert); err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	// Record audit event with diff info
	changes := map[string]interface{}{}
	if existing.Status != cert.Status {
		changes["status"] = fmt.Sprintf("%s -> %s", existing.Status, cert.Status)
	}
	if existing.ExpiresAt != cert.ExpiresAt {
		changes["expiry"] = fmt.Sprintf("%s -> %s", existing.ExpiresAt, cert.ExpiresAt)
	}

	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"certificate_updated", "certificate", cert.ID, changes); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// Archive marks a certificate as archived.
func (s *CertificateService) Archive(ctx context.Context, id string, actor string) error {
	cert, err := s.certRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	if err := s.certRepo.Archive(ctx, id); err != nil {
		return fmt.Errorf("failed to archive certificate: %w", err)
	}

	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"certificate_archived", "certificate", id,
		map[string]interface{}{"common_name": cert.CommonName}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// GetVersions returns all versions of a certificate.
func (s *CertificateService) GetVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error) {
	versions, err := s.certRepo.ListVersions(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate versions: %w", err)
	}
	return versions, nil
}

// TriggerRenewalWithActor initiates a renewal job if the certificate is eligible.
func (s *CertificateService) TriggerRenewalWithActor(ctx context.Context, certID string, actor string) error {
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	// Validate eligibility
	if cert.Status == domain.CertificateStatusArchived {
		return fmt.Errorf("cannot renew archived certificate")
	}
	if cert.Status == domain.CertificateStatusExpired {
		return fmt.Errorf("cannot renew expired certificate; reissue instead")
	}

	// Check if already renewing
	if cert.Status == domain.CertificateStatusRenewalInProgress {
		return fmt.Errorf("certificate renewal already in progress")
	}

	// Update status
	cert.Status = domain.CertificateStatusRenewalInProgress
	if err := s.certRepo.Update(ctx, cert); err != nil {
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"renewal_triggered", "certificate", certID,
		map[string]interface{}{"common_name": cert.CommonName}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// TriggerDeploymentWithActor creates deployment jobs for all targets of a certificate.
func (s *CertificateService) TriggerDeploymentWithActor(ctx context.Context, certID string, actor string) error {
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	if cert.Status == domain.CertificateStatusArchived {
		return fmt.Errorf("cannot deploy archived certificate")
	}

	// Note: In practice, the DeploymentService would be called to create jobs.
	// This is a placeholder for the coordination logic.
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"deployment_triggered", "certificate", certID,
		map[string]interface{}{"common_name": cert.CommonName}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// ListCertificates returns paginated certificates with optional filtering (handler interface method).
func (s *CertificateService) ListCertificates(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	// Build filter for repository
	filter := &repository.CertificateFilter{
		Status:      status,
		Environment: environment,
		OwnerID:     ownerID,
		TeamID:      teamID,
		IssuerID:    issuerID,
		Page:        page,
		PerPage:     perPage,
	}

	certs, total, err := s.certRepo.List(context.Background(), filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificates: %w", err)
	}

	var result []domain.ManagedCertificate
	for _, c := range certs {
		if c != nil {
			result = append(result, *c)
		}
	}

	return result, int64(total), nil
}

// GetCertificate returns a single certificate (handler interface method).
func (s *CertificateService) GetCertificate(id string) (*domain.ManagedCertificate, error) {
	return s.certRepo.Get(context.Background(), id)
}

// CreateCertificate creates a new certificate (handler interface method).
func (s *CertificateService) CreateCertificate(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
	if cert.ID == "" {
		cert.ID = generateID("cert")
	}
	now := time.Now()
	if cert.CreatedAt.IsZero() {
		cert.CreatedAt = now
	}
	if cert.UpdatedAt.IsZero() {
		cert.UpdatedAt = now
	}
	if err := s.certRepo.Create(context.Background(), &cert); err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return &cert, nil
}

// UpdateCertificate modifies a certificate (handler interface method).
func (s *CertificateService) UpdateCertificate(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
	cert.ID = id
	if err := s.certRepo.Update(context.Background(), &cert); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}
	return &cert, nil
}

// ArchiveCertificate marks a certificate as archived (handler interface method).
func (s *CertificateService) ArchiveCertificate(id string) error {
	return s.certRepo.Archive(context.Background(), id)
}

// GetCertificateVersions returns certificate versions (handler interface method).
func (s *CertificateService) GetCertificateVersions(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	versions, err := s.certRepo.ListVersions(context.Background(), certID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificate versions: %w", err)
	}

	total := int64(len(versions))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	var result []domain.CertificateVersion
	for _, v := range versions[start:end] {
		if v != nil {
			result = append(result, *v)
		}
	}

	return result, total, nil
}

// TriggerRenewal initiates renewal (handler interface method).
func (s *CertificateService) TriggerRenewal(certID string) error {
	return s.TriggerRenewalWithActor(context.Background(), certID, "api")
}

// TriggerDeployment triggers deployment (handler interface method).
func (s *CertificateService) TriggerDeployment(certID string, targetID string) error {
	return s.TriggerDeploymentWithActor(context.Background(), certID, "api")
}

// RevokeCertificate revokes a certificate with the given reason.
// Steps:
// 1. Validate the certificate exists and is revocable
// 2. Get the latest certificate version (for serial number)
// 3. Update certificate status to Revoked
// 4. Record revocation in certificate_revocations table
// 5. Notify the issuer connector (best-effort)
// 6. Record audit event
// 7. Send revocation notification
func (s *CertificateService) RevokeCertificate(certID string, reason string) error {
	return s.RevokeCertificateWithActor(context.Background(), certID, reason, "api")
}

// RevokeCertificateWithActor performs revocation with actor tracking.
func (s *CertificateService) RevokeCertificateWithActor(ctx context.Context, certID string, reason string, actor string) error {
	// 1. Validate certificate exists and is revocable
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	if cert.Status == domain.CertificateStatusRevoked {
		return fmt.Errorf("certificate is already revoked")
	}
	if cert.Status == domain.CertificateStatusArchived {
		return fmt.Errorf("cannot revoke archived certificate")
	}

	// Validate reason code
	if reason == "" {
		reason = string(domain.RevocationReasonUnspecified)
	}
	if !domain.IsValidRevocationReason(reason) {
		return fmt.Errorf("invalid revocation reason: %s", reason)
	}

	// 2. Get latest certificate version for serial number
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		return fmt.Errorf("failed to get certificate version: %w", err)
	}

	// 3. Update certificate status to Revoked
	now := time.Now()
	cert.Status = domain.CertificateStatusRevoked
	cert.RevokedAt = &now
	cert.RevocationReason = reason
	cert.UpdatedAt = now
	if err := s.certRepo.Update(ctx, cert); err != nil {
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	// 4. Record revocation in certificate_revocations table (for CRL generation)
	if s.revocationRepo != nil {
		revocation := &domain.CertificateRevocation{
			ID:            generateID("rev"),
			CertificateID: certID,
			SerialNumber:  version.SerialNumber,
			Reason:        reason,
			RevokedBy:     actor,
			RevokedAt:     now,
			IssuerID:      cert.IssuerID,
			CreatedAt:     now,
		}
		if err := s.revocationRepo.Create(ctx, revocation); err != nil {
			slog.Error("failed to record revocation for CRL", "error", err, "certificate_id", certID)
			// Don't fail the overall revocation — the cert status is already updated
		}
	}

	// 5. Notify the issuer connector (best-effort)
	if s.issuerRegistry != nil {
		if issuerConn, ok := s.issuerRegistry[cert.IssuerID]; ok {
			if err := issuerConn.RevokeCertificate(ctx, version.SerialNumber, reason); err != nil {
				slog.Error("failed to notify issuer of revocation",
					"error", err,
					"issuer_id", cert.IssuerID,
					"serial", version.SerialNumber)
				// Best-effort — don't fail the overall revocation
			} else if s.revocationRepo != nil {
				// Mark issuer as notified
				revocations, _ := s.revocationRepo.ListByCertificate(ctx, certID)
				for _, rev := range revocations {
					if rev.SerialNumber == version.SerialNumber {
						_ = s.revocationRepo.MarkIssuerNotified(ctx, rev.ID)
					}
				}
			}
		}
	}

	// 6. Record audit event
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"certificate_revoked", "certificate", certID,
		map[string]interface{}{
			"common_name": cert.CommonName,
			"serial":      version.SerialNumber,
			"reason":      reason,
		}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	// 7. Send revocation notification
	if s.notificationSvc != nil {
		if err := s.notificationSvc.SendRevocationNotification(ctx, cert, reason); err != nil {
			slog.Error("failed to send revocation notification", "error", err, "certificate_id", certID)
		}
	}

	return nil
}

// GetRevokedCertificates returns all revoked certificate records (for CRL generation).
func (s *CertificateService) GetRevokedCertificates() ([]*domain.CertificateRevocation, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	return s.revocationRepo.ListAll(context.Background())
}

// GenerateDERCRL generates a DER-encoded X.509 CRL for the given issuer.
// Short-lived certificates (profile TTL < 1 hour) are excluded from the CRL.
func (s *CertificateService) GenerateDERCRL(issuerID string) ([]byte, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	if s.issuerRegistry == nil {
		return nil, fmt.Errorf("issuer registry not configured")
	}

	issuerConn, ok := s.issuerRegistry[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer not found: %s", issuerID)
	}

	revocations, err := s.revocationRepo.ListAll(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to list revocations: %w", err)
	}

	// Filter to this issuer and convert to CRL entries.
	// Short-lived certificates (profile TTL < 1 hour) are excluded — expiry is sufficient revocation.
	var entries []CRLEntry
	for _, rev := range revocations {
		if rev.IssuerID != issuerID {
			continue
		}

		// Check short-lived exemption: look up the cert's profile
		if s.profileRepo != nil && s.certRepo != nil {
			cert, err := s.certRepo.Get(context.Background(), rev.CertificateID)
			if err == nil && cert.CertificateProfileID != "" {
				profile, err := s.profileRepo.Get(context.Background(), cert.CertificateProfileID)
				if err == nil && profile.IsShortLived() {
					slog.Debug("skipping short-lived cert from CRL",
						"certificate_id", rev.CertificateID,
						"profile_id", cert.CertificateProfileID)
					continue
				}
			}
		}

		// Parse serial number from hex string
		serial := new(big.Int)
		serial.SetString(rev.SerialNumber, 16)

		entries = append(entries, CRLEntry{
			SerialNumber: serial,
			RevokedAt:    rev.RevokedAt,
			ReasonCode:   domain.CRLReasonCode(domain.RevocationReason(rev.Reason)),
		})
	}

	return issuerConn.GenerateCRL(context.Background(), entries)
}

// GetOCSPResponse generates a signed OCSP response for the given certificate serial.
func (s *CertificateService) GetOCSPResponse(issuerID string, serialHex string) ([]byte, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	if s.issuerRegistry == nil {
		return nil, fmt.Errorf("issuer registry not configured")
	}

	issuerConn, ok := s.issuerRegistry[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer not found: %s", issuerID)
	}

	serial := new(big.Int)
	serial.SetString(serialHex, 16)

	now := time.Now()

	// Short-lived cert exemption: if the cert's profile has TTL < 1 hour,
	// always return "good" — expiry is sufficient revocation for short-lived certs.
	if s.profileRepo != nil && s.certRepo != nil {
		// Look up cert by serial through revocation table
		rev, _ := s.revocationRepo.GetBySerial(context.Background(), serialHex)
		if rev != nil {
			cert, err := s.certRepo.Get(context.Background(), rev.CertificateID)
			if err == nil && cert.CertificateProfileID != "" {
				profile, err := s.profileRepo.Get(context.Background(), cert.CertificateProfileID)
				if err == nil && profile.IsShortLived() {
					return issuerConn.SignOCSPResponse(context.Background(), OCSPSignRequest{
						CertSerial: serial,
						CertStatus: 0, // good — short-lived exemption
						ThisUpdate: now,
						NextUpdate: now.Add(1 * time.Hour),
					})
				}
			}
		}
	}

	// Check if this serial is revoked
	rev, err := s.revocationRepo.GetBySerial(context.Background(), serialHex)
	if err != nil {
		// Not revoked — return "good" status
		return issuerConn.SignOCSPResponse(context.Background(), OCSPSignRequest{
			CertSerial: serial,
			CertStatus: 0, // good
			ThisUpdate: now,
			NextUpdate: now.Add(1 * time.Hour),
		})
	}

	// Revoked
	return issuerConn.SignOCSPResponse(context.Background(), OCSPSignRequest{
		CertSerial:       serial,
		CertStatus:       1, // revoked
		RevokedAt:        rev.RevokedAt,
		RevocationReason: domain.CRLReasonCode(domain.RevocationReason(rev.Reason)),
		ThisUpdate:       now,
		NextUpdate:       now.Add(1 * time.Hour),
	})
}

// GetCertificateDeployments returns all deployment targets for a certificate (M20).
func (s *CertificateService) GetCertificateDeployments(certID string) ([]domain.DeploymentTarget, error) {
	// Verify certificate exists
	_, err := s.certRepo.Get(context.Background(), certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	if s.targetRepo == nil {
		return []domain.DeploymentTarget{}, nil
	}

	// Get targets from repository
	targets, err := s.targetRepo.ListByCertificate(context.Background(), certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list deployment targets: %w", err)
	}

	// Convert pointers to values
	result := make([]domain.DeploymentTarget, len(targets))
	for i, target := range targets {
		result[i] = *target
	}
	return result, nil
}
