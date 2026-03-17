package service

import (
	"context"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// CertificateService provides business logic for certificate management.
type CertificateService struct {
	certRepo      repository.CertificateRepository
	policyService *PolicyService
	auditService  *AuditService
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

// List returns a paginated list of certificates matching the filter.
func (s *CertificateService) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	certs, total, err := s.certRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificates: %w", err)
	}
	return certs, total, nil
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
			_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
				"policy_violation_detected", "certificate", cert.ID,
				map[string]interface{}{"rule_id": v.RuleID, "message": v.Message})
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
		fmt.Printf("failed to record audit event: %v\n", err)
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
			_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
				"policy_violation_detected", "certificate", cert.ID,
				map[string]interface{}{"rule_id": v.RuleID, "message": v.Message})
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
		fmt.Printf("failed to record audit event: %v\n", err)
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
		fmt.Printf("failed to record audit event: %v\n", err)
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
		fmt.Printf("failed to record audit event: %v\n", err)
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
		fmt.Printf("failed to record audit event: %v\n", err)
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
