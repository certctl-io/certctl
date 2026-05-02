package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// CertificateService provides business logic for certificate management.
type CertificateService struct {
	certRepo      repository.CertificateRepository
	targetRepo    repository.TargetRepository
	jobRepo       repository.JobRepository
	policyService *PolicyService
	auditService  *AuditService
	revSvc        *RevocationSvc
	caSvc         *CAOperationsSvc
	// tx, when set, wraps the issuance write (cert insert + audit row)
	// in a single transaction so the audit row cannot be silently lost
	// after a successful cert insert. Closes the #3 audit-readiness
	// blocker (atomic audit rows). Optional via SetTransactor — when
	// nil, Create falls back to the legacy non-transactional path
	// (cert.Create + best-effort RecordEvent) for backward compatibility.
	tx repository.Transactor
	// crlCacheSvc, when set, makes GenerateDERCRL serve from the
	// pre-generated cache instead of regenerating per request. Bundle
	// CRL/OCSP-Responder Phase 4. Optional; when nil GenerateDERCRL
	// falls back to the historical on-demand path via caSvc.
	crlCacheSvc *CRLCacheService
	keygenMode  string
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

// SetTransactor wires a Transactor for atomic issuance (cert insert +
// audit row) and atomic revocation (cert update + revocation row + audit
// row). Closes the #3 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit. Optional — when nil, Create falls back to the
// legacy non-transactional path for backward compat with callers that
// haven't been updated.
func (s *CertificateService) SetTransactor(tx repository.Transactor) {
	s.tx = tx
}

// SetRevocationSvc sets the revocation service.
func (s *CertificateService) SetRevocationSvc(svc *RevocationSvc) {
	s.revSvc = svc
}

// SetCAOperationsSvc sets the CA operations service.
func (s *CertificateService) SetCAOperationsSvc(svc *CAOperationsSvc) {
	s.caSvc = svc
}

// SetCRLCacheSvc wires the CRL cache service. When set, GenerateDERCRL
// reads from the scheduler-pre-generated cache (cheap DB lookup) and
// only triggers an on-demand regeneration on cache miss / staleness.
// When unset, GenerateDERCRL falls back to the historical per-request
// regeneration via caSvc.
//
// Bundle CRL/OCSP-Responder Phase 4.
func (s *CertificateService) SetCRLCacheSvc(svc *CRLCacheService) {
	s.crlCacheSvc = svc
}

// SetTargetRepo sets the target repository for deployment queries.
func (s *CertificateService) SetTargetRepo(repo repository.TargetRepository) {
	s.targetRepo = repo
}

// SetJobRepo sets the job repository for creating renewal/issuance jobs.
func (s *CertificateService) SetJobRepo(repo repository.JobRepository) {
	s.jobRepo = repo
}

// SetKeygenMode sets the key generation mode (agent or server).
func (s *CertificateService) SetKeygenMode(mode string) {
	s.keygenMode = mode
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
func (s *CertificateService) ListCertificatesWithFilter(ctx context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
	certs, total, err := s.certRepo.List(ctx, filter)
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

	auditDetails := map[string]interface{}{"common_name": cert.CommonName}

	// Atomic path (production): cert insert + audit row in a single
	// transaction. Closes the #3 audit-readiness blocker — if the audit
	// insert fails after the cert insert, the cert insert rolls back so
	// the operator sees the failure and the audit trail is never silently
	// incomplete.
	if s.tx != nil {
		return s.tx.WithinTx(ctx, func(q repository.Querier) error {
			if err := s.certRepo.CreateWithTx(ctx, q, cert); err != nil {
				return fmt.Errorf("failed to create certificate: %w", err)
			}
			if err := s.auditService.RecordEventWithTx(ctx, q, actor, domain.ActorTypeUser,
				"certificate_created", "certificate", cert.ID, auditDetails); err != nil {
				return fmt.Errorf("failed to record audit event: %w", err)
			}
			return nil
		})
	}

	// Legacy non-transactional path — kept for callers that haven't
	// wired SetTransactor yet. Fails open on audit-insert failure (logs
	// and returns success), which is the pre-fix behavior; do not
	// rely on this path for compliance-relevant audit trails.
	if err := s.certRepo.Create(ctx, cert); err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"certificate_created", "certificate", cert.ID, auditDetails); err != nil {
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

// TriggerRenewal initiates a renewal job if the certificate is eligible.
// Creates a Renewal job (or Issuance for new certs) so the scheduler's job processor
// can pick it up and route it through the issuer connector.
func (s *CertificateService) TriggerRenewal(ctx context.Context, certID string, actor string) error {
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

	// Create a renewal job so the job processor can pick it up.
	// In agent keygen mode, the job starts as AwaitingCSR so the agent
	// generates the key pair and submits a CSR. In server mode, it starts as Pending.
	if s.jobRepo != nil {
		jobStatus := domain.JobStatusPending
		if s.keygenMode == "agent" {
			jobStatus = domain.JobStatusAwaitingCSR
		}

		// Determine job type: Issuance for certs that have never been issued,
		// Renewal for certs that already have a version.
		jobType := domain.JobTypeRenewal
		if cert.ExpiresAt.IsZero() || cert.ExpiresAt.Year() < 2000 {
			jobType = domain.JobTypeIssuance
		}

		job := &domain.Job{
			ID:            generateID("job"),
			CertificateID: cert.ID,
			Type:          jobType,
			Status:        jobStatus,
			MaxAttempts:   3,
			ScheduledAt:   time.Now(),
			CreatedAt:     time.Now(),
		}

		if err := s.jobRepo.Create(ctx, job); err != nil {
			slog.Error("failed to create renewal job", "cert_id", cert.ID, "error", err)
			return fmt.Errorf("failed to create renewal job: %w", err)
		}

		slog.Info("created renewal job via API trigger",
			"job_id", job.ID,
			"cert_id", cert.ID,
			"job_type", string(jobType),
			"job_status", string(jobStatus),
			"keygen_mode", s.keygenMode)
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"renewal_triggered", "certificate", certID,
		map[string]interface{}{"common_name": cert.CommonName}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// TriggerDeployment creates deployment jobs for all targets of a certificate.
// The targetID parameter is accepted from the handler interface but currently unused;
// deployment coordination happens per-certificate across all of its targets.
func (s *CertificateService) TriggerDeployment(ctx context.Context, certID string, targetID string, actor string) error {
	_ = targetID
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
func (s *CertificateService) ListCertificates(ctx context.Context, status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
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

	certs, total, err := s.certRepo.List(ctx, filter)
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
func (s *CertificateService) GetCertificate(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	return s.certRepo.Get(ctx, id)
}

// CreateCertificate creates a new certificate (handler interface method).
func (s *CertificateService) CreateCertificate(ctx context.Context, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
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
	// Default status to Pending if not set (DB column DEFAULT only applies when column is omitted from INSERT)
	if cert.Status == "" {
		cert.Status = domain.CertificateStatusPending
	}
	// Default tags to empty map if nil (avoids JSON null in JSONB column)
	if cert.Tags == nil {
		cert.Tags = make(map[string]string)
	}
	if err := s.certRepo.Create(ctx, &cert); err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return &cert, nil
}

// UpdateCertificate modifies a certificate (handler interface method).
func (s *CertificateService) UpdateCertificate(ctx context.Context, id string, patch domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
	// Fetch existing certificate so partial updates don't zero out fields
	existing, err := s.certRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	// Merge non-zero fields from patch into existing
	if patch.Name != "" {
		existing.Name = patch.Name
	}
	if patch.CommonName != "" {
		existing.CommonName = patch.CommonName
	}
	if len(patch.SANs) > 0 {
		existing.SANs = patch.SANs
	}
	if patch.Environment != "" {
		existing.Environment = patch.Environment
	}
	if patch.OwnerID != "" {
		existing.OwnerID = patch.OwnerID
	}
	if patch.TeamID != "" {
		existing.TeamID = patch.TeamID
	}
	if patch.IssuerID != "" {
		existing.IssuerID = patch.IssuerID
	}
	if patch.RenewalPolicyID != "" {
		existing.RenewalPolicyID = patch.RenewalPolicyID
	}
	if patch.CertificateProfileID != "" {
		existing.CertificateProfileID = patch.CertificateProfileID
	}
	if patch.Status != "" {
		existing.Status = patch.Status
	}
	if patch.Tags != nil {
		existing.Tags = patch.Tags
	}

	existing.UpdatedAt = time.Now()

	if err := s.certRepo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}
	return existing, nil
}

// ArchiveCertificate marks a certificate as archived (handler interface method).
func (s *CertificateService) ArchiveCertificate(ctx context.Context, id string) error {
	return s.certRepo.Archive(ctx, id)
}

// GetCertificateVersions returns certificate versions (handler interface method).
func (s *CertificateService) GetCertificateVersions(ctx context.Context, certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	versions, err := s.certRepo.ListVersions(ctx, certID)
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

// RevokeCertificate performs revocation with actor tracking. Delegates to RevocationSvc.
func (s *CertificateService) RevokeCertificate(ctx context.Context, certID string, reason string, actor string) error {
	if s.revSvc == nil {
		return fmt.Errorf("revocation service not configured")
	}
	return s.revSvc.RevokeCertificateWithActor(ctx, certID, reason, actor)
}

// GetRevokedCertificates returns all revoked certificate records (for CRL generation).
// Delegates to RevocationSvc.
func (s *CertificateService) GetRevokedCertificates(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	if s.revSvc == nil {
		return nil, fmt.Errorf("revocation service not configured")
	}
	return s.revSvc.GetRevokedCertificates(ctx)
}

// GenerateDERCRL returns the DER-encoded X.509 CRL for the given
// issuer. When the CRL cache service is wired (SetCRLCacheSvc), reads
// from the scheduler-pre-generated cache and only regenerates on miss
// / staleness — the cache layer's singleflight gate collapses
// concurrent miss requests to a single underlying generation.
//
// When the cache service is not wired, falls back to the historical
// on-demand path via CAOperationsSvc.GenerateDERCRL — every HTTP fetch
// triggers a fresh generation.
//
// Backward-compatible: existing callers that don't wire the cache see
// no behavioural change.
func (s *CertificateService) GenerateDERCRL(ctx context.Context, issuerID string) ([]byte, error) {
	if s.crlCacheSvc != nil {
		der, _, err := s.crlCacheSvc.Get(ctx, issuerID)
		return der, err
	}
	if s.caSvc == nil {
		return nil, fmt.Errorf("CA operations service not configured")
	}
	return s.caSvc.GenerateDERCRL(ctx, issuerID)
}

// GetOCSPResponse generates a signed OCSP response for the given certificate serial.
// Back-compat wrapper around GetOCSPResponseWithNonce; passes nil nonce so the
// response omits the RFC 6960 §4.4.1 nonce extension.
func (s *CertificateService) GetOCSPResponse(ctx context.Context, issuerID string, serialHex string) ([]byte, error) {
	return s.GetOCSPResponseWithNonce(ctx, issuerID, serialHex, nil)
}

// GetOCSPResponseWithNonce generates a signed OCSP response and (when
// nonce != nil) echoes the nonce in the response per RFC 6960 §4.4.1.
// Production hardening II Phase 1.
func (s *CertificateService) GetOCSPResponseWithNonce(ctx context.Context, issuerID string, serialHex string, nonce []byte) ([]byte, error) {
	if s.caSvc == nil {
		return nil, fmt.Errorf("CA operations service not configured")
	}
	return s.caSvc.GetOCSPResponseWithNonce(ctx, issuerID, serialHex, nonce)
}

// GetCertificateDeployments returns all deployment targets for a certificate (M20).
func (s *CertificateService) GetCertificateDeployments(ctx context.Context, certID string) ([]domain.DeploymentTarget, error) {
	// Verify certificate exists
	_, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	if s.targetRepo == nil {
		return []domain.DeploymentTarget{}, nil
	}

	// Get targets from repository
	targets, err := s.targetRepo.ListByCertificate(ctx, certID)
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
