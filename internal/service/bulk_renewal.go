package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// BulkRenewalService coordinates bulk certificate renewal operations.
// Mirrors BulkRevocationService in shape: resolve criteria → status filter →
// per-cert action loop → aggregate result + emit one bulk audit event.
//
// L-1 master closure (cat-l-fa0c1ac07ab5): the GUI used to loop
// `await triggerRenewal(id)` over the selection at
// `web/src/pages/CertificatesPage.tsx::handleBulkRenewal` (~line 411).
// 100 certs = 100 sequential HTTP round-trips. Post-L-1 the GUI POSTs
// once; this service does the loop server-side and returns a single
// envelope with per-cert {certificate_id, job_id} pairs in
// EnqueuedJobs and per-cert errors in Errors.
//
// Action verb is sync-enqueue (not sync-issue): for each matched cert
// flip status to RenewalInProgress and create a Job row. The
// scheduler's job processor picks up the jobs asynchronously. Sync-
// issue would block the HTTP request for minutes against a slow ACME
// issuer, which defeats the bulk-endpoint latency improvement.
type BulkRenewalService struct {
	certRepo     repository.CertificateRepository
	jobRepo      repository.JobRepository
	auditService *AuditService
	logger       *slog.Logger
	keygenMode   string
}

// NewBulkRenewalService creates a new BulkRenewalService.
//
// keygenMode mirrors CertificateService.keygenMode — agent-mode jobs
// start as AwaitingCSR (the agent generates the key + submits a CSR);
// server-mode jobs start as Pending. The bulk path must produce jobs in
// the SAME initial status the single-cert path does, otherwise the
// scheduler routes them differently.
func NewBulkRenewalService(
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	auditService *AuditService,
	logger *slog.Logger,
	keygenMode string,
) *BulkRenewalService {
	return &BulkRenewalService{
		certRepo:     certRepo,
		jobRepo:      jobRepo,
		auditService: auditService,
		logger:       logger,
		keygenMode:   keygenMode,
	}
}

// BulkRenew enqueues a renewal job for every certificate matching the
// criteria (or in the explicit IDs list). Status filter:
//   - Archived / Expired / Revoked → silent skip (TotalSkipped++)
//   - RenewalInProgress → silent skip (avoid double-enqueue)
//   - everything else → flip to RenewalInProgress + create job
//
// Partial failures don't abort the batch — the failing cert lands in
// Errors[] with the error string, and the loop continues. Mirrors
// BulkRevocationService.BulkRevoke's partial-failure semantics.
//
// Audit: a single audit event is emitted at the end with the criteria
// + counts (NOT N events). The single-cert TriggerRenewal path emits
// per-cert audit events; the bulk path uses one bulk envelope to keep
// audit_events from growing 100x for one operator click.
func (s *BulkRenewalService) BulkRenew(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
	if criteria.IsEmpty() {
		return nil, fmt.Errorf("at least one filter criterion is required")
	}

	certs, err := s.resolveCertificates(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve certificates: %w", err)
	}

	result := &domain.BulkRenewalResult{
		TotalMatched: len(certs),
	}

	for _, cert := range certs {
		// Status-filter the cert before mutating. Mirrors the
		// eligibility checks in CertificateService.TriggerRenewal so a
		// bulk caller can't bypass them. Each illegal status maps to a
		// silent TotalSkipped++ rather than an Error so the operator
		// sees "5 of your 10 selections were no-ops" without triaging
		// fake errors.
		if cert.Status == domain.CertificateStatusArchived ||
			cert.Status == domain.CertificateStatusRevoked ||
			cert.Status == domain.CertificateStatusExpired ||
			cert.Status == domain.CertificateStatusRenewalInProgress {
			result.TotalSkipped++
			continue
		}

		// Flip status + create job. Bug-for-bug match with
		// CertificateService.TriggerRenewal so the scheduler routing
		// stays identical between the single-cert and bulk paths.
		cert.Status = domain.CertificateStatusRenewalInProgress
		if err := s.certRepo.Update(ctx, cert); err != nil {
			result.TotalFailed++
			result.Errors = append(result.Errors, domain.BulkOperationError{
				CertificateID: cert.ID,
				Error:         fmt.Sprintf("failed to update certificate status: %v", err),
			})
			s.logger.Warn("bulk renewal: status update failed",
				"certificate_id", cert.ID, "error", err)
			continue
		}

		jobStatus := domain.JobStatusPending
		if s.keygenMode == "agent" {
			jobStatus = domain.JobStatusAwaitingCSR
		}
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
			result.TotalFailed++
			result.Errors = append(result.Errors, domain.BulkOperationError{
				CertificateID: cert.ID,
				Error:         fmt.Sprintf("failed to create renewal job: %v", err),
			})
			s.logger.Warn("bulk renewal: job creation failed",
				"certificate_id", cert.ID, "error", err)
			continue
		}

		result.TotalEnqueued++
		result.EnqueuedJobs = append(result.EnqueuedJobs, domain.BulkEnqueuedJob{
			CertificateID: cert.ID,
			JobID:         job.ID,
		})
	}

	// Single bulk audit event at the end. Mirrors
	// BulkRevocationService.BulkRevoke shape so the audit dashboard's
	// rendering of bulk events is uniform across {revoke, renew, reassign}.
	criteriaDetails := s.buildAuditDetails(criteria)
	criteriaDetails["total_matched"] = result.TotalMatched
	criteriaDetails["total_enqueued"] = result.TotalEnqueued
	criteriaDetails["total_skipped"] = result.TotalSkipped
	criteriaDetails["total_failed"] = result.TotalFailed
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"bulk_renewal_initiated", "certificate", "bulk",
		criteriaDetails); err != nil {
		s.logger.Error("failed to record bulk renewal audit event", "error", err)
	}

	return result, nil
}

// resolveCertificates fetches the set of certificates matching the bulk
// renewal criteria. Mirrors BulkRevocationService.resolveCertificates
// behaviour exactly: explicit IDs alone → fetch each by ID; filter
// criteria → repo.List with high per_page; both → intersect.
func (s *BulkRenewalService) resolveCertificates(ctx context.Context, criteria domain.BulkRenewalCriteria) ([]*domain.ManagedCertificate, error) {
	hasFilterCriteria := criteria.ProfileID != "" || criteria.OwnerID != "" ||
		criteria.AgentID != "" || criteria.IssuerID != "" || criteria.TeamID != ""
	hasExplicitIDs := len(criteria.CertificateIDs) > 0

	if hasExplicitIDs && !hasFilterCriteria {
		var certs []*domain.ManagedCertificate
		for _, id := range criteria.CertificateIDs {
			cert, err := s.certRepo.Get(ctx, id)
			if err != nil {
				continue // not-found certs silently drop out of the matched set
			}
			certs = append(certs, cert)
		}
		return certs, nil
	}

	filter := &repository.CertificateFilter{
		OwnerID:   criteria.OwnerID,
		TeamID:    criteria.TeamID,
		IssuerID:  criteria.IssuerID,
		AgentID:   criteria.AgentID,
		ProfileID: criteria.ProfileID,
		PerPage:   10000,
	}
	certs, _, err := s.certRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}
	if hasExplicitIDs {
		idSet := make(map[string]bool, len(criteria.CertificateIDs))
		for _, id := range criteria.CertificateIDs {
			idSet[id] = true
		}
		var filtered []*domain.ManagedCertificate
		for _, cert := range certs {
			if idSet[cert.ID] {
				filtered = append(filtered, cert)
			}
		}
		return filtered, nil
	}
	return certs, nil
}

// buildAuditDetails constructs a map of criteria fields for the audit
// event. Mirrors BulkRevocationService.buildAuditDetails so the audit
// dashboard renders bulk events uniformly.
func (s *BulkRenewalService) buildAuditDetails(criteria domain.BulkRenewalCriteria) map[string]interface{} {
	details := map[string]interface{}{}
	if criteria.ProfileID != "" {
		details["profile_id"] = criteria.ProfileID
	}
	if criteria.OwnerID != "" {
		details["owner_id"] = criteria.OwnerID
	}
	if criteria.AgentID != "" {
		details["agent_id"] = criteria.AgentID
	}
	if criteria.IssuerID != "" {
		details["issuer_id"] = criteria.IssuerID
	}
	if criteria.TeamID != "" {
		details["team_id"] = criteria.TeamID
	}
	if len(criteria.CertificateIDs) > 0 {
		details["certificate_ids"] = strings.Join(criteria.CertificateIDs, ",")
	}
	return details
}
