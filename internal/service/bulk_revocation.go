package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// BulkRevocationService coordinates bulk certificate revocation operations.
// It builds on the single-cert RevokeCertificateWithActor flow — no duplicate logic.
type BulkRevocationService struct {
	revSvc       *RevocationSvc
	certRepo     repository.CertificateRepository
	auditService *AuditService
	logger       *slog.Logger
}

// NewBulkRevocationService creates a new BulkRevocationService.
func NewBulkRevocationService(
	revSvc *RevocationSvc,
	certRepo repository.CertificateRepository,
	auditService *AuditService,
	logger *slog.Logger,
) *BulkRevocationService {
	return &BulkRevocationService{
		revSvc:       revSvc,
		certRepo:     certRepo,
		auditService: auditService,
		logger:       logger,
	}
}

// BulkRevoke revokes all certificates matching the given criteria.
// It reuses RevokeCertificateWithActor for each cert — partial failures don't abort the batch.
func (s *BulkRevocationService) BulkRevoke(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
	// Validate inputs
	if criteria.IsEmpty() {
		return nil, fmt.Errorf("at least one filter criterion is required")
	}
	if reason == "" {
		return nil, fmt.Errorf("revocation reason is required")
	}
	if !domain.IsValidRevocationReason(reason) {
		return nil, fmt.Errorf("invalid revocation reason: %s", reason)
	}

	// Resolve matching certificates
	certs, err := s.resolveCertificates(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve certificates: %w", err)
	}

	result := &domain.BulkRevocationResult{
		TotalMatched: len(certs),
	}

	// Revoke each certificate, continuing on individual failures
	for _, cert := range certs {
		// Skip already-revoked or archived certs
		if cert.Status == domain.CertificateStatusRevoked {
			result.TotalSkipped++
			continue
		}
		if cert.Status == domain.CertificateStatusArchived {
			result.TotalSkipped++
			continue
		}

		err := s.revSvc.RevokeCertificateWithActor(ctx, cert.ID, reason, actor)
		if err != nil {
			result.TotalFailed++
			result.Errors = append(result.Errors, domain.BulkRevocationError{
				CertificateID: cert.ID,
				Error:         err.Error(),
			})
			s.logger.Warn("bulk revocation: individual cert failed",
				"certificate_id", cert.ID,
				"error", err)
		} else {
			result.TotalRevoked++
		}
	}

	// Record audit event for the bulk operation
	criteriaDetails := s.buildAuditDetails(criteria)
	criteriaDetails["reason"] = reason
	criteriaDetails["total_matched"] = result.TotalMatched
	criteriaDetails["total_revoked"] = result.TotalRevoked
	criteriaDetails["total_skipped"] = result.TotalSkipped
	criteriaDetails["total_failed"] = result.TotalFailed
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"bulk_revocation_initiated", "certificate", "bulk",
		criteriaDetails); err != nil {
		s.logger.Error("failed to record bulk revocation audit event", "error", err)
	}

	return result, nil
}

// resolveCertificates fetches the set of certificates matching the bulk revocation criteria.
// When CertificateIDs are provided, it fetches each cert by ID individually.
// When filter criteria (profile, owner, etc.) are provided, it uses the repository List method.
// When both are provided, it intersects: only IDs that also match the filter criteria.
func (s *BulkRevocationService) resolveCertificates(ctx context.Context, criteria domain.BulkRevocationCriteria) ([]*domain.ManagedCertificate, error) {
	hasFilterCriteria := criteria.ProfileID != "" || criteria.OwnerID != "" ||
		criteria.AgentID != "" || criteria.IssuerID != "" || criteria.TeamID != ""
	hasExplicitIDs := len(criteria.CertificateIDs) > 0

	if hasExplicitIDs && !hasFilterCriteria {
		// Only explicit IDs — fetch each cert by ID
		var certs []*domain.ManagedCertificate
		for _, id := range criteria.CertificateIDs {
			cert, err := s.certRepo.Get(ctx, id)
			if err != nil {
				// Skip not-found certs — they'll count as "matched" but skipped
				continue
			}
			certs = append(certs, cert)
		}
		return certs, nil
	}

	// Use filter-based query
	filter := &repository.CertificateFilter{
		OwnerID:   criteria.OwnerID,
		TeamID:    criteria.TeamID,
		IssuerID:  criteria.IssuerID,
		AgentID:   criteria.AgentID,
		ProfileID: criteria.ProfileID,
		PerPage:   10000, // High limit to get all matching certs in one query
	}

	certs, _, err := s.certRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// If explicit IDs also provided, intersect
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
		certs = filtered
	}

	// EST RFC 7030 hardening master bundle Phase 11.2: per-source
	// post-filter. Empty Source matches anything (back-compat); a
	// non-empty Source narrows the result set to only certs stamped
	// with that provenance value. Filter is applied here rather than
	// in the SQL query so existing CertificateFilter callers are
	// unaffected; the small per-cert pass is fine because bulk-revoke
	// is already a low-frequency operation.
	if criteria.Source != "" {
		var bySource []*domain.ManagedCertificate
		for _, cert := range certs {
			if cert.Source == criteria.Source {
				bySource = append(bySource, cert)
			}
		}
		certs = bySource
	}

	return certs, nil
}

// buildAuditDetails constructs a map of criteria fields for the audit event.
func (s *BulkRevocationService) buildAuditDetails(criteria domain.BulkRevocationCriteria) map[string]interface{} {
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
