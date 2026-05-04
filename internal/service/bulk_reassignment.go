package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// ErrBulkReassignOwnerNotFound is the typed sentinel for a non-existent
// target OwnerID. The handler maps it to 400 (bad input — the operator
// picked an owner that doesn't exist) rather than 500 (server error).
// Sentinel-error rather than substring-error matches the project's
// post-M-1 error-mapping convention.
var ErrBulkReassignOwnerNotFound = errors.New("owner not found")

// BulkReassignmentService coordinates bulk owner-reassignment of
// certificates.
//
// L-2 closure (cat-l-8a1fb258a38a): the GUI used to loop
// `await updateCertificate(id, { owner_id })` over the selection at
// `web/src/pages/CertificatesPage.tsx::handleReassign`. Post-L-2 the
// GUI POSTs once. Narrower than BulkRenewal: explicit IDs only, no
// criteria-mode (criteria-mode reassignment doesn't have a strong use
// case — operators query first then reassign by ID).
//
// Validation order: empty IDs → 400, missing OwnerID → 400, OwnerID
// not in owners table → 400 (ErrBulkReassignOwnerNotFound). Resolving
// the owner upfront means we fail-fast without mutating any cert if
// the operator typo'd the owner ID.
type BulkReassignmentService struct {
	certRepo     repository.CertificateRepository
	ownerRepo    repository.OwnerRepository
	auditService *AuditService
	logger       *slog.Logger
}

// NewBulkReassignmentService creates a new BulkReassignmentService.
func NewBulkReassignmentService(
	certRepo repository.CertificateRepository,
	ownerRepo repository.OwnerRepository,
	auditService *AuditService,
	logger *slog.Logger,
) *BulkReassignmentService {
	return &BulkReassignmentService{
		certRepo:     certRepo,
		ownerRepo:    ownerRepo,
		auditService: auditService,
		logger:       logger,
	}
}

// BulkReassign updates owner_id (and optionally team_id) on every cert
// in request.CertificateIDs. Skips certs whose owner_id already equals
// the target (silent no-op — surfaced as TotalSkipped++, not as a fake
// "succeeded" count, so operators see "5 of your 10 selections were
// no-ops because Alice already owned them" without triaging fake
// errors).
//
// Partial failures don't abort the batch — the failing cert lands in
// Errors[]; the loop continues. Mirrors BulkRevocationService and
// BulkRenewalService partial-failure semantics.
//
// Audit: a single audit event is emitted at the end with the criteria
// + counts. NOT N events.
func (s *BulkReassignmentService) BulkReassign(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
	if request.IsEmpty() {
		return nil, fmt.Errorf("at least one certificate_id is required")
	}
	if request.OwnerID == "" {
		return nil, fmt.Errorf("owner_id is required")
	}

	// Validate the target owner exists BEFORE touching any cert. This
	// fail-fast pattern means an operator who typo'd 'o-alic' (missing
	// 'e') doesn't half-reassign 50 certs before the 51st surfaces the
	// FK violation.
	if _, err := s.ownerRepo.Get(ctx, request.OwnerID); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBulkReassignOwnerNotFound, request.OwnerID)
	}

	result := &domain.BulkReassignmentResult{}

	for _, id := range request.CertificateIDs {
		cert, err := s.certRepo.Get(ctx, id)
		if err != nil {
			result.TotalFailed++
			result.Errors = append(result.Errors, domain.BulkOperationError{
				CertificateID: id,
				Error:         fmt.Sprintf("failed to fetch certificate: %v", err),
			})
			continue
		}
		result.TotalMatched++

		// No-op skip: cert already owned by the target. team_id may
		// still differ — we still skip if owner matches AND
		// team_id-update is a no-op (team unchanged or team_id field
		// not set on the request). This prevents fake "reassigned"
		// counts when nothing actually changed.
		ownerUnchanged := cert.OwnerID == request.OwnerID
		teamUnchanged := request.TeamID == "" || cert.TeamID == request.TeamID
		if ownerUnchanged && teamUnchanged {
			result.TotalSkipped++
			continue
		}

		cert.OwnerID = request.OwnerID
		if request.TeamID != "" {
			cert.TeamID = request.TeamID
		}
		if err := s.certRepo.Update(ctx, cert); err != nil {
			result.TotalFailed++
			result.Errors = append(result.Errors, domain.BulkOperationError{
				CertificateID: id,
				Error:         fmt.Sprintf("failed to update certificate: %v", err),
			})
			s.logger.Warn("bulk reassignment: update failed",
				"certificate_id", id, "error", err)
			continue
		}
		result.TotalReassigned++
	}

	// Single bulk audit event at the end.
	auditDetails := map[string]interface{}{
		"owner_id":         request.OwnerID,
		"certificate_ids":  strings.Join(request.CertificateIDs, ","),
		"total_matched":    result.TotalMatched,
		"total_reassigned": result.TotalReassigned,
		"total_skipped":    result.TotalSkipped,
		"total_failed":     result.TotalFailed,
	}
	if request.TeamID != "" {
		auditDetails["team_id"] = request.TeamID
	}
	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"bulk_reassignment_initiated", "certificate", "bulk",
		auditDetails); err != nil {
		s.logger.Error("failed to record bulk reassignment audit event", "error", err)
	}

	return result, nil
}
