package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// RevocationSvc provides revocation-related business logic.
// It handles certificate revocation, revocation notifications, and issuer coordination.
type RevocationSvc struct {
	certRepo        repository.CertificateRepository
	revocationRepo  repository.RevocationRepository
	auditService    *AuditService
	notificationSvc *NotificationService
	issuerRegistry  *IssuerRegistry
	// tx — when set, wraps the cert status update + revocation row
	// insert + audit row in a single transaction. Closes the #3 audit-
	// readiness blocker for the revocation path. Optional via
	// SetTransactor; nil means legacy non-transactional behavior
	// (cert.Update committed independently from revocation row +
	// audit, with revocation insert + audit logged-but-not-failed).
	tx repository.Transactor
	// ocspCacheInvalidator — production hardening II Phase 2 load-
	// bearing security wire. After a successful revocation, the
	// service MUST invalidate the OCSP response cache for this
	// (issuer, serial) so the next OCSP fetch returns the revoked
	// status (not the stale "good" cached blob).
	ocspCacheInvalidator OCSPCacheInvalidator
}

// SetTransactor wires a Transactor for atomic revocation (cert update
// + revocation row + audit row in a single transaction). Closes the
// #3 audit-readiness blocker for the revocation path. Optional —
// nil reverts to the legacy non-transactional behavior.
func (s *RevocationSvc) SetTransactor(tx repository.Transactor) {
	s.tx = tx
}

// OCSPCacheInvalidator is the minimum surface RevocationSvc needs
// from the OCSP cache. The cache service implements this interface;
// the indirection keeps RevocationSvc from depending on the cache
// type and lets tests inject a fake invalidator.
type OCSPCacheInvalidator interface {
	InvalidateOnRevoke(ctx context.Context, issuerID, serialHex string) error
}

// SetOCSPCacheInvalidator wires the OCSP cache for invalidate-on-
// revoke. Production hardening II Phase 2.
func (s *RevocationSvc) SetOCSPCacheInvalidator(c OCSPCacheInvalidator) {
	s.ocspCacheInvalidator = c
}

// NewRevocationSvc creates a new revocation service.
func NewRevocationSvc(
	certRepo repository.CertificateRepository,
	revocationRepo repository.RevocationRepository,
	auditService *AuditService,
) *RevocationSvc {
	return &RevocationSvc{
		certRepo:       certRepo,
		revocationRepo: revocationRepo,
		auditService:   auditService,
	}
}

// SetNotificationService sets the notification service for revocation alerts.
func (s *RevocationSvc) SetNotificationService(svc *NotificationService) {
	s.notificationSvc = svc
}

// SetIssuerRegistry sets the issuer registry for issuer-level revocation.
func (s *RevocationSvc) SetIssuerRegistry(registry *IssuerRegistry) {
	s.issuerRegistry = registry
}

// RevokeCertificateWithActor performs revocation with actor tracking.
// Steps:
// 1. Validate the certificate exists and is revocable
// 2. Get the latest certificate version (for serial number)
// 3. Update certificate status to Revoked
// 4. Record revocation in certificate_revocations table
// 5. Notify the issuer connector (best-effort)
// 6. Record audit event
// 7. Send revocation notification
func (s *RevocationSvc) RevokeCertificateWithActor(ctx context.Context, certID string, reason string, actor string) error {
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

	// 3. + 4. + audit: cert status update + revocation row + audit row.
	// Atomic path (when SetTransactor was wired) keeps these three
	// writes consistent: a failure in any one rolls back the others.
	// Closes the #3 audit-readiness blocker for the revocation path.
	now := time.Now()
	cert.Status = domain.CertificateStatusRevoked
	cert.RevokedAt = &now
	cert.RevocationReason = reason
	cert.UpdatedAt = now

	auditDetails := map[string]interface{}{
		"common_name": cert.CommonName,
		"serial":      version.SerialNumber,
		"reason":      reason,
	}

	if s.tx != nil {
		// Atomic three-write path.
		if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
			if err := s.certRepo.UpdateWithTx(ctx, q, cert); err != nil {
				return fmt.Errorf("failed to update certificate status: %w", err)
			}
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
				if err := s.revocationRepo.CreateWithTx(ctx, q, revocation); err != nil {
					return fmt.Errorf("failed to record revocation: %w", err)
				}
			}
			if err := s.auditService.RecordEventWithTx(ctx, q, actor, domain.ActorTypeUser,
				"certificate_revoked", "certificate", certID, auditDetails); err != nil {
				return fmt.Errorf("failed to record audit event: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	} else {
		// Legacy non-transactional path. Pre-fix behavior preserved
		// for backward compat with callers that haven't wired
		// SetTransactor.
		if err := s.certRepo.Update(ctx, cert); err != nil {
			return fmt.Errorf("failed to update certificate status: %w", err)
		}
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
	}

	// 5. Notify the issuer connector (best-effort)
	if s.issuerRegistry != nil {
		if issuerConn, ok := s.issuerRegistry.Get(cert.IssuerID); ok {
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

	// 5.5. Invalidate the OCSP response cache for this (issuer, serial)
	// so the next OCSP fetch returns the revoked status (not the stale
	// "good" cached blob). Production hardening II Phase 2 LOAD-BEARING
	// security wire — without this, a revoked cert keeps returning
	// "good" until the next ocspCacheRefreshLoop tick.
	//
	// Failure is logged and swallowed: the revocation row is committed,
	// the CRL will reflect the revocation on the next regen, and the
	// admin can manually nuke the cache row if necessary. Failing the
	// caller's revoke on cache-failure would leave the operator's
	// intent unachieved (cert appears not-revoked); failing-soft +
	// logging is the right tradeoff.
	if s.ocspCacheInvalidator != nil {
		if err := s.ocspCacheInvalidator.InvalidateOnRevoke(ctx, cert.IssuerID, version.SerialNumber); err != nil {
			slog.Warn("failed to invalidate OCSP response cache after revocation (revocation still committed)",
				"error", err,
				"issuer_id", cert.IssuerID,
				"serial", version.SerialNumber,
				"certificate_id", certID)
		}
	}

	// 6. Record audit event (legacy non-transactional path only — the
	// atomic path already recorded the audit inside the tx above).
	if s.tx == nil {
		if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
			"certificate_revoked", "certificate", certID, auditDetails); err != nil {
			slog.Error("failed to record audit event", "error", err)
		}
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
func (s *RevocationSvc) GetRevokedCertificates(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	return s.revocationRepo.ListAll(ctx)
}
