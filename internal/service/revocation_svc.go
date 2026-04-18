package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// RevocationSvc provides revocation-related business logic.
// It handles certificate revocation, revocation notifications, and issuer coordination.
type RevocationSvc struct {
	certRepo         repository.CertificateRepository
	revocationRepo   repository.RevocationRepository
	auditService     *AuditService
	notificationSvc  *NotificationService
	issuerRegistry   *IssuerRegistry
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
func (s *RevocationSvc) GetRevokedCertificates(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	return s.revocationRepo.ListAll(ctx)
}
