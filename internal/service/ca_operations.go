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

// CAOperationsSvc provides CA operations: CRL generation and OCSP response signing.
// This service handles revocation status queries and certificate lifecycle operations
// related to the certificate authority.
type CAOperationsSvc struct {
	revocationRepo repository.RevocationRepository
	certRepo       repository.CertificateRepository
	profileRepo    repository.CertificateProfileRepository
	issuerRegistry *IssuerRegistry
}

// NewCAOperationsSvc creates a new CA operations service.
func NewCAOperationsSvc(
	revocationRepo repository.RevocationRepository,
	certRepo repository.CertificateRepository,
	profileRepo repository.CertificateProfileRepository,
) *CAOperationsSvc {
	return &CAOperationsSvc{
		revocationRepo: revocationRepo,
		certRepo:       certRepo,
		profileRepo:    profileRepo,
	}
}

// SetIssuerRegistry sets the issuer registry for CRL and OCSP operations.
func (s *CAOperationsSvc) SetIssuerRegistry(registry *IssuerRegistry) {
	s.issuerRegistry = registry
}

// GenerateDERCRL generates a DER-encoded X.509 CRL for the given issuer.
// Short-lived certificates (profile TTL < 1 hour) are excluded from the CRL.
func (s *CAOperationsSvc) GenerateDERCRL(ctx context.Context, issuerID string) ([]byte, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	if s.issuerRegistry == nil {
		return nil, fmt.Errorf("issuer registry not configured")
	}

	issuerConn, ok := s.issuerRegistry.Get(issuerID)
	if !ok {
		return nil, fmt.Errorf("issuer not found: %s", issuerID)
	}

	revocations, err := s.revocationRepo.ListAll(ctx)
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
			cert, err := s.certRepo.Get(ctx, rev.CertificateID)
			if err == nil && cert.CertificateProfileID != "" {
				profile, err := s.profileRepo.Get(ctx, cert.CertificateProfileID)
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

	return issuerConn.GenerateCRL(ctx, entries)
}

// GetOCSPResponse generates a signed OCSP response for the given certificate serial.
func (s *CAOperationsSvc) GetOCSPResponse(ctx context.Context, issuerID string, serialHex string) ([]byte, error) {
	if s.revocationRepo == nil {
		return nil, fmt.Errorf("revocation repository not configured")
	}
	if s.issuerRegistry == nil {
		return nil, fmt.Errorf("issuer registry not configured")
	}

	issuerConn, ok := s.issuerRegistry.Get(issuerID)
	if !ok {
		return nil, fmt.Errorf("issuer not found: %s", issuerID)
	}

	serial := new(big.Int)
	serial.SetString(serialHex, 16)

	now := time.Now()

	// Short-lived cert exemption: if the cert's profile has TTL < 1 hour,
	// always return "good" — expiry is sufficient revocation for short-lived certs.
	if s.profileRepo != nil && s.certRepo != nil {
		// Look up cert by (issuer_id, serial) — per RFC 5280 §5.2.3, serial numbers
		// are unique only within a single issuer. The OCSP URL path carries issuer_id,
		// so we scope the lookup to avoid cross-issuer collisions.
		rev, _ := s.revocationRepo.GetByIssuerAndSerial(ctx, issuerID, serialHex)
		if rev != nil {
			cert, err := s.certRepo.Get(ctx, rev.CertificateID)
			if err == nil && cert.CertificateProfileID != "" {
				profile, err := s.profileRepo.Get(ctx, cert.CertificateProfileID)
				if err == nil && profile.IsShortLived() {
					return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
						CertSerial: serial,
						CertStatus: 0, // good — short-lived exemption
						ThisUpdate: now,
						NextUpdate: now.Add(1 * time.Hour),
					})
				}
			}
		}
	}

	// Check if this (issuer_id, serial) is revoked — RFC 5280 §5.2.3 scoping.
	rev, err := s.revocationRepo.GetByIssuerAndSerial(ctx, issuerID, serialHex)
	if err != nil {
		// Not revoked — return "good" status
		return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
			CertSerial: serial,
			CertStatus: 0, // good
			ThisUpdate: now,
			NextUpdate: now.Add(1 * time.Hour),
		})
	}

	// Revoked
	return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
		CertSerial:       serial,
		CertStatus:       1, // revoked
		RevokedAt:        rev.RevokedAt,
		RevocationReason: domain.CRLReasonCode(domain.RevocationReason(rev.Reason)),
		ThisUpdate:       now,
		NextUpdate:       now.Add(1 * time.Hour),
	})
}
