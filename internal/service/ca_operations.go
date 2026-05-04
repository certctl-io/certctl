package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// CAOperationsSvc provides CA operations: CRL generation and OCSP response signing.
// This service handles revocation status queries and certificate lifecycle operations
// related to the certificate authority.
type CAOperationsSvc struct {
	revocationRepo repository.RevocationRepository
	certRepo       repository.CertificateRepository
	profileRepo    repository.CertificateProfileRepository
	issuerRegistry *IssuerRegistry
	// ocspCacheSvc — production hardening II Phase 2 read-through
	// cache. When set, GetOCSPResponseWithNonce serves nil-nonce
	// requests from the cache; nonce-bearing requests always go
	// through the live signing path (the cached blob is signed with
	// nil nonce, so a request that wants a nonce echo can't use it).
	// Use SetOCSPCacheSvc to wire.
	ocspCacheSvc OCSPResponseCacher
}

// OCSPResponseCacher is the minimum surface CAOperationsSvc consumes
// from the OCSP response cache. The cache service implements this
// interface; the indirection lets tests inject a fake cacher and
// avoids a service→service hard dep on the cache type.
type OCSPResponseCacher interface {
	Get(ctx context.Context, issuerID, serialHex string) ([]byte, error)
	InvalidateOnRevoke(ctx context.Context, issuerID, serialHex string) error
}

// SetOCSPCacheSvc wires the OCSP response cache. When set, nil-nonce
// requests through GetOCSPResponseWithNonce serve from the cache;
// nonce-bearing requests bypass.
func (s *CAOperationsSvc) SetOCSPCacheSvc(c OCSPResponseCacher) {
	s.ocspCacheSvc = c
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

	// Scope the query to this issuer so the migration 000012 composite index
	// drives a prefix scan; previously this path read every revocation in the
	// table and filtered in Go, which did not scale as the revocation table
	// grew across many issuers (F-001).
	revocations, err := s.revocationRepo.ListByIssuer(ctx, issuerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list revocations for issuer %s: %w", issuerID, err)
	}

	// Convert revocations to CRL entries. Short-lived certificates (profile
	// TTL < 1 hour) are excluded — expiry is sufficient revocation.
	var entries []CRLEntry
	for _, rev := range revocations {
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
// Back-compat wrapper around GetOCSPResponseWithNonce: passes nil nonce,
// which produces a response without the RFC 6960 §4.4.1 nonce extension.
// Older callers that don't carry a nonce see no behavior change.
func (s *CAOperationsSvc) GetOCSPResponse(ctx context.Context, issuerID string, serialHex string) ([]byte, error) {
	return s.GetOCSPResponseWithNonce(ctx, issuerID, serialHex, nil)
}

// GetOCSPResponseWithNonce returns a signed OCSP response for the
// given certificate serial. When nonce is non-nil, the responder
// echoes it in the response per RFC 6960 §4.4.1; nil nonce omits the
// extension (back-compat).
//
// Dispatch: nil-nonce requests served from the OCSP response cache
// when wired (production hardening II Phase 2); nonce-bearing
// requests always live-sign because the cache stores nil-nonce blobs
// and re-signing to add the nonce defeats the point of caching.
//
// Production hardening II Phase 1 (nonce) + Phase 2 (cache dispatch).
func (s *CAOperationsSvc) GetOCSPResponseWithNonce(ctx context.Context, issuerID string, serialHex string, nonce []byte) ([]byte, error) {
	if s.ocspCacheSvc != nil && len(nonce) == 0 {
		// Cache wired and request has no nonce → read-through cache.
		// On cache miss the cache service calls back into
		// LiveSignOCSPResponse(nil) and writes the result back.
		return s.ocspCacheSvc.Get(ctx, issuerID, serialHex)
	}
	return s.LiveSignOCSPResponse(ctx, issuerID, serialHex, nonce)
}

// LiveSignOCSPResponse is the unconditional signing path: it consults
// the revocation repo, decides good/revoked/unknown, and signs via
// the issuer connector. Bypasses the OCSP response cache.
//
// Used by:
//   - GetOCSPResponseWithNonce when nonce != nil OR cache not wired.
//   - OCSPResponseCacheService.Get on cache miss (the read-through
//     fallback that produces the blob to write back to cache).
//
// Exported because the cache service needs to call it without
// re-entering the cache; ordinary handler callers should still go
// through GetOCSPResponseWithNonce.
//
// Production hardening II Phase 2.
func (s *CAOperationsSvc) LiveSignOCSPResponse(ctx context.Context, issuerID string, serialHex string, nonce []byte) ([]byte, error) {
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
						Nonce:      nonce,
					})
				}
			}
		}
	}

	// Check if this (issuer_id, serial) is revoked — RFC 5280 §5.2.3 scoping.
	rev, err := s.revocationRepo.GetByIssuerAndSerial(ctx, issuerID, serialHex)
	if err == nil && rev != nil {
		// Revoked
		return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
			CertSerial:       serial,
			CertStatus:       1, // revoked
			RevokedAt:        rev.RevokedAt,
			RevocationReason: domain.CRLReasonCode(domain.RevocationReason(rev.Reason)),
			ThisUpdate:       now,
			NextUpdate:       now.Add(1 * time.Hour),
			Nonce:            nonce,
		})
	}

	// Not revoked. Per RFC 6960 §2.2, we must only return "good" for a
	// certificate that was actually issued by this CA. Verify the
	// (issuer_id, serial) tuple maps to a real certificate in inventory
	// before asserting "good"; otherwise return "unknown". This closes the
	// coverage gap where forged/guessed serials would be accepted as valid
	// because they had no revocation row (M-004).
	if s.certRepo != nil {
		cert, certErr := s.certRepo.GetByIssuerAndSerial(ctx, issuerID, serialHex)
		if certErr != nil || cert == nil {
			if certErr != nil && !errors.Is(certErr, sql.ErrNoRows) {
				// Real repository failure — log but still fail closed with "unknown"
				// rather than leaking a bogus "good" assertion.
				slog.Warn("OCSP cert lookup failed; returning unknown",
					"issuer_id", issuerID,
					"serial", serialHex,
					"error", certErr)
			}
			return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
				CertSerial: serial,
				CertStatus: 2, // unknown
				ThisUpdate: now,
				NextUpdate: now.Add(1 * time.Hour),
				Nonce:      nonce,
			})
		}
	}

	// Known cert, not revoked — return "good"
	return issuerConn.SignOCSPResponse(ctx, OCSPSignRequest{
		CertSerial: serial,
		CertStatus: 0, // good
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
		Nonce:      nonce,
	})
}
