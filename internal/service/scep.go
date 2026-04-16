package service

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// SCEPService implements the SCEP (RFC 8894) enrollment protocol.
// It delegates certificate operations to an existing IssuerConnector and records
// enrollment events in the audit trail.
type SCEPService struct {
	issuer            IssuerConnector
	issuerID          string
	auditService      *AuditService
	logger            *slog.Logger
	profileID         string // optional: constrain enrollments to a specific profile
	profileRepo       repository.CertificateProfileRepository
	challengePassword string // shared secret for enrollment authentication
}

// NewSCEPService creates a new SCEPService for the given issuer connector.
func NewSCEPService(issuerID string, issuer IssuerConnector, auditService *AuditService, logger *slog.Logger, challengePassword string) *SCEPService {
	return &SCEPService{
		issuer:            issuer,
		issuerID:          issuerID,
		auditService:      auditService,
		logger:            logger,
		challengePassword: challengePassword,
	}
}

// SetProfileID constrains SCEP enrollments to a specific certificate profile.
func (s *SCEPService) SetProfileID(profileID string) {
	s.profileID = profileID
}

// SetProfileRepo sets the profile repository for crypto policy enforcement during enrollment.
func (s *SCEPService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// GetCACaps returns the capabilities of this SCEP server.
// RFC 8894 Section 3.5.2: GetCACaps returns a list of capabilities, one per line.
func (s *SCEPService) GetCACaps(ctx context.Context) string {
	return "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\n"
}

// GetCACert returns the PEM-encoded CA certificate chain for this SCEP server.
// RFC 8894 Section 3.5.1: GetCACert distributes the CA certificate(s).
func (s *SCEPService) GetCACert(ctx context.Context) (string, error) {
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates from issuer %s: %w", s.issuerID, err)
	}
	if caPEM == "" {
		return "", fmt.Errorf("issuer %s does not provide CA certificates for SCEP", s.issuerID)
	}
	return caPEM, nil
}

// PKCSReq processes a SCEP enrollment request.
// RFC 8894 Section 3.3.1: PKCSReq contains a PKCS#10 CSR for certificate enrollment.
// The CSR PEM and challenge password are extracted by the handler from the PKCS#7 envelope.
//
// H-2 fix (CWE-306): the previous implementation skipped the shared-secret
// check entirely when s.challengePassword was empty, meaning any unauthenticated
// client that could reach /scep could enroll a CSR against the configured
// issuer. Reject that configuration defense-in-depth even though main() already
// refuses to start in the same state (see preflightSCEPChallengePassword). The
// non-empty branch now uses crypto/subtle.ConstantTimeCompare to avoid leaking
// the shared secret through a response-time side channel.
func (s *SCEPService) PKCSReq(ctx context.Context, csrPEM string, challengePassword string, transactionID string) (*domain.SCEPEnrollResult, error) {
	// Defense-in-depth: refuse any enrollment when no shared secret is
	// configured. The server-level pre-flight check in cmd/server/main.go
	// normally prevents the service from being constructed in this state, but
	// this branch also protects future call sites (tests, library reuse, a
	// future REST-over-HTTPS wrapper) from silently accepting unauthenticated
	// CSRs.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP enrollment rejected: server has no challenge password configured",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("SCEP challenge password not configured on server")
	}
	// Constant-time compare avoids leaking the configured secret through
	// response-time variance. ConstantTimeCompare returns 1 only when both
	// slices have equal length AND equal content; a mismatched-length input
	// still takes the same path as a content mismatch.
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP enrollment rejected: invalid challenge password",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("invalid challenge password")
	}

	return s.processEnrollment(ctx, csrPEM, transactionID, "scep_pkcsreq")
}

// processEnrollment handles the common enrollment logic.
func (s *SCEPService) processEnrollment(ctx context.Context, csrPEM string, transactionID string, auditAction string) (*domain.SCEPEnrollResult, error) {
	// Parse the CSR to extract CN and SANs
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	commonName := csr.Subject.CommonName
	if commonName == "" {
		return nil, fmt.Errorf("CSR must include a Common Name")
	}

	// Collect SANs
	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range csr.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	// Validate CSR key algorithm/size against profile (crypto policy enforcement)
	var profile *domain.CertificateProfile
	var ekus []string
	if s.profileID != "" && s.profileRepo != nil {
		if p, profileErr := s.profileRepo.Get(ctx, s.profileID); profileErr == nil && p != nil {
			profile = p
			ekus = profile.AllowedEKUs
		}
	}
	if _, csrErr := ValidateCSRAgainstProfile(csrPEM, profile); csrErr != nil {
		s.logger.Error("SCEP enrollment rejected: crypto policy violation",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", csrErr)
		return nil, fmt.Errorf("SCEP enrollment rejected: %w", csrErr)
	}

	s.logger.Info("SCEP enrollment request",
		"action", auditAction,
		"common_name", commonName,
		"sans", strings.Join(sans, ","),
		"transaction_id", transactionID,
		"issuer", s.issuerID)

	// Resolve MaxTTL from profile
	var maxTTLSeconds int
	if profile != nil {
		maxTTLSeconds = profile.MaxTTLSeconds
	}

	// Issue the certificate via the configured issuer connector
	// SCEP enrollments use profile EKUs if available, otherwise default (serverAuth + clientAuth fallback)
	result, err := s.issuer.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds)
	if err != nil {
		s.logger.Error("SCEP enrollment failed",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", err)
		return nil, fmt.Errorf("certificate issuance failed: %w", err)
	}

	// Audit the enrollment
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name":    commonName,
			"sans":           sans,
			"issuer_id":      s.issuerID,
			"serial":         result.Serial,
			"transaction_id": transactionID,
			"protocol":       "SCEP",
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "scep-client", "system", auditAction, "certificate", result.Serial, details)
	}

	s.logger.Info("SCEP enrollment successful",
		"action", auditAction,
		"common_name", commonName,
		"serial", result.Serial,
		"transaction_id", transactionID,
		"not_after", result.NotAfter)

	return &domain.SCEPEnrollResult{
		CertPEM:  result.CertPEM,
		ChainPEM: result.ChainPEM,
	}, nil
}
