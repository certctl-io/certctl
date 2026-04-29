package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ESTService implements the EST (RFC 7030) enrollment protocol.
// It delegates certificate operations to an existing IssuerConnector and records
// enrollment events in the audit trail.
type ESTService struct {
	issuer       IssuerConnector
	issuerID     string
	auditService *AuditService
	logger       *slog.Logger
	profileID    string // optional: constrain enrollments to a specific profile
	profileRepo  repository.CertificateProfileRepository
}

// NewESTService creates a new ESTService for the given issuer connector.
func NewESTService(issuerID string, issuer IssuerConnector, auditService *AuditService, logger *slog.Logger) *ESTService {
	return &ESTService{
		issuer:       issuer,
		issuerID:     issuerID,
		auditService: auditService,
		logger:       logger,
	}
}

// SetProfileID constrains EST enrollments to a specific certificate profile.
func (s *ESTService) SetProfileID(profileID string) {
	s.profileID = profileID
}

// SetProfileRepo sets the profile repository for crypto policy enforcement during enrollment.
func (s *ESTService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// GetCACerts returns the PEM-encoded CA certificate chain for this EST server.
// RFC 7030 Section 4.1: /cacerts distributes the current CA certificates.
func (s *ESTService) GetCACerts(ctx context.Context) (string, error) {
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates from issuer %s: %w", s.issuerID, err)
	}
	if caPEM == "" {
		return "", fmt.Errorf("issuer %s does not provide CA certificates for EST", s.issuerID)
	}
	return caPEM, nil
}

// SimpleEnroll processes an initial enrollment request.
// RFC 7030 Section 4.2: /simpleenroll accepts a PKCS#10 CSR and returns a signed cert.
func (s *ESTService) SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return s.processEnrollment(ctx, csrPEM, "est_simple_enroll")
}

// SimpleReEnroll processes a re-enrollment request.
// RFC 7030 Section 4.2.2: /simplereenroll is functionally identical to /simpleenroll
// but is used when renewing an existing certificate.
func (s *ESTService) SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return s.processEnrollment(ctx, csrPEM, "est_simple_reenroll")
}

// GetCSRAttrs returns the CSR attributes the server wants clients to include.
// RFC 7030 Section 4.5: /csrattrs tells clients what to put in their CSR.
// Returns nil if no specific attributes are required.
func (s *ESTService) GetCSRAttrs(ctx context.Context) ([]byte, error) {
	// For now, we don't require specific CSR attributes.
	// In the future, this could return key type constraints from the profile.
	return nil, nil
}

// processEnrollment handles the common enrollment logic for both simpleenroll and simplereenroll.
func (s *ESTService) processEnrollment(ctx context.Context, csrPEM string, auditAction string) (*domain.ESTEnrollResult, error) {
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
		s.logger.Error("EST enrollment rejected: crypto policy violation",
			"action", auditAction,
			"common_name", commonName,
			"error", csrErr)
		return nil, fmt.Errorf("EST enrollment rejected: %w", csrErr)
	}

	s.logger.Info("EST enrollment request",
		"action", auditAction,
		"common_name", commonName,
		"sans", strings.Join(sans, ","),
		"issuer", s.issuerID)

	// Resolve MaxTTL + must-staple from profile.
	// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: thread
	// profile.MustStaple through to the issuer so the local issuer can
	// add the RFC 7633 id-pe-tlsfeature extension.
	var (
		maxTTLSeconds int
		mustStaple    bool
	)
	if profile != nil {
		maxTTLSeconds = profile.MaxTTLSeconds
		mustStaple = profile.MustStaple
	}

	// Issue the certificate via the configured issuer connector
	// EST enrollments use profile EKUs if available, otherwise default (serverAuth + clientAuth fallback)
	result, err := s.issuer.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
	if err != nil {
		s.logger.Error("EST enrollment failed",
			"action", auditAction,
			"common_name", commonName,
			"error", err)
		return nil, fmt.Errorf("certificate issuance failed: %w", err)
	}

	// Audit the enrollment
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name": commonName,
			"sans":        sans,
			"issuer_id":   s.issuerID,
			"serial":      result.Serial,
			"protocol":    "EST",
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", auditAction, "certificate", result.Serial, details)
	}

	s.logger.Info("EST enrollment successful",
		"action", auditAction,
		"common_name", commonName,
		"serial", result.Serial,
		"not_after", result.NotAfter)

	return &domain.ESTEnrollResult{
		CertPEM:  result.CertPEM,
		ChainPEM: result.ChainPEM,
	}, nil
}
