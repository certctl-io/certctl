package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"software.sslmate.com/src/go-pkcs12"
)

// ExportService provides certificate export functionality (PEM and PKCS#12).
type ExportService struct {
	certRepo     repository.CertificateRepository
	auditService *AuditService
}

// NewExportService creates a new export service.
func NewExportService(
	certRepo repository.CertificateRepository,
	auditService *AuditService,
) *ExportService {
	return &ExportService{
		certRepo:     certRepo,
		auditService: auditService,
	}
}

// ExportPEMResult contains the PEM-encoded certificate chain.
type ExportPEMResult struct {
	CertPEM  string `json:"cert_pem"`
	ChainPEM string `json:"chain_pem"`
	FullPEM  string `json:"full_pem"` // cert + chain concatenated
}

// ExportPEM returns the PEM-encoded certificate and chain for the latest version.
func (s *ExportService) ExportPEM(ctx context.Context, certID string) (*ExportPEMResult, error) {
	// Verify certificate exists
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	// Get latest version (contains the PEM chain)
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("no certificate version found: %w", err)
	}

	// Split PEM chain into leaf cert + chain
	certPEM, chainPEM := splitPEMChain(version.PEMChain)

	// Audit the export — split-emit per Phase 7 split-emit pattern.
	// Legacy bare code "export_pem" preserved for back-compat with
	// existing audit-log analysers; typed AuditActionCertExportPEM
	// emitted alongside as the new operator grep target. Mirrors
	// est.go::processEnrollment's split-emit pattern.
	if s.auditService != nil {
		details := map[string]interface{}{
			"serial":          version.SerialNumber,
			"has_private_key": false, // V2: cert-only path
			"actor_kind":      "user",
		}
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"export_pem", "certificate", cert.ID, details); auditErr != nil {
			slog.Error("failed to record audit event (legacy)", "error", auditErr)
		}
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			AuditActionCertExportPEM, "certificate", cert.ID, details); auditErr != nil {
			slog.Error("failed to record audit event (typed)", "error", auditErr)
		}
	}

	return &ExportPEMResult{
		CertPEM:  certPEM,
		ChainPEM: chainPEM,
		FullPEM:  version.PEMChain,
	}, nil
}

// ExportPKCS12 returns a PKCS#12 bundle containing the certificate chain.
// The private key is NOT included — it lives on the agent and never touches the control plane.
// The PKCS#12 bundle is encrypted with the provided password (can be empty for cert-only bundles).
func (s *ExportService) ExportPKCS12(ctx context.Context, certID string, password string) ([]byte, error) {
	// Verify certificate exists
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	// Get latest version
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("no certificate version found: %w", err)
	}

	// Parse PEM chain into x509.Certificate objects
	certs, err := parsePEMCertificates(version.PEMChain)
	if err != nil {
		return nil, fmt.Errorf("certificate data cannot be parsed as X.509: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM chain")
	}

	// Build PKCS#12 bundle: leaf cert + CA chain (no private key)
	leaf := certs[0]
	var caCerts []*x509.Certificate
	if len(certs) > 1 {
		caCerts = certs[1:]
	}

	// Encode as PKCS#12 trust store (cert-only bundle, no private key)
	pfxData, err := encodePKCS12CertOnly(leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	// Audit the export — split-emit per Phase 7. Typed code
	// AuditActionCertExportPKCS12 + cipher detail. The cipher value
	// is pinned to PKCS12CipherModernAES256 so a future dependency
	// upgrade that changes the encoder default surfaces in audit
	// drift review.
	if s.auditService != nil {
		details := map[string]interface{}{
			"serial":          version.SerialNumber,
			"has_private_key": false, // V2: trust-store mode only
			"cipher":          PKCS12CipherModernAES256,
			"actor_kind":      "user",
		}
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"export_pkcs12", "certificate", cert.ID, details); auditErr != nil {
			slog.Error("failed to record audit event (legacy)", "error", auditErr)
		}
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			AuditActionCertExportPKCS12, "certificate", cert.ID, details); auditErr != nil {
			slog.Error("failed to record audit event (typed)", "error", auditErr)
		}
	}

	return pfxData, nil
}

// encodePKCS12CertOnly creates a PKCS#12 bundle with certificate(s) but no private key.
// Uses the go-pkcs12 library's Modern encoder for strong encryption.
func encodePKCS12CertOnly(leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	// go-pkcs12's Modern.Encode expects a private key; for cert-only bundles we use
	// EncodeTrustStore which stores certs as trusted entries.
	// Include the leaf in the trust store alongside CA certs.
	allCerts := make([]*x509.Certificate, 0, 1+len(caCerts))
	allCerts = append(allCerts, leaf)
	allCerts = append(allCerts, caCerts...)
	return pkcs12.Modern.EncodeTrustStore(allCerts, password)
}

// splitPEMChain splits a PEM chain into the first certificate (leaf) and remaining chain.
func splitPEMChain(fullPEM string) (string, string) {
	data := []byte(fullPEM)
	var blocks []*pem.Block
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}

	if len(blocks) == 0 {
		return fullPEM, ""
	}

	certPEM := string(pem.EncodeToMemory(blocks[0]))
	var chainPEM string
	for i := 1; i < len(blocks); i++ {
		chainPEM += string(pem.EncodeToMemory(blocks[i]))
	}

	return certPEM, chainPEM
}

// parsePEMCertificates parses all certificates from a PEM-encoded string.
func parsePEMCertificates(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data := []byte(pemData)

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}
