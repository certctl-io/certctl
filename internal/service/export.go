package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
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
	// Verify certificate exists.
	//
	// M-1 (P2): the pre-M-1 wrap was `"certificate not found: %w"` on every
	// certRepo.Get error — which gave the handler's strings.Contains(err.Error(),
	// "not found") check a false positive on transient DB failures (connection
	// refused, context deadline, etc.), demoting a 500 to a 404. Now the repo
	// wraps only the genuine sql.ErrNoRows path with repository.ErrNotFound
	// (certificate.go Get), so the errors.Is walk through the handler's
	// errToStatus discriminates correctly: truly-missing → 404, everything else
	// → 500 (the intended outcome). The wrap text is changed from "certificate
	// not found" to "failed to get certificate" to match the semantic.
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Get latest version (contains the PEM chain).
	//
	// M-1 (P2): same wrap-text correction as above — pre-M-1 any
	// GetLatestVersion error surfaced as "no certificate version found",
	// which bled into the handler's substring classifier. Now the repo wraps
	// sql.ErrNoRows with repository.ErrNotFound; the wrap chain walks cleanly.
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest certificate version: %w", err)
	}

	// Split PEM chain into leaf cert + chain
	certPEM, chainPEM := splitPEMChain(version.PEMChain)

	// Audit the export
	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"export_pem", "certificate", cert.ID,
			map[string]interface{}{"serial": version.SerialNumber}); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
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
	// Verify certificate exists. See M-1 (P2) note on ExportPEM for the wrap-text
	// correction — same rationale applies here.
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Get latest version. Same wrap-text correction as ExportPEM.
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest certificate version: %w", err)
	}

	// Parse PEM chain into x509.Certificate objects.
	//
	// M-1 (P2): wrap both parse-failure paths with ErrUnprocessable so the
	// handler's errToStatus choke point dispatches to 422 Unprocessable Entity
	// via errors.Is instead of the pre-M-1 two-term substring net
	// (`"cannot be parsed"|"no certificates found"`) at handler/export.go:101.
	// 422 is the correct status here — the caller's request is syntactically
	// fine; the stored PEM chain is what can't be processed. The composed
	// Error() string still carries the "certificate data cannot be parsed as
	// X.509"/"no certificates found in PEM chain" wording so server-side
	// slog.Error capture and any future 422 body propagation stay readable.
	certs, err := parsePEMCertificates(version.PEMChain)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate data cannot be parsed as X.509: %v", ErrUnprocessable, err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates found in PEM chain", ErrUnprocessable)
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

	// Audit the export
	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"export_pkcs12", "certificate", cert.ID,
			map[string]interface{}{"serial": version.SerialNumber, "has_private_key": false}); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
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
