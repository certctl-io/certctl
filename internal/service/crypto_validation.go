package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/certctl-io/certctl/internal/domain"
)

// CSRValidationResult contains metadata extracted from a validated CSR.
type CSRValidationResult struct {
	KeyAlgorithm string
	KeySize      int
}

// ValidateCSRAgainstProfile parses a CSR PEM and validates that its key algorithm
// and size comply with the profile's allowed_key_algorithms rules.
// Returns extracted key metadata on success for storage in certificate_versions.
func ValidateCSRAgainstProfile(csrPEM string, profile *domain.CertificateProfile) (*CSRValidationResult, error) {
	if profile == nil {
		// No profile assigned — skip validation, extract metadata only
		return extractCSRKeyInfo(csrPEM)
	}

	result, err := extractCSRKeyInfo(csrPEM)
	if err != nil {
		return nil, err
	}

	// Check that the CSR's key algorithm + size matches at least one allowed rule
	if len(profile.AllowedKeyAlgorithms) == 0 {
		// No restrictions defined — allow anything
		return result, nil
	}

	for _, rule := range profile.AllowedKeyAlgorithms {
		if rule.Algorithm == result.KeyAlgorithm && result.KeySize >= rule.MinSize {
			return result, nil
		}
	}

	return nil, fmt.Errorf("CSR key (%s %d-bit) does not match any allowed algorithm in profile %q: %v",
		result.KeyAlgorithm, result.KeySize, profile.Name, profile.AllowedKeyAlgorithms)
}

// extractCSRKeyInfo parses a CSR PEM and extracts the key algorithm and size.
func extractCSRKeyInfo(csrPEM string) (*CSRValidationResult, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return &CSRValidationResult{
			KeyAlgorithm: domain.KeyAlgorithmRSA,
			KeySize:      key.N.BitLen(),
		}, nil
	case *ecdsa.PublicKey:
		return &CSRValidationResult{
			KeyAlgorithm: domain.KeyAlgorithmECDSA,
			KeySize:      key.Curve.Params().BitSize,
		}, nil
	case ed25519.PublicKey:
		return &CSRValidationResult{
			KeyAlgorithm: domain.KeyAlgorithmEd25519,
			KeySize:      256, // Ed25519 is fixed 256-bit
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type in CSR: %T", csr.PublicKey)
	}
}
