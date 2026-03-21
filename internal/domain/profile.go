package domain

import (
	"time"
)

// CertificateProfile defines an enrollment profile that controls what kinds of
// certificates can be issued: allowed key algorithms, maximum TTL, permitted EKUs,
// required SAN patterns, and optional SPIFFE URI SANs for workload identity.
type CertificateProfile struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	Description          string             `json:"description"`
	AllowedKeyAlgorithms []KeyAlgorithmRule `json:"allowed_key_algorithms"`
	MaxTTLSeconds        int                `json:"max_ttl_seconds"`
	AllowedEKUs          []string           `json:"allowed_ekus"`
	RequiredSANPatterns  []string           `json:"required_san_patterns"`
	SPIFFEURIPattern     string             `json:"spiffe_uri_pattern"`
	AllowShortLived      bool               `json:"allow_short_lived"`
	Enabled              bool               `json:"enabled"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

// KeyAlgorithmRule defines an allowed key algorithm and its minimum key size.
type KeyAlgorithmRule struct {
	Algorithm string `json:"algorithm"` // "RSA", "ECDSA", "Ed25519"
	MinSize   int    `json:"min_size"`  // RSA: 2048/4096, ECDSA: 256/384, Ed25519: 0 (fixed)
}

// IsShortLived returns true if this profile's max TTL is under 1 hour (3600 seconds).
// Short-lived certs use expiry as revocation — no CRL/OCSP needed.
func (p *CertificateProfile) IsShortLived() bool {
	return p.AllowShortLived && p.MaxTTLSeconds > 0 && p.MaxTTLSeconds < 3600
}

// DefaultKeyAlgorithms returns sensible defaults for profiles without explicit rules.
func DefaultKeyAlgorithms() []KeyAlgorithmRule {
	return []KeyAlgorithmRule{
		{Algorithm: "ECDSA", MinSize: 256},
		{Algorithm: "RSA", MinSize: 2048},
	}
}

// DefaultEKUs returns the default extended key usages.
func DefaultEKUs() []string {
	return []string{"serverAuth"}
}

// Supported key algorithm constants for validation.
const (
	KeyAlgorithmRSA     = "RSA"
	KeyAlgorithmECDSA   = "ECDSA"
	KeyAlgorithmEd25519 = "Ed25519"
)

// ValidKeyAlgorithms is the set of recognized key algorithm names.
var ValidKeyAlgorithms = map[string]bool{
	KeyAlgorithmRSA:     true,
	KeyAlgorithmECDSA:   true,
	KeyAlgorithmEd25519: true,
}

// ValidEKUs is the set of recognized extended key usage names.
var ValidEKUs = map[string]bool{
	"serverAuth":      true,
	"clientAuth":      true,
	"codeSigning":     true,
	"emailProtection": true,
	"timeStamping":    true,
}
