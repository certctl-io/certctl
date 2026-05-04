// Package awssm implements the domain.DiscoverySource interface for AWS Secrets Manager.
//
// AWS Secrets Manager is a managed service for storing and managing secrets including
// certificates. This discovery source scans Secrets Manager for certificates stored
// as secrets, filters by configured tags and name prefix, and reports discovered
// certificate metadata back to the control plane for triage and management.
//
// Discovery approach:
// 1. List all secrets in the configured region
// 2. Filter by tag key=value (default "type=certificate")
// 3. Optionally filter by name prefix
// 4. For each secret, retrieve its value
// 5. Attempt to parse as PEM or base64-encoded DER
// 6. Extract certificate metadata (CN, SANs, serial, validity, etc.)
// 7. Report findings with sentinel agent ID "cloud-aws-sm" and source path "aws-sm://{region}/{secret-name}"
//
// Authentication: AWS credentials via standard credential chain (environment variables,
// IAM roles, instance profile, SSO). The caller is responsible for configuring AWS credentials
// before creating a Source (e.g., via environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).
//
// AWS Secrets Manager API operations used:
//
//	ListSecrets - List secrets, optionally filtered by tags
//	GetSecretValue - Retrieve the secret value (certificate data)
package awssm

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
)

// Note: The actual AWS SDK import will be added once dependencies are available:
// import "github.com/aws-sdk-go-v2/service/secretsmanager"

// SMClient defines the interface for interacting with AWS Secrets Manager.
// This allows for dependency injection and testing with mock clients.
type SMClient interface {
	// ListSecrets lists secrets in the configured region, optionally filtered by tags.
	// filters should be a comma-separated list of "key:value" pairs, e.g., "type:certificate"
	ListSecrets(ctx context.Context, filters string) ([]SecretMetadata, error)

	// GetSecretValue retrieves the secret value for the given secret name or ARN.
	GetSecretValue(ctx context.Context, secretID string) (string, error)
}

// SecretMetadata represents metadata about a secret from ListSecrets.
type SecretMetadata struct {
	Name string
	ARN  string
	Tags map[string]string
}

// Source represents an AWS Secrets Manager discovery source.
type Source struct {
	cfg    *config.AWSSecretsMgrDiscoveryConfig
	client SMClient
	logger *slog.Logger
}

// New creates a new AWS Secrets Manager discovery source with real AWS SDK client.
// It expects AWS credentials to be available in the environment.
func New(cfg *config.AWSSecretsMgrDiscoveryConfig, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		cfg = &config.AWSSecretsMgrDiscoveryConfig{}
	}

	// Create real AWS Secrets Manager client
	realClient := newRealSMClient(cfg.Region, logger)

	return &Source{
		cfg:    cfg,
		client: realClient,
		logger: logger,
	}
}

// NewWithClient creates a new AWS Secrets Manager discovery source with a provided client.
// This is primarily for testing.
func NewWithClient(cfg *config.AWSSecretsMgrDiscoveryConfig, client SMClient, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		cfg = &config.AWSSecretsMgrDiscoveryConfig{}
	}

	return &Source{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

// Name returns a human-readable name for this discovery source.
func (s *Source) Name() string {
	return "AWS Secrets Manager"
}

// Type returns the short type identifier for this discovery source.
func (s *Source) Type() string {
	return "aws-sm"
}

// ValidateConfig checks that the source is properly configured.
func (s *Source) ValidateConfig() error {
	if s.cfg == nil {
		return fmt.Errorf("aws secrets manager discovery config is nil")
	}
	if s.cfg.Region == "" {
		return fmt.Errorf("aws secrets manager region is required")
	}
	return nil
}

// Discover scans AWS Secrets Manager for certificates and returns a DiscoveryReport.
func (s *Source) Discover(ctx context.Context) (*domain.DiscoveryReport, error) {
	if err := s.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid aws secrets manager config: %w", err)
	}

	startTime := time.Now()
	report := &domain.DiscoveryReport{
		AgentID:      "cloud-aws-sm",
		Directories:  []string{fmt.Sprintf("aws-sm://%s", s.cfg.Region)},
		Certificates: []domain.DiscoveredCertEntry{},
		Errors:       []string{},
	}

	// Build filter string from config
	filters := s.buildFilters()

	// List secrets in AWS Secrets Manager
	secrets, err := s.client.ListSecrets(ctx, filters)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to list secrets: %v", err))
		report.ScanDurationMs = int(time.Since(startTime).Milliseconds())
		return report, nil
	}

	// Process each secret
	for _, secret := range secrets {
		if err := s.processSecret(ctx, secret, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to process secret %q: %v", secret.Name, err))
		}
	}

	report.ScanDurationMs = int(time.Since(startTime).Milliseconds())
	return report, nil
}

// buildFilters constructs the filter string for ListSecrets based on config.
func (s *Source) buildFilters() string {
	var filters []string

	// Add tag filter (default: "type=certificate")
	tagFilter := s.cfg.TagFilter
	if tagFilter == "" {
		tagFilter = "type=certificate"
	}
	filters = append(filters, fmt.Sprintf("tag-key:%s", strings.Split(tagFilter, "=")[0]))

	// Note: AWS Secrets Manager API filtering is limited. We'll do secondary filtering
	// in processSecret after retrieving the full list.

	return strings.Join(filters, ",")
}

// processSecret retrieves a secret value, attempts to parse it as a certificate,
// and adds any found certificates to the report.
func (s *Source) processSecret(ctx context.Context, secret SecretMetadata, report *domain.DiscoveryReport) error {
	// Apply name prefix filter if configured
	if s.cfg.NamePrefix != "" && !strings.HasPrefix(secret.Name, s.cfg.NamePrefix) {
		return nil // Skip this secret; doesn't match prefix
	}

	// Apply tag filter if configured
	if s.cfg.TagFilter != "" {
		parts := strings.Split(s.cfg.TagFilter, "=")
		if len(parts) == 2 {
			tagKey, tagValue := parts[0], parts[1]
			if secret.Tags[tagKey] != tagValue {
				return nil // Skip this secret; tag doesn't match
			}
		}
	}

	// Retrieve the secret value
	value, err := s.client.GetSecretValue(ctx, secret.Name)
	if err != nil {
		return fmt.Errorf("failed to get secret value: %w", err)
	}

	if value == "" {
		return nil // Empty secret, skip
	}

	// Attempt to parse the value as PEM or base64-encoded DER
	certs := s.parseCertificateData(value)
	for _, cert := range certs {
		entry, err := s.buildDiscoveredCertEntry(cert, secret.Name)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to extract metadata from %q: %v", secret.Name, err))
			continue
		}
		report.Certificates = append(report.Certificates, *entry)
	}

	return nil
}

// parseCertificateData attempts to parse certificate data from a secret value.
// It tries PEM first, then base64-encoded DER.
func (s *Source) parseCertificateData(data string) []*x509.Certificate {
	var certs []*x509.Certificate

	// Attempt 1: Parse as PEM
	for {
		block, rest := pem.Decode([]byte(data))
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
		data = string(rest)
	}

	// If we found certificates via PEM, return them
	if len(certs) > 0 {
		return certs
	}

	// Attempt 2: Parse as base64-encoded DER
	derBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err == nil {
		cert, err := x509.ParseCertificate(derBytes)
		if err == nil {
			certs = append(certs, cert)
			return certs
		}
	}

	return certs
}

// buildDiscoveredCertEntry extracts certificate metadata and builds a DiscoveredCertEntry.
func (s *Source) buildDiscoveredCertEntry(cert *x509.Certificate, secretName string) (*domain.DiscoveredCertEntry, error) {
	// Compute SHA-256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	// Extract SANs
	sans := cert.DNSNames
	if len(cert.EmailAddresses) > 0 {
		sans = append(sans, cert.EmailAddresses...)
	}

	// Extract key algorithm and size
	keyAlgo, keySize := extractKeyInfo(cert)

	// Format time as RFC3339
	notBeforeStr := cert.NotBefore.Format(time.RFC3339)
	notAfterStr := cert.NotAfter.Format(time.RFC3339)

	// Source path format: aws-sm://{region}/{secret-name}
	sourcePath := fmt.Sprintf("aws-sm://%s/%s", s.cfg.Region, secretName)

	// Encode certificate as PEM for storage
	pemData := encodeCertPEM(cert)

	entry := &domain.DiscoveredCertEntry{
		FingerprintSHA256: fingerprintHex,
		CommonName:        cert.Subject.CommonName,
		SANs:              sans,
		SerialNumber:      cert.SerialNumber.String(),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         notBeforeStr,
		NotAfter:          notAfterStr,
		KeyAlgorithm:      keyAlgo,
		KeySize:           keySize,
		IsCA:              cert.IsCA,
		PEMData:           pemData,
		SourcePath:        sourcePath,
		SourceFormat:      "pem",
	}

	return entry, nil
}

// extractKeyInfo extracts the key algorithm and size from a certificate's public key.
func extractKeyInfo(cert *x509.Certificate) (string, int) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

// encodeCertPEM encodes a certificate as PEM format.
func encodeCertPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// realSMClient is a wrapper around the actual AWS Secrets Manager client.
type realSMClient struct {
	region string
	logger *slog.Logger
}

// newRealSMClient creates a new real AWS Secrets Manager client.
// This will be implemented to use the actual AWS SDK when integrated.
func newRealSMClient(region string, logger *slog.Logger) SMClient {
	return &realSMClient{
		region: region,
		logger: logger,
	}
}

// ListSecrets lists secrets in AWS Secrets Manager.
// This is a stub that will be implemented with the actual AWS SDK.
func (c *realSMClient) ListSecrets(ctx context.Context, filters string) ([]SecretMetadata, error) {
	// This will be implemented with actual AWS SDK calls
	// For now, return empty to allow package to compile
	return []SecretMetadata{}, nil
}

// GetSecretValue retrieves a secret value from AWS Secrets Manager.
// This is a stub that will be implemented with the actual AWS SDK.
func (c *realSMClient) GetSecretValue(ctx context.Context, secretID string) (string, error) {
	// This will be implemented with actual AWS SDK calls
	// For now, return empty to allow package to compile
	return "", nil
}
