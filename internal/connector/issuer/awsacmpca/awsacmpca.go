// Package awsacmpca implements the issuer.Connector interface for AWS Certificate Authority Service (CAS).
//
// AWS ACM Private CA (ACM PCA) provides a fully managed private certificate authority
// with certificate signing, revocation, and CRL capabilities. This connector uses the
// AWS ACM PCA API to issue and manage certificates.
//
// This connector issues certificates synchronously: the IssueCertificate call returns
// the issued certificate immediately. GetOrderStatus always returns "completed" since
// issuance is synchronous. CRL and OCSP operations are delegated to AWS PCA's own
// endpoints.
//
// Authentication: AWS credentials via the standard credential chain (environment variables,
// IAM role, instance profile, or SSO). Configuration specifies the CA ARN, region, and
// optional signing algorithm and validity days.
//
// AWS ACM PCA API used (abstracted via ACMPCAClient interface):
//
//	IssueCertificate  - Issue a certificate from a CSR
//	GetCertificate    - Retrieve the issued certificate
//	RevokeCertificate - Revoke a certificate
//	GetCACertificate  - Get the CA certificate chain
package awsacmpca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the AWS ACM Private CA issuer connector configuration.
type Config struct {
	// Region is the AWS region where the CA resides (e.g., "us-east-1").
	// Required. Set via CERTCTL_GOOGLE_CAS_PROJECT environment variable.
	Region string `json:"region"`

	// CAArn is the ARN of the AWS Certificate Authority Service CA.
	// Required. Set via CERTCTL_GOOGLE_CAS_CA_ARN environment variable.
	// Example: arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012
	CAArn string `json:"ca_arn"`

	// SigningAlgorithm is the algorithm used to sign certificates.
	// Default: "SHA256WITHRSA". Set via CERTCTL_AWS_PCA_SIGNING_ALGORITHM.
	// Valid values: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA,
	//              SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`

	// ValidityDays is the number of days the certificate is valid.
	// Default: 365. Set via CERTCTL_AWS_PCA_VALIDITY_DAYS.
	ValidityDays int `json:"validity_days,omitempty"`

	// TemplateArn is the optional certificate template ARN for subordinate CAs with restrictions.
	// Set via CERTCTL_AWS_PCA_TEMPLATE_ARN.
	TemplateArn string `json:"template_arn,omitempty"`
}

// ACMPCAClient defines the interface for interacting with AWS ACM Private CA.
// This allows for dependency injection and testing with mock clients.
type ACMPCAClient interface {
	// IssueCertificate issues a new certificate.
	IssueCertificate(ctx context.Context, input *IssueCertificateInput) (*IssueCertificateOutput, error)

	// GetCertificate retrieves an issued certificate.
	GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error)

	// RevokeCertificate revokes a certificate.
	RevokeCertificate(ctx context.Context, input *RevokeCertificateInput) error

	// GetCACertificate retrieves the CA certificate chain.
	GetCACertificate(ctx context.Context, input *GetCACertificateInput) (*GetCACertificateOutput, error)
}

// IssueCertificateInput represents the request to issue a certificate.
type IssueCertificateInput struct {
	CAArn            string
	CSR              []byte // DER-encoded CSR
	SigningAlgorithm string
	ValidityDays     int
	TemplateArn      string
}

// IssueCertificateOutput represents the response to an issue request.
type IssueCertificateOutput struct {
	CertificateArn string
}

// GetCertificateInput represents the request to retrieve a certificate.
type GetCertificateInput struct {
	CAArn          string
	CertificateArn string
}

// GetCertificateOutput represents the response containing the certificate.
type GetCertificateOutput struct {
	Certificate      string // PEM-encoded certificate
	CertificateChain string // PEM-encoded certificate chain
}

// RevokeCertificateInput represents the request to revoke a certificate.
type RevokeCertificateInput struct {
	CAArn               string
	CertificateSerial   string
	RevocationReason    string
}

// GetCACertificateInput represents the request to retrieve the CA certificate.
type GetCACertificateInput struct {
	CAArn string
}

// GetCACertificateOutput represents the response containing the CA certificate.
type GetCACertificateOutput struct {
	Certificate      string // PEM-encoded CA certificate
	CertificateChain string // PEM-encoded CA chain
}

// Connector implements the issuer.Connector interface for AWS ACM Private CA.
type Connector struct {
	config *Config
	client ACMPCAClient
	logger *slog.Logger
}

// New creates a new AWS ACM Private CA connector with the given configuration and logger.
// The real client will use the AWS SDK via the standard credential chain.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.SigningAlgorithm == "" {
			config.SigningAlgorithm = "SHA256WITHRSA"
		}
		if config.ValidityDays == 0 {
			config.ValidityDays = 365
		}
	}

	return &Connector{
		config: config,
		client: &stubClient{}, // Placeholder; real AWS client will be injected or implemented
		logger: logger,
	}
}

// NewWithClient creates a new AWS ACM Private CA connector with a custom client.
// Used primarily for testing with mock clients.
func NewWithClient(config *Config, client ACMPCAClient, logger *slog.Logger) *Connector {
	if config != nil {
		if config.SigningAlgorithm == "" {
			config.SigningAlgorithm = "SHA256WITHRSA"
		}
		if config.ValidityDays == 0 {
			config.ValidityDays = 365
		}
	}

	return &Connector{
		config: config,
		client: client,
		logger: logger,
	}
}

// stubClient is a placeholder client that returns "not implemented" errors.
// In production, this would be replaced with a real AWS SDK client.
type stubClient struct{}

func (s *stubClient) IssueCertificate(ctx context.Context, input *IssueCertificateInput) (*IssueCertificateOutput, error) {
	return nil, fmt.Errorf("AWS SDK client not initialized (stub)")
}

func (s *stubClient) GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error) {
	return nil, fmt.Errorf("AWS SDK client not initialized (stub)")
}

func (s *stubClient) RevokeCertificate(ctx context.Context, input *RevokeCertificateInput) error {
	return fmt.Errorf("AWS SDK client not initialized (stub)")
}

func (s *stubClient) GetCACertificate(ctx context.Context, input *GetCACertificateInput) (*GetCACertificateOutput, error) {
	return nil, fmt.Errorf("AWS SDK client not initialized (stub)")
}

// ValidateConfig checks that the AWS ACM Private CA configuration is valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid AWS ACM PCA config: %w", err)
	}

	if cfg.Region == "" {
		return fmt.Errorf("AWS region is required")
	}

	if cfg.CAArn == "" {
		return fmt.Errorf("AWS CA ARN is required")
	}

	// Validate ARN format: arn:aws(-[a-z]+)?:acm-pca:[a-z0-9-]+:\d{12}:certificate-authority/[a-f0-9-]+
	arnPattern := regexp.MustCompile(`^arn:aws(-[a-z]+)?:acm-pca:[a-z0-9-]+:\d{12}:certificate-authority/[a-f0-9-]+$`)
	if !arnPattern.MatchString(cfg.CAArn) {
		return fmt.Errorf("invalid CA ARN format: %s", cfg.CAArn)
	}

	// Validate signing algorithm if provided
	if cfg.SigningAlgorithm != "" {
		validAlgorithms := map[string]bool{
			"SHA256WITHRSA":   true,
			"SHA384WITHRSA":   true,
			"SHA512WITHRSA":   true,
			"SHA256WITHECDSA": true,
			"SHA384WITHECDSA": true,
			"SHA512WITHECDSA": true,
		}
		if !validAlgorithms[cfg.SigningAlgorithm] {
			return fmt.Errorf("invalid signing algorithm: %s", cfg.SigningAlgorithm)
		}
	} else {
		cfg.SigningAlgorithm = "SHA256WITHRSA"
	}

	// Validate validity days if provided
	if cfg.ValidityDays < 0 {
		return fmt.Errorf("validity days must be non-negative")
	}
	if cfg.ValidityDays == 0 {
		cfg.ValidityDays = 365
	}

	c.config = &cfg
	c.logger.Info("AWS ACM Private CA configuration validated",
		"region", cfg.Region,
		"ca_arn", cfg.CAArn,
		"signing_algorithm", cfg.SigningAlgorithm,
		"validity_days", cfg.ValidityDays)

	return nil
}

// IssueCertificate issues a new certificate using AWS ACM Private CA.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing AWS ACM PCA issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Decode CSR from PEM
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	// Call AWS API to issue certificate
	issueOutput, err := c.client.IssueCertificate(ctx, &IssueCertificateInput{
		CAArn:            c.config.CAArn,
		CSR:              csrBlock.Bytes,
		SigningAlgorithm: c.config.SigningAlgorithm,
		ValidityDays:     c.config.ValidityDays,
		TemplateArn:      c.config.TemplateArn,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS IssueCertificate failed: %w", err)
	}

	// Retrieve the issued certificate
	getCertOutput, err := c.client.GetCertificate(ctx, &GetCertificateInput{
		CAArn:          c.config.CAArn,
		CertificateArn: issueOutput.CertificateArn,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS GetCertificate failed: %w", err)
	}

	if getCertOutput.Certificate == "" {
		return nil, fmt.Errorf("no certificate in AWS response")
	}

	// Parse the certificate to extract metadata
	block, _ := pem.Decode([]byte(getCertOutput.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM from AWS")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract serial number (hex format, uppercase)
	serial := strings.ToUpper(fmt.Sprintf("%x", cert.SerialNumber))

	// Use certificate ARN as OrderID for revocation lookup
	orderID := issueOutput.CertificateArn

	c.logger.Info("AWS ACM PCA certificate issued",
		"common_name", request.CommonName,
		"serial", serial,
		"not_after", cert.NotAfter)

	return &issuer.IssuanceResult{
		CertPEM:   getCertOutput.Certificate,
		ChainPEM:  getCertOutput.CertificateChain,
		Serial:    serial,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}, nil
}

// RenewCertificate renews a certificate by creating a new signing request.
// For AWS ACM PCA, renewal is functionally identical to issuance (new cert signed from CSR).
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing AWS ACM PCA renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at AWS ACM Private CA.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing AWS ACM PCA revocation request", "serial", request.Serial)

	// Map RFC 5280 reason string to AWS reason
	reason := mapRevocationReason(request.Reason)

	err := c.client.RevokeCertificate(ctx, &RevokeCertificateInput{
		CAArn:             c.config.CAArn,
		CertificateSerial: request.Serial,
		RevocationReason:  reason,
	})
	if err != nil {
		return fmt.Errorf("AWS RevokeCertificate failed: %w", err)
	}

	c.logger.Info("AWS ACM PCA certificate revoked", "serial", request.Serial)
	return nil
}

// GetOrderStatus returns the status of an AWS ACM PCA order.
// AWS ACM PCA issues synchronously, so orders are always "completed" immediately.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	return &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		UpdatedAt: time.Now(),
	}, nil
}

// GenerateCRL is not supported because AWS ACM PCA serves CRL directly.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("CRL delegated to AWS ACM Private CA; use AWS endpoint directly")
}

// SignOCSPResponse is not supported because AWS ACM PCA serves OCSP directly.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("OCSP delegated to AWS ACM Private CA; use AWS endpoint directly")
}

// GetCACertPEM retrieves the CA certificate from AWS ACM Private CA.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	caCertOutput, err := c.client.GetCACertificate(ctx, &GetCACertificateInput{
		CAArn: c.config.CAArn,
	})
	if err != nil {
		return "", fmt.Errorf("AWS GetCACertificate failed: %w", err)
	}

	// Combine CA certificate and chain
	if caCertOutput.CertificateChain != "" {
		return caCertOutput.Certificate + "\n" + caCertOutput.CertificateChain, nil
	}

	return caCertOutput.Certificate, nil
}

// GetRenewalInfo returns nil, nil as AWS ACM PCA does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// mapRevocationReason converts RFC 5280 reason strings to AWS ACM PCA reason codes.
func mapRevocationReason(reason *string) string {
	if reason == nil {
		return "UNSPECIFIED"
	}

	reasonMap := map[string]string{
		"unspecified":           "UNSPECIFIED",
		"keyCompromise":         "KEY_COMPROMISE",
		"caCompromise":          "CERTIFICATE_AUTHORITY_COMPROMISE",
		"affiliationChanged":    "AFFILIATION_CHANGED",
		"superseded":            "SUPERSEDED",
		"cessationOfOperation":  "CESSATION_OF_OPERATION",
		"certificateHold":       "CERTIFICATE_HOLD",
		"privilegeWithdrawn":    "PRIVILEGE_WITHDRAWN",
	}

	if mapped, ok := reasonMap[*reason]; ok {
		return mapped
	}

	return "UNSPECIFIED"
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
