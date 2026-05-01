// Package awsacmpca implements the issuer.Connector interface for AWS Certificate Manager Private CA (ACM PCA).
//
// AWS ACM Private CA provides a fully managed private certificate authority
// with certificate signing, revocation, CRL, and OCSP capabilities. This
// connector uses the AWS SDK v2 (aws-sdk-go-v2/service/acmpca) to drive the
// ACM PCA API.
//
// Issuance is asynchronous at the API level — IssueCertificate returns a
// certificate ARN immediately, and GetCertificate is then polled until the
// cert reaches the CERTIFICATE_ISSUED state. The sdkClient wrapper hides
// this asynchrony behind the connector's two-call pattern by running the
// SDK's NewCertificateIssuedWaiter between the IssueCertificate and
// GetCertificate calls. Callers see synchronous-via-waiter behavior with
// a configurable wait deadline (default 5 minutes; see WaiterTimeout).
//
// Authentication: AWS credentials via the standard credential chain
// (environment variables, shared config / shared credentials files,
// IAM role for service accounts, EC2 instance profile, ECS task role,
// SSO). awsconfig.LoadDefaultConfig handles all of these transparently;
// certctl does not store AWS credentials directly. Configuration
// specifies the CA ARN, region, and optional signing algorithm,
// validity days, and template ARN.
//
// CRL and OCSP are served by AWS ACM PCA directly (the CA owns those
// endpoints). certctl records revocations locally and notifies AWS
// via the RevokeCertificate API with RFC 5280 reason mapping.
//
// AWS ACM PCA SDK calls used (abstracted via the local ACMPCAClient
// interface so tests can inject a mock without depending on the SDK):
//
//	IssueCertificate                       — submit a CSR for signing
//	GetCertificate                         — retrieve the issued cert
//	RevokeCertificate                      — revoke an issued cert
//	GetCertificateAuthorityCertificate     — fetch the CA cert + chain
//	NewCertificateIssuedWaiter (internal)  — wait for cert to be ready
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// defaultWaiterTimeout is how long sdkClient.IssueCertificate will wait for
// the issued cert to reach CERTIFICATE_ISSUED state before giving up. Five
// minutes covers slow CA backends and short-lived rate-limit pauses; the
// SDK waiter retries with exponential backoff inside this window.
const defaultWaiterTimeout = 5 * time.Minute

// Config represents the AWS ACM Private CA issuer connector configuration.
type Config struct {
	// Region is the AWS region where the CA resides (e.g., "us-east-1").
	// Required. Set via CERTCTL_AWS_PCA_REGION environment variable.
	Region string `json:"region"`

	// CAArn is the ARN of the AWS Certificate Manager Private CA.
	// Required. Set via CERTCTL_AWS_PCA_CA_ARN environment variable.
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
// This allows for dependency injection and testing with mock clients without
// importing aws-sdk-go-v2 from test code.
//
// The production implementation (sdkClient) wraps *acmpca.Client and
// translates between local input/output types and the SDK's typed
// inputs/outputs. The sdkClient also runs the SDK's
// NewCertificateIssuedWaiter inside IssueCertificate so callers see
// synchronous-via-waiter semantics; the waiter is hidden from the
// interface to keep mock implementations simple.
type ACMPCAClient interface {
	// IssueCertificate submits a CSR for signing and waits for the issued
	// cert to be retrievable. Returns the certificate ARN.
	IssueCertificate(ctx context.Context, input *IssueCertificateInput) (*IssueCertificateOutput, error)

	// GetCertificate retrieves a previously issued certificate by ARN.
	GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error)

	// RevokeCertificate revokes a certificate by serial number.
	RevokeCertificate(ctx context.Context, input *RevokeCertificateInput) error

	// GetCACertificate retrieves the CA certificate and chain.
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
	CAArn             string
	CertificateSerial string
	RevocationReason  string
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

// New creates a new AWS ACM Private CA connector with the given configuration
// and logger. If config is non-nil and config.Region is set, New attempts to
// load the AWS SDK default credential chain (environment variables, shared
// config, IAM role, instance profile, SSO) and constructs an *acmpca.Client
// pinned to the region. Returns an error if SDK config load fails.
//
// If config is nil or config.Region is empty, the connector is constructed
// with no client; ValidateConfig will lazily build the client on first
// successful validation. This keeps backward compatibility with the
// "construct then validate" pattern used by tests that exercise
// ValidateConfig in isolation.
//
// Callers wanting to inject a mock client (tests, fake CAs) should use
// NewWithClient instead, which bypasses the SDK loading path entirely.
func New(config *Config, logger *slog.Logger) (*Connector, error) {
	if config != nil {
		if config.SigningAlgorithm == "" {
			config.SigningAlgorithm = "SHA256WITHRSA"
		}
		if config.ValidityDays == 0 {
			config.ValidityDays = 365
		}
	}

	c := &Connector{
		config: config,
		logger: logger,
	}

	if config != nil && config.Region != "" {
		client, err := buildSDKClient(context.Background(), config.Region)
		if err != nil {
			return nil, fmt.Errorf("AWS ACM PCA SDK init: %w", err)
		}
		c.client = client
	}

	return c, nil
}

// NewWithClient creates a new AWS ACM Private CA connector with a custom
// client implementation. Used primarily for testing with mock clients;
// production code should use New, which wires the real SDK-backed client.
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

// buildSDKClient loads the AWS default credential chain pinned to the given
// region and returns a sdkClient ready for use. Separated from New so
// ValidateConfig can also call it when the connector was constructed with
// no config (the test-init path).
func buildSDKClient(ctx context.Context, region string) (ACMPCAClient, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("LoadDefaultConfig: %w", err)
	}
	return &sdkClient{
		client:        acmpca.NewFromConfig(awsCfg),
		waiterTimeout: defaultWaiterTimeout,
	}, nil
}

// sdkClient wraps *acmpca.Client and translates between local input/output
// types and the SDK's typed inputs/outputs. The waiter for asynchronous
// issuance is run inside IssueCertificate so the connector layer's two-call
// pattern (IssueCertificate → GetCertificate) sees synchronous-via-waiter
// semantics.
type sdkClient struct {
	client        *acmpca.Client
	waiterTimeout time.Duration
}

func (s *sdkClient) IssueCertificate(ctx context.Context, input *IssueCertificateInput) (*IssueCertificateOutput, error) {
	sdkInput := &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(input.CAArn),
		Csr:                     input.CSR,
		SigningAlgorithm:        acmpcatypes.SigningAlgorithm(input.SigningAlgorithm),
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeDays,
			Value: aws.Int64(int64(input.ValidityDays)),
		},
	}
	if input.TemplateArn != "" {
		sdkInput.TemplateArn = aws.String(input.TemplateArn)
	}

	output, err := s.client.IssueCertificate(ctx, sdkInput)
	if err != nil {
		return nil, fmt.Errorf("acmpca IssueCertificate: %w", err)
	}
	if output == nil || output.CertificateArn == nil {
		return nil, fmt.Errorf("acmpca IssueCertificate returned no CertificateArn")
	}

	// Wait for the certificate to reach CERTIFICATE_ISSUED state. The SDK's
	// waiter polls GetCertificate with exponential backoff until either the
	// cert is ready or the deadline expires.
	waiter := acmpca.NewCertificateIssuedWaiter(s.client)
	waitErr := waiter.Wait(ctx, &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(input.CAArn),
		CertificateArn:          output.CertificateArn,
	}, s.waiterTimeout)
	if waitErr != nil {
		return nil, fmt.Errorf("acmpca waiter (waiting for issuance): %w", waitErr)
	}

	return &IssueCertificateOutput{
		CertificateArn: aws.ToString(output.CertificateArn),
	}, nil
}

func (s *sdkClient) GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error) {
	output, err := s.client.GetCertificate(ctx, &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(input.CAArn),
		CertificateArn:          aws.String(input.CertificateArn),
	})
	if err != nil {
		return nil, fmt.Errorf("acmpca GetCertificate: %w", err)
	}
	if output == nil {
		return nil, fmt.Errorf("acmpca GetCertificate returned nil output")
	}
	return &GetCertificateOutput{
		Certificate:      aws.ToString(output.Certificate),
		CertificateChain: aws.ToString(output.CertificateChain),
	}, nil
}

func (s *sdkClient) RevokeCertificate(ctx context.Context, input *RevokeCertificateInput) error {
	_, err := s.client.RevokeCertificate(ctx, &acmpca.RevokeCertificateInput{
		CertificateAuthorityArn: aws.String(input.CAArn),
		CertificateSerial:       aws.String(input.CertificateSerial),
		RevocationReason:        acmpcatypes.RevocationReason(input.RevocationReason),
	})
	if err != nil {
		return fmt.Errorf("acmpca RevokeCertificate: %w", err)
	}
	return nil
}

func (s *sdkClient) GetCACertificate(ctx context.Context, input *GetCACertificateInput) (*GetCACertificateOutput, error) {
	output, err := s.client.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: aws.String(input.CAArn),
	})
	if err != nil {
		return nil, fmt.Errorf("acmpca GetCertificateAuthorityCertificate: %w", err)
	}
	if output == nil {
		return nil, fmt.Errorf("acmpca GetCertificateAuthorityCertificate returned nil output")
	}
	return &GetCACertificateOutput{
		Certificate:      aws.ToString(output.Certificate),
		CertificateChain: aws.ToString(output.CertificateChain),
	}, nil
}

// ValidateConfig checks that the AWS ACM Private CA configuration is valid.
// On success, ValidateConfig also lazily builds the SDK client if the
// connector was constructed with no config (the test-init path: New(nil, ...)).
// In production, the factory always passes a fully-populated config to New,
// so the SDK client is built at New time and ValidateConfig only re-validates.
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

	// Lazily build the SDK client if the connector was constructed without one
	// (e.g., New(nil, logger)). NewWithClient injects a mock and we leave it
	// alone; production New with a populated config builds the client up
	// front and we leave it alone too.
	if c.client == nil {
		client, err := buildSDKClient(ctx, cfg.Region)
		if err != nil {
			return fmt.Errorf("AWS ACM PCA SDK init: %w", err)
		}
		c.client = client
	}

	return nil
}

// IssueCertificate issues a new certificate using AWS ACM Private CA.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("AWS ACM PCA client not initialized; ValidateConfig must be called first")
	}

	c.logger.Info("processing AWS ACM PCA issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Decode CSR from PEM
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	// Call AWS API to issue certificate. The sdkClient hides the asynchronous
	// IssueCertificate → waiter → GetCertificate dance behind this single call;
	// IssueCertificate returns only after the cert has reached
	// CERTIFICATE_ISSUED state (or the waiter timeout has expired).
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
	if c.client == nil {
		return fmt.Errorf("AWS ACM PCA client not initialized; ValidateConfig must be called first")
	}

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

// GetOrderStatus returns the status of an AWS ACM PCA order. From the
// connector's perspective, issuance is synchronous (the sdkClient runs the
// SDK waiter inside IssueCertificate), so by the time a caller reaches
// GetOrderStatus the cert is already available.
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
	if c.client == nil {
		return "", fmt.Errorf("AWS ACM PCA client not initialized; ValidateConfig must be called first")
	}

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

// mapRevocationReason converts RFC 5280 reason strings to AWS ACM PCA reason
// codes. The returned string corresponds to a valid acmpcatypes.RevocationReason
// value, which sdkClient.RevokeCertificate then casts back to the SDK enum.
func mapRevocationReason(reason *string) string {
	if reason == nil {
		return "UNSPECIFIED"
	}

	reasonMap := map[string]string{
		"unspecified":          "UNSPECIFIED",
		"keyCompromise":        "KEY_COMPROMISE",
		"caCompromise":         "CERTIFICATE_AUTHORITY_COMPROMISE",
		"affiliationChanged":   "AFFILIATION_CHANGED",
		"superseded":           "SUPERSEDED",
		"cessationOfOperation": "CESSATION_OF_OPERATION",
		"certificateHold":      "CERTIFICATE_HOLD",
		"privilegeWithdrawn":   "PRIVILEGE_WITHDRAWN",
	}

	if mapped, ok := reasonMap[*reason]; ok {
		return mapped
	}

	return "UNSPECIFIED"
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)

// Ensure sdkClient implements the ACMPCAClient interface.
var _ ACMPCAClient = (*sdkClient)(nil)
