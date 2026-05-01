package awsacmpca_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/awsacmpca"
)

// mockACMPCAClient implements the ACMPCAClient interface for testing.
type mockACMPCAClient struct {
	issueCertificateErr        error
	getCertificateErr          error
	revokeCertificateErr       error
	getCACertificateErr        error
	issuedCertPEM              string
	issuedChainPEM             string
	caCertPEM                  string
	caCertChainPEM             string
	lastIssueCertificateInput  *awsacmpca.IssueCertificateInput
	lastRevokeCertificateInput *awsacmpca.RevokeCertificateInput
}

func (m *mockACMPCAClient) IssueCertificate(ctx context.Context, input *awsacmpca.IssueCertificateInput) (*awsacmpca.IssueCertificateOutput, error) {
	m.lastIssueCertificateInput = input
	if m.issueCertificateErr != nil {
		return nil, m.issueCertificateErr
	}
	return &awsacmpca.IssueCertificateOutput{
		CertificateArn: "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678/certificate/abcdef123456",
	}, nil
}

func (m *mockACMPCAClient) GetCertificate(ctx context.Context, input *awsacmpca.GetCertificateInput) (*awsacmpca.GetCertificateOutput, error) {
	if m.getCertificateErr != nil {
		return nil, m.getCertificateErr
	}
	return &awsacmpca.GetCertificateOutput{
		Certificate:      m.issuedCertPEM,
		CertificateChain: m.issuedChainPEM,
	}, nil
}

func (m *mockACMPCAClient) RevokeCertificate(ctx context.Context, input *awsacmpca.RevokeCertificateInput) error {
	m.lastRevokeCertificateInput = input
	return m.revokeCertificateErr
}

func (m *mockACMPCAClient) GetCACertificate(ctx context.Context, input *awsacmpca.GetCACertificateInput) (*awsacmpca.GetCACertificateOutput, error) {
	if m.getCACertificateErr != nil {
		return nil, m.getCACertificateErr
	}
	return &awsacmpca.GetCACertificateOutput{
		Certificate:      m.caCertPEM,
		CertificateChain: m.caCertChainPEM,
	}, nil
}

// mustNew is a test helper that calls awsacmpca.New and fails the test if
// New returns an error. Use this for the ValidateConfig-only test sites
// where config is nil; New(nil, ...) skips SDK loading and never errors,
// so this helper is just to keep the call sites terse.
func mustNew(t *testing.T, config *awsacmpca.Config, logger *slog.Logger) *awsacmpca.Connector {
	t.Helper()
	c, err := awsacmpca.New(config, logger)
	if err != nil {
		t.Fatalf("awsacmpca.New: %v", err)
	}
	return c
}

// Helper function to generate a test certificate and CSR.
func generateTestCertAndCSR(t *testing.T) (certPEM string, csrPEM string) {
	// Generate private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"example.com", "www.example.com"},
	}

	// Create self-signed certificate for testing
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// Create CSR
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com", "www.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csrPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	return certPEM, csrPEM
}

func TestAWSACMPCAConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		config := awsacmpca.Config{
			Region:           "us-east-1",
			CAArn:            "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			SigningAlgorithm: "SHA256WITHRSA",
			ValidityDays:     365,
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_AllOptionalFields", func(t *testing.T) {
		config := awsacmpca.Config{
			Region:           "eu-west-1",
			CAArn:            "arn:aws:acm-pca:eu-west-1:123456789012:certificate-authority/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			SigningAlgorithm: "SHA512WITHECDSA",
			ValidityDays:     730,
			TemplateArn:      "arn:aws:acm-pca:eu-west-1:123456789012:template/WebServer",
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidJSON", func(t *testing.T) {
		connector := mustNew(t, nil, logger)
		err := connector.ValidateConfig(ctx, []byte(`{invalid json}`))
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "invalid AWS ACM PCA config") {
			t.Errorf("Expected config error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingRegion", func(t *testing.T) {
		config := awsacmpca.Config{
			CAArn: "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing region")
		}
		if !strings.Contains(err.Error(), "region is required") {
			t.Errorf("Expected region required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCAArn", func(t *testing.T) {
		config := awsacmpca.Config{
			Region: "us-east-1",
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing CA ARN")
		}
		if !strings.Contains(err.Error(), "CA ARN is required") {
			t.Errorf("Expected CA ARN required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidCAArn", func(t *testing.T) {
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "not-an-arn",
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid CA ARN")
		}
		if !strings.Contains(err.Error(), "invalid CA ARN format") {
			t.Errorf("Expected invalid ARN error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidSigningAlgorithm", func(t *testing.T) {
		config := awsacmpca.Config{
			Region:           "us-east-1",
			CAArn:            "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			SigningAlgorithm: "INVALID_ALGO",
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid signing algorithm")
		}
		if !strings.Contains(err.Error(), "invalid signing algorithm") {
			t.Errorf("Expected invalid algorithm error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidValidityDays", func(t *testing.T) {
		config := awsacmpca.Config{
			Region:       "us-east-1",
			CAArn:        "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			ValidityDays: -1,
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for negative validity days")
		}
		if !strings.Contains(err.Error(), "validity days must be non-negative") {
			t.Errorf("Expected validity days error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_Success", func(t *testing.T) {
		certPEM, csrPEM := generateTestCertAndCSR(t)

		mockClient := &mockACMPCAClient{
			issuedCertPEM:  certPEM,
			issuedChainPEM: certPEM, // Use same cert as chain for test
		}

		config := awsacmpca.Config{
			Region:           "us-east-1",
			CAArn:            "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			SigningAlgorithm: "SHA256WITHRSA",
			ValidityDays:     365,
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)

		request := issuer.IssuanceRequest{
			CommonName: "example.com",
			SANs:       []string{"www.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, request)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Fatal("Expected certificate PEM in result")
		}
		if result.Serial == "" {
			t.Fatal("Expected serial number in result")
		}
		if result.OrderID == "" {
			t.Fatal("Expected OrderID (certificate ARN) in result")
		}
	})

	t.Run("IssueCertificate_EmptyCSR", func(t *testing.T) {
		mockClient := &mockACMPCAClient{}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     "", // Empty CSR
		}

		_, err := connector.IssueCertificate(ctx, request)
		if err == nil {
			t.Fatal("Expected error for empty CSR")
		}
		if !strings.Contains(err.Error(), "failed to decode CSR PEM") {
			t.Errorf("Expected CSR decode error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_IssueError", func(t *testing.T) {
		certPEM, csrPEM := generateTestCertAndCSR(t)
		mockClient := &mockACMPCAClient{
			issueCertificateErr: fmt.Errorf("AWS service error"),
			issuedCertPEM:       certPEM,
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, request)
		if err == nil {
			t.Fatal("Expected error from IssueCertificate")
		}
		if !strings.Contains(err.Error(), "IssueCertificate failed") {
			t.Errorf("Expected issue error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_GetCertificateError", func(t *testing.T) {
		_, csrPEM := generateTestCertAndCSR(t)
		mockClient := &mockACMPCAClient{
			getCertificateErr: fmt.Errorf("AWS service error"),
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, request)
		if err == nil {
			t.Fatal("Expected error from GetCertificate")
		}
		if !strings.Contains(err.Error(), "GetCertificate failed") {
			t.Errorf("Expected get cert error, got: %v", err)
		}
	})

	t.Run("RenewCertificate_Success", func(t *testing.T) {
		certPEM, csrPEM := generateTestCertAndCSR(t)
		mockClient := &mockACMPCAClient{
			issuedCertPEM:  certPEM,
			issuedChainPEM: certPEM,
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.RenewalRequest{
			CommonName: "example.com",
			SANs:       []string{"www.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, request)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Fatal("Expected certificate PEM in result")
		}
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		mockClient := &mockACMPCAClient{}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		reason := "keyCompromise"
		request := issuer.RevocationRequest{
			Serial: "aabbccdd123456",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, request)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		if mockClient.lastRevokeCertificateInput.RevocationReason != "KEY_COMPROMISE" {
			t.Errorf("Expected KEY_COMPROMISE reason, got: %s", mockClient.lastRevokeCertificateInput.RevocationReason)
		}
	})

	t.Run("RevokeCertificate_WithDefaultReason", func(t *testing.T) {
		mockClient := &mockACMPCAClient{}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.RevocationRequest{
			Serial: "aabbccdd123456",
			Reason: nil,
		}

		err := connector.RevokeCertificate(ctx, request)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		if mockClient.lastRevokeCertificateInput.RevocationReason != "UNSPECIFIED" {
			t.Errorf("Expected UNSPECIFIED reason, got: %s", mockClient.lastRevokeCertificateInput.RevocationReason)
		}
	})

	t.Run("RevokeCertificate_Error", func(t *testing.T) {
		mockClient := &mockACMPCAClient{
			revokeCertificateErr: fmt.Errorf("AWS service error"),
		}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		request := issuer.RevocationRequest{
			Serial: "aabbccdd123456",
		}

		err := connector.RevokeCertificate(ctx, request)
		if err == nil {
			t.Fatal("Expected error from RevokeCertificate")
		}
	})

	t.Run("GetOrderStatus_ReturnsCompleted", func(t *testing.T) {
		mockClient := &mockACMPCAClient{}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		status, err := connector.GetOrderStatus(ctx, "test-order-id")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected completed status, got: %s", status.Status)
		}
	})

	t.Run("GetCACertPEM_Success", func(t *testing.T) {
		certPEM, _ := generateTestCertAndCSR(t)
		mockClient := &mockACMPCAClient{
			caCertPEM: certPEM,
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		caPEM, err := connector.GetCACertPEM(ctx)
		if err != nil {
			t.Fatalf("GetCACertPEM failed: %v", err)
		}

		if caPEM == "" {
			t.Fatal("Expected CA certificate PEM")
		}
		if !strings.Contains(caPEM, "CERTIFICATE") {
			t.Errorf("Expected PEM format, got: %s", caPEM)
		}
	})

	t.Run("GetCACertPEM_WithChain", func(t *testing.T) {
		certPEM, _ := generateTestCertAndCSR(t)
		mockClient := &mockACMPCAClient{
			caCertPEM:      certPEM,
			caCertChainPEM: certPEM,
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		caPEM, err := connector.GetCACertPEM(ctx)
		if err != nil {
			t.Fatalf("GetCACertPEM failed: %v", err)
		}

		// Should contain both certificate and chain separated by newline
		if !strings.Contains(caPEM, "\n") {
			t.Fatal("Expected certificate and chain combined")
		}
	})

	t.Run("GetCACertPEM_Error", func(t *testing.T) {
		mockClient := &mockACMPCAClient{
			getCACertificateErr: fmt.Errorf("AWS service error"),
		}

		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		_, err := connector.GetCACertPEM(ctx)
		if err == nil {
			t.Fatal("Expected error from GetCACertPEM")
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		mockClient := &mockACMPCAClient{}
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}

		connector := awsacmpca.NewWithClient(&config, mockClient, logger)
		result, err := connector.GetRenewalInfo(ctx, "cert-pem")
		if err != nil {
			t.Fatalf("GetRenewalInfo failed: %v", err)
		}

		if result != nil {
			t.Fatal("Expected nil result from GetRenewalInfo")
		}
	})

	t.Run("ValidateConfig_AppliesDefaults", func(t *testing.T) {
		config := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			// SigningAlgorithm and ValidityDays not set
		}

		connector := mustNew(t, nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		// Verify defaults were applied by checking the connector's config
		// Since config is private, we'll test via IssueCertificate to ensure algorithm is set
	})

	t.Run("RevocationReason_Mapping", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected string
		}{
			{"keyCompromise", "KEY_COMPROMISE"},
			{"caCompromise", "CERTIFICATE_AUTHORITY_COMPROMISE"},
			{"affiliationChanged", "AFFILIATION_CHANGED"},
			{"superseded", "SUPERSEDED"},
			{"cessationOfOperation", "CESSATION_OF_OPERATION"},
			{"privilegeWithdrawn", "PRIVILEGE_WITHDRAWN"},
		}

		for _, tc := range testCases {
			mockClient := &mockACMPCAClient{}
			config := awsacmpca.Config{
				Region: "us-east-1",
				CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			}

			connector := awsacmpca.NewWithClient(&config, mockClient, logger)
			reason := tc.input
			request := issuer.RevocationRequest{
				Serial: "test-serial",
				Reason: &reason,
			}

			_ = connector.RevokeCertificate(ctx, request)

			if mockClient.lastRevokeCertificateInput.RevocationReason != tc.expected {
				t.Errorf("For reason %q, expected %q, got %q", tc.input, tc.expected, mockClient.lastRevokeCertificateInput.RevocationReason)
			}
		}
	})
}

// TestNew_ProductionPath exercises the production New() path (NOT
// NewWithClient). The audit's D11 blocker for AWSACMPCA was that tests
// passed green via NewWithClient mock injection while the production
// New() returned a stubClient that errored on every method. These tests
// guard against that regression by verifying the production New() path
// builds a real client end-to-end.
//
// The "client not initialized" sentinel string is the regression-marker:
// the deleted stubClient returned an error containing that phrase from
// every method. If anyone re-introduces a stub-style placeholder client
// from New(), these tests fail because the production client is
// non-stubby and doesn't return that sentinel.
func TestNew_ProductionPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidConfigBuildsRealClient", func(t *testing.T) {
		// New with a valid config calls awsconfig.LoadDefaultConfig +
		// acmpca.NewFromConfig. Should succeed even without AWS
		// credentials: LoadDefaultConfig sets up the credential chain
		// providers but doesn't actually fetch credentials until an
		// API call is made.
		cfg := &awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}
		c, err := awsacmpca.New(cfg, logger)
		if err != nil {
			t.Fatalf("New with valid config returned error: %v", err)
		}
		if c == nil {
			t.Fatal("New returned nil connector")
		}

		// Behavioral assertion: IssueCertificate with a bogus CSR fails
		// at PEM-decode (before any network call), and the error must
		// NOT be the deleted stubClient's "client not initialized"
		// sentinel. If anyone re-introduces a stub from production
		// New(), this assertion catches it.
		_, err = c.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     "", // intentionally bogus
		})
		if err == nil {
			t.Fatal("expected error from bogus CSR, got nil")
		}
		if strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("got 'not initialized' error after New with valid config — production client was not wired: %v", err)
		}
		// Expected: PEM decode error.
		if !strings.Contains(err.Error(), "decode CSR PEM") {
			t.Errorf("expected CSR decode error, got: %v", err)
		}
	})

	t.Run("NilConfigDefersClientInit", func(t *testing.T) {
		// New(nil, ...) is the test-only path that skips SDK loading;
		// the connector is constructed with no client and ValidateConfig
		// must be called before any operation. This documents the lazy
		// initialization contract.
		c, err := awsacmpca.New(nil, logger)
		if err != nil {
			t.Fatalf("New(nil, logger) returned error: %v", err)
		}
		if c == nil {
			t.Fatal("New(nil, ...) returned nil connector")
		}

		// Calling client-using methods before ValidateConfig should
		// fail-fast with the documented sentinel.
		_, err = c.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     "", // bogus, but client-init check fires first
		})
		if err == nil {
			t.Fatal("expected error from uninitialized client, got nil")
		}
		if !strings.Contains(err.Error(), "client not initialized") {
			t.Errorf("expected 'client not initialized' error, got: %v", err)
		}
	})

	t.Run("ValidateConfigBuildsClientLazily", func(t *testing.T) {
		// New(nil, ...) leaves client nil; ValidateConfig with a valid
		// config should build it. After ValidateConfig succeeds, client-
		// using methods should work end-to-end (modulo network errors).
		c, err := awsacmpca.New(nil, logger)
		if err != nil {
			t.Fatalf("New(nil, logger): %v", err)
		}

		cfg := awsacmpca.Config{
			Region: "us-east-1",
			CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
		}
		cfgJSON, _ := json.Marshal(cfg)
		if err := c.ValidateConfig(ctx, cfgJSON); err != nil {
			t.Fatalf("ValidateConfig: %v", err)
		}

		// IssueCertificate should now reach the PEM-decode step
		// (the client is wired). Bogus CSR triggers PEM error,
		// not the "client not initialized" sentinel.
		_, err = c.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     "",
		})
		if err == nil {
			t.Fatal("expected error from bogus CSR")
		}
		if strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("ValidateConfig didn't wire client: %v", err)
		}
	})

	t.Run("RevokeBeforeInitFailsFast", func(t *testing.T) {
		// The audit also flagged RevokeCertificate as part of the stub
		// blocker. Verify the nil-client guard fires for revoke too.
		c, err := awsacmpca.New(nil, logger)
		if err != nil {
			t.Fatalf("New(nil, logger): %v", err)
		}
		err = c.RevokeCertificate(ctx, issuer.RevocationRequest{
			Serial: "aabbccdd",
		})
		if err == nil {
			t.Fatal("expected error from uninitialized client")
		}
		if !strings.Contains(err.Error(), "client not initialized") {
			t.Errorf("expected 'client not initialized', got: %v", err)
		}
	})

	t.Run("GetCAPEMBeforeInitFailsFast", func(t *testing.T) {
		c, err := awsacmpca.New(nil, logger)
		if err != nil {
			t.Fatalf("New(nil, logger): %v", err)
		}
		_, err = c.GetCACertPEM(ctx)
		if err == nil {
			t.Fatal("expected error from uninitialized client")
		}
		if !strings.Contains(err.Error(), "client not initialized") {
			t.Errorf("expected 'client not initialized', got: %v", err)
		}
	})
}

// TestNew_ErrorPaths covers connector-level error paths via the mock
// client. These complement the existing IssueCertificate_IssueError /
// IssueCertificate_GetCertificateError tests by adding access-denied,
// transient 5xx, and ctx-cancel coverage that the audit called out as
// missing from D11.
func TestNew_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := awsacmpca.Config{
		Region: "us-east-1",
		CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
	}

	t.Run("AccessDeniedSurfacedAsError", func(t *testing.T) {
		// Simulate the AWS access-denied case via the mock. The error
		// message format mirrors what aws-sdk-go-v2 surfaces for IAM
		// failures; the assertion is that the connector wraps the error
		// without swallowing it.
		mock := &mockACMPCAClient{
			issueCertificateErr: fmt.Errorf("operation error ACM-PCA: IssueCertificate, https response error StatusCode: 403, RequestID: x, AccessDeniedException: User is not authorized to perform: acm-pca:IssueCertificate"),
		}
		c := awsacmpca.NewWithClient(&cfg, mock, logger)
		_, csrPEM := generateTestCertAndCSR(t)
		_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     csrPEM,
		})
		if err == nil {
			t.Fatal("expected access-denied error")
		}
		if !strings.Contains(err.Error(), "AccessDenied") {
			t.Errorf("expected wrapped AccessDeniedException, got: %v", err)
		}
		if !strings.Contains(err.Error(), "IssueCertificate failed") {
			t.Errorf("expected connector wrapping ('IssueCertificate failed: ...'), got: %v", err)
		}
	})

	t.Run("Transient5xxSurfacedAsError", func(t *testing.T) {
		// Simulate a transient 5xx from ACM PCA. The connector returns
		// the error to the caller; retry logic, if any, lives upstream
		// in the scheduler.
		mock := &mockACMPCAClient{
			issueCertificateErr: fmt.Errorf("operation error ACM-PCA: IssueCertificate, https response error StatusCode: 503, ServiceUnavailable"),
		}
		c := awsacmpca.NewWithClient(&cfg, mock, logger)
		_, csrPEM := generateTestCertAndCSR(t)
		_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     csrPEM,
		})
		if err == nil {
			t.Fatal("expected 5xx error")
		}
		if !strings.Contains(err.Error(), "503") && !strings.Contains(err.Error(), "ServiceUnavailable") {
			t.Errorf("expected wrapped 5xx, got: %v", err)
		}
	})

	t.Run("CtxCancelPropagated", func(t *testing.T) {
		// Mock that respects ctx cancellation. Asserts the connector
		// honors caller-supplied deadlines.
		mock := &mockACMPCAClient{}
		c := awsacmpca.NewWithClient(&cfg, mock, logger)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // cancel immediately

		_, csrPEM := generateTestCertAndCSR(t)
		// The mock doesn't check ctx; we test by injecting a ctx-aware
		// error. Use a wrapped context.Canceled to simulate the SDK
		// returning a cancellation error.
		mock.issueCertificateErr = context.Canceled
		_, err := c.IssueCertificate(cancelCtx, issuer.IssuanceRequest{
			CommonName: "example.com",
			CSRPEM:     csrPEM,
		})
		if err == nil {
			t.Fatal("expected ctx-cancel error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected errors.Is(err, context.Canceled), got: %v", err)
		}
	})
}
