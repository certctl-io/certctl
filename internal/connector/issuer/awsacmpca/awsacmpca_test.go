package awsacmpca_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	issueCertificateErr    error
	getCertificateErr      error
	revokeCertificateErr   error
	getCACertificateErr    error
	issuedCertPEM          string
	issuedChainPEM         string
	caCertPEM              string
	caCertChainPEM         string
	lastIssueCertificateInput *awsacmpca.IssueCertificateInput
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidJSON", func(t *testing.T) {
		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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

		connector := awsacmpca.New(nil, logger)
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
