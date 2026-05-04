package awssm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
)

// mockSMClient is a mock implementation of SMClient for testing.
type mockSMClient struct {
	secrets        map[string]string         // secret name -> secret value
	secretMetadata map[string]SecretMetadata // secret name -> metadata
	listError      error
	getErrors      map[string]error // secret name -> error
}

func newMockSMClient() *mockSMClient {
	return &mockSMClient{
		secrets:        make(map[string]string),
		secretMetadata: make(map[string]SecretMetadata),
		getErrors:      make(map[string]error),
	}
}

func (m *mockSMClient) ListSecrets(ctx context.Context, filters string) ([]SecretMetadata, error) {
	if m.listError != nil {
		return nil, m.listError
	}

	var result []SecretMetadata
	for _, meta := range m.secretMetadata {
		result = append(result, meta)
	}
	return result, nil
}

func (m *mockSMClient) GetSecretValue(ctx context.Context, secretID string) (string, error) {
	if err, ok := m.getErrors[secretID]; ok {
		return "", err
	}
	return m.secrets[secretID], nil
}

// generateTestCert generates a test certificate with the given subject and returns it as PEM.
func generateTestCert(commonName string, sans []string) (string, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     sans,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", nil, err
	}

	return string(certPEM), cert, nil
}

func TestSource_ValidateConfig_Success(t *testing.T) {
	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "us-east-1",
	}
	source := NewWithClient(cfg, newMockSMClient(), nil)

	err := source.ValidateConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSource_ValidateConfig_MissingRegion(t *testing.T) {
	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "",
	}
	source := NewWithClient(cfg, newMockSMClient(), nil)

	err := source.ValidateConfig()
	if err == nil {
		t.Fatal("expected error for missing region")
	}
	if err.Error() != "aws secrets manager region is required" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSource_Name(t *testing.T) {
	source := NewWithClient(&config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}, newMockSMClient(), nil)
	if source.Name() != "AWS Secrets Manager" {
		t.Errorf("expected 'AWS Secrets Manager', got %s", source.Name())
	}
}

func TestSource_Type(t *testing.T) {
	source := NewWithClient(&config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}, newMockSMClient(), nil)
	if source.Type() != "aws-sm" {
		t.Errorf("expected 'aws-sm', got %s", source.Type())
	}
}

func TestSource_Discover_Success(t *testing.T) {
	// Generate test certificates
	certPEM1, _, err := generateTestCert("test1.example.com", []string{"www.test1.example.com"})
	if err != nil {
		t.Fatalf("failed to generate test cert 1: %v", err)
	}

	certPEM2, _, err := generateTestCert("test2.example.com", []string{"mail.test2.example.com", "smtp.test2.example.com"})
	if err != nil {
		t.Fatalf("failed to generate test cert 2: %v", err)
	}

	// Set up mock client
	mockClient := newMockSMClient()
	mockClient.secrets["cert1"] = certPEM1
	mockClient.secrets["cert2"] = certPEM2
	mockClient.secretMetadata["cert1"] = SecretMetadata{
		Name: "cert1",
		ARN:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:cert1",
		Tags: map[string]string{"type": "certificate"},
	}
	mockClient.secretMetadata["cert2"] = SecretMetadata{
		Name: "cert2",
		ARN:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:cert2",
		Tags: map[string]string{"type": "certificate"},
	}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled:   true,
		Region:    "us-east-1",
		TagFilter: "type=certificate",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.AgentID != "cloud-aws-sm" {
		t.Errorf("expected agent ID 'cloud-aws-sm', got %s", report.AgentID)
	}

	if len(report.Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(report.Certificates))
	}

	// Find the certificates by common name (order is not guaranteed)
	var cert1, cert2 *domain.DiscoveredCertEntry
	for i := range report.Certificates {
		if report.Certificates[i].CommonName == "test1.example.com" {
			cert1 = &report.Certificates[i]
		} else if report.Certificates[i].CommonName == "test2.example.com" {
			cert2 = &report.Certificates[i]
		}
	}

	if cert1 == nil {
		t.Fatalf("certificate with CN 'test1.example.com' not found")
	}
	if cert2 == nil {
		t.Fatalf("certificate with CN 'test2.example.com' not found")
	}

	// Check first certificate
	if len(cert1.SANs) != 1 || cert1.SANs[0] != "www.test1.example.com" {
		t.Errorf("unexpected SANs for cert1: %v", cert1.SANs)
	}

	// Check second certificate has 2 SANs
	if len(cert2.SANs) != 2 {
		t.Errorf("expected 2 SANs for cert2, got %d", len(cert2.SANs))
	}

	// Check source path format for first cert
	if cert1.SourcePath != "aws-sm://us-east-1/cert1" {
		t.Errorf("unexpected source path for cert1: %s", cert1.SourcePath)
	}

	// Check that scan duration is reasonable
	if report.ScanDurationMs < 0 {
		t.Errorf("unexpected negative scan duration: %d", report.ScanDurationMs)
	}
}

func TestSource_Discover_EmptyResults(t *testing.T) {
	mockClient := newMockSMClient()

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "us-east-1",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.AgentID != "cloud-aws-sm" {
		t.Errorf("expected agent ID 'cloud-aws-sm', got %s", report.AgentID)
	}

	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(report.Certificates))
	}

	if len(report.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(report.Errors))
	}
}

func TestSource_Discover_ListError(t *testing.T) {
	mockClient := newMockSMClient()
	mockClient.listError = fmt.Errorf("ListSecrets failed")

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "us-east-1",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover should not return error for list failure: %v", err)
	}

	// Should have recorded the error but still return a report
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(report.Errors))
	}
}

func TestSource_Discover_GetSecretError(t *testing.T) {
	// Generate test certificate
	certPEM, _, err := generateTestCert("good.example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	mockClient := newMockSMClient()
	mockClient.secrets["good-secret"] = certPEM
	mockClient.secretMetadata["good-secret"] = SecretMetadata{
		Name: "good-secret",
		Tags: map[string]string{"type": "certificate"},
	}
	mockClient.secrets["bad-secret"] = "dummy"
	mockClient.secretMetadata["bad-secret"] = SecretMetadata{
		Name: "bad-secret",
		Tags: map[string]string{"type": "certificate"},
	}
	mockClient.getErrors["bad-secret"] = fmt.Errorf("GetSecretValue failed")

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "us-east-1",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 1 good certificate and 1 error
	if len(report.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(report.Certificates))
	}
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(report.Errors))
	}
}

func TestSource_Discover_DERCert(t *testing.T) {
	// Generate test certificate in DER format, then base64 encode it
	_, parsedCert, err := generateTestCert("der.example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	derEncoded := base64.StdEncoding.EncodeToString(parsedCert.Raw)

	mockClient := newMockSMClient()
	mockClient.secrets["der-cert"] = derEncoded
	mockClient.secretMetadata["der-cert"] = SecretMetadata{
		Name: "der-cert",
		Tags: map[string]string{"type": "certificate"},
	}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "us-east-1",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(report.Certificates))
	}

	if report.Certificates[0].CommonName != "der.example.com" {
		t.Errorf("expected CN 'der.example.com', got %s", report.Certificates[0].CommonName)
	}
}

func TestSource_Discover_AgentIDAndSourcePath(t *testing.T) {
	// Generate test certificate
	certPEM, _, err := generateTestCert("source-path.example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	mockClient := newMockSMClient()
	mockClient.secrets["my-secret"] = certPEM
	mockClient.secretMetadata["my-secret"] = SecretMetadata{
		Name: "my-secret",
		Tags: map[string]string{"type": "certificate"},
	}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Enabled: true,
		Region:  "eu-west-1",
	}
	source := NewWithClient(cfg, mockClient, nil)

	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.AgentID != "cloud-aws-sm" {
		t.Errorf("expected agent ID 'cloud-aws-sm', got %s", report.AgentID)
	}

	if report.Certificates[0].SourcePath != "aws-sm://eu-west-1/my-secret" {
		t.Errorf("expected source path 'aws-sm://eu-west-1/my-secret', got %s", report.Certificates[0].SourcePath)
	}
}
