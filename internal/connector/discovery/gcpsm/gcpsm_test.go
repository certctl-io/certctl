package gcpsm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
)

// mockSMClient implements SMClient for testing.
type mockSMClient struct {
	secrets          map[string][]byte
	accessErrors     map[string]error
	listSecretsError error
	listSecretsHook  func(ctx context.Context, project string) ([]SecretEntry, error)
}

func newMockSMClient() *mockSMClient {
	return &mockSMClient{
		secrets:      make(map[string][]byte),
		accessErrors: make(map[string]error),
	}
}

func (m *mockSMClient) ListSecrets(ctx context.Context, project string) ([]SecretEntry, error) {
	if m.listSecretsHook != nil {
		return m.listSecretsHook(ctx, project)
	}

	if m.listSecretsError != nil {
		return nil, m.listSecretsError
	}

	var entries []SecretEntry
	for name := range m.secrets {
		entries = append(entries, SecretEntry{
			Name:   fmt.Sprintf("projects/%s/secrets/%s", project, name),
			Labels: map[string]string{"type": "certificate"},
		})
	}
	return entries, nil
}

func (m *mockSMClient) AccessSecretVersion(ctx context.Context, project, secretName string) ([]byte, error) {
	if err, ok := m.accessErrors[secretName]; ok {
		return nil, err
	}
	if data, ok := m.secrets[secretName]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("secret not found: %s", secretName)
}

// generateTestCertificate generates a self-signed test certificate.
func generateTestCertificate(cn string, expire time.Duration) (*x509.Certificate, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(expire),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"example.com", "*.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse the DER-encoded cert
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// Return both the cert object and the PEM-encoded version
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, pemData, nil
}

// createTempServiceAccountKey creates a temporary service account key file for testing.
func createTempServiceAccountKey() (string, error) {
	tmpfile, err := os.CreateTemp("", "gcpsm-test-*.json")
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()

	// Generate a minimal RSA key for the test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	// Convert to PKCS#8 PEM format
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	// Create a minimal service account key JSON
	keyJSON := fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key": %q,
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`, string(privateKeyPEM))

	_, err = tmpfile.WriteString(keyJSON)
	if err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}

	return tmpfile.Name(), nil
}

func TestValidateConfig_Success(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := New(cfg, slog.Default())
	if err := source.ValidateConfig(); err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}

func TestValidateConfig_MissingProject(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "",
		Credentials: tmpfile,
	}

	source := New(cfg, slog.Default())
	if err := source.ValidateConfig(); err == nil {
		t.Error("expected ValidateConfig to fail with missing project")
	}
}

func TestValidateConfig_MissingCredentials(t *testing.T) {
	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: "",
	}

	source := New(cfg, slog.Default())
	if err := source.ValidateConfig(); err == nil {
		t.Error("expected ValidateConfig to fail with missing credentials")
	}
}

func TestValidateConfig_InvalidCredentialsFile(t *testing.T) {
	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: "/nonexistent/path/to/creds.json",
	}

	source := New(cfg, slog.Default())
	if err := source.ValidateConfig(); err == nil {
		t.Error("expected ValidateConfig to fail with invalid credentials file")
	}
}

func TestDiscover_Success(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	// Generate two test certificates: one valid, one that will cause a parse error
	validCert, validPEM, err := generateTestCertificate("test.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	// Create a mock client with both secrets
	mockClient := newMockSMClient()
	mockClient.secrets["valid-cert"] = validPEM
	mockClient.secrets["invalid-data"] = []byte("not a certificate at all")

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())
	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Should have discovered 1 valid certificate
	if len(report.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(report.Certificates))
	}

	// Should have 1 error (invalid-data)
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(report.Errors))
	}

	// Verify certificate metadata
	entry := report.Certificates[0]
	if entry.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", entry.CommonName)
	}
	if entry.KeyAlgorithm != "RSA" {
		t.Errorf("expected RSA key algorithm, got %s", entry.KeyAlgorithm)
	}
	if entry.KeySize != 2048 {
		t.Errorf("expected 2048-bit key, got %d", entry.KeySize)
	}

	// Verify source path
	if !contains(report.Directories, "gcp-sm://test-project/") {
		t.Errorf("expected directory 'gcp-sm://test-project/', got %v", report.Directories)
	}

	// Verify fingerprint calculation
	if entry.FingerprintSHA256 == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Verify SANs
	if !contains(entry.SANs, "example.com") || !contains(entry.SANs, "*.example.com") {
		t.Errorf("expected DNS SANs, got %v", entry.SANs)
	}

	// Verify cert serial number matches
	if entry.SerialNumber != fmt.Sprintf("%x", validCert.SerialNumber) {
		t.Errorf("serial number mismatch: expected %x, got %s", validCert.SerialNumber, entry.SerialNumber)
	}
}

func TestDiscover_EmptySecrets(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	mockClient := newMockSMClient()

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())
	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(report.Certificates))
	}
}

func TestDiscover_ListSecretsError(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	// Create a mock client that fails on ListSecrets
	mockClient := newMockSMClient()
	mockClient.listSecretsError = fmt.Errorf("simulated ListSecrets error")

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())
	report, err := source.Discover(context.Background())

	// Should return error
	if err == nil {
		t.Error("expected Discover to fail when ListSecrets fails")
	}

	// But should still return a report with the error recorded
	if report == nil || len(report.Errors) == 0 {
		t.Error("expected error to be recorded in report")
	}
}

func TestDiscover_AccessSecretError(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	mockClient := newMockSMClient()
	mockClient.accessErrors["broken-secret"] = fmt.Errorf("simulated AccessSecretVersion error")
	// Add to list via the hook since we need it listed but access should fail
	mockClient.listSecretsHook = func(ctx context.Context, project string) ([]SecretEntry, error) {
		return []SecretEntry{
			{Name: fmt.Sprintf("projects/%s/secrets/broken-secret", project), Labels: map[string]string{"type": "certificate"}},
		}, nil
	}

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())
	report, _ := source.Discover(context.Background())

	// Should record error but not fail the whole operation
	if len(report.Errors) == 0 {
		t.Error("expected error to be recorded in report")
	}
	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(report.Certificates))
	}
}

func TestDiscover_AgentIDAndSourcePath(t *testing.T) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	_, certPEM, err := generateTestCertificate("test.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	mockClient := newMockSMClient()
	mockClient.secrets["my-cert"] = certPEM

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "my-gcp-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())
	report, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify agent ID
	if report.AgentID != "cloud-gcp-sm" {
		t.Errorf("expected agent ID 'cloud-gcp-sm', got '%s'", report.AgentID)
	}

	// Verify source path format
	if len(report.Certificates) > 0 {
		entry := report.Certificates[0]
		expectedPath := "gcp-sm://my-gcp-project/my-cert"
		if entry.SourcePath != expectedPath {
			t.Errorf("expected source path '%s', got '%s'", expectedPath, entry.SourcePath)
		}
	}
}

func TestParseCertificate_PEM(t *testing.T) {
	_, certPEM, err := generateTestCertificate("test.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Errorf("failed to parse PEM certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.com" {
		t.Errorf("expected CN 'test.com', got '%s'", cert.Subject.CommonName)
	}
}

func TestParseCertificate_Base64DER(t *testing.T) {
	_, certPEM, err := generateTestCertificate("test.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	// Decode PEM and re-encode as base64 DER
	block, _ := pem.Decode(certPEM)
	base64DER := []byte(base64.StdEncoding.EncodeToString(block.Bytes))

	cert, err := parseCertificate(base64DER)
	if err != nil {
		t.Errorf("failed to parse base64 DER certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.com" {
		t.Errorf("expected CN 'test.com', got '%s'", cert.Subject.CommonName)
	}
}

func TestParseCertificate_RawDER(t *testing.T) {
	_, certPEM, err := generateTestCertificate("test.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	// Decode PEM to get raw DER
	block, _ := pem.Decode(certPEM)

	cert, err := parseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("failed to parse raw DER certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.com" {
		t.Errorf("expected CN 'test.com', got '%s'", cert.Subject.CommonName)
	}
}

func TestParseCertificate_Invalid(t *testing.T) {
	invalidData := []byte("not a certificate at all")

	_, err := parseCertificate(invalidData)
	if err == nil {
		t.Error("expected parseCertificate to fail on invalid data")
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// TestSourceImplementsInterface ensures Source implements domain.DiscoverySource
func TestSourceImplementsInterface(t *testing.T) {
	var _ domain.DiscoverySource = (*Source)(nil)
}

// BenchmarkDiscover provides basic performance metrics for discovery
func BenchmarkDiscover(b *testing.B) {
	tmpfile, err := createTempServiceAccountKey()
	if err != nil {
		b.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(tmpfile)

	// Generate 10 test certificates
	mockClient := newMockSMClient()
	for i := 0; i < 10; i++ {
		_, certPEM, err := generateTestCertificate(fmt.Sprintf("test%d.example.com", i), 24*time.Hour)
		if err != nil {
			b.Fatalf("failed to generate test certificate: %v", err)
		}
		mockClient.secrets[fmt.Sprintf("cert-%d", i)] = certPEM
	}

	cfg := &config.GCPSecretMgrDiscoveryConfig{
		Project:     "test-project",
		Credentials: tmpfile,
	}

	source := NewWithClient(cfg, mockClient, slog.Default())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := source.Discover(context.Background())
		if err != nil {
			b.Fatalf("Discover failed: %v", err)
		}
	}
}
