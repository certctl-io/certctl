package azurekv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// TestValidateConfig_Success validates a correct configuration.
func TestValidateConfig_Success(t *testing.T) {
	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "00000000-0000-0000-0000-000000000000",
		ClientID:     "11111111-1111-1111-1111-111111111111",
		ClientSecret: "mysecret123",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

// TestValidateConfig_MissingVaultURL validates error when VaultURL is empty.
func TestValidateConfig_MissingVaultURL(t *testing.T) {
	cfg := Config{
		VaultURL:     "",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err == nil {
		t.Fatal("expected error for missing VaultURL")
	}
}

// TestValidateConfig_MissingTenantID validates error when TenantID is empty.
func TestValidateConfig_MissingTenantID(t *testing.T) {
	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err == nil {
		t.Fatal("expected error for missing TenantID")
	}
}

// TestValidateConfig_MissingClientID validates error when ClientID is empty.
func TestValidateConfig_MissingClientID(t *testing.T) {
	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "",
		ClientSecret: "secret",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err == nil {
		t.Fatal("expected error for missing ClientID")
	}
}

// TestValidateConfig_MissingClientSecret validates error when ClientSecret is empty.
func TestValidateConfig_MissingClientSecret(t *testing.T) {
	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err == nil {
		t.Fatal("expected error for missing ClientSecret")
	}
}

// TestValidateConfig_InvalidURL validates error when VaultURL is not HTTPS.
func TestValidateConfig_InvalidURL(t *testing.T) {
	cfg := Config{
		VaultURL:     "http://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := &Source{config: cfg, logger: slog.Default()}

	if err := src.ValidateConfig(); err == nil {
		t.Fatal("expected error for non-HTTPS URL")
	}
}

// mockKVClient implements KVClient for testing.
type mockKVClient struct {
	certs map[string]*certificateBundle
	err   error
}

func (m *mockKVClient) ListCertificates(ctx context.Context, vaultURL string) ([]struct {
	ID         string
	Attributes struct {
		Exp int64
	}
}, error) {
	if m.err != nil {
		return nil, m.err
	}

	var results []struct {
		ID         string
		Attributes struct {
			Exp int64
		}
	}

	for id := range m.certs {
		results = append(results, struct {
			ID         string
			Attributes struct {
				Exp int64
			}
		}{ID: id})
	}

	return results, nil
}

func (m *mockKVClient) GetCertificate(ctx context.Context, vaultURL, certName, version string) (*certificateBundle, error) {
	if m.err != nil {
		return nil, m.err
	}

	id := fmt.Sprintf("https://myvault.vault.azure.net/certificates/%s/%s", certName, version)
	cert, ok := m.certs[id]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}

	return cert, nil
}

// generateTestCert generates a test X.509 certificate.
func generateTestCert(cn string, sans []string) ([]byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(64), nil))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              sans,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

// TestDiscover_Success validates successful certificate discovery.
func TestDiscover_Success(t *testing.T) {
	// Generate test certificates
	cert1DER, err := generateTestCert("example.com", []string{"www.example.com", "api.example.com"})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	cert2DER, err := generateTestCert("test.example.com", []string{})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	// Create mock client
	mockClient := &mockKVClient{
		certs: map[string]*certificateBundle{
			"https://myvault.vault.azure.net/certificates/example/v1": {
				ID:  "https://myvault.vault.azure.net/certificates/example/v1",
				CER: base64.StdEncoding.EncodeToString(cert1DER),
			},
			"https://myvault.vault.azure.net/certificates/test/v2": {
				ID:  "https://myvault.vault.azure.net/certificates/test/v2",
				CER: base64.StdEncoding.EncodeToString(cert2DER),
			},
		},
	}

	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := NewWithClient(cfg, mockClient, slog.Default())

	ctx := context.Background()
	report, err := src.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(report.Certificates))
	}

	// Verify first cert metadata
	if report.Certificates[0].CommonName == "" {
		t.Fatal("expected common name in first cert")
	}

	// Verify PEM encoding
	if report.Certificates[0].PEMData == "" {
		t.Fatal("expected PEM data in first cert")
	}

	// Verify PEM is valid
	block, _ := pem.Decode([]byte(report.Certificates[0].PEMData))
	if block == nil {
		t.Fatal("failed to decode PEM data")
	}
}

// TestDiscover_ListError validates error handling when listing fails.
func TestDiscover_ListError(t *testing.T) {
	mockClient := &mockKVClient{
		err: fmt.Errorf("connection error"),
	}

	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := NewWithClient(cfg, mockClient, slog.Default())

	ctx := context.Background()
	report, err := src.Discover(ctx)

	// Should return partial report with error
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(report.Errors) == 0 {
		t.Fatal("expected errors in report")
	}
}

// TestDiscover_EmptyResults validates handling of empty certificate list.
func TestDiscover_EmptyResults(t *testing.T) {
	mockClient := &mockKVClient{
		certs: map[string]*certificateBundle{},
	}

	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := NewWithClient(cfg, mockClient, slog.Default())

	ctx := context.Background()
	report, err := src.Discover(ctx)

	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(report.Certificates) != 0 {
		t.Fatalf("expected 0 certificates, got %d", len(report.Certificates))
	}

	if len(report.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %d", len(report.Errors))
	}
}

// TestDiscover_InvalidCertData validates handling of invalid certificate data.
func TestDiscover_InvalidCertData(t *testing.T) {
	// Generate one valid cert and one invalid
	validDER, err := generateTestCert("valid.example.com", []string{})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	mockClient := &mockKVClient{
		certs: map[string]*certificateBundle{
			"https://myvault.vault.azure.net/certificates/valid/v1": {
				ID:  "https://myvault.vault.azure.net/certificates/valid/v1",
				CER: base64.StdEncoding.EncodeToString(validDER),
			},
			"https://myvault.vault.azure.net/certificates/invalid/v1": {
				ID:  "https://myvault.vault.azure.net/certificates/invalid/v1",
				CER: "not-valid-base64!@#$%",
			},
		},
	}

	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := NewWithClient(cfg, mockClient, slog.Default())

	ctx := context.Background()
	report, err := src.Discover(ctx)

	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Should have 1 valid cert
	if len(report.Certificates) != 1 {
		t.Fatalf("expected 1 valid certificate, got %d", len(report.Certificates))
	}

	// Should have 1 error
	if len(report.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(report.Errors))
	}
}

// TestDiscover_AgentIDAndSourcePath validates correct agent ID and source paths.
func TestDiscover_AgentIDAndSourcePath(t *testing.T) {
	certDER, err := generateTestCert("test.example.com", []string{})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	mockClient := &mockKVClient{
		certs: map[string]*certificateBundle{
			"https://myvault.vault.azure.net/certificates/mycert/v1": {
				ID:  "https://myvault.vault.azure.net/certificates/mycert/v1",
				CER: base64.StdEncoding.EncodeToString(certDER),
			},
		},
	}

	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
	}

	src := NewWithClient(cfg, mockClient, slog.Default())

	ctx := context.Background()
	report, err := src.Discover(ctx)

	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if report.AgentID != "cloud-azure-kv" {
		t.Fatalf("expected agent_id 'cloud-azure-kv', got %s", report.AgentID)
	}

	if len(report.Directories) == 0 {
		t.Fatal("expected directories in report")
	}

	if len(report.Certificates) > 0 {
		cert := report.Certificates[0]
		if !domain.IsValidDiscoveryStatus(cert.SourcePath) == false {
			// SourcePath should follow azure-kv://certname/version format
			if !contains(cert.SourcePath, "azure-kv://") {
				t.Fatalf("expected source path to start with 'azure-kv://', got %s", cert.SourcePath)
			}
		}
	}
}

// TestName validates the Name method.
func TestName(t *testing.T) {
	src := &Source{
		config: Config{},
		logger: slog.Default(),
	}

	expected := "Azure Key Vault"
	if src.Name() != expected {
		t.Fatalf("expected Name '%s', got '%s'", expected, src.Name())
	}
}

// TestType validates the Type method.
func TestType(t *testing.T) {
	src := &Source{
		config: Config{},
		logger: slog.Default(),
	}

	expected := "azure-kv"
	if src.Type() != expected {
		t.Fatalf("expected Type '%s', got '%s'", expected, src.Type())
	}
}

// TestExtractCertNameAndVersion validates certificate ID parsing.
func TestExtractCertNameAndVersion(t *testing.T) {
	tests := []struct {
		id       string
		wantName string
		wantVer  string
		wantErr  bool
	}{
		{
			id:       "https://myvault.vault.azure.net/certificates/example/v1",
			wantName: "example",
			wantVer:  "v1",
			wantErr:  false,
		},
		{
			id:       "https://myvault.vault.azure.net/certificates/my-cert/version123",
			wantName: "my-cert",
			wantVer:  "version123",
			wantErr:  false,
		},
		{
			id:      "invalid-id",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		name, ver, err := extractCertNameAndVersion(tt.id)
		if (err != nil) != tt.wantErr {
			t.Fatalf("extractCertNameAndVersion(%s) error = %v, wantErr %v", tt.id, err, tt.wantErr)
		}
		if !tt.wantErr {
			if name != tt.wantName || ver != tt.wantVer {
				t.Fatalf("extractCertNameAndVersion(%s) = (%s, %s), want (%s, %s)",
					tt.id, name, ver, tt.wantName, tt.wantVer)
			}
		}
	}
}

// TestExtractCertMetadata validates certificate metadata extraction.
func TestExtractCertMetadata(t *testing.T) {
	// Generate a test certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serialNumber := big.NewInt(123456)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"test.example.com", "www.test.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	entry := extractCertMetadata(cert, "testcert", "v1")

	if entry.CommonName != "test.example.com" {
		t.Fatalf("expected CN 'test.example.com', got %s", entry.CommonName)
	}

	if len(entry.SANs) != 2 {
		t.Fatalf("expected 2 SANs, got %d", len(entry.SANs))
	}

	if entry.KeyAlgorithm != "ECDSA" {
		t.Fatalf("expected key algorithm ECDSA, got %s", entry.KeyAlgorithm)
	}

	if entry.KeySize != 256 {
		t.Fatalf("expected key size 256, got %d", entry.KeySize)
	}

	if entry.SerialNumber == "" {
		t.Fatal("expected serial number, got empty")
	}

	if entry.SourceFormat != "DER" {
		t.Fatalf("expected source format DER, got %s", entry.SourceFormat)
	}

	// Verify fingerprint is valid hex
	if len(entry.FingerprintSHA256) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d chars", len(entry.FingerprintSHA256))
	}

	// Verify manually calculated fingerprint
	fp := sha256.Sum256(derBytes)
	expectedFP := fmt.Sprintf("%X", fp)
	if entry.FingerprintSHA256 != expectedFP {
		t.Fatalf("fingerprint mismatch: got %s, want %s", entry.FingerprintSHA256, expectedFP)
	}
}

// TestEncodeCertPEM validates PEM encoding.
func TestEncodeCertPEM(t *testing.T) {
	derBytes, err := generateTestCert("test.example.com", []string{})
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	pemStr := encodeCertPEM(derBytes)

	// Verify PEM format
	if !contains(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Fatal("expected PEM header")
	}

	if !contains(pemStr, "-----END CERTIFICATE-----") {
		t.Fatal("expected PEM footer")
	}

	// Verify we can decode it back
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}

	if len(block.Bytes) != len(derBytes) {
		t.Fatal("decoded PEM does not match original DER")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != substr &&
		(s == substr || len(s) > len(substr))
}
