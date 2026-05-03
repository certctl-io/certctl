package azurekv_test

// Rank 5 of the 2026-05-03 Infisical deep-research deliverable
// (cowork/infisical-deep-research-results.md Part 5). Happy-path tests
// for the Azure Key Vault target connector. Mirrors the awsacm_test.go
// shape so cross-cloud regressions are bisectable side-by-side.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/azurekv"
)

// mockKeyVaultClient fakes the KeyVaultClient interface seam.
type mockKeyVaultClient struct {
	mu sync.Mutex

	importCalls       []*azurekv.ImportCertificateInput
	getCalls          []*azurekv.GetCertificateInput
	listVersionsCalls []*azurekv.ListVersionsInput

	importOutput *azurekv.ImportCertificateOutput
	importErr    error
	getOutput    *azurekv.GetCertificateOutput
	getErr       error
	listOutput   *azurekv.ListVersionsOutput
	listErr      error

	rollbackImportErr error // injected on the SECOND import call
}

func (m *mockKeyVaultClient) ImportCertificate(ctx context.Context, in *azurekv.ImportCertificateInput) (*azurekv.ImportCertificateOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.importCalls = append(m.importCalls, in)
	if len(m.importCalls) > 1 && m.rollbackImportErr != nil {
		return nil, m.rollbackImportErr
	}
	if m.importErr != nil {
		return nil, m.importErr
	}
	if m.importOutput != nil {
		return m.importOutput, nil
	}
	return &azurekv.ImportCertificateOutput{
		VersionID: "01234567890abcdef01234567890abcd",
		KID:       "https://test-vault.vault.azure.net/certificates/" + in.CertificateName + "/01234567890abcdef01234567890abcd",
	}, nil
}

func (m *mockKeyVaultClient) GetCertificate(ctx context.Context, in *azurekv.GetCertificateInput) (*azurekv.GetCertificateOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls = append(m.getCalls, in)
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.getOutput != nil {
		return m.getOutput, nil
	}
	return &azurekv.GetCertificateOutput{}, nil
}

func (m *mockKeyVaultClient) ListVersions(ctx context.Context, in *azurekv.ListVersionsInput) (*azurekv.ListVersionsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listVersionsCalls = append(m.listVersionsCalls, in)
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listOutput != nil {
		return m.listOutput, nil
	}
	return &azurekv.ListVersionsOutput{}, nil
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// generateTestCert creates a self-signed ECDSA P-256 cert + key for tests.
// Mirrors the awsacm test helper but emits the cert+key as separate
// PEM strings (the connector handles the PFX wrapping internally).
// Returns (certPEM, keyPEM, derBytes, serial).
func generateTestCert(t *testing.T, cn string) (certPEM, keyPEM string, derBytes []byte, serial string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serialNum, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serialNum,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	derBytes = der
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	hex := fmt.Sprintf("%x", serialNum)
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	serial = b.String()
	return
}

func TestAzureKV_ValidateConfig_Success(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	cfg := azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo-cert",
	}
	raw, _ := json.Marshal(cfg)
	if err := c.ValidateConfig(ctx, raw); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
}

func TestAzureKV_ValidateConfig_MissingVaultURL(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	raw, _ := json.Marshal(azurekv.Config{CertificateName: "x"})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "vault_url is required") {
		t.Errorf("expected vault_url-required error; got %v", err)
	}
}

func TestAzureKV_ValidateConfig_MalformedVaultURL(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	raw, _ := json.Marshal(azurekv.Config{
		VaultURL:        "http://not-https",
		CertificateName: "demo",
	})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "vault_url malformed") {
		t.Errorf("expected vault_url-malformed error; got %v", err)
	}
}

func TestAzureKV_ValidateConfig_MissingCertName(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	raw, _ := json.Marshal(azurekv.Config{VaultURL: "https://x.vault.azure.net"})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "certificate_name is required") {
		t.Errorf("expected cert-name-required error; got %v", err)
	}
}

func TestAzureKV_ValidateConfig_InvalidCredentialMode(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	raw, _ := json.Marshal(azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
		CredentialMode:  "invalid-mode",
	})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "credential_mode invalid") {
		t.Errorf("expected credential_mode-invalid error; got %v", err)
	}
}

func TestAzureKV_ValidateConfig_RejectsReservedTags(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(nil, &mockKeyVaultClient{}, quietTestLogger())
	raw, _ := json.Marshal(azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
		Tags:            map[string]string{"certctl-managed-by": "spoofed"},
	})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "reserved provenance key") {
		t.Errorf("expected reserved-key rejection; got %v", err)
	}
}

func TestAzureKV_DeployCertificate_FreshImport(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, derBytes, serial := generateTestCert(t, "fresh.example.com")

	mock := &mockKeyVaultClient{
		// Snapshot read returns NotFound-equivalent (empty CER).
		// Post-verify returns the CER bytes of the cert we just imported.
		getOutput: &azurekv.GetCertificateOutput{
			VersionID: "01234567890abcdef01234567890abcd",
			Serial:    serial,
			CERBytes:  derBytes,
		},
	}
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "fresh-cert",
	}
	c := azurekv.NewWithClient(cfg, mock, quietTestLogger())

	res, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-fresh"},
	})
	if err != nil {
		t.Fatalf("DeployCertificate: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true")
	}
	if res.DeploymentID == "" {
		t.Errorf("expected version ID populated")
	}
	if !strings.HasPrefix(res.TargetAddress, "https://test-vault.vault.azure.net/certificates/fresh-cert/") {
		t.Errorf("expected KID URI in TargetAddress; got %s", res.TargetAddress)
	}
	if len(mock.importCalls) != 1 {
		t.Errorf("expected exactly 1 ImportCertificate call; got %d", len(mock.importCalls))
	}
	// PFX is the wire format; assert the import call carries non-empty PFX bytes.
	if mock.importCalls[0].PFXBase64 == "" {
		t.Error("expected PFXBase64 populated on import call")
	}
	// Provenance tags applied.
	if mock.importCalls[0].Tags["certctl-managed-by"] != "certctl" {
		t.Error("expected certctl-managed-by=certctl provenance tag")
	}
	if mock.importCalls[0].Tags["certctl-certificate-id"] != "mc-fresh" {
		t.Error("expected certctl-certificate-id provenance tag")
	}
}

func TestAzureKV_DeployCertificate_RollbackOnSerialMismatch(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _, _ := generateTestCert(t, "mismatch.example.com")
	_, _, snapshotDER, _ := generateTestCert(t, "snapshot.example.com")

	// Snapshot returns previous version's bytes; post-verify returns
	// a serial that doesn't match the cert we just imported → trigger
	// rollback.
	mock := &mockKeyVaultClient{
		getOutput: &azurekv.GetCertificateOutput{
			Serial:   "ff:ff:ff:ff",
			CERBytes: snapshotDER,
		},
	}
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "rollback-cert",
	}
	c := azurekv.NewWithClient(cfg, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-rollback"},
	})
	if err == nil {
		t.Fatal("expected error on serial mismatch")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected error to mention rollback; got %v", err)
	}
	// Two import calls: initial + rollback.
	if len(mock.importCalls) != 2 {
		t.Errorf("expected 2 import calls (initial + rollback); got %d", len(mock.importCalls))
	}
}

func TestAzureKV_DeployCertificate_EmptyKey(t *testing.T) {
	ctx := context.Background()
	certPEM, _, _, _ := generateTestCert(t, "nokey.example.com")
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
	}
	c := azurekv.NewWithClient(cfg, &mockKeyVaultClient{}, quietTestLogger())
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  "",
	})
	if err == nil || !strings.Contains(err.Error(), "key_pem is required") {
		t.Errorf("expected key-required error; got %v", err)
	}
}

func TestAzureKV_DeployCertificate_NoClient(t *testing.T) {
	ctx := context.Background()
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
	}
	c := azurekv.NewWithClient(cfg, nil, quietTestLogger())
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{CertPEM: "x", KeyPEM: "y"})
	if err == nil || !strings.Contains(err.Error(), "client not initialized") {
		t.Errorf("expected client-not-initialized; got %v", err)
	}
}

func TestAzureKV_ValidateOnly_NotSupported(t *testing.T) {
	ctx := context.Background()
	c := azurekv.NewWithClient(&azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
	}, &mockKeyVaultClient{}, quietTestLogger())
	err := c.ValidateOnly(ctx, target.DeploymentRequest{})
	if !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("expected ErrValidateOnlyNotSupported; got %v", err)
	}
}

func TestAzureKV_ValidateDeployment_SerialMatch(t *testing.T) {
	ctx := context.Background()
	mock := &mockKeyVaultClient{
		getOutput: &azurekv.GetCertificateOutput{Serial: "ab:cd:01"},
	}
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
	}
	c := azurekv.NewWithClient(cfg, mock, quietTestLogger())
	res, err := c.ValidateDeployment(ctx, target.ValidationRequest{Serial: "ab:cd:01"})
	if err != nil {
		t.Fatalf("ValidateDeployment: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid=true; got %+v", res)
	}
}

func TestAzureKV_ValidateDeployment_SerialMismatch(t *testing.T) {
	ctx := context.Background()
	mock := &mockKeyVaultClient{
		getOutput: &azurekv.GetCertificateOutput{Serial: "00:00"},
	}
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "demo",
	}
	c := azurekv.NewWithClient(cfg, mock, quietTestLogger())
	res, err := c.ValidateDeployment(ctx, target.ValidationRequest{Serial: "ab:cd:01"})
	if err != nil {
		t.Fatalf("ValidateDeployment: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid=false on serial mismatch; got %+v", res)
	}
}

// TestAzureKV_DeployCertificate_AzureSDKError_Surfaced pins that an
// underlying SDK error from the SDK client (e.g. 403 Forbidden, 404
// NotFound, 429 Throttled) bubbles up through the connector's wrap
// layer cleanly. Mirrors the AWS ACM failure-test shape — the Azure
// SDK uses azcore.ResponseError as its typed-error shape but Key
// Vault wraps it as a generic error in many cases; we test the
// generic-error wrap chain rather than reach into azcore.
func TestAzureKV_DeployCertificate_AzureSDKError_Surfaced(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _, _ := generateTestCert(t, "sdkerr.example.com")

	mock := &mockKeyVaultClient{
		importErr: errors.New("azcertificates: 403 Forbidden — caller does not have certificates/import permission"),
	}
	cfg := &azurekv.Config{
		VaultURL:        "https://test-vault.vault.azure.net",
		CertificateName: "sdkerr",
	}
	c := azurekv.NewWithClient(cfg, mock, quietTestLogger())
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM, KeyPEM: keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-sdkerr"},
	})
	if err == nil {
		t.Fatal("expected SDK error")
	}
	if !strings.Contains(err.Error(), "ImportCertificate failed") {
		t.Errorf("expected adapter wrap framing; got %v", err)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("expected SDK error substring preserved; got %v", err)
	}
}
