package wincertstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/shankar0123/certctl/internal/connector/target"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// mockExecutor records PowerShell scripts and returns configurable responses.
type mockExecutor struct {
	scripts   []string
	responses []string
	errors    []error
	callIndex int
}

func (m *mockExecutor) Execute(ctx context.Context, script string) (string, error) {
	m.scripts = append(m.scripts, script)
	idx := m.callIndex
	m.callIndex++
	if idx < len(m.errors) && m.errors[idx] != nil {
		resp := ""
		if idx < len(m.responses) {
			resp = m.responses[idx]
		}
		return resp, m.errors[idx]
	}
	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return "", nil
}

// generateTestCertAndKey creates a self-signed certificate and key for testing.
func generateTestCertAndKey() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}

// --- ValidateConfig Tests ---

func TestValidateConfig_Success(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"store_name":"My","store_location":"LocalMachine"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestValidateConfig_Defaults(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("expected success with defaults, got: %v", err)
	}
	if c.config.StoreName != "My" {
		t.Errorf("expected default store_name 'My', got: %s", c.config.StoreName)
	}
	if c.config.StoreLocation != "LocalMachine" {
		t.Errorf("expected default store_location 'LocalMachine', got: %s", c.config.StoreLocation)
	}
	if c.config.Mode != "local" {
		t.Errorf("expected default mode 'local', got: %s", c.config.Mode)
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	err := c.ValidateConfig(context.Background(), json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateConfig_InvalidStoreName(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"store_name":"My; Drop-Database"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "invalid store_name") {
		t.Fatalf("expected invalid store_name error, got: %v", err)
	}
}

func TestValidateConfig_InvalidStoreLocation(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"store_location":"InvalidLocation"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "invalid store_location") {
		t.Fatalf("expected invalid store_location error, got: %v", err)
	}
}

func TestValidateConfig_CurrentUser(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"store_location":"CurrentUser"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("expected success with CurrentUser, got: %v", err)
	}
}

func TestValidateConfig_InvalidMode(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"mode":"ssh"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("expected invalid mode error, got: %v", err)
	}
}

func TestValidateConfig_WinRM_MissingHost(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"mode":"winrm","winrm_username":"admin","winrm_password":"pass"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "winrm_host") {
		t.Fatalf("expected winrm_host error, got: %v", err)
	}
}

func TestValidateConfig_WinRM_MissingUsername(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"mode":"winrm","winrm_host":"host","winrm_password":"pass"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "winrm_username") {
		t.Fatalf("expected winrm_username error, got: %v", err)
	}
}

func TestValidateConfig_InvalidFriendlyName(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"friendly_name":"cert; rm -rf /"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err == nil || !strings.Contains(err.Error(), "invalid friendly_name") {
		t.Fatalf("expected invalid friendly_name error, got: %v", err)
	}
}

func TestValidateConfig_WithFriendlyName(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg := `{"friendly_name":"My Production Cert"}`
	err := c.ValidateConfig(context.Background(), json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("expected success with friendly name, got: %v", err)
	}
}

// --- DeployCertificate Tests ---

func TestDeployCertificate_Success(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []string{"SUCCESS:AABBCCDD"},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if result.TargetAddress != "cert:\\LocalMachine\\My" {
		t.Errorf("expected target address cert:\\LocalMachine\\My, got: %s", result.TargetAddress)
	}
	if result.Metadata["store_name"] != "My" {
		t.Errorf("expected store_name metadata 'My', got: %s", result.Metadata["store_name"])
	}

	// Verify the PowerShell script was called
	if len(mock.scripts) != 1 {
		t.Fatalf("expected 1 script call, got %d", len(mock.scripts))
	}
	script := mock.scripts[0]
	if !strings.Contains(script, "Import-PfxCertificate") {
		t.Error("expected Import-PfxCertificate in script")
	}
	if !strings.Contains(script, "Cert:\\LocalMachine\\My") {
		t.Error("expected correct cert store path in script")
	}
}

func TestDeployCertificate_MissingKey(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("expected missing key error, got: %v", err)
	}
}

func TestDeployCertificate_InvalidCert(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: "not-a-cert",
		KeyPEM:  "not-a-key",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert")
	}
}

func TestDeployCertificate_ImportFailed(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []string{"Access denied"},
		errors:    []error{fmt.Errorf("exit code 1")},
	}
	c := NewWithExecutor(&Config{}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "PowerShell import failed") {
		t.Fatalf("expected import failure error, got: %v", err)
	}
}

func TestDeployCertificate_WithFriendlyName(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{responses: []string{"SUCCESS:AABB"}}
	c := NewWithExecutor(&Config{
		StoreName:    "My",
		FriendlyName: "Production API Cert",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !strings.Contains(mock.scripts[0], "FriendlyName") {
		t.Error("expected FriendlyName in PowerShell script")
	}
}

func TestDeployCertificate_WithRemoveExpired(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{responses: []string{"SUCCESS:AABB"}}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		RemoveExpired: true,
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !strings.Contains(mock.scripts[0], "Remove-Item") {
		t.Error("expected Remove-Item for expired cert cleanup in script")
	}
}

// --- ValidateDeployment Tests ---

func TestValidateDeployment_Success(t *testing.T) {
	mock := &mockExecutor{
		responses: []string{"FOUND:AABBCCDD:2027-01-01T00:00:00"},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "01",
		Metadata: map[string]string{
			"thumbprint": "AABBCCDD",
		},
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid=true")
	}
	if result.Metadata["thumbprint"] != "AABBCCDD" {
		t.Errorf("expected thumbprint AABBCCDD, got: %s", result.Metadata["thumbprint"])
	}
}

func TestValidateDeployment_NotFound(t *testing.T) {
	mock := &mockExecutor{
		responses: []string{"NOT_FOUND"},
	}
	c := NewWithExecutor(&Config{}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "01",
	})
	if err == nil {
		t.Fatal("expected error for not found cert")
	}
	if result.Valid {
		t.Error("expected valid=false")
	}
}

func TestValidateDeployment_QueryFailed(t *testing.T) {
	mock := &mockExecutor{
		responses: []string{"error"},
		errors:    []error{fmt.Errorf("powershell error")},
	}
	c := NewWithExecutor(&Config{}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "01",
	})
	if err == nil {
		t.Fatal("expected error for query failure")
	}
	if result.Valid {
		t.Error("expected valid=false")
	}
}

func TestValidateDeployment_BySerial(t *testing.T) {
	mock := &mockExecutor{
		responses: []string{"FOUND:AABB:2027-01-01T00:00:00"},
	}
	c := NewWithExecutor(&Config{}, testLogger(), mock)

	// No thumbprint in metadata — should query by serial
	_, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "DEADBEEF",
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if !strings.Contains(mock.scripts[0], "SerialNumber") {
		t.Error("expected serial number query in script")
	}
}
