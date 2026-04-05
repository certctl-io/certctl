package javakeystore

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

// mockExecutor records commands and returns configurable responses.
type mockExecutor struct {
	calls     []mockCall
	responses []mockResponse
	callIndex int
}

type mockCall struct {
	Name string
	Args []string
}

type mockResponse struct {
	Output string
	Err    error
}

func (m *mockExecutor) Execute(ctx context.Context, name string, args ...string) (string, error) {
	m.calls = append(m.calls, mockCall{Name: name, Args: args})
	idx := m.callIndex
	m.callIndex++
	if idx < len(m.responses) {
		return m.responses[idx].Output, m.responses[idx].Err
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
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.jks",
		KeystorePassword: "changeit",
		KeystoreType:     "JKS",
		Alias:            "server",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestValidateConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.p12",
		KeystorePassword: "changeit",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected success with defaults, got: %v", err)
	}
	if c.config.KeystoreType != "PKCS12" {
		t.Errorf("expected default type PKCS12, got: %s", c.config.KeystoreType)
	}
	if c.config.Alias != "server" {
		t.Errorf("expected default alias 'server', got: %s", c.config.Alias)
	}
	if c.config.KeytoolPath != "keytool" {
		t.Errorf("expected default keytool path, got: %s", c.config.KeytoolPath)
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	err := c.ValidateConfig(context.Background(), json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateConfig_MissingKeystorePath(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{KeystorePassword: "changeit"})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "keystore_path is required") {
		t.Fatalf("expected keystore_path error, got: %v", err)
	}
}

func TestValidateConfig_MissingPassword(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{KeystorePath: tmpDir + "/app.jks"})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "keystore_password is required") {
		t.Fatalf("expected password error, got: %v", err)
	}
}

func TestValidateConfig_InvalidKeystoreType(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.jks",
		KeystorePassword: "changeit",
		KeystoreType:     "BCFKS",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid keystore_type") {
		t.Fatalf("expected keystore_type error, got: %v", err)
	}
}

func TestValidateConfig_InvalidAlias(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.jks",
		KeystorePassword: "changeit",
		Alias:            "alias; rm -rf /",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid alias") {
		t.Fatalf("expected invalid alias error, got: %v", err)
	}
}

func TestValidateConfig_PathTraversal(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     "/etc/../../tmp/app.jks",
		KeystorePassword: "changeit",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("expected path traversal error, got: %v", err)
	}
}

func TestValidateConfig_DirNotExists(t *testing.T) {
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     "/nonexistent/dir/app.jks",
		KeystorePassword: "changeit",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "keystore directory does not exist") {
		t.Fatalf("expected dir not exist error, got: %v", err)
	}
}

func TestValidateConfig_ReloadCommandInjection(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.jks",
		KeystorePassword: "changeit",
		ReloadCommand:    "systemctl restart tomcat; rm -rf /",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid reload_command") {
		t.Fatalf("expected reload_command error, got: %v", err)
	}
}

func TestValidateConfig_ValidReloadCommand(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewWithExecutor(&Config{}, testLogger(), &mockExecutor{})
	cfg, _ := json.Marshal(Config{
		KeystorePath:     tmpDir + "/app.p12",
		KeystorePassword: "changeit",
		ReloadCommand:    "systemctl restart tomcat",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected success with valid reload command, got: %v", err)
	}
}

// --- DeployCertificate Tests ---

func TestDeployCertificate_Success(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tmpDir := t.TempDir()

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "", Err: nil},                    // keytool -delete (alias may not exist)
			{Output: "Import command completed", Err: nil}, // keytool -importkeystore
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     tmpDir + "/app.p12",
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
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
	if result.TargetAddress != tmpDir+"/app.p12" {
		t.Errorf("expected keystore path as target address, got: %s", result.TargetAddress)
	}
	if result.Metadata["alias"] != "server" {
		t.Errorf("expected alias 'server' in metadata, got: %s", result.Metadata["alias"])
	}

	// Verify keytool was called with correct args
	if len(mock.calls) < 1 {
		t.Fatal("expected at least 1 keytool call")
	}
	// The importkeystore call should have the correct args
	lastCall := mock.calls[len(mock.calls)-1]
	if lastCall.Name != "keytool" {
		t.Errorf("expected keytool command, got: %s", lastCall.Name)
	}
	argsStr := strings.Join(lastCall.Args, " ")
	if !strings.Contains(argsStr, "-importkeystore") {
		t.Error("expected -importkeystore flag")
	}
	if !strings.Contains(argsStr, "-destalias server") {
		t.Error("expected -destalias server")
	}
}

func TestDeployCertificate_MissingKey(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
	}, testLogger(), &mockExecutor{})

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("expected missing key error, got: %v", err)
	}
}

func TestDeployCertificate_InvalidCert(t *testing.T) {
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
	}, testLogger(), &mockExecutor{})

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
		responses: []mockResponse{
			// No existing keystore → delete is skipped → import is the first call
			{Output: "keytool error: keystore password incorrect", Err: fmt.Errorf("exit 1")},
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "wrongpassword",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "keytool import failed") {
		t.Fatalf("expected import failure error, got: %v", err)
	}
}

func TestDeployCertificate_WithReload(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			// No existing keystore → delete skipped → import is call 0, reload is call 1
			{Output: "Imported", Err: nil},   // import
			{Output: "restarted", Err: nil},  // reload
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
		ReloadCommand:    "systemctl restart tomcat",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	// Verify reload command was called (no existing keystore → delete skipped)
	if len(mock.calls) < 2 {
		t.Fatalf("expected 2 calls (import, reload), got %d", len(mock.calls))
	}
	reloadCall := mock.calls[1]
	if reloadCall.Name != "sh" {
		t.Errorf("expected sh for reload, got: %s", reloadCall.Name)
	}
}

func TestDeployCertificate_ReloadFailed_NonFatal(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "", Err: nil},                        // delete
			{Output: "Imported", Err: nil},                // import
			{Output: "Failed to restart", Err: fmt.Errorf("exit 1")}, // reload fails
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
		ReloadCommand:    "systemctl restart tomcat",
	}, testLogger(), mock)

	// Reload failure should NOT cause deploy to fail
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy should succeed even when reload fails, got: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestDeployCertificate_JKSType(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "", Err: nil},
			{Output: "Imported", Err: nil},
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.jks",
		KeystorePassword: "changeit",
		KeystoreType:     "JKS",
		Alias:            "myapp",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if result.Metadata["keystore_type"] != "JKS" {
		t.Errorf("expected JKS type in metadata, got: %s", result.Metadata["keystore_type"])
	}

	// Verify keytool used JKS type
	importCall := mock.calls[len(mock.calls)-1]
	argsStr := strings.Join(importCall.Args, " ")
	if !strings.Contains(argsStr, "-deststoretype JKS") {
		t.Error("expected -deststoretype JKS")
	}
}

// --- ValidateDeployment Tests ---

func TestValidateDeployment_Success(t *testing.T) {
	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Alias name: server\nCreation date: Jan 1, 2026\nEntry type: PrivateKeyEntry\nSerial number: DEADBEEF", Err: nil},
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
		Alias:            "server",
	}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "DEADBEEF",
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid=true")
	}
	if result.Metadata["serial_match"] != "true" {
		t.Error("expected serial_match=true")
	}
}

func TestValidateDeployment_AliasNotFound(t *testing.T) {
	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "keytool error: java.lang.Exception: Alias <server> does not exist", Err: fmt.Errorf("exit 1")},
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
		Alias:            "server",
	}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "01",
	})
	if err == nil {
		t.Fatal("expected error for missing alias")
	}
	if result.Valid {
		t.Error("expected valid=false")
	}
}

func TestValidateDeployment_SerialMismatch(t *testing.T) {
	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Alias name: server\nSerial number: AABBCCDD", Err: nil},
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     "/tmp/test.p12",
		KeystorePassword: "changeit",
		Alias:            "server",
	}, testLogger(), mock)

	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		Serial: "DEADBEEF",
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid=true (cert exists, just serial mismatch)")
	}
	if result.Metadata["serial_match"] != "false" {
		t.Error("expected serial_match=false")
	}
}
