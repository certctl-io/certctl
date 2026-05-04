package javakeystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/certutil"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// mockExecutor records commands and returns configurable responses.
//
// Bundle 8 (2026-05-02 deployment-target audit) added the optional
// `onCall` hook so retention-pruning tests can simulate keytool's
// file-write side effects (e.g. -exportkeystore writes a .p12 to the
// -destkeystore path). Existing tests that don't set onCall behave
// identically to before.
type mockExecutor struct {
	calls     []mockCall
	responses []mockResponse
	callIndex int
	onCall    func(name string, args []string)
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
	if m.onCall != nil {
		m.onCall(name, args)
	}
	idx := m.callIndex
	m.callIndex++
	if idx < len(m.responses) {
		return m.responses[idx].Output, m.responses[idx].Err
	}
	return "", nil
}

// simulateExportSideEffect returns an onCall handler that mimics what real
// keytool -exportkeystore does: writes a small placeholder file at the
// path passed via -destkeystore. Used by Bundle 8 retention-pruning tests
// where the deploy-created backup file needs to actually exist on disk
// for the pruner's ReadDir to find it.
func simulateExportSideEffect(t *testing.T) func(name string, args []string) {
	t.Helper()
	return func(name string, args []string) {
		isExport := false
		for _, a := range args {
			if a == "-exportkeystore" {
				isExport = true
				break
			}
		}
		if !isExport {
			return
		}
		var dest string
		for i, a := range args {
			if a == "-destkeystore" && i+1 < len(args) {
				dest = args[i+1]
				break
			}
		}
		if dest == "" {
			return
		}
		if err := os.WriteFile(dest, []byte("simulated-backup-pkcs12"), 0644); err != nil {
			t.Logf("simulateExportSideEffect: write %s failed: %v", dest, err)
		}
	}
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
			{Output: "", Err: nil},                         // keytool -delete (alias may not exist)
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
			{Output: "Imported", Err: nil},  // import
			{Output: "restarted", Err: nil}, // reload
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
			{Output: "", Err: nil},                                   // delete
			{Output: "Imported", Err: nil},                           // import
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

// --- Bundle 8: pre-delete snapshot + on-import-failure rollback ---
//
// These seven tests pin the load-bearing rollback contract added in
// Bundle 8 of the 2026-05-02 deployment-target audit:
//   - snapshot order (export runs BEFORE delete BEFORE import);
//   - first-time deploy skips the snapshot (no keystore file = nothing
//     to roll back to, so no -exportkeystore call);
//   - happy rollback path (import fails → rollback re-imports from the
//     backup PFX);
//   - rollback-also-fails (operator-actionable wrapped error containing
//     both errors AND the backup path for manual recovery);
//   - retention pruning (5 pre-existing → 3 newest kept after deploy);
//   - retention zero defaults to 3;
//   - retention negative opts out of pruning entirely.

func TestJKS_Snapshot_RunsBefore_Delete(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	// Pre-create the keystore file so the snapshot phase fires (the
	// snapshot is gated on os.Stat returning nil for the keystore path).
	if err := os.WriteFile(keystorePath, []byte("fake-existing-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			// Top-10 fix #3 idempotency probe — alias missing → IDEM_MISS, fall through.
			{Output: "", Err: fmt.Errorf("keytool exit 1: alias <server> does not exist")},
			{Output: "Imported keystore for alias <server>", Err: nil}, // -exportkeystore (snapshot)
			{Output: "", Err: nil},                         // -delete (alias may exist)
			{Output: "Import command completed", Err: nil}, // -importkeystore (the actual deploy)
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
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

	// 4 keytool calls: probe → export (snapshot) → delete → import. The
	// snapshot-before-delete ordering is load-bearing: the delete destroys
	// the state the snapshot is meant to capture.
	if len(mock.calls) != 4 {
		t.Fatalf("expected 4 keytool calls (probe + export + delete + import), got %d", len(mock.calls))
	}

	// Call 0: probe (-list -alias -v).
	args0 := strings.Join(mock.calls[0].Args, " ")
	if !strings.Contains(args0, "-list") {
		t.Errorf("call 0: expected -list probe, got: %s", args0)
	}

	// Call 1: -exportkeystore.
	if mock.calls[1].Name != "keytool" {
		t.Errorf("call 1: expected keytool, got %s", mock.calls[1].Name)
	}
	args1 := strings.Join(mock.calls[1].Args, " ")
	if !strings.Contains(args1, "-exportkeystore") {
		t.Errorf("call 1: expected -exportkeystore in args, got: %s", args1)
	}
	if !strings.Contains(args1, "-srckeystore "+keystorePath) {
		t.Errorf("call 1: expected -srckeystore %s, got: %s", keystorePath, args1)
	}
	// Backup path: <tmpDir>/.certctl-bak.<unix-nanos>.p12
	if !strings.Contains(args1, ".certctl-bak.") || !strings.Contains(args1, ".p12") {
		t.Errorf("call 1: expected .certctl-bak.*.p12 backup path, got: %s", args1)
	}

	// Call 2: -delete.
	args2 := strings.Join(mock.calls[2].Args, " ")
	if !strings.Contains(args2, "-delete") {
		t.Errorf("call 2: expected -delete in args, got: %s", args2)
	}

	// Call 3: -importkeystore (the deploy itself).
	args3 := strings.Join(mock.calls[3].Args, " ")
	if !strings.Contains(args3, "-importkeystore") {
		t.Errorf("call 3: expected -importkeystore in args, got: %s", args3)
	}
	if !strings.Contains(args3, "-destkeystore "+keystorePath) {
		t.Errorf("call 3: expected -destkeystore %s, got: %s", keystorePath, args3)
	}
}

func TestJKS_Snapshot_FirstTimeDeploy_NoExport(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	// NO keystore file pre-created — first-time deploy. Snapshot phase
	// gated on os.Stat returning nil; with no file, the snapshot is
	// skipped, the -delete is skipped, only the -importkeystore runs.
	keystorePath := tmpDir + "/app.p12"

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Import command completed", Err: nil}, // -importkeystore only
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
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

	// Exactly 1 call: -importkeystore. No -exportkeystore (no keystore
	// file existed pre-deploy), no -delete (same reason).
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 keytool call (import only), got %d: %v", len(mock.calls), mock.calls)
	}
	args := strings.Join(mock.calls[0].Args, " ")
	if strings.Contains(args, "-exportkeystore") {
		t.Errorf("expected no -exportkeystore on first-time deploy, got: %s", args)
	}
	if !strings.Contains(args, "-importkeystore") {
		t.Errorf("expected -importkeystore in args, got: %s", args)
	}
}

func TestJKS_ImportFails_RollsBack(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-existing-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	// Snapshot succeeds → delete succeeds → import fails → rollback runs:
	// rollback delete (best-effort) + rollback re-import from backup PFX.
	mock := &mockExecutor{
		responses: []mockResponse{
			// Top-10 fix #3 idempotency probe — alias missing → fall through.
			{Output: "", Err: fmt.Errorf("alias <server> does not exist")},
			{Output: "Imported keystore for alias <server>", Err: nil}, // 1: -exportkeystore (snapshot)
			{Output: "", Err: nil}, // 2: -delete (pre-import)
			{Output: "keystore corruption error", Err: fmt.Errorf("exit 1")}, // 3: -importkeystore FAILS
			{Output: "", Err: nil}, // 4: -delete (rollback step 1)
			{Output: "Imported keystore for alias <server>", Err: nil}, // 5: -importkeystore (rollback step 2)
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when import fails")
	}
	// Wrapped error must surface BOTH the import failure AND the rollback
	// success ("rolled back from <backupPath>") so operators know they
	// don't need to manually recover.
	if !strings.Contains(err.Error(), "keytool import failed") {
		t.Errorf("expected error to mention import failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rolled back from") {
		t.Errorf("expected error to mention rollback from <backup>, got: %v", err)
	}

	// 6 keytool calls with the new probe at index 0:
	//   probe, export, delete, import-fail, rollback-delete, rollback-import.
	// Locate the rollback re-import call (now at index 5) and assert it
	// references the backup path that the snapshot wrote.
	if len(mock.calls) != 6 {
		t.Fatalf("expected 6 keytool calls (probe, export, delete, import, rollback-delete, rollback-import), got %d", len(mock.calls))
	}
	rollbackImportArgs := strings.Join(mock.calls[5].Args, " ")
	if !strings.Contains(rollbackImportArgs, "-importkeystore") {
		t.Errorf("call 5: expected -importkeystore for rollback, got: %s", rollbackImportArgs)
	}
	if !strings.Contains(rollbackImportArgs, ".certctl-bak.") {
		t.Errorf("call 5: expected backup path (.certctl-bak.*) as -srckeystore, got: %s", rollbackImportArgs)
	}
	// The backup path that the snapshot wrote (call 1) must be the source
	// for the rollback re-import (call 5).
	exportArgs := strings.Join(mock.calls[1].Args, " ")
	for _, arg := range mock.calls[1].Args {
		if strings.Contains(arg, ".certctl-bak.") && strings.HasSuffix(arg, ".p12") {
			if !strings.Contains(rollbackImportArgs, arg) {
				t.Errorf("rollback re-import did not reference snapshot backup %q\n  export args: %s\n  rollback args: %s", arg, exportArgs, rollbackImportArgs)
			}
			break
		}
	}
}

func TestJKS_ImportFails_RollbackAlsoFails_OperatorActionable(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-existing-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	// Probe → snapshot → delete → import-fail → rollback-delete →
	// rollback-import ALSO fails. Operator-actionable case: BOTH errors
	// AND the backup path must be in the wrapped error so operators can
	// manually recover from the .p12 file on disk.
	mock := &mockExecutor{
		responses: []mockResponse{
			// Top-10 fix #3 idempotency probe — alias missing → fall through.
			{Output: "", Err: fmt.Errorf("alias <server> does not exist")},
			{Output: "Imported keystore for alias <server>", Err: nil}, // 1: snapshot
			{Output: "", Err: nil}, // 2: pre-import delete
			{Output: "import-step error", Err: fmt.Errorf("import exit 1")}, // 3: import FAILS
			{Output: "", Err: nil}, // 4: rollback delete
			{Output: "rollback-step error", Err: fmt.Errorf("rollback exit 2")}, // 5: rollback import FAILS
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when both import and rollback fail")
	}
	// Wrapped error must mention BOTH errors AND the backup path so the
	// operator can manually recover.
	if !strings.Contains(err.Error(), "keytool import failed") {
		t.Errorf("expected error to mention import failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("expected error to mention rollback failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "manual operator inspection required") {
		t.Errorf("expected error to flag manual inspection, got: %v", err)
	}
	if !strings.Contains(err.Error(), ".certctl-bak.") {
		t.Errorf("expected error to surface the backup path so operator can recover manually, got: %v", err)
	}
}

func TestJKS_BackupRetention_PrunesOldBackups(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-create 5 backup files with staggered ModTimes so the pruner
	// has a deterministic newest-first ordering. The deploy will create
	// a 6th; with retention=3, pruning keeps the 3 newest (which are
	// the deploy-created backup + the two newest pre-existing).
	preExistingNames := []string{
		".certctl-bak.100000000.p12", // oldest
		".certctl-bak.200000000.p12",
		".certctl-bak.300000000.p12",
		".certctl-bak.400000000.p12",
		".certctl-bak.500000000.p12", // newest pre-existing
	}
	baseTime := time.Now().Add(-24 * time.Hour)
	for i, name := range preExistingNames {
		path := tmpDir + "/" + name
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatal(err)
		}
		// Stagger ModTime: oldest = baseTime, newest = baseTime + 4 hours.
		modTime := baseTime.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatal(err)
		}
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Imported keystore for alias <server>", Err: nil}, // export
			{Output: "", Err: nil},                         // delete
			{Output: "Import command completed", Err: nil}, // import
		},
		onCall: simulateExportSideEffect(t),
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
		BackupRetention:  3,
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	// Count remaining .certctl-bak.*.p12 files. Should be exactly 3:
	// - the newest pre-existing (500000000) — survives
	// - the second-newest pre-existing (400000000) — survives
	// - the deploy-created backup — survives (just-now ModTime is the
	//   newest of all)
	// The 3 oldest pre-existing (300000000, 200000000, 100000000) are
	// pruned.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	var remaining []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".certctl-bak.") && strings.HasSuffix(name, ".p12") {
			remaining = append(remaining, name)
		}
	}
	if len(remaining) != 3 {
		t.Errorf("expected exactly 3 backups after pruning (BackupRetention=3), got %d: %v", len(remaining), remaining)
	}
	// The two newest pre-existing must survive.
	for _, want := range []string{".certctl-bak.500000000.p12", ".certctl-bak.400000000.p12"} {
		found := false
		for _, got := range remaining {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s to survive pruning, got remaining: %v", want, remaining)
		}
	}
	// The three oldest pre-existing must be pruned.
	for _, gone := range []string{".certctl-bak.100000000.p12", ".certctl-bak.200000000.p12", ".certctl-bak.300000000.p12"} {
		for _, got := range remaining {
			if got == gone {
				t.Errorf("expected %s to be pruned, but it remained: %v", gone, remaining)
			}
		}
	}
}

func TestJKS_BackupRetention_Zero_DefaultsTo3(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-create 5 staggered backups; with retention=0 (which defaults
	// to 3), the pruner should behave identically to the explicit-3 test.
	baseTime := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 5; i++ {
		path := tmpDir + "/.certctl-bak." + fmt.Sprintf("%d", (i+1)*100000000) + ".p12"
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatal(err)
		}
		modTime := baseTime.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatal(err)
		}
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Imported keystore for alias <server>", Err: nil},
			{Output: "", Err: nil},
			{Output: "Import command completed", Err: nil},
		},
		onCall: simulateExportSideEffect(t),
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
		BackupRetention:  0, // explicit zero — must default to 3
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".certctl-bak.") && strings.HasSuffix(e.Name(), ".p12") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 backups after pruning (BackupRetention=0 → default 3), got %d", count)
	}
}

func TestJKS_BackupRetention_Negative_OptsOut(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-create 5 backups; with retention=-1, NONE are pruned. After the
	// deploy creates a 6th, all 6 remain.
	baseTime := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 5; i++ {
		path := tmpDir + "/.certctl-bak." + fmt.Sprintf("%d", (i+1)*100000000) + ".p12"
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatal(err)
		}
		modTime := baseTime.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatal(err)
		}
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: "Imported keystore for alias <server>", Err: nil},
			{Output: "", Err: nil},
			{Output: "Import command completed", Err: nil},
		},
		onCall: simulateExportSideEffect(t),
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
		BackupRetention:  -1, // opt out
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".certctl-bak.") && strings.HasSuffix(e.Name(), ".p12") {
			count++
		}
	}
	// 5 pre-existing + 1 deploy-created = 6; retention=-1 means no pruning.
	if count != 6 {
		t.Errorf("expected 6 backups after deploy with BackupRetention=-1, got %d", count)
	}
}

func TestJKS_Snapshot_AliasNotInKeystore_ProceedsCleanly(t *testing.T) {
	// Edge case: keystore file exists but the configured alias isn't
	// present in it. keytool -exportkeystore returns non-zero with
	// "alias <X> does not exist" — the snapshot helper recognises this
	// as a normal first-time-on-existing-keystore signal and returns
	// ("", nil), letting the deploy proceed without a backup.
	// The subsequent import-failure path then becomes the no-backup
	// branch (returns the import error verbatim).
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tmpDir := t.TempDir()
	keystorePath := tmpDir + "/app.p12"
	if err := os.WriteFile(keystorePath, []byte("fake-keystore-with-other-aliases"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &mockExecutor{
		responses: []mockResponse{
			// keytool -exportkeystore: alias not present → non-zero exit
			// with the well-known "Alias <server> does not exist" message.
			{Output: "keytool error: java.lang.Exception: Alias <server> does not exist", Err: fmt.Errorf("exit 1")},
			{Output: "", Err: nil},                         // -delete (best-effort, alias may not exist)
			{Output: "Import command completed", Err: nil}, // -importkeystore (deploy)
		},
	}
	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "changeit",
		KeystoreType:     "PKCS12",
		Alias:            "server",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy should succeed when alias not in pre-existing keystore: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestJKS_Idempotent_SkipsDeployWhenAliasMatches(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "jks-idem-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keystorePath := filepath.Join(tmpDir, "test.p12")
	// Create a placeholder keystore file
	if err := os.WriteFile(keystorePath, []byte("placeholder"), 0644); err != nil {
		t.Fatalf("write keystore: %v", err)
	}

	// Compute SHA-256 of the new cert's DER
	newCert, _ := certutil.ParseCertificatePEM(certPEM)
	sha256Hex := fmt.Sprintf("%x", sha256.Sum256(newCert.Raw))

	// Format as keytool output: "SHA256: AA:BB:CC:..."
	keytoolOutput := fmt.Sprintf("Alias name: server\n"+
		"Creation date: ...\n"+
		"Certificate fingerprints (SHA-256):\n"+
		"SHA256: %s\n",
		formatSHA256WithColons(sha256Hex))

	// Probe returns the matching output; no other calls should run.
	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: keytoolOutput, Err: nil}, // probe — match
		},
	}

	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "password",
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

	// Verify idempotent flag is set
	if result.Metadata["idempotent"] != "true" {
		t.Errorf("expected idempotent=true, got %s", result.Metadata["idempotent"])
	}

	// Only the probe should have run (1 keytool call). Subsequent keytool
	// invocations would be -delete / -importkeystore — none of those should
	// fire on idempotent skip.
	if len(mock.calls) != 1 {
		t.Errorf("expected 1 keytool call (probe only), got %d", len(mock.calls))
	}
	if len(mock.calls) > 0 {
		args := mock.calls[0].Args
		hasList := false
		for _, a := range args {
			if a == "-list" {
				hasList = true
				break
			}
		}
		if !hasList {
			t.Errorf("expected first call to be `-list` probe, got args: %v", args)
		}
	}
}

func TestJKS_Idempotent_DifferentAlias_FallsThroughToDeploy(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "jks-idem-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keystorePath := filepath.Join(tmpDir, "test.p12")
	// Create a placeholder keystore file
	if err := os.WriteFile(keystorePath, []byte("placeholder"), 0644); err != nil {
		t.Fatalf("write keystore: %v", err)
	}

	// Probe returns a DIFFERENT SHA-256 → IDEM_MISS → fall through to full
	// snapshot+delete+importkeystore deploy path. Bundle 8 snapshot uses
	// keytool -exportkeystore, which simulateExportSideEffect needs to
	// fake on disk so post-deploy file checks see the backup.
	differentFingerprint := "SHA256: FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF\n"

	mock := &mockExecutor{
		responses: []mockResponse{
			{Output: differentFingerprint, Err: nil},       // probe — miss
			{Output: "Keystore exported", Err: nil},        // snapshot -exportkeystore
			{Output: "", Err: nil},                         // -delete (best-effort)
			{Output: "Import command completed", Err: nil}, // -importkeystore
		},
		onCall: simulateExportSideEffect(t),
	}

	c := NewWithExecutor(&Config{
		KeystorePath:     keystorePath,
		KeystorePassword: "password",
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

	// Verify idempotent flag is NOT set (full deploy path ran)
	if result.Metadata["idempotent"] != "" {
		t.Errorf("expected no idempotent flag, got %q", result.Metadata["idempotent"])
	}

	// 4 keytool calls expected: probe, snapshot -exportkeystore, -delete, -importkeystore.
	if len(mock.calls) != 4 {
		t.Errorf("expected 4 keytool calls (probe + snapshot + delete + import), got %d", len(mock.calls))
		for i, c := range mock.calls {
			t.Logf("call[%d] args=%v", i, c.Args)
		}
	}
	// First call must be the -list probe.
	if len(mock.calls) > 0 {
		hasList := false
		for _, a := range mock.calls[0].Args {
			if a == "-list" {
				hasList = true
				break
			}
		}
		if !hasList {
			t.Errorf("expected first call to be `-list` probe, got args: %v", mock.calls[0].Args)
		}
	}
}

func formatSHA256WithColons(hexStr string) string {
	var result strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(strings.ToUpper(hexStr[i : i+2]))
	}
	return result.String()
}
