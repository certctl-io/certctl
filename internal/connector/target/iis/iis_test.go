package iis

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
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// mockExecutor records PowerShell commands and returns configurable responses.
type mockExecutor struct {
	// commands records all scripts passed to Execute in order
	commands []string
	// responses maps script substrings to (output, error) pairs.
	// First matching substring wins.
	responses map[string]mockResponse
	// defaultOutput is returned when no response matches
	defaultOutput string
	// defaultErr is returned when no response matches
	defaultErr error
}

type mockResponse struct {
	output string
	err    error
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		responses: make(map[string]mockResponse),
	}
}

func (m *mockExecutor) Execute(ctx context.Context, script string) (string, error) {
	m.commands = append(m.commands, script)
	for substr, resp := range m.responses {
		if strings.Contains(script, substr) {
			return resp.output, resp.err
		}
	}
	return m.defaultOutput, m.defaultErr
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// --- ValidateConfig tests ---

func TestIISConnector_ValidateConfig_Success(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-Website"] = mockResponse{output: "Default Web Site\n", err: nil}
	executor.responses["Test-Path"] = mockResponse{output: "True\n", err: nil}

	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}

	// We need powershell.exe in PATH for LookPath — skip on non-Windows
	connector := NewWithExecutor(&cfg, testLogger(), executor)
	rawConfig, _ := json.Marshal(cfg)

	// On non-Windows, LookPath("powershell.exe") will fail.
	// We test the validation logic up to that point by checking the error message.
	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err != nil {
		// Q-1 closure (cat-s3-58ce7e9840be): platform-gated skip — IIS
		// connector dispatches via powershell.exe; the binary only exists
		// on Windows hosts. This branch lets the test pass on Linux/macOS
		// CI runners where powershell.exe isn't available; on Windows
		// runners the assertion below runs normally. The iis_connector.go
		// production code has the same platform check; this skip mirrors
		// it at test-fixture level.
		if strings.Contains(err.Error(), "powershell.exe not found") {
			t.Skip("Skipping: powershell.exe not available (non-Windows)")
		}
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestIISConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	err := connector.ValidateConfig(context.Background(), json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid IIS config") {
		t.Errorf("expected 'invalid IIS config' in error, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_MissingSiteName(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{CertStore: "My"}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for missing site_name")
	}
	if !strings.Contains(err.Error(), "site_name") {
		t.Errorf("expected error about site_name, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_MissingCertStore(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{SiteName: "Default Web Site"}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for missing cert_store")
	}
	if !strings.Contains(err.Error(), "cert_store") {
		t.Errorf("expected error about cert_store, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_InvalidSiteName_Injection(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{
		SiteName:  "Default'; Drop-Database",
		CertStore: "My",
	}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for injection characters in site_name")
	}
	if !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("expected 'invalid characters' in error, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_InvalidCertStore_Injection(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My$(whoami)",
	}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for injection characters in cert_store")
	}
}

func TestIISConnector_ValidateConfig_InvalidPort(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      99999,
	}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("expected error about port, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_InvalidIPAddress(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
		IPAddress: "not_an_ip",
	}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid IP address")
	}
	if !strings.Contains(err.Error(), "ip_address") {
		t.Errorf("expected error about ip_address, got: %v", err)
	}
}

func TestIISConnector_ValidateConfig_DefaultValues(t *testing.T) {
	// Test that defaults are applied (port 443, IP *)
	executor := newMockExecutor()
	executor.responses["Get-Website"] = mockResponse{output: "TestSite\n", err: nil}
	executor.responses["Test-Path"] = mockResponse{output: "True\n", err: nil}

	cfg := Config{
		SiteName:  "TestSite",
		CertStore: "WebHosting",
		// Port and IPAddress intentionally left empty
	}

	connector := NewWithExecutor(&cfg, testLogger(), executor)
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err != nil {
		// Q-1 closure (cat-s3-58ce7e9840be): same platform-gate as
		// TestIIS_ValidateConfig_Empty above; mirrors the production
		// LookPath("powershell.exe") guard in iis_connector.go.
		if strings.Contains(err.Error(), "powershell.exe not found") {
			t.Skip("Skipping: powershell.exe not available (non-Windows)")
		}
		t.Fatalf("ValidateConfig failed: %v", err)
	}

	// Verify defaults were applied
	if connector.config.Port != 443 {
		t.Errorf("expected default port 443, got %d", connector.config.Port)
	}
	if connector.config.IPAddress != "*" {
		t.Errorf("expected default IP '*', got %s", connector.config.IPAddress)
	}
}

// --- DeployCertificate tests ---

// generateTestCertAndKey creates a self-signed ECDSA P-256 cert+key for testing.
func generateTestCertAndKey() (certPEM, keyPEM, chainPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}

	certPEMStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	keyPEMStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	// Use the self-signed cert as its own "chain" for testing
	chainPEMStr := certPEMStr

	return certPEMStr, keyPEMStr, chainPEMStr, nil
}

func TestIISConnector_DeployCertificate_Success(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	executor.defaultOutput = "OK"

	cfg := &Config{
		Hostname:  "web01.example.com",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
		IPAddress: "*",
	}

	connector := NewWithExecutor(cfg, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify thumbprint is in metadata
	if result.Metadata["thumbprint"] == "" {
		t.Error("expected thumbprint in metadata")
	}
	// SHA-1 thumbprint = 40 hex chars uppercase
	if len(result.Metadata["thumbprint"]) != 40 {
		t.Errorf("expected 40-char thumbprint, got %d", len(result.Metadata["thumbprint"]))
	}

	// Bundle 5: snapshot script runs FIRST, then import, then binding.
	// Three PowerShell commands total on the success path.
	if len(executor.commands) != 3 {
		t.Errorf("expected 3 PowerShell commands (snapshot, import, binding), got %d", len(executor.commands))
	}

	// First command should be the Bundle 5 snapshot.
	if len(executor.commands) > 0 && !strings.Contains(executor.commands[0], "# CERTCTL_SNAPSHOT") {
		t.Errorf("expected # CERTCTL_SNAPSHOT in first command, got: %s", executor.commands[0])
	}

	// Second command should be PFX import.
	if len(executor.commands) > 1 && !strings.Contains(executor.commands[1], "Import-PfxCertificate") {
		t.Errorf("expected Import-PfxCertificate in second command, got: %s", executor.commands[1])
	}

	// Third command should be binding update.
	if len(executor.commands) > 2 && !strings.Contains(executor.commands[2], "New-WebBinding") {
		t.Errorf("expected New-WebBinding in third command, got: %s", executor.commands[2])
	}

	// Verify metadata
	if result.Metadata["site_name"] != "Default Web Site" {
		t.Errorf("expected site_name in metadata")
	}
	if result.Metadata["cert_store"] != "My" {
		t.Errorf("expected cert_store in metadata")
	}
	if _, ok := result.Metadata["duration_ms"]; !ok {
		t.Error("expected duration_ms in metadata")
	}
}

func TestIISConnector_DeployCertificate_MissingKeyPEM(t *testing.T) {
	certPEM, _, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	connector := NewWithExecutor(&Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
	}, testLogger(), newMockExecutor())

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   "", // Missing key
		ChainPEM: chainPEM,
	})
	if err == nil {
		t.Fatal("expected error for missing KeyPEM")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("expected error about private key, got: %v", err)
	}
}

func TestIISConnector_DeployCertificate_InvalidCertPEM(t *testing.T) {
	_, keyPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	connector := NewWithExecutor(&Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
	}, testLogger(), newMockExecutor())

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  "not a valid cert",
		KeyPEM:   keyPEM,
		ChainPEM: "",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestIISConnector_DeployCertificate_InvalidKeyPEM(t *testing.T) {
	certPEM, _, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	connector := NewWithExecutor(&Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
	}, testLogger(), newMockExecutor())

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   "not a valid key",
		ChainPEM: "",
	})
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestIISConnector_DeployCertificate_ImportFails(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	executor.responses["Import-PfxCertificate"] = mockResponse{
		output: "Access denied",
		err:    fmt.Errorf("exit status 1"),
	}

	connector := NewWithExecutor(&Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
	}, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err == nil {
		t.Fatal("expected error when PFX import fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
	if !strings.Contains(err.Error(), "PFX import failed") {
		t.Errorf("expected 'PFX import failed' in error, got: %v", err)
	}
}

// --- Bundle 5: pre-deploy binding snapshot + on-failure rollback ---
//
// Mock matchers below use the unique `# CERTCTL_*` PowerShell comment tags
// inserted by snapshotOldBinding / rollbackBinding / verifyRollback. The
// binding-update script is matched via "Remove-WebBinding" — that token is
// only present in the binding-update script (the rollback script uses
// "Remove-Item" instead, and the snapshot/verify scripts only read state).
// The import script is matched via "Import-PfxCertificate" (only present
// in the import script). This isolation is required because the rollback
// script's no-old-binding fallback branch contains "New-WebBinding", which
// would otherwise collide with the binding-update script and produce
// non-deterministic mock matching under Go's randomized map iteration.

func TestIIS_BindingUpdateFails_RemovesNewCert_RebindsOld(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	// Snapshot returns a pre-existing thumbprint (rollback target).
	executor.responses["# CERTCTL_SNAPSHOT"] = mockResponse{
		output: "OLD_THUMBPRINT:abc123\n",
		err:    nil,
	}
	// Import succeeds.
	executor.responses["Import-PfxCertificate"] = mockResponse{output: "OK", err: nil}
	// Binding update fails.
	executor.responses["Remove-WebBinding"] = mockResponse{
		output: "The website 'Default Web Site' already has a binding",
		err:    fmt.Errorf("exit status 1"),
	}
	// Rollback succeeds.
	executor.responses["# CERTCTL_ROLLBACK"] = mockResponse{
		output: "REBOUND_EXISTING\n",
		err:    nil,
	}
	// Verify confirms old thumbprint is back.
	executor.responses["# CERTCTL_VERIFY"] = mockResponse{
		output: "VERIFY_OK\n",
		err:    nil,
	}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err == nil {
		t.Fatal("expected error when binding update fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
	if !strings.Contains(err.Error(), "binding update failed") {
		t.Errorf("expected error to mention 'binding update failed', got: %v", err)
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected error to mention 'rolled back', got: %v", err)
	}

	// Find the rollback script in the recorded commands.
	var rollbackCmd string
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "# CERTCTL_ROLLBACK") {
			rollbackCmd = cmd
			break
		}
	}
	if rollbackCmd == "" {
		t.Fatal("expected rollback script to be executed")
	}

	// Rollback must remove the freshly-imported cert.
	thumbprint := result.Metadata["thumbprint"]
	if thumbprint == "" {
		t.Fatal("expected thumbprint in metadata")
	}
	if !strings.Contains(rollbackCmd, "Remove-Item") {
		t.Errorf("expected rollback to contain Remove-Item, got: %s", rollbackCmd)
	}
	if !strings.Contains(rollbackCmd, thumbprint) {
		t.Errorf("expected rollback to reference new thumbprint %q, got: %s", thumbprint, rollbackCmd)
	}
	// Rollback must re-bind the old thumbprint.
	if !strings.Contains(rollbackCmd, "AddSslCertificate('abc123'") {
		t.Errorf("expected rollback to AddSslCertificate('abc123', ...), got: %s", rollbackCmd)
	}

	if result.Metadata["old_thumbprint"] != "abc123" {
		t.Errorf("expected old_thumbprint=abc123 in metadata, got: %s", result.Metadata["old_thumbprint"])
	}
	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true in metadata, got: %s", result.Metadata["rolled_back"])
	}
}

func TestIIS_BindingUpdateFails_NoOldBinding_RemovesNewCertOnly(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	// First-time deploy: snapshot finds no existing binding.
	executor.responses["# CERTCTL_SNAPSHOT"] = mockResponse{
		output: "NO_OLD_BINDING\n",
		err:    nil,
	}
	executor.responses["Import-PfxCertificate"] = mockResponse{output: "OK", err: nil}
	executor.responses["Remove-WebBinding"] = mockResponse{
		output: "binding update failed",
		err:    fmt.Errorf("exit status 1"),
	}
	// Rollback succeeds (cert removed, no rebind).
	executor.responses["# CERTCTL_ROLLBACK"] = mockResponse{
		output: "CERT_REMOVED_NO_REBIND\n",
		err:    nil,
	}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err == nil {
		t.Fatal("expected error when binding update fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Find the rollback script.
	var rollbackCmd string
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "# CERTCTL_ROLLBACK") {
			rollbackCmd = cmd
			break
		}
	}
	if rollbackCmd == "" {
		t.Fatal("expected rollback script to be executed")
	}

	// Rollback must remove the freshly-imported cert.
	if !strings.Contains(rollbackCmd, "Remove-Item") {
		t.Errorf("expected rollback to contain Remove-Item, got: %s", rollbackCmd)
	}
	// First-time deploy: rollback must NOT call AddSslCertificate (nothing
	// to re-bind to). The rollback emits the CERT_REMOVED_NO_REBIND marker
	// instead.
	if strings.Contains(rollbackCmd, "AddSslCertificate") {
		t.Errorf("expected no AddSslCertificate call when oldThumbprint is empty, got: %s", rollbackCmd)
	}
	if !strings.Contains(rollbackCmd, "CERT_REMOVED_NO_REBIND") {
		t.Errorf("expected CERT_REMOVED_NO_REBIND marker in rollback script, got: %s", rollbackCmd)
	}

	// No verify script should run when oldThumbprint is empty.
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "# CERTCTL_VERIFY") {
			t.Errorf("did not expect verify script when oldThumbprint is empty, got: %s", cmd)
		}
	}

	if result.Metadata["old_thumbprint"] != "" {
		t.Errorf("expected empty old_thumbprint in metadata, got: %s", result.Metadata["old_thumbprint"])
	}
	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true in metadata, got: %s", result.Metadata["rolled_back"])
	}
}

func TestIIS_BindingUpdateFails_RollbackAlsoFails_OperatorActionable(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	executor.responses["# CERTCTL_SNAPSHOT"] = mockResponse{
		output: "OLD_THUMBPRINT:abc123\n",
		err:    nil,
	}
	executor.responses["Import-PfxCertificate"] = mockResponse{output: "OK", err: nil}
	executor.responses["Remove-WebBinding"] = mockResponse{
		output: "binding error",
		err:    fmt.Errorf("binding-step exit status 1"),
	}
	// Rollback ALSO fails — operator-actionable case.
	executor.responses["# CERTCTL_ROLLBACK"] = mockResponse{
		output: "rollback step failed",
		err:    fmt.Errorf("rollback-step exit status 2"),
	}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err == nil {
		t.Fatal("expected error when both binding and rollback fail")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Wrapped error must reference BOTH the binding error and the rollback
	// error so an operator can see what state the host is in.
	if !strings.Contains(err.Error(), "binding update failed") {
		t.Errorf("expected error to mention binding error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("expected error to mention rollback error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "manual operator inspection required") {
		t.Errorf("expected error to flag manual operator inspection, got: %v", err)
	}

	// Metadata must explicitly flag manual action and surface both errors.
	if result.Metadata["manual_action_required"] != "true" {
		t.Errorf("expected manual_action_required=true in metadata, got: %s", result.Metadata["manual_action_required"])
	}
	if result.Metadata["rolled_back"] != "false" {
		t.Errorf("expected rolled_back=false in metadata, got: %s", result.Metadata["rolled_back"])
	}
	if result.Metadata["rollback_error"] == "" {
		t.Error("expected rollback_error to be populated in metadata")
	}
	if result.Metadata["binding_error"] == "" {
		t.Error("expected binding_error to be populated in metadata")
	}
	if result.Metadata["thumbprint"] == "" {
		t.Error("expected thumbprint in metadata even on rollback failure")
	}
	if result.Metadata["old_thumbprint"] != "abc123" {
		t.Errorf("expected old_thumbprint=abc123 in metadata, got: %s", result.Metadata["old_thumbprint"])
	}
}

func TestIISConnector_DeployCertificate_SNIEnabled(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	executor := newMockExecutor()
	executor.defaultOutput = "OK"

	connector := NewWithExecutor(&Config{
		Hostname:    "web01",
		SiteName:    "Default Web Site",
		CertStore:   "My",
		Port:        443,
		SNI:         true,
		BindingInfo: "test.example.com",
	}, testLogger(), executor)

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Bundle 5: snapshot is commands[0], import is commands[1], binding is commands[2].
	if len(executor.commands) < 3 {
		t.Fatal("expected at least 3 commands (snapshot, import, binding)")
	}
	bindingCmd := executor.commands[2]
	if !strings.Contains(bindingCmd, "-SslFlags 1") {
		t.Errorf("expected -SslFlags 1 for SNI, got: %s", bindingCmd)
	}
	if result.Metadata["sni"] != "true" {
		t.Error("expected sni=true in metadata")
	}
}

// --- ValidateDeployment tests ---

func TestIISConnector_ValidateDeployment_Success(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-WebBinding"] = mockResponse{output: "ABC123DEF456\n", err: nil}
	executor.responses["Get-ChildItem"] = mockResponse{output: "VALID\n", err: nil}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	})
	if err != nil {
		t.Fatalf("ValidateDeployment failed: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid deployment, got: %s", result.Message)
	}
	if result.Metadata["thumbprint"] != "ABC123DEF456" {
		t.Errorf("expected thumbprint in metadata, got: %s", result.Metadata["thumbprint"])
	}
	if _, ok := result.Metadata["duration_ms"]; !ok {
		t.Error("expected duration_ms in metadata")
	}
}

func TestIISConnector_ValidateDeployment_NoBinding(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-WebBinding"] = mockResponse{output: "NO_BINDING\n", err: nil}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "TestSite",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	})
	if err == nil {
		t.Fatal("expected error when no binding found")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
	if !strings.Contains(err.Error(), "no HTTPS binding found") {
		t.Errorf("expected 'no HTTPS binding found' in error, got: %v", err)
	}
}

func TestIISConnector_ValidateDeployment_CertNotInStore(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-WebBinding"] = mockResponse{output: "DEADBEEF1234\n", err: nil}
	executor.responses["Get-ChildItem"] = mockResponse{output: "NOT_FOUND\n", err: nil}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	})
	if err == nil {
		t.Fatal("expected error when cert not in store")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
	if result.Metadata["status"] != "not_found" {
		t.Errorf("expected status=not_found in metadata, got: %s", result.Metadata["status"])
	}
}

func TestIISConnector_ValidateDeployment_CertExpired(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-WebBinding"] = mockResponse{output: "DEADBEEF1234\n", err: nil}
	executor.responses["Get-ChildItem"] = mockResponse{output: "EXPIRED\n", err: nil}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	})
	if err == nil {
		t.Fatal("expected error when cert is expired")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
	if result.Metadata["status"] != "expired" {
		t.Errorf("expected status=expired in metadata, got: %s", result.Metadata["status"])
	}
}

func TestIISConnector_ValidateDeployment_QueryFails(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-WebBinding"] = mockResponse{
		output: "Permission denied",
		err:    fmt.Errorf("exit status 1"),
	}

	connector := NewWithExecutor(&Config{
		Hostname:  "web01",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
	}, testLogger(), executor)

	result, err := connector.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	})
	if err == nil {
		t.Fatal("expected error when query fails")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
}

// --- PFX conversion tests (pure Go crypto, runs on any OS) ---

func TestCreatePFX_Success(t *testing.T) {
	certPEM, keyPEM, chainPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	pfxData, err := certutil.CreatePFX(certPEM, keyPEM, chainPEM, "testpassword")
	if err != nil {
		t.Fatalf("createPFX failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Fatal("expected non-empty PFX data")
	}

	// Verify PFX is parseable
	_, _, _, err = pkcs12.DecodeChain(pfxData, "testpassword")
	if err != nil {
		t.Fatalf("PFX data is not valid PKCS#12: %v", err)
	}
}

func TestCreatePFX_NoChain(t *testing.T) {
	certPEM, keyPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	pfxData, err := certutil.CreatePFX(certPEM, keyPEM, "", "testpassword")
	if err != nil {
		t.Fatalf("createPFX with no chain failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Fatal("expected non-empty PFX data")
	}
}

func TestCreatePFX_InvalidCert(t *testing.T) {
	_, keyPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	_, err = certutil.CreatePFX("not a valid cert", keyPEM, "", "password")
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestCreatePFX_InvalidKey(t *testing.T) {
	certPEM, _, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	_, err = certutil.CreatePFX(certPEM, "not a valid key", "", "password")
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
}

// --- Thumbprint tests ---

func TestComputeThumbprint_Success(t *testing.T) {
	certPEM, _, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	thumbprint, err := certutil.ComputeThumbprint(certPEM)
	if err != nil {
		t.Fatalf("computeThumbprint failed: %v", err)
	}

	// SHA-1 = 20 bytes = 40 hex chars
	if len(thumbprint) != 40 {
		t.Errorf("expected 40-char thumbprint, got %d chars: %s", len(thumbprint), thumbprint)
	}

	// Should be uppercase hex
	if thumbprint != strings.ToUpper(thumbprint) {
		t.Errorf("thumbprint should be uppercase, got: %s", thumbprint)
	}
}

func TestComputeThumbprint_InvalidPEM(t *testing.T) {
	_, err := certutil.ComputeThumbprint("not a valid pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestComputeThumbprint_EmptyString(t *testing.T) {
	_, err := certutil.ComputeThumbprint("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

// --- Validation helper tests ---

func TestValidateIISName_Valid(t *testing.T) {
	tests := []string{
		"Default Web Site",
		"My",
		"WebHosting",
		"site-01",
		"my_site.prod",
		"Test 123",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateIISName(name, "test_field"); err != nil {
				t.Errorf("expected valid name %q, got error: %v", name, err)
			}
		})
	}
}

func TestValidateIISName_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"semicolon", "My;Store"},
		{"dollar", "My$Store"},
		{"backtick", "My`Store"},
		{"pipe", "My|Store"},
		{"ampersand", "My&Store"},
		{"parentheses", "My(Store)"},
		{"quotes", `My"Store"`},
		{"angle_brackets", "My<Store>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateIISName(tt.input, "test_field"); err == nil {
				t.Errorf("expected error for name %q", tt.input)
			}
		})
	}
}

func TestValidateIISName_TooLong(t *testing.T) {
	longName := strings.Repeat("a", 257)
	if err := validateIISName(longName, "test_field"); err == nil {
		t.Fatal("expected error for name exceeding 256 chars")
	}
}

// --- Random password generation ---

func TestGenerateRandomPassword(t *testing.T) {
	pw, err := certutil.GenerateRandomPassword(32)
	if err != nil {
		t.Fatalf("generateRandomPassword failed: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("expected 32-char password, got %d", len(pw))
	}

	// Verify it only contains allowed characters
	for _, c := range pw {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Errorf("unexpected character in password: %c", c)
		}
	}

	// Verify two passwords are different (probabilistic but reliable)
	pw2, _ := certutil.GenerateRandomPassword(32)
	if pw == pw2 {
		t.Error("two generated passwords should be different")
	}
}

// --- WinRM mode tests ---

func TestIISConnector_ValidateConfig_WinRMMode(t *testing.T) {
	executor := newMockExecutor()
	executor.responses["Get-Website"] = mockResponse{output: "Default Web Site\n", err: nil}
	executor.responses["Test-Path"] = mockResponse{output: "True\n", err: nil}

	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
		Mode:      "winrm",
		WinRM: WinRMConfig{
			Host:     "iis-server.example.com",
			Port:     5985,
			Username: "Administrator",
			Password: "P@ssw0rd",
		},
	}

	// WinRM mode should NOT check for powershell.exe locally
	connector := NewWithExecutor(&cfg, testLogger(), executor)
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed in WinRM mode: %v", err)
	}

	// Verify PowerShell commands were executed via the executor (not locally)
	if len(executor.commands) < 2 {
		t.Fatalf("expected at least 2 executor commands, got %d", len(executor.commands))
	}
}

func TestIISConnector_ValidateConfig_InvalidMode(t *testing.T) {
	connector := NewWithExecutor(&Config{}, testLogger(), newMockExecutor())
	cfg := Config{
		SiteName:  "Default Web Site",
		CertStore: "My",
		Mode:      "invalid",
	}
	rawConfig, _ := json.Marshal(cfg)

	err := connector.ValidateConfig(context.Background(), rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "unsupported mode") {
		t.Errorf("expected 'unsupported mode' in error, got: %v", err)
	}
}

func TestIISConnector_DeployCertificate_WinRMMode(t *testing.T) {
	executor := newMockExecutor()
	executor.defaultOutput = "OK"

	cfg := Config{
		Hostname:  "iis-server.example.com",
		SiteName:  "Default Web Site",
		CertStore: "My",
		Port:      443,
		IPAddress: "*",
		Mode:      "winrm",
	}

	connector := NewWithExecutor(&cfg, testLogger(), executor)
	certPEM, keyPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	result, err := connector.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: "",
	})
	if err != nil {
		t.Fatalf("DeployCertificate in WinRM mode failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify the import script used base64 encoding (WinRM mode)
	foundBase64Import := false
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "FromBase64String") && strings.Contains(cmd, "Import-PfxCertificate") {
			foundBase64Import = true
			break
		}
	}
	if !foundBase64Import {
		t.Error("WinRM mode should use base64-encoded PFX transfer, but no FromBase64String found in commands")
	}

	// Verify remote temp file cleanup is in the script
	foundCleanup := false
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "Remove-Item") && strings.Contains(cmd, "finally") {
			foundCleanup = true
			break
		}
	}
	if !foundCleanup {
		t.Error("WinRM mode should include remote temp file cleanup (try/finally Remove-Item)")
	}
}

func TestIISConnector_New_WinRMMode_MissingHost(t *testing.T) {
	cfg := Config{
		Mode: "winrm",
		WinRM: WinRMConfig{
			Username: "admin",
			Password: "pass",
		},
	}
	_, err := New(&cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for missing WinRM host")
	}
	if !strings.Contains(err.Error(), "winrm_host is required") {
		t.Errorf("expected 'winrm_host is required' error, got: %v", err)
	}
}

func TestIISConnector_New_WinRMMode_MissingUsername(t *testing.T) {
	cfg := Config{
		Mode: "winrm",
		WinRM: WinRMConfig{
			Host:     "server.example.com",
			Password: "pass",
		},
	}
	_, err := New(&cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for missing WinRM username")
	}
	if !strings.Contains(err.Error(), "winrm_username is required") {
		t.Errorf("expected 'winrm_username is required' error, got: %v", err)
	}
}

func TestIISConnector_New_WinRMMode_MissingPassword(t *testing.T) {
	cfg := Config{
		Mode: "winrm",
		WinRM: WinRMConfig{
			Host:     "server.example.com",
			Username: "admin",
		},
	}
	_, err := New(&cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for missing WinRM password")
	}
	if !strings.Contains(err.Error(), "winrm_password is required") {
		t.Errorf("expected 'winrm_password is required' error, got: %v", err)
	}
}

func TestIISConnector_New_InvalidMode(t *testing.T) {
	cfg := Config{Mode: "ssh"}
	_, err := New(&cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "unsupported IIS connector mode") {
		t.Errorf("expected 'unsupported IIS connector mode' error, got: %v", err)
	}
}

func TestIISConnector_New_DefaultLocalMode(t *testing.T) {
	cfg := Config{} // No mode specified — should default to local
	connector, err := New(&cfg, testLogger())
	if err != nil {
		t.Fatalf("New() with default mode failed: %v", err)
	}
	if connector == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestWinRMConfig_DefaultPorts(t *testing.T) {
	// HTTP default: 5985
	cfg := &WinRMConfig{
		Host:     "server.example.com",
		Username: "admin",
		Password: "pass",
	}
	exec, err := newWinRMExecutor(cfg)
	if err != nil {
		t.Fatalf("newWinRMExecutor failed: %v", err)
	}
	if exec == nil {
		t.Fatal("expected non-nil executor")
	}

	// HTTPS default: 5986
	cfgHTTPS := &WinRMConfig{
		Host:     "server.example.com",
		Username: "admin",
		Password: "pass",
		UseHTTPS: true,
		Insecure: true,
	}
	execHTTPS, err := newWinRMExecutor(cfgHTTPS)
	if err != nil {
		t.Fatalf("newWinRMExecutor (HTTPS) failed: %v", err)
	}
	if execHTTPS == nil {
		t.Fatal("expected non-nil HTTPS executor")
	}
}
