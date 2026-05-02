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

	// Bundle 10: idempotency probe runs first (returns IDEM_MISS by default),
	// then Bundle 7: success path runs 3 PowerShell scripts in order:
	// probe → snapshot → import → cleanup. Seed responses for each.
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"TEMPDIR:/tmp/certctl-snapshot-abc",
			"SUCCESS:AABBCCDD",
			"CLEANUP_OK",
		},
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

	// Bundle 10: 4 scripts on success path (probe + snapshot + import + cleanup).
	if len(mock.scripts) != 4 {
		t.Fatalf("expected 4 script calls (probe + snapshot + import + cleanup), got %d", len(mock.scripts))
	}
	if !strings.Contains(mock.scripts[0], "# CERTCTL_IDEM_PROBE") {
		t.Errorf("expected # CERTCTL_IDEM_PROBE in first script, got: %s", mock.scripts[0])
	}
	if !strings.Contains(mock.scripts[1], "# CERTCTL_SNAPSHOT") {
		t.Errorf("expected # CERTCTL_SNAPSHOT in second script, got: %s", mock.scripts[1])
	}
	importScript := mock.scripts[2]
	if !strings.Contains(importScript, "Import-PfxCertificate") {
		t.Error("expected Import-PfxCertificate in third script")
	}
	if !strings.Contains(importScript, "Cert:\\LocalMachine\\My") {
		t.Error("expected correct cert store path in third script")
	}
	if !strings.Contains(mock.scripts[3], "# CERTCTL_CLEANUP") {
		t.Errorf("expected # CERTCTL_CLEANUP in fourth script, got: %s", mock.scripts[3])
	}
}

func TestWinCertStore_Idempotent_SkipsImportWhenCertInStore(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Probe returns IDEM_MATCH
	mock := &mockExecutor{
		responses: []string{"IDEM_MATCH"},
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

	// Verify idempotent flag is set
	if result.Metadata["idempotent"] != "true" {
		t.Errorf("expected idempotent=true, got %s", result.Metadata["idempotent"])
	}

	// Only the probe should have run (1 script call)
	if len(mock.scripts) != 1 {
		t.Errorf("expected 1 script call (probe only), got %d", len(mock.scripts))
	}
	if !strings.Contains(mock.scripts[0], "# CERTCTL_IDEM_PROBE") {
		t.Errorf("expected probe script, got: %s", mock.scripts[0])
	}

	// Verify no Import-PfxCertificate call
	for i, script := range mock.scripts {
		if strings.Contains(script, "Import-PfxCertificate") {
			t.Errorf("script %d should not contain Import-PfxCertificate (idempotent short-circuit): %s", i, script)
		}
	}
}

func TestWinCertStore_Idempotent_NotInStore_FallsThroughToDeploy(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Probe returns IDEM_MISS, then standard snapshot + import + cleanup responses
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"TEMPDIR:/tmp/certctl-snapshot-def",
			"SUCCESS:DDEEFFGG",
			"CLEANUP_OK",
		},
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

	// Verify idempotent flag is NOT set
	if result.Metadata["idempotent"] != "" {
		t.Errorf("expected no idempotent flag, got %s", result.Metadata["idempotent"])
	}

	// Full flow: probe + snapshot + import + cleanup = 4 scripts
	if len(mock.scripts) != 4 {
		t.Errorf("expected 4 script calls (probe, snapshot, import, cleanup), got %d", len(mock.scripts))
	}

	// Verify probe ran first
	if !strings.Contains(mock.scripts[0], "# CERTCTL_IDEM_PROBE") {
		t.Errorf("expected probe as first script, got: %s", mock.scripts[0])
	}

	// Verify import happened
	hasImport := false
	for _, script := range mock.scripts {
		if strings.Contains(script, "Import-PfxCertificate") {
			hasImport = true
			break
		}
	}
	if !hasImport {
		t.Error("expected Import-PfxCertificate in scripts")
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

	// Bundle 10 / Top-10 fix #3 idempotency probe runs first → IDEM_MISS,
	// fall through. Bundle 7: snapshot returns empty → import fails →
	// rollback runs (and succeeds since snapshot was empty, only removes
	// the new cert if it landed).
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"TEMPDIR:/tmp/certctl-snapshot-xyz",
			"Access denied",
			"ROLLBACK_OK",
		},
		errors: []error{nil, nil, fmt.Errorf("exit code 1"), nil},
	}
	c := NewWithExecutor(&Config{}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "PowerShell import failed") {
		t.Fatalf("expected import failure error, got: %v", err)
	}
	// Bundle 7: error message must reference rollback so operators know
	// the deploy left the store in a known state.
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected error to mention 'rolled back', got: %v", err)
	}
}

func TestDeployCertificate_WithFriendlyName(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"TEMPDIR:/tmp/certctl-snapshot-fn",
			"SUCCESS:AABB",
			"CLEANUP_OK",
		},
	}
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
	// Bundle 10: probe at [0], snapshot at [1], import at [2].
	if len(mock.scripts) < 3 {
		t.Fatalf("expected at least 3 scripts (probe + snapshot + import), got %d", len(mock.scripts))
	}
	if !strings.Contains(mock.scripts[2], "FriendlyName") {
		t.Error("expected FriendlyName in import script")
	}
}

func TestDeployCertificate_WithRemoveExpired(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"TEMPDIR:/tmp/certctl-snapshot-re",
			"SUCCESS:AABB",
			"CLEANUP_OK",
		},
	}
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
	// Bundle 10: probe at [0], snapshot at [1], import at [2].
	if len(mock.scripts) < 3 {
		t.Fatalf("expected at least 3 scripts (probe + snapshot + import), got %d", len(mock.scripts))
	}
	if !strings.Contains(mock.scripts[2], "Remove-Item") {
		t.Error("expected Remove-Item for expired cert cleanup in import script")
	}
}

// --- Bundle 7: pre-deploy snapshot + on-import-failure rollback ---
//
// These four tests pin the load-bearing rollback contract added in
// Bundle 7 of the 2026-05-02 deployment-target audit:
//   - happy rollback path: snapshot finds same-Subject cert → import
//     fails → rollback removes new cert + re-imports snapshot;
//   - first-time deploy: snapshot finds no same-Subject certs → import
//     fails → rollback only removes the new cert (no re-import);
//   - FriendlyName-step failure: import script fails on Set
//     FriendlyName → same rollback path;
//   - rollback-also-fails: operator-actionable wrapped error.

func TestWinCertStore_ImportFails_RemovesNewCert_RestoresOldFromSnapshot(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Probe → IDEM_MISS, fall through. Snapshot finds one same-Subject
	// cert and exports it. Import fails. Rollback succeeds. Verify confirms.
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"SNAPSHOT:OLDTHUMB123:/tmp/certctl-snapshot-abc/OLDTHUMB123.pfx\nTEMPDIR:/tmp/certctl-snapshot-abc",
			"PFX import error",
			"ROLLBACK_OK",
			"VERIFY_OK",
		},
		errors: []error{nil, nil, fmt.Errorf("exit code 1"), nil, nil},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when import fails")
	}
	if result == nil {
		t.Fatal("expected non-nil result on rollback path")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
	if !strings.Contains(err.Error(), "PowerShell import failed") {
		t.Errorf("expected error to mention import failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected error to mention 'rolled back', got: %v", err)
	}

	// 5 scripts: probe + snapshot + import + rollback + verify.
	if len(mock.scripts) != 5 {
		t.Fatalf("expected 5 scripts (probe + snapshot + import + rollback + verify), got %d", len(mock.scripts))
	}

	// Locate the rollback script and assert it contains BOTH a Remove-Item
	// for the new thumbprint AND an Import-PfxCertificate for the
	// snapshotted PFX.
	var rollbackScript string
	for _, s := range mock.scripts {
		if strings.Contains(s, "# CERTCTL_ROLLBACK") {
			rollbackScript = s
			break
		}
	}
	if rollbackScript == "" {
		t.Fatal("expected rollback script to be executed")
	}
	if !strings.Contains(rollbackScript, "Remove-Item") {
		t.Errorf("expected rollback to contain Remove-Item, got: %s", rollbackScript)
	}
	if !strings.Contains(rollbackScript, "Import-PfxCertificate") {
		t.Errorf("expected rollback to Import-PfxCertificate the snapshot, got: %s", rollbackScript)
	}
	if !strings.Contains(rollbackScript, "OLDTHUMB123.pfx") {
		t.Errorf("expected rollback to reference the snapshot pfx path, got: %s", rollbackScript)
	}

	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true in metadata, got: %s", result.Metadata["rolled_back"])
	}
}

func TestWinCertStore_ImportFails_NoExistingSameSubject_RemovesNewCertOnly(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Probe → IDEM_MISS, fall through. Snapshot returns THUMB lines
	// (different-Subject certs in store) but NO SNAPSHOT lines — no
	// same-Subject cert was exported. Rollback removes the new cert but
	// does NOT call Import-PfxCertificate.
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"THUMB:UNRELATED1\nTHUMB:UNRELATED2\nTEMPDIR:/tmp/certctl-snapshot-noss",
			"PFX import error",
			"ROLLBACK_OK",
			"VERIFY_OK",
		},
		errors: []error{nil, nil, fmt.Errorf("exit code 1"), nil, nil},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger(), mock)

	_, err = c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when import fails")
	}

	var rollbackScript string
	for _, s := range mock.scripts {
		if strings.Contains(s, "# CERTCTL_ROLLBACK") {
			rollbackScript = s
			break
		}
	}
	if rollbackScript == "" {
		t.Fatal("expected rollback script to be executed")
	}
	if !strings.Contains(rollbackScript, "Remove-Item") {
		t.Errorf("expected rollback to remove new cert via Remove-Item, got: %s", rollbackScript)
	}
	// No same-Subject snapshots → no Import-PfxCertificate during rollback.
	if strings.Contains(rollbackScript, "Import-PfxCertificate") {
		t.Errorf("expected no Import-PfxCertificate when snapshot has no same-Subject entries, got: %s", rollbackScript)
	}
}

func TestWinCertStore_FriendlyNameFails_NewCertRemoved_OldCertsRestored(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// The connector cannot inspect WHICH step inside the import script
	// failed — Execute returns a single (output, error). Operators see
	// the FriendlyName failure surfaced via the error output. The
	// rollback runs the same way regardless of which post-Import step
	// failed (FriendlyName, Get-ChildItem verify, RemoveExpired).
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"SNAPSHOT:OLDTHUMB456:/tmp/certctl-snapshot-fn/OLDTHUMB456.pfx\nTEMPDIR:/tmp/certctl-snapshot-fn",
			"Cannot set FriendlyName: invalid character in friendly name",
			"ROLLBACK_OK",
			"VERIFY_OK",
		},
		errors: []error{nil, nil, fmt.Errorf("Set-ItemProperty failed"), nil, nil},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
		FriendlyName:  "Production",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when FriendlyName step fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
	// Operator visibility: the import_error in metadata should preserve
	// the PowerShell output so operators can tell what went wrong.
	if !strings.Contains(result.Metadata["import_error"], "FriendlyName") {
		t.Errorf("expected import_error to reference FriendlyName, got: %s", result.Metadata["import_error"])
	}

	var rollbackScript string
	for _, s := range mock.scripts {
		if strings.Contains(s, "# CERTCTL_ROLLBACK") {
			rollbackScript = s
			break
		}
	}
	if rollbackScript == "" {
		t.Fatal("expected rollback script to be executed")
	}
	if !strings.Contains(rollbackScript, "Remove-Item") {
		t.Errorf("expected rollback to Remove-Item the new cert, got: %s", rollbackScript)
	}
	if !strings.Contains(rollbackScript, "OLDTHUMB456.pfx") {
		t.Errorf("expected rollback to restore snapshotted cert, got: %s", rollbackScript)
	}

	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true, got: %s", result.Metadata["rolled_back"])
	}
}

func TestWinCertStore_ImportFails_RollbackAlsoFails_OperatorActionable(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Probe → IDEM_MISS, fall through. Snapshot succeeds; import fails;
	// rollback ALSO fails. Operator-actionable case: both errors must be
	// surfaced + metadata flags manual_action_required.
	mock := &mockExecutor{
		responses: []string{
			"IDEM_MISS",
			"SNAPSHOT:OLDTHUMB789:/tmp/certctl-snapshot-rbf/OLDTHUMB789.pfx\nTEMPDIR:/tmp/certctl-snapshot-rbf",
			"Import error",
			"Rollback step failed",
		},
		errors: []error{
			nil,
			nil,
			fmt.Errorf("import-step exit code 1"),
			fmt.Errorf("rollback-step exit code 2"),
		},
	}
	c := NewWithExecutor(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger(), mock)

	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected error when both import and rollback fail")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Wrapped error must mention BOTH errors.
	if !strings.Contains(err.Error(), "PowerShell import failed") {
		t.Errorf("expected error to mention import failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("expected error to mention rollback failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "manual operator inspection required") {
		t.Errorf("expected error to flag manual inspection, got: %v", err)
	}

	// Metadata flags manual action + surfaces both errors.
	if result.Metadata["manual_action_required"] != "true" {
		t.Errorf("expected manual_action_required=true, got: %s", result.Metadata["manual_action_required"])
	}
	if result.Metadata["rolled_back"] != "false" {
		t.Errorf("expected rolled_back=false, got: %s", result.Metadata["rolled_back"])
	}
	if result.Metadata["rollback_error"] == "" {
		t.Error("expected rollback_error in metadata")
	}
	if result.Metadata["import_error"] == "" {
		t.Error("expected import_error in metadata")
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

// --- Top-10 fix #4: default-deadline ctx wrapper for PowerShell exec calls ---
//
// These tests pin realExecutor's safety-net behavior. See the matching pair
// in iis_test.go for the rationale (subprocess fails fast on non-Windows
// runners / deadline cancels on Windows; either path must return fast).

func TestWinCertStore_RealExecutor_AttachesDefaultDeadlineWhenCallerHasNone(t *testing.T) {
	e := &realExecutor{deadline: 100 * time.Millisecond}
	start := time.Now()
	_, err := e.Execute(context.Background(), "Start-Sleep -Seconds 5")
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected fast return (default deadline = 100ms), took %v: err=%v", elapsed, err)
	}
	if err == nil {
		t.Error("expected an error (context.DeadlineExceeded on Windows / powershell.exe missing on Linux)")
	}
}

func TestWinCertStore_RealExecutor_RespectsCallerDeadlineWhenSet(t *testing.T) {
	e := &realExecutor{deadline: 10 * time.Second} // long fallback
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = e.Execute(ctx, "Start-Sleep -Seconds 5")
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected caller's tight 50ms deadline to fire fast, took %v", elapsed)
	}
}

func TestWinCertStore_RealExecutor_NoDeadlineWiredWhenZero(t *testing.T) {
	// deadline=0 means "no fallback wrapper". Pass a tight caller deadline.
	e := &realExecutor{deadline: 0}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = e.Execute(ctx, "Start-Sleep -Seconds 5")
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected caller deadline to bound the call, took %v", elapsed)
	}
}

func TestWinCertStore_New_DefaultsExecDeadlineTo60s(t *testing.T) {
	c, err := New(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
	}, testLogger())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if c.config.ExecDeadline != 60*time.Second {
		t.Errorf("expected default ExecDeadline=60s, got %v", c.config.ExecDeadline)
	}
}

func TestWinCertStore_New_RespectsExplicitExecDeadline(t *testing.T) {
	c, err := New(&Config{
		StoreName:     "My",
		StoreLocation: "LocalMachine",
		ExecDeadline:  10 * time.Minute,
	}, testLogger())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if c.config.ExecDeadline != 10*time.Minute {
		t.Errorf("expected ExecDeadline=10m, got %v", c.config.ExecDeadline)
	}
}
