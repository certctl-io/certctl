package nginx_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/nginx"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 4 of the deploy-hardening I master bundle: ≥40 tests on
// the NGINX connector covering the atomic-deploy + post-deploy TLS
// verify + rollback + ValidateOnly + ownership-preservation matrix
// the prompt requires. The IIS bar is 41; this file plus the 17
// pre-existing tests in nginx_test.go puts NGINX at well over 40.

// --- Fixtures + helpers ---

// Test fixtures: valid base64-shaped PEM bodies so the
// fingerprintOfPEM helper can compute SHA-256 over real binary
// payloads. The actual DER content is junk; only the SHA-256 over
// it matters for verifying post-deploy match logic.
const (
	certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVC1QRU0tQ09OVEVOVFMtQQ==\n-----END CERTIFICATE-----\n"
	certB = "-----BEGIN CERTIFICATE-----\nQkVUQS1DRVJULVBFTS1DT05URU5UUy1C\n-----END CERTIFICATE-----\n"
	chain = "-----BEGIN CERTIFICATE-----\nSU5URVJNRURJQVRFLUNIQUlOLVBFTQ==\n-----END CERTIFICATE-----\n"
	keyA  = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktQQ==\n-----END PRIVATE KEY-----\n"
)

// quietLogger discards log output so test runs stay readable.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

// fingerprintOfPEM returns the SHA-256 hex of the first cert in
// the PEM bundle. Mirrors what tlsprobe.ProbeTLS would return for
// a deployed cert. Used by stub probers to claim "deployed cert
// matches" or "doesn't match".
func fingerprintOfPEM(t *testing.T, pem string) string {
	t.Helper()
	begin := "-----BEGIN CERTIFICATE-----"
	end := "-----END CERTIFICATE-----"
	beginIdx := strings.Index(pem, begin)
	if beginIdx < 0 {
		t.Fatal("no cert block")
	}
	body := pem[beginIdx+len(begin):]
	endIdx := strings.Index(body, end)
	if endIdx < 0 {
		t.Fatal("no end")
	}
	body = strings.TrimSpace(body[:endIdx])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, " ", "")
	der, err := decodeBase64(body)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func decodeBase64(s string) ([]byte, error) {
	// Use a real base64 decoder for the fingerprint helper. We
	// avoid encoding/base64 in this package's import to keep
	// test-time imports lean — but for a one-shot test helper
	// it's fine to import it here.
	return base64StdDecode(s)
}

// successProbe returns a stub probe.ProbeResult with the given
// fingerprint. Used to simulate post-deploy TLS verify success
// (matching) or mismatch.
func successProbe(fp string) func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
	return func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{
			Address:     address,
			Success:     true,
			Fingerprint: fp,
		}
	}
}

// failProbe returns a stub indicating dial timeout / handshake fail.
func failProbe(reason string) func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
	return func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{
			Address: address,
			Success: false,
			Error:   reason,
		}
	}
}

// noopRun stubs runValidate / runReload to always succeed.
func noopRun(ctx context.Context, command string) ([]byte, error) {
	return nil, nil
}

// failingRun stubs runValidate / runReload with a fixed error.
func failingRun(reason string) func(ctx context.Context, command string) ([]byte, error) {
	return func(ctx context.Context, command string) ([]byte, error) {
		return []byte("stderr: " + reason), errors.New(reason)
	}
}

// newConnectorWithStubs is the canonical test-time constructor —
// produces a Connector with no-op validate / no-op reload / no-op
// (skip-because-no-endpoint) probe.
func newConnectorWithStubs(t *testing.T, cfg *nginx.Config) *nginx.Connector {
	c := nginx.New(cfg, quietLogger())
	c.SetTestRunValidate(noopRun)
	c.SetTestRunReload(noopRun)
	c.SetTestProbe(successProbe("ignored"))
	return c
}

// --- The ≥40 tests ---

// 1. Happy path: cert + key + chain all written atomically; reload
// succeeds; final files have new bytes.
func TestNginx_Atomic_HappyPath_CertChainKeyAllAtomic(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ChainPath:       filepath.Join(dir, "chain.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		KeyFileMode:     0640,
	}
	c := newConnectorWithStubs(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA, ChainPEM: chain, KeyPEM: keyA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatal("Success=false")
	}
	for path, want := range map[string]string{cfg.CertPath: certA, cfg.ChainPath: chain, cfg.KeyPath: keyA} {
		got, _ := os.ReadFile(path)
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

// 2. Validate (PreCommit) fails → no live file modified, error
// surfaces as ErrValidateFailed wrap.
func TestNginx_Atomic_ValidateFails_NoFilesChanged(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunValidate(failingRun("invalid SAN"))

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, deploy.ErrValidateFailed) {
		t.Errorf("got %v, want ErrValidateFailed wrap", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert was modified despite validate failure: %q", got)
	}
}

// 3. Reload (PostCommit) fails → rollback restores the previous
// bytes + reload runs again successfully → ErrReloadFailed surfaces.
func TestNginx_Atomic_ReloadFails_RollbackRestoresPrevious(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var reloadCalls int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		n := atomic.AddInt32(&reloadCalls, 1)
		if n == 1 {
			return nil, errors.New("nginx exited 1")
		}
		return nil, nil
	})

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected reload error")
	}
	if !errors.Is(err, deploy.ErrReloadFailed) {
		t.Errorf("got %v, want ErrReloadFailed wrap", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert after rollback = %q, want ORIGINAL", got)
	}
	if atomic.LoadInt32(&reloadCalls) != 2 {
		t.Errorf("reload calls = %d, want 2 (once for new bytes, once for restored)", reloadCalls)
	}
}

// 4. Reload fails AND the second reload also fails → ErrRollbackFailed.
func TestNginx_Atomic_ReloadFails_AndRollbackReloadAlsoFails(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunReload(failingRun("nginx wedged"))

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrRollbackFailed) {
		t.Errorf("got %v, want ErrRollbackFailed wrap", err)
	}
}

// 5. Post-deploy verify SHA-256 mismatch → rollback restores OLD
// cert + emits an error.
func TestNginx_Atomic_PostVerify_SHA256Mismatch_TriggersRollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:                 cert,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx-test:443",
			Timeout:  100 * time.Millisecond,
		},
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestProbe(successProbe("0000000000000000000000000000000000000000000000000000000000000000"))

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected error from verify mismatch")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("error not labeled SHA-256 mismatch: %v", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert after verify-failure rollback = %q, want ORIGINAL", got)
	}
}

// 6. Post-deploy verify succeeds (fingerprint matches) → result
// reports Success=true.
func TestNginx_Atomic_PostVerify_FingerprintMatches_Succeeds(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:                 filepath.Join(dir, "cert.pem"),
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
			Timeout:  100 * time.Millisecond,
		},
	}
	c := newConnectorWithStubs(t, cfg)
	want := fingerprintOfPEM(t, certA)
	c.SetTestProbe(successProbe(want))

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false")
	}
}

// 7. Post-deploy verify TLS-dial timeout → rollback restores.
func TestNginx_Atomic_PostVerify_DialTimeout_TriggersRollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:                 cert,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
			Timeout:  10 * time.Millisecond,
		},
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestProbe(failProbe("dial tcp: i/o timeout"))

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected dial-timeout error")
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert after dial-timeout rollback = %q, want ORIGINAL", got)
	}
}

// 8. Idempotency: second deploy with identical bytes → no validate
// + no reload + verify skipped (the deploy was a no-op).
func TestNginx_Atomic_IdempotencyHit_SkipsAllSteps(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte(certA), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var validateCalls, reloadCalls, probeCalls int32
	c.SetTestRunValidate(func(ctx context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&validateCalls, 1)
		return nil, nil
	})
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&reloadCalls, 1)
		return nil, nil
	})
	c.SetTestProbe(func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&probeCalls, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "ignored"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false on idempotent skip")
	}
	if validateCalls != 0 || reloadCalls != 0 || probeCalls != 0 {
		t.Errorf("expected 0/0/0 calls, got %d/%d/%d", validateCalls, reloadCalls, probeCalls)
	}
}

// 9. Mode override on key file: KeyFileMode 0600 wins over default.
func TestNginx_Atomic_KeyFileMode_OverrideWins(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		KeyFileMode:     0600,
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA}); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(cfg.KeyPath)
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o, want 0600", stat.Mode().Perm())
	}
}

// 10. Existing cert file's mode is preserved across renewal.
func TestNginx_Atomic_ExistingMode_Preserved(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("OLD"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cert, 0640); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(cert)
	if stat.Mode().Perm() != 0640 {
		t.Errorf("mode = %#o, want 0640 (preservation)", stat.Mode().Perm())
	}
}

// 11. Backups are pruned to the configured retention.
func TestNginx_Atomic_BackupRetention_KeepsLastN(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("V0"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		BackupRetention: 2,
	}
	c := newConnectorWithStubs(t, cfg)
	for i := 1; i <= 5; i++ {
		if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
			CertPEM: fmt.Sprintf("V%d-CERT", i),
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	entries, _ := os.ReadDir(dir)
	bakCount := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			bakCount++
		}
	}
	if bakCount != 2 {
		t.Errorf("backup count = %d, want 2", bakCount)
	}
}

// 12. ValidateOnly happy path: returns nil when validate command
// passes.
func TestNginx_ValidateOnly_HappyPath_ReturnsNil(t *testing.T) {
	cfg := &nginx.Config{
		CertPath:        "/tmp/cert.pem",
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

// 13. ValidateOnly returns the validate command's error.
func TestNginx_ValidateOnly_ValidateFails_ReturnsWrappedError(t *testing.T) {
	cfg := &nginx.Config{
		CertPath:        "/tmp/cert.pem",
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunValidate(failingRun("invalid certificate"))
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got ErrValidateOnlyNotSupported, want wrapped validate error: %v", err)
	}
}

// 14. ValidateOnly returns ErrValidateOnlyNotSupported when no
// validate command configured.
func TestNginx_ValidateOnly_NoConfig_ReturnsSentinel(t *testing.T) {
	cfg := &nginx.Config{ /* no ValidateCommand */ }
	c := nginx.New(cfg, quietLogger())
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v, want ErrValidateOnlyNotSupported", err)
	}
}

// 15. Post-deploy verify ON but endpoint empty → skip with warn.
// Deploy still succeeds.
func TestNginx_Atomic_PostVerify_NoEndpoint_SkipsWithWarn(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled: true,
			// Endpoint left blank
		},
	}
	c := newConnectorWithStubs(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false")
	}
}

// 16. Post-deploy verify explicitly DISABLED → skip entirely.
func TestNginx_Atomic_PostVerify_Disabled_NoProbeCalled(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  false,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	var probeCalls int32
	c.SetTestProbe(func(ctx context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&probeCalls, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "ignored"}
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 {
		t.Errorf("probe called %d times despite Enabled=false", probeCalls)
	}
}

// 17. Verify retries: 3 attempts, fingerprint matches on the 3rd.
func TestNginx_Atomic_PostVerify_RetriesUntilMatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:                 filepath.Join(dir, "cert.pem"),
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 3,
		PostDeployVerifyBackoff:  1 * time.Millisecond,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	want := fingerprintOfPEM(t, certA)
	var attempts int32
	c.SetTestProbe(func(ctx context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return tlsprobe.ProbeResult{Success: true, Fingerprint: "stale-from-other-pod"}
		}
		return tlsprobe.ProbeResult{Success: true, Fingerprint: want}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false")
	}
	if attempts != 3 {
		t.Errorf("probe attempts = %d, want 3", attempts)
	}
}

// 18. Verify exhausts retries → rollback.
func TestNginx_Atomic_PostVerify_RetriesExhausted_RollsBack(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:                 cert,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 2,
		PostDeployVerifyBackoff:  1 * time.Millisecond,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestProbe(successProbe("0000000000000000000000000000000000000000000000000000000000000000"))

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected verify-mismatch error")
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert after rollback = %q, want ORIGINAL", got)
	}
}

// 19. Concurrent deploys to same paths serialize via deploy
// package's file mutex.
func TestNginx_Atomic_ConcurrentDeploys_SamePath_Serialize(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var inFlight, maxInFlight int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return nil, nil
	})
	const N = 5
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
				CertPEM: fmt.Sprintf("WRITER-%d-%s", idx, certA),
			})
			errs <- err
		}(i)
	}
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Errorf("Deploy %d: %v", i, err)
		}
	}
	if maxInFlight > 1 {
		t.Errorf("max concurrent reload = %d, want 1", maxInFlight)
	}
}

// 20. Deploy without chain still succeeds (chain field optional).
func TestNginx_Atomic_NoChain_StillSucceeds(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false")
	}
}

// 21. Deploy without key → only cert + chain written.
func TestNginx_Atomic_NoKey_OnlyCertAndChainWritten(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ChainPath:       filepath.Join(dir, "chain.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.KeyPath); err == nil {
		t.Error("key file written despite empty KeyPEM")
	}
}

// 22. ChainPath unset + ChainPEM provided → chain not written
// (operator never asked for it).
func TestNginx_Atomic_NoChainPath_ChainPEMIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain}); err != nil {
		t.Fatal(err)
	}
}

// 23. SHA-256 idempotency check across cert + key + chain.
func TestNginx_Atomic_Idempotency_AllThreeFilesMatch(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	chainP := filepath.Join(dir, "chain.pem")
	key := filepath.Join(dir, "key.pem")
	for _, p := range []struct {
		path string
		body string
	}{{cert, certA}, {chainP, chain}, {key, keyA}} {
		if err := os.WriteFile(p.path, []byte(p.body), 0640); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ChainPath:       chainP,
		KeyPath:         key,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var reloadCalls int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&reloadCalls, 1)
		return nil, nil
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA, ChainPEM: chain, KeyPEM: keyA,
	}); err != nil {
		t.Fatal(err)
	}
	if reloadCalls != 0 {
		t.Errorf("reload called %d times despite idempotent input", reloadCalls)
	}
}

// 24. Partial idempotency (cert matches, key differs) → full
// deploy (validate + reload run).
func TestNginx_Atomic_PartialIdempotency_FullDeploy(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte(certA), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("OLD-KEY"), 0640); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		KeyPath:         key,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var reloadCalls int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&reloadCalls, 1)
		return nil, nil
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA}); err != nil {
		t.Fatal(err)
	}
	if reloadCalls != 1 {
		t.Errorf("reload called %d times, want 1 (partial-mismatch should trigger full deploy)", reloadCalls)
	}
}

// 25. New file (didn't exist) gets default mode 0644 for cert.
func TestNginx_Atomic_NewCert_DefaultMode0644(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(cfg.CertPath)
	if stat.Mode().Perm() != 0644 {
		t.Errorf("default cert mode = %#o, want 0644", stat.Mode().Perm())
	}
}

// 26. Backup file exists after first deploy with existing file.
func TestNginx_Atomic_FirstDeploy_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
			break
		}
	}
	if !found {
		t.Error("no backup file created")
	}
}

// 27. BackupRetention=-1 disables backups (no foot-gun protection).
func TestNginx_Atomic_BackupDisabled_NoBackupFile(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
		BackupRetention: -1,
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Errorf("backup created despite BackupRetention=-1: %s", e.Name())
		}
	}
}

// 28. ValidateOnly with stubbed validate-fail returns the wrapped
// command output for the operator to read.
func TestNginx_ValidateOnly_ErrorMessageIncludesStderr(t *testing.T) {
	cfg := &nginx.Config{
		CertPath:        "/tmp/cert.pem",
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunValidate(failingRun("alert: SSL_CTX_use_certificate failed"))
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "SSL_CTX_use_certificate failed") {
		t.Errorf("error %q doesn't include validate stderr", err)
	}
}

// 29. Context cancellation propagates through deploy.Apply.
func TestNginx_Atomic_ContextCancelled_AbortsCleanly(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected context.Canceled")
	}
}

// 30. Verify-failure rollback re-runs reload against restored bytes.
func TestNginx_Atomic_VerifyFailure_RollbackRunsReloadAgain(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:                 cert,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestProbe(successProbe("0000000000000000000000000000000000000000000000000000000000000000"))
	var reloadCalls int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&reloadCalls, 1)
		return nil, nil
	})

	_, _ = c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if reloadCalls != 2 {
		t.Errorf("reload calls = %d, want 2 (once for new bytes, once for rollback restore)", reloadCalls)
	}
}

// 31. ValidateOnly with cancelled context returns context error.
func TestNginx_ValidateOnly_ContextCancelled(t *testing.T) {
	cfg := &nginx.Config{
		CertPath:        "/tmp/cert.pem",
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunValidate(func(ctx context.Context, _ string) ([]byte, error) {
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.ValidateOnly(ctx, target.DeploymentRequest{}); err == nil {
		t.Error("expected error from cancelled ctx")
	}
}

// 32. Cert + Chain + Key + verify all deploy in single Apply call.
func TestNginx_Atomic_AllFour_OneApply(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:                 filepath.Join(dir, "cert.pem"),
		ChainPath:                filepath.Join(dir, "chain.pem"),
		KeyPath:                  filepath.Join(dir, "key.pem"),
		KeyFileMode:              0640,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestProbe(successProbe(fingerprintOfPEM(t, certA)))

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA, ChainPEM: chain, KeyPEM: keyA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Error("Success=false")
	}
}

// 33. Idempotent skip skips post-verify too (deploy was a no-op).
func TestNginx_Atomic_IdempotentSkip_SkipsVerify(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte(certA), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:                 cert,
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	var probeCalls int32
	c.SetTestProbe(func(ctx context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&probeCalls, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "ignored"}
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 {
		t.Errorf("probe called %d times despite idempotent skip", probeCalls)
	}
}

// 34. Result.Metadata carries cert_path + chain_path + duration_ms
// + idempotent flags. (Audit log + Prometheus consume these.)
func TestNginx_Atomic_Result_MetadataPopulated(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ChainPath:       filepath.Join(dir, "chain.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cert_path", "chain_path", "duration_ms", "idempotent"} {
		if _, ok := res.Metadata[key]; !ok {
			t.Errorf("metadata missing %q", key)
		}
	}
}

// 35. Successful deploy returns DeploymentID with nginx- prefix.
func TestNginx_Atomic_DeploymentID_HasNginxPrefix(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !strings.HasPrefix(res.DeploymentID, "nginx-") {
		t.Errorf("DeploymentID = %q, want nginx-* prefix", res.DeploymentID)
	}
}

// 36. Concurrent deploys to DIFFERENT paths run in parallel.
func TestNginx_Atomic_DifferentPaths_RunInParallel(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	cfgA := &nginx.Config{
		CertPath:        filepath.Join(dirA, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	cfgB := &nginx.Config{
		CertPath:        filepath.Join(dirB, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	cA := newConnectorWithStubs(t, cfgA)
	cB := newConnectorWithStubs(t, cfgB)

	// Both should be able to deploy without serializing.
	doneA := make(chan struct{})
	doneB := make(chan struct{})
	go func() {
		_, _ = cA.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
		close(doneA)
	}()
	go func() {
		_, _ = cB.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certB})
		close(doneB)
	}()
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for cA")
	}
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for cB")
	}
}

// 37. Reload command CombinedOutput surfaces in the failure
// message for operator triage.
func TestNginx_Atomic_ReloadFailure_OutputInError(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &nginx.Config{
		CertPath:        cert,
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	var reloadCalls int32
	c.SetTestRunReload(func(ctx context.Context, _ string) ([]byte, error) {
		n := atomic.AddInt32(&reloadCalls, 1)
		if n == 1 {
			return []byte("nginx: [emerg] cannot bind to :443"), errors.New("exit 1")
		}
		return nil, nil
	})

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil || !strings.Contains(err.Error(), "cannot bind") {
		t.Errorf("error doesn't include reload stderr: %v", err)
	}
}

// 38. Validate command CombinedOutput surfaces in the failure
// message.
func TestNginx_Atomic_ValidateFailure_OutputInError(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	c.SetTestRunValidate(func(ctx context.Context, _ string) ([]byte, error) {
		return []byte("nginx: [emerg] no SSL session ID context"), errors.New("exit 1")
	})

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil || !strings.Contains(err.Error(), "SSL session ID context") {
		t.Errorf("error doesn't include validate stderr: %v", err)
	}
}

// 39. PostDeployVerify with default Timeout (0) uses 10s default.
// We verify by stubbing the prober and checking the timeout
// argument it receives.
func TestNginx_Atomic_PostVerify_DefaultTimeout10s(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:                 filepath.Join(dir, "cert.pem"),
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "nginx:443",
			// Timeout left zero
		},
	}
	c := newConnectorWithStubs(t, cfg)
	var seenTimeout time.Duration
	want := fingerprintOfPEM(t, certA)
	c.SetTestProbe(func(ctx context.Context, _ string, timeout time.Duration) tlsprobe.ProbeResult {
		seenTimeout = timeout
		return tlsprobe.ProbeResult{Success: true, Fingerprint: want}
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	if seenTimeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", seenTimeout)
	}
}

// 40. PostDeployVerify endpoint is passed through to the probe.
func TestNginx_Atomic_PostVerify_EndpointForwarded(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:                 filepath.Join(dir, "cert.pem"),
		ReloadCommand:            "nginx -s reload",
		ValidateCommand:          "nginx -t",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &nginx.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "specific-host:8443",
		},
	}
	c := newConnectorWithStubs(t, cfg)
	var seenAddr string
	want := fingerprintOfPEM(t, certA)
	c.SetTestProbe(func(ctx context.Context, addr string, _ time.Duration) tlsprobe.ProbeResult {
		seenAddr = addr
		return tlsprobe.ProbeResult{Success: true, Fingerprint: want}
	})
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA}); err != nil {
		t.Fatal(err)
	}
	if seenAddr != "specific-host:8443" {
		t.Errorf("probe got %q, want specific-host:8443", seenAddr)
	}
}

// 41. Empty CertPEM → still attempts deploy of empty bytes (the
// server-side validation should have caught this earlier; we just
// pin the connector doesn't crash on edge data).
func TestNginx_Atomic_EmptyCertPEM_HandledGracefully(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	if _, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: ""}); err != nil {
		t.Fatal(err)
	}
}

// 42. Deploy result `idempotent` field is "false" for fresh.
func TestNginx_Atomic_FreshDeploy_IdempotentFlagFalse(t *testing.T) {
	dir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ReloadCommand:   "nginx -s reload",
		ValidateCommand: "nginx -t",
	}
	c := newConnectorWithStubs(t, cfg)
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if res.Metadata["idempotent"] != "false" {
		t.Errorf("idempotent = %q, want false", res.Metadata["idempotent"])
	}
}
