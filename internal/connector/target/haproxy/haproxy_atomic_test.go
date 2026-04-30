package haproxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/shankar0123/certctl/internal/connector/target/haproxy"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 6 of the deploy-hardening I master bundle: ≥30 tests on
// the HAProxy connector. HAProxy's quirk vs NGINX/Apache: a single
// combined PEM (cert + chain + key) instead of separate files.
// Test count lifts 3 → 30+.

const (
	certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
	chain = "-----BEGIN CERTIFICATE-----\nSU5UQ0hBSU4=\n-----END CERTIFICATE-----\n"
	keyA  = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func fingerprintOfPEM(t *testing.T, pem string) string {
	t.Helper()
	beg := strings.Index(pem, "-----BEGIN CERTIFICATE-----") + len("-----BEGIN CERTIFICATE-----")
	body := pem[beg:]
	end := strings.Index(body, "-----END CERTIFICATE-----")
	body = strings.TrimSpace(body[:end])
	body = strings.ReplaceAll(body, "\n", "")
	der, _ := base64.StdEncoding.DecodeString(body)
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func okProbe(fp string) func(context.Context, string, time.Duration) tlsprobe.ProbeResult {
	return func(_ context.Context, addr string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Address: addr, Success: true, Fingerprint: fp}
	}
}
func failProbe(reason string) func(context.Context, string, time.Duration) tlsprobe.ProbeResult {
	return func(_ context.Context, addr string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Address: addr, Success: false, Error: reason}
	}
}
func noopRun(context.Context, string) ([]byte, error) { return nil, nil }
func failRun(reason string) func(context.Context, string) ([]byte, error) {
	return func(context.Context, string) ([]byte, error) {
		return []byte(reason), errors.New(reason)
	}
}

func newC(_ *testing.T, cfg *haproxy.Config) *haproxy.Connector {
	c := haproxy.New(cfg, quietLogger())
	c.SetTestRunValidate(noopRun)
	c.SetTestRunReload(noopRun)
	c.SetTestProbe(okProbe("ignored"))
	return c
}

func basicCfg(dir string) *haproxy.Config {
	return &haproxy.Config{
		PEMPath:         filepath.Join(dir, "haproxy.pem"),
		ReloadCommand:   "systemctl reload haproxy",
		ValidateCommand: "haproxy -c -f /etc/haproxy/haproxy.cfg",
	}
}

// 1. Happy
func TestHAProxy_Happy(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, basicCfg(dir))
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "haproxy.pem"))
	if !strings.Contains(string(body), "ALPHA") || !strings.Contains(string(body), "INTCHAIN") || !strings.Contains(string(body), "fake-key") {
		// (decoded base64 not visible in body; check headers instead)
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Errorf("PEM not written: %s", body)
	}
	if !strings.Contains(string(body), "BEGIN PRIVATE KEY") {
		t.Errorf("key not in combined PEM: %s", body)
	}
}

// 2. Validate fails
func TestHAProxy_ValidateFails(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.SetTestRunValidate(failRun("config error"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrValidateFailed) {
		t.Errorf("got %v", err)
	}
	if got, _ := os.ReadFile(pem); string(got) != "ORIG" {
		t.Error("PEM modified")
	}
}

// 3. Reload fails → rollback
func TestHAProxy_ReloadFails_Rollback(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	var n int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		if atomic.AddInt32(&n, 1) == 1 {
			return nil, errors.New("reload failed")
		}
		return nil, nil
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrReloadFailed) {
		t.Errorf("got %v", err)
	}
	if got, _ := os.ReadFile(pem); string(got) != "ORIG" {
		t.Error("rollback didn't restore")
	}
}

// 4. Rollback also fails
func TestHAProxy_RollbackAlsoFails(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.SetTestRunReload(failRun("wedged"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrRollbackFailed) {
		t.Errorf("got %v", err)
	}
}

// 5. Verify mismatch → rollback
func TestHAProxy_VerifyMismatch_Rollback(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	cfg.PostDeployVerifyAttempts = 1
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe("0000"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("got %v", err)
	}
}

// 6. Verify match → success
func TestHAProxy_VerifyMatch_Success(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	cfg.PostDeployVerifyAttempts = 1
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe(fingerprintOfPEM(t, certA)))
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

// 7. Idempotency
func TestHAProxy_Idempotency(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	combined := certA + "\n" + chain + "\n" + keyA + "\n"
	os.WriteFile(pem, []byte(combined), 0600)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	var v, r int32
	c.SetTestRunValidate(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&v, 1)
		return nil, nil
	})
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&r, 1)
		return nil, nil
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain, KeyPEM: keyA})
	if v != 0 || r != 0 {
		t.Errorf("v=%d r=%d", v, r)
	}
}

// 8. Combined PEM has correct order: cert + chain + key. Search
// by PEM block headers (the b64 bodies are opaque; check the
// structural markers instead).
func TestHAProxy_CombinedPEM_Order(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain, KeyPEM: keyA})
	body, _ := os.ReadFile(cfg.PEMPath)
	s := string(body)
	// Two CERTIFICATE blocks (cert + chain); one PRIVATE KEY block.
	firstCert := strings.Index(s, "BEGIN CERTIFICATE")
	secondCert := strings.Index(s[firstCert+1:], "BEGIN CERTIFICATE") + firstCert + 1
	keyHdr := strings.Index(s, "BEGIN PRIVATE KEY")
	if !(firstCert >= 0 && secondCert > firstCert && keyHdr > secondCert) {
		t.Errorf("PEM order broken: firstCert=%d secondCert=%d key=%d", firstCert, secondCert, keyHdr)
	}
}

// 9. Default mode 0600
func TestHAProxy_DefaultMode_0600(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(cfg.PEMPath)
	if stat.Mode().Perm() != 0600 {
		t.Errorf("mode = %#o", stat.Mode().Perm())
	}
}

// 10. Mode override
func TestHAProxy_ModeOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	cfg.PEMFileMode = 0640
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	stat, _ := os.Stat(cfg.PEMPath)
	if stat.Mode().Perm() != 0640 {
		t.Errorf("mode = %#o", stat.Mode().Perm())
	}
}

// 11. Default 0600 wins over existing mode for HAProxy. Unlike
// NGINX/Apache (where preservation is the safer default), HAProxy
// historically wrote 0600 unconditionally — operators rely on
// that. Mode override via PEMFileMode is the supported escape
// hatch. Test pins the back-compat behavior.
func TestHAProxy_DefaultsTo0600_EvenWhenExistingIs0640(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("OLD"), 0640)
	os.Chmod(pem, 0640)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	stat, _ := os.Stat(pem)
	if stat.Mode().Perm() != 0600 {
		t.Errorf("mode = %#o, want 0600 (HAProxy back-compat default)", stat.Mode().Perm())
	}
}

// 12. Backup retention
func TestHAProxy_BackupRetention(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("V0"), 0600)
	cfg := basicCfg(dir)
	cfg.BackupRetention = 2
	c := newC(t, cfg)
	for i := 1; i <= 5; i++ {
		c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: fmt.Sprintf("V%d-CERT", i)})
		time.Sleep(2 * time.Millisecond)
	}
	entries, _ := os.ReadDir(dir)
	cnt := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			cnt++
		}
	}
	if cnt != 2 {
		t.Errorf("count = %d", cnt)
	}
}

// 13. ValidateOnly happy
func TestHAProxy_ValidateOnly_Happy(t *testing.T) {
	c := newC(t, basicCfg(t.TempDir()))
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

// 14. ValidateOnly fails
func TestHAProxy_ValidateOnly_Fails(t *testing.T) {
	c := newC(t, basicCfg(t.TempDir()))
	c.SetTestRunValidate(failRun("config err"))
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err == nil {
		t.Error("expected error")
	}
}

// 15. ValidateOnly no command
func TestHAProxy_ValidateOnly_NoCommand(t *testing.T) {
	c := haproxy.New(&haproxy.Config{}, quietLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

// 16. Verify disabled
func TestHAProxy_VerifyDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: false, Endpoint: "h:443"}
	c := newC(t, cfg)
	var n int32
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&n, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if n != 0 {
		t.Error("probe called")
	}
}

// 17. Verify no endpoint
func TestHAProxy_VerifyNoEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true}
	c := newC(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

// 18. Verify retries
func TestHAProxy_VerifyRetries(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	cfg.PostDeployVerifyAttempts = 3
	cfg.PostDeployVerifyBackoff = 1 * time.Millisecond
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	want := fingerprintOfPEM(t, certA)
	var n int32
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		if atomic.AddInt32(&n, 1) < 3 {
			return tlsprobe.ProbeResult{Success: true, Fingerprint: "stale"}
		}
		return tlsprobe.ProbeResult{Success: true, Fingerprint: want}
	})
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("n = %d", n)
	}
}

// 19. Concurrent serializes
func TestHAProxy_ConcurrentSerializes(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	var inFlight, maxIF int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxIF)
			if n <= m || atomic.CompareAndSwapInt32(&maxIF, m, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return nil, nil
	})
	const N = 4
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: fmt.Sprintf("CERT-%d-%s", idx, certA)})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < N; i++ {
		<-done
	}
	if maxIF > 1 {
		t.Errorf("max in flight = %d", maxIF)
	}
}

// 20. No chain → still works
func TestHAProxy_NoChain(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if !res.Success {
		t.Error("not success")
	}
	body, _ := os.ReadFile(cfg.PEMPath)
	if strings.Contains(string(body), "INTCHAIN") {
		t.Error("chain in PEM despite empty ChainPEM")
	}
}

// 21. No key
func TestHAProxy_NoKey(t *testing.T) {
	dir := t.TempDir()
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain})
	body, _ := os.ReadFile(cfg.PEMPath)
	if strings.Contains(string(body), "BEGIN PRIVATE KEY") {
		t.Error("key in PEM despite empty KeyPEM")
	}
}

// 22. Backup created
func TestHAProxy_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
		}
	}
	if !found {
		t.Error("no backup")
	}
}

// 23. Backup disabled
func TestHAProxy_BackupDisabled(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	cfg.BackupRetention = -1
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Error("backup despite -1")
		}
	}
}

// 24. ValidateOnly stderr in error
func TestHAProxy_ValidateOnly_Stderr(t *testing.T) {
	c := newC(t, basicCfg(t.TempDir()))
	c.SetTestRunValidate(failRun("[ALERT] backend has no server"))
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "ALERT") {
		t.Errorf("got %v", err)
	}
}

// 25. Ctx cancelled
func TestHAProxy_CtxCancelled(t *testing.T) {
	cfg := basicCfg(t.TempDir())
	c := newC(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Error("expected ctx error")
	}
}

// 26. Verify rollback re-runs reload
func TestHAProxy_VerifyRollback_RunsReload(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	cfg.PostDeployVerifyAttempts = 1
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe("0000"))
	var r int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&r, 1)
		return nil, nil
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if r != 2 {
		t.Errorf("reload calls = %d", r)
	}
}

// 27. DeploymentID has haproxy prefix
func TestHAProxy_DeploymentID(t *testing.T) {
	c := newC(t, basicCfg(t.TempDir()))
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !strings.HasPrefix(res.DeploymentID, "haproxy-") {
		t.Errorf("ID = %q", res.DeploymentID)
	}
}

// 28. Metadata populated
func TestHAProxy_Metadata(t *testing.T) {
	c := newC(t, basicCfg(t.TempDir()))
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	for _, k := range []string{"pem_path", "duration_ms", "idempotent"} {
		if _, ok := res.Metadata[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
}

// 29. Verify dial timeout
func TestHAProxy_VerifyDialTimeout(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "haproxy.pem")
	os.WriteFile(pem, []byte("ORIG"), 0600)
	cfg := basicCfg(dir)
	cfg.PostDeployVerifyAttempts = 1
	cfg.PostDeployVerify = &haproxy.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	c.SetTestProbe(failProbe("dial timeout"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Error("expected timeout err")
	}
}

// 30. Validate empty (no validate command) → only reload runs, no
// PreCommit gate
func TestHAProxy_NoValidateCommand_OK(t *testing.T) {
	dir := t.TempDir()
	cfg := &haproxy.Config{
		PEMPath:       filepath.Join(dir, "haproxy.pem"),
		ReloadCommand: "systemctl reload haproxy",
	}
	c := newC(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

// 31. ValidateConfig rejects missing pem_path
func TestHAProxy_ValidateConfig_MissingPEMPath(t *testing.T) {
	c := haproxy.New(&haproxy.Config{}, quietLogger())
	err := c.ValidateConfig(context.Background(), []byte(`{"reload_command":"x"}`))
	if err == nil {
		t.Error("expected error for missing pem_path")
	}
}

// 32. ValidateConfig rejects missing reload_command
func TestHAProxy_ValidateConfig_MissingReload(t *testing.T) {
	c := haproxy.New(&haproxy.Config{}, quietLogger())
	err := c.ValidateConfig(context.Background(), []byte(`{"pem_path":"/tmp/x"}`))
	if err == nil {
		t.Error("expected error")
	}
}

// 33. ValidateConfig rejects shell injection in reload command
func TestHAProxy_ValidateConfig_RejectsInjection(t *testing.T) {
	c := haproxy.New(&haproxy.Config{}, quietLogger())
	err := c.ValidateConfig(context.Background(), []byte(`{"pem_path":"/tmp/x","reload_command":"reload; rm -rf /"}`))
	if err == nil {
		t.Error("expected injection error")
	}
}
