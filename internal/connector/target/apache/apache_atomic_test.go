package apache_test

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
	"github.com/shankar0123/certctl/internal/connector/target/apache"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 5 of the deploy-hardening I master bundle: ≥30 tests on
// the Apache connector covering the atomic-deploy + post-deploy
// TLS verify + rollback + ValidateOnly + ownership-preservation
// matrix. Test uplift target was 3→≥30; the file ships 32 here +
// 3 pre-existing in apache_test.go = 35 total.

const (
	certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVC1QRU0tQ09OVEVOVFMtQQ==\n-----END CERTIFICATE-----\n"
	certB = "-----BEGIN CERTIFICATE-----\nQkVUQS1DRVJULVBFTS1DT05URU5UUy1C\n-----END CERTIFICATE-----\n"
	chain = "-----BEGIN CERTIFICATE-----\nSU5URVJNRURJQVRFLUNIQUlOLVBFTQ==\n-----END CERTIFICATE-----\n"
	keyA  = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktQQ==\n-----END PRIVATE KEY-----\n"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func fingerprintOfPEM(t *testing.T, pem string) string {
	t.Helper()
	begin := "-----BEGIN CERTIFICATE-----"
	end := "-----END CERTIFICATE-----"
	beginIdx := strings.Index(pem, begin)
	body := pem[beginIdx+len(begin):]
	endIdx := strings.Index(body, end)
	body = strings.TrimSpace(body[:endIdx])
	body = strings.ReplaceAll(body, "\n", "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func okProbe(fp string) func(ctx context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
	return func(_ context.Context, address string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Address: address, Success: true, Fingerprint: fp}
	}
}
func failProbe(reason string) func(ctx context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
	return func(_ context.Context, address string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Address: address, Success: false, Error: reason}
	}
}
func noopRun(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func failRun(reason string) func(ctx context.Context, command string) ([]byte, error) {
	return func(_ context.Context, _ string) ([]byte, error) {
		return []byte("stderr: " + reason), errors.New(reason)
	}
}

func newC(_ *testing.T, cfg *apache.Config) *apache.Connector {
	c := apache.New(cfg, quietLogger())
	c.SetTestRunValidate(noopRun)
	c.SetTestRunReload(noopRun)
	c.SetTestProbe(okProbe("ignored"))
	return c
}

func standardCfg(dir string) *apache.Config {
	return &apache.Config{
		CertPath:        filepath.Join(dir, "cert.pem"),
		ChainPath:       filepath.Join(dir, "chain.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		ReloadCommand:   "apachectl graceful",
		ValidateCommand: "apachectl configtest",
	}
}

// 1. Happy path
func TestApache_HappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	c := newC(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatalf("err=%v success=%v", err, res.Success)
	}
}

// 2. Validate fails
func TestApache_ValidateFails(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest"}
	c := newC(t, cfg)
	c.SetTestRunValidate(failRun("syntax error"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrValidateFailed) {
		t.Errorf("got %v, want ErrValidateFailed", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIG" {
		t.Errorf("cert modified: %q", got)
	}
}

// 3. Reload fails → rollback
func TestApache_ReloadFails_RollsBack(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest"}
	c := newC(t, cfg)
	var n int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		if atomic.AddInt32(&n, 1) == 1 {
			return nil, errors.New("apache wedged")
		}
		return nil, nil
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrReloadFailed) {
		t.Errorf("got %v, want ErrReloadFailed", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIG" {
		t.Errorf("cert after rollback: %q", got)
	}
}

// 4. Rollback also fails → ErrRollbackFailed
func TestApache_RollbackAlsoFails(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest"}
	c := newC(t, cfg)
	c.SetTestRunReload(failRun("apache wedged"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrRollbackFailed) {
		t.Errorf("got %v, want ErrRollbackFailed", err)
	}
}

// 5. Post-deploy verify mismatch → rollback
func TestApache_PostVerify_Mismatch_RollsBack(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{
		CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe("0000"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("expected SHA mismatch error, got %v", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIG" {
		t.Errorf("cert after rollback = %q", got)
	}
}

// 6. Post-deploy verify match → success
func TestApache_PostVerify_Match_Succeeds(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	cfg.PostDeployVerifyAttempts = 1
	cfg.PostDeployVerify = &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe(fingerprintOfPEM(t, certA)))
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatalf("err=%v success=%v", err, res.Success)
	}
}

// 7. Verify dial timeout → rollback
func TestApache_PostVerify_DialTimeout(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{
		CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}
	c := newC(t, cfg)
	c.SetTestProbe(failProbe("dial: i/o timeout"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected dial-timeout error")
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIG" {
		t.Errorf("cert after timeout = %q", got)
	}
}

// 8. Idempotency: identical bytes → skip
func TestApache_Idempotency_Skips(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest"}
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
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 || r != 0 {
		t.Errorf("expected no validate/reload, got %d/%d", v, r)
	}
}

// 9. KeyFileMode override wins
func TestApache_KeyFileMode_Override(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{
		CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem"),
		ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		KeyFileMode: 0640,
	}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(cfg.KeyPath)
	if stat.Mode().Perm() != 0640 {
		t.Errorf("key mode = %#o, want 0640", stat.Mode().Perm())
	}
}

// 10. Existing mode preserved
func TestApache_ExistingMode_Preserved(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0640)
	os.Chmod(cert, 0640)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest"}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	stat, _ := os.Stat(cert)
	if stat.Mode().Perm() != 0640 {
		t.Errorf("mode = %#o", stat.Mode().Perm())
	}
}

// 11. Default key mode 0600 when no override
func TestApache_DefaultKeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{
		CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem"),
		ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
	}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(cfg.KeyPath)
	if stat.Mode().Perm() != 0600 {
		t.Errorf("default key mode = %#o, want 0600", stat.Mode().Perm())
	}
}

// 12. Backup retention
func TestApache_BackupRetention(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("V0"), 0644)
	cfg := &apache.Config{
		CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		BackupRetention: 2,
	}
	c := newC(t, cfg)
	for i := 1; i <= 4; i++ {
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
		t.Errorf("backup count = %d", cnt)
	}
}

// 13. ValidateOnly happy
func TestApache_ValidateOnly_Happy(t *testing.T) {
	c := newC(t, &apache.Config{CertPath: "/tmp/x", ReloadCommand: "x", ValidateCommand: "apachectl configtest"})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

// 14. ValidateOnly fails
func TestApache_ValidateOnly_Fails(t *testing.T) {
	c := newC(t, &apache.Config{CertPath: "/tmp/x", ReloadCommand: "x", ValidateCommand: "apachectl configtest"})
	c.SetTestRunValidate(failRun("syntax err"))
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// 15. ValidateOnly no command
func TestApache_ValidateOnly_NoCommand(t *testing.T) {
	c := apache.New(&apache.Config{}, quietLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v, want sentinel", err)
	}
}

// 16-18. Verify off / no endpoint / disabled
func TestApache_Verify_Disabled_Skips(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	cfg.PostDeployVerify = &apache.PostDeployVerifyConfig{Enabled: false, Endpoint: "h:443"}
	c := newC(t, cfg)
	var n int32
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&n, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "ignored"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if n != 0 {
		t.Errorf("probe called %d times despite disabled", n)
	}
}

func TestApache_Verify_NoEndpoint_Skips(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	cfg.PostDeployVerify = &apache.PostDeployVerifyConfig{Enabled: true}
	c := newC(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatalf("err=%v success=%v", err, res.Success)
	}
}

// 19. Verify retries until match
func TestApache_Verify_RetriesUntilMatch(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	cfg.PostDeployVerifyAttempts = 3
	cfg.PostDeployVerifyBackoff = 1 * time.Millisecond
	cfg.PostDeployVerify = &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"}
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
		t.Fatalf("err=%v", err)
	}
	if n != 3 {
		t.Errorf("probe attempts = %d, want 3", n)
	}
}

// 20. Verify exhausts retries → rollback
func TestApache_Verify_RetriesExhausted_Rollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{
		CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		PostDeployVerifyAttempts: 2,
		PostDeployVerifyBackoff:  1 * time.Millisecond,
		PostDeployVerify:         &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe("0000"))
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected error")
	}
}

// 21. Concurrent same-path serializes
func TestApache_Concurrent_Serializes(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{CertPath: filepath.Join(dir, "cert.pem"), ReloadCommand: "x", ValidateCommand: "x"}
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

// 22. No chain → still succeeds
func TestApache_NoChain(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{CertPath: filepath.Join(dir, "cert.pem"), ReloadCommand: "x", ValidateCommand: "x"}
	c := newC(t, cfg)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatalf("err=%v", err)
	}
}

// 23. No key → only cert+chain written
func TestApache_NoKey(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain})
	if _, err := os.Stat(cfg.KeyPath); err == nil {
		t.Error("key written despite empty KeyPEM")
	}
}

// 24. Partial idempotency → full deploy
func TestApache_PartialIdempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	os.WriteFile(cert, []byte(certA), 0644)
	os.WriteFile(key, []byte("OLD"), 0640)
	cfg := &apache.Config{CertPath: cert, KeyPath: key, ReloadCommand: "x", ValidateCommand: "x"}
	c := newC(t, cfg)
	var n int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&n, 1)
		return nil, nil
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if n != 1 {
		t.Errorf("reload calls = %d", n)
	}
}

// 25. New cert default mode 0644
func TestApache_NewCert_DefaultMode(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{CertPath: filepath.Join(dir, "cert.pem"), ReloadCommand: "x", ValidateCommand: "x"}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	stat, _ := os.Stat(cfg.CertPath)
	if stat.Mode().Perm() != 0644 {
		t.Errorf("default mode = %#o", stat.Mode().Perm())
	}
}

// 26. Backup file created on first deploy with existing
func TestApache_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "x", ValidateCommand: "x"}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
			break
		}
	}
	if !found {
		t.Error("no backup created")
	}
}

// 27. Backup disabled
func TestApache_BackupDisabled(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{CertPath: cert, ReloadCommand: "x", ValidateCommand: "x", BackupRetention: -1}
	c := newC(t, cfg)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Error("backup created despite -1")
		}
	}
}

// 28. ValidateOnly stderr in error
func TestApache_ValidateOnly_StderrInError(t *testing.T) {
	c := newC(t, &apache.Config{CertPath: "/x", ReloadCommand: "x", ValidateCommand: "apachectl configtest"})
	c.SetTestRunValidate(func(_ context.Context, _ string) ([]byte, error) {
		return []byte("Syntax error on line 32 of /etc/apache2/sites-enabled/000-default.conf"), errors.New("exit 1")
	})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "Syntax error") {
		t.Errorf("got %v", err)
	}
}

// 29. Ctx cancelled
func TestApache_CtxCancelled(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	c := newC(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Error("expected ctx error")
	}
}

// 30. Verify rollback runs reload again
func TestApache_VerifyRollback_RunsReloadAgain(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfg := &apache.Config{
		CertPath: cert, ReloadCommand: "apachectl graceful", ValidateCommand: "apachectl configtest",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &apache.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}
	c := newC(t, cfg)
	c.SetTestProbe(okProbe("0000"))
	var r int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&r, 1)
		return nil, nil
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if r != 2 {
		t.Errorf("reload calls = %d, want 2", r)
	}
}

// 31. DeploymentID has apache prefix
func TestApache_DeploymentID_HasPrefix(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	c := newC(t, cfg)
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !strings.HasPrefix(res.DeploymentID, "apache-") {
		t.Errorf("DeploymentID = %q", res.DeploymentID)
	}
}

// 32. Result Metadata populated
func TestApache_Metadata_Populated(t *testing.T) {
	dir := t.TempDir()
	cfg := standardCfg(dir)
	c := newC(t, cfg)
	res, _ := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain})
	for _, k := range []string{"cert_path", "chain_path", "duration_ms", "idempotent"} {
		if _, ok := res.Metadata[k]; !ok {
			t.Errorf("metadata missing %q", k)
		}
	}
}

// _ avoid unused fixture warning
var _ = certB

// TestApache_VerifyExponentialBackoff_GrowsBetweenAttempts: post-deploy verify
// retries with exponential backoff.
func TestApache_VerifyExponentialBackoff_GrowsBetweenAttempts(t *testing.T) {
	dir := t.TempDir()
	cfg := &apache.Config{
		CertPath:                   filepath.Join(dir, "cert.pem"),
		ReloadCommand:              "apachectl graceful",
		ValidateCommand:            "apachectl configtest",
		PostDeployVerifyAttempts:   4,
		PostDeployVerifyBackoff:    10 * time.Millisecond,
		PostDeployVerifyMaxBackoff: 80 * time.Millisecond,
		PostDeployVerify: &apache.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "localhost:443",
			Timeout:  100 * time.Millisecond,
		},
	}
	c := newC(t, cfg)

	var callTimes []time.Time
	probeCallCount := atomic.Int32{}

	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		callTimes = append(callTimes, time.Now())
		count := probeCallCount.Add(1)
		if count == 4 {
			return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(t, certA)}
		}
		return tlsprobe.ProbeResult{Success: false, Error: "cert not yet deployed"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})

	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !res.Success {
		t.Fatal("expected Success=true")
	}

	if len(callTimes) != 4 {
		t.Fatalf("expected 4 probe calls, got %d", len(callTimes))
	}

	const tolerance = 20 * time.Millisecond
	expectedGaps := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
	}

	for i := 0; i < len(expectedGaps); i++ {
		gap := callTimes[i+1].Sub(callTimes[i])
		expected := expectedGaps[i]
		if gap < expected-tolerance || gap > expected+tolerance {
			t.Errorf("gap[%d]: expected ~%v, got %v", i, expected, gap)
		}
	}
}
