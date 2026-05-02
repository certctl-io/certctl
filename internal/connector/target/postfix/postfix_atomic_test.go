package postfix_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/shankar0123/certctl/internal/connector/target/postfix"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 7 of the deploy-hardening I master bundle: atomic + verify
// + rollback for Postfix/Dovecot. Pre-existing 18 tests + these
// new ones puts the connector well above the >=20 target.

const (
	certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
	chain = "-----BEGIN CERTIFICATE-----\nSU5UQ0hBSU4=\n-----END CERTIFICATE-----\n"
	keyA  = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func fingerprintOfPEM(pem string) string {
	beg := strings.Index(pem, "-----BEGIN CERTIFICATE-----") + len("-----BEGIN CERTIFICATE-----")
	body := pem[beg:]
	end := strings.Index(body, "-----END CERTIFICATE-----")
	body = strings.TrimSpace(body[:end])
	body = strings.ReplaceAll(body, "\n", "")
	der, _ := base64.StdEncoding.DecodeString(body)
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func newC(_ *testing.T, cfg *postfix.Config) *postfix.Connector {
	c := postfix.New(cfg, quietLogger())
	c.SetTestRunValidate(func(_ context.Context, _ string) ([]byte, error) { return nil, nil })
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) { return nil, nil })
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	return c
}

func cfg(dir string) *postfix.Config {
	return &postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(dir, "cert.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		ChainPath:       filepath.Join(dir, "chain.pem"),
		ReloadCommand:   "postfix reload",
		ValidateCommand: "postfix check",
	}
}

func TestPostfix_HappyPath(t *testing.T) {
	c := newC(t, cfg(t.TempDir()))
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestPostfix_ValidateFails(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	c := newC(t, &postfix.Config{Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x"})
	c.SetTestRunValidate(func(_ context.Context, _ string) ([]byte, error) {
		return []byte("err"), errors.New("bad config")
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if !errors.Is(err, deploy.ErrValidateFailed) {
		t.Errorf("got %v", err)
	}
	if got, _ := os.ReadFile(cert); string(got) != "OLD" {
		t.Error("cert modified")
	}
}

func TestPostfix_ReloadFails_Rollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	c := newC(t, &postfix.Config{Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x"})
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
}

func TestPostfix_VerifyMismatch_Rollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("ORIG"), 0644)
	cfgV := &postfix.Config{
		Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &postfix.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:25"},
	}
	c := newC(t, cfgV)
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "0000"}
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Error("expected verify error")
	}
}

func TestPostfix_VerifyMatch_Success(t *testing.T) {
	dir := t.TempDir()
	cfgV := &postfix.Config{
		Mode: "postfix", CertPath: filepath.Join(dir, "cert.pem"), ReloadCommand: "x", ValidateCommand: "x",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &postfix.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:25"},
	}
	c := newC(t, cfgV)
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(certA)}
	})
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestPostfix_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA), 0644)
	c := newC(t, &postfix.Config{Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x"})
	var n int32
	c.SetTestRunReload(func(_ context.Context, _ string) ([]byte, error) {
		atomic.AddInt32(&n, 1)
		return nil, nil
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if n != 0 {
		t.Errorf("reload calls = %d", n)
	}
}

func TestPostfix_ChainAppendedToCert_WhenNoChainPath(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	c := newC(t, &postfix.Config{Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x"})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, ChainPEM: chain})
	body, _ := os.ReadFile(cert)
	s := string(body)
	if !strings.Contains(s, "ALPHA") || !strings.Contains(s, "INTCHAIN") {
		// (b64 encoded — check headers instead)
	}
	first := strings.Index(s, "BEGIN CERTIFICATE")
	second := strings.Index(s[first+1:], "BEGIN CERTIFICATE")
	if second < 0 {
		t.Errorf("chain not appended to cert: %s", s)
	}
}

func TestPostfix_DefaultKeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, &postfix.Config{
		Mode: "postfix", CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:       filepath.Join(dir, "key.pem"),
		ReloadCommand: "x", ValidateCommand: "x",
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestPostfix_ValidateOnly_Happy(t *testing.T) {
	c := newC(t, cfg(t.TempDir()))
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestPostfix_ValidateOnly_Sentinel_NoCommand(t *testing.T) {
	c := postfix.New(&postfix.Config{}, quietLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestPostfix_BackupRetention(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("V0"), 0644)
	c := newC(t, &postfix.Config{
		Mode: "postfix", CertPath: cert, ReloadCommand: "x", ValidateCommand: "x", BackupRetention: 2,
	})
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
		t.Errorf("count = %d", cnt)
	}
}

func TestPostfix_DovecotMode(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, &postfix.Config{
		Mode: "dovecot", CertPath: filepath.Join(dir, "cert.pem"),
		ReloadCommand: "doveadm reload", ValidateCommand: "doveconf -n",
	})
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.DeploymentID, "dovecot-") {
		t.Errorf("DeploymentID = %q", res.DeploymentID)
	}
}

// --- Bundle 11: Mode=dovecot atomic-test variants ---
//
// The existing TestPostfix_DovecotMode (above) is a smoke test that
// asserts the DeploymentID prefix only — it sets ReloadCommand and
// ValidateCommand explicitly, so it doesn't pin applyDefaults's
// dovecot-specific behavior. The two tests below close that gap:
//
//   1. TestPostfix_Atomic_DovecotMode_HappyPath: builds a Config with
//      Mode="dovecot" and NO ValidateCommand / NO ReloadCommand set,
//      runs ValidateConfig (which is what triggers applyDefaults),
//      then asserts the deploy uses `doveconf -n` for validate and
//      `doveadm reload` for reload — i.e. applyDefaults populated
//      them AND DeployCertificate threaded them all the way to the
//      runValidate / runReload hooks.
//
//   2. TestPostfix_Atomic_DovecotMode_VerifyFails_Rollback: pre-populates
//      cert+key with known "ORIG" bytes, configures the post-deploy
//      TLS verify probe to fail, and asserts the rollback restored
//      the original bytes verbatim under Mode="dovecot". Mirrors the
//      existing TestPostfix_VerifyMismatch_Rollback (which exercises
//      Mode="postfix") but additionally pins the file-content
//      restoration that the existing test doesn't.

func TestPostfix_Atomic_DovecotMode_HappyPath(t *testing.T) {
	dir := t.TempDir()

	// Build the Config WITHOUT setting ValidateCommand / ReloadCommand.
	// The whole point of this test is to assert applyDefaults populates
	// them with the dovecot strings (`doveconf -n` / `doveadm reload`)
	// — and that DeployCertificate then threads those captured values
	// through to the test hooks.
	cfgIn := postfix.Config{
		Mode:     "dovecot",
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(dir, "key.pem"),
		// NO ChainPath: empty path means the connector appends the
		// chain to the cert (mail-server convention; preserved by
		// applyDefaults's no-op for an unset ChainPath).
	}
	rawCfg, err := json.Marshal(cfgIn)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	// Build an empty Config — ValidateConfig will overwrite the
	// connector's internal config from the parsed-and-defaulted JSON.
	c := postfix.New(&postfix.Config{}, quietLogger())

	var capturedValidateCmd, capturedReloadCmd string
	c.SetTestRunValidate(func(_ context.Context, cmd string) ([]byte, error) {
		capturedValidateCmd = cmd
		return nil, nil
	})
	c.SetTestRunReload(func(_ context.Context, cmd string) ([]byte, error) {
		capturedReloadCmd = cmd
		return nil, nil
	})
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})

	// Trigger applyDefaults via ValidateConfig — that's what populates
	// the dovecot-specific defaults onto cfgIn.
	if err := c.ValidateConfig(context.Background(), rawCfg); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got: %s", res.Message)
	}

	// applyDefaults must have populated the dovecot validate command
	// AND DeployCertificate must have threaded it through to runValidate.
	if capturedValidateCmd == "" {
		t.Fatal("expected runValidate to be invoked (ValidateCommand should be populated by applyDefaults)")
	}
	if !strings.Contains(capturedValidateCmd, "doveconf -n") {
		t.Errorf("expected validate command to contain 'doveconf -n', got: %q", capturedValidateCmd)
	}

	// Same contract for ReloadCommand → runReload.
	if capturedReloadCmd == "" {
		t.Fatal("expected runReload to be invoked (ReloadCommand should be populated by applyDefaults)")
	}
	if !strings.Contains(capturedReloadCmd, "doveadm reload") {
		t.Errorf("expected reload command to contain 'doveadm reload', got: %q", capturedReloadCmd)
	}

	// DeploymentID prefix sanity (matches the smoke test's assertion +
	// confirms Mode=dovecot survived through to the result message).
	if !strings.HasPrefix(res.DeploymentID, "dovecot-") {
		t.Errorf("expected DeploymentID prefix 'dovecot-', got: %q", res.DeploymentID)
	}
	if res.Metadata["mode"] != "dovecot" {
		t.Errorf("expected metadata.mode='dovecot', got: %q", res.Metadata["mode"])
	}
}

func TestPostfix_Atomic_DovecotMode_VerifyFails_Rollback(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Pre-populate cert AND key with known "ORIG" bytes so the rollback
	// has something to restore to (vs. first-time deploy where rollback
	// removes the new files instead). This is a Bundle-11 strengthening
	// over the existing TestPostfix_VerifyMismatch_Rollback (Mode=postfix)
	// which only pre-creates the cert.
	const origCert = "-----BEGIN CERTIFICATE-----\nT1JJRy1DRVJU\n-----END CERTIFICATE-----\n"
	const origKey = "-----BEGIN PRIVATE KEY-----\nT1JJRy1LRVk=\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(certPath, []byte(origCert), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(origKey), 0600); err != nil {
		t.Fatal(err)
	}

	// PostDeployVerifyAttempts=1 so the verify path fails fast (default
	// is 3 attempts × 2s backoff = 4+ seconds; we don't need that for
	// a unit test). Endpoint just needs to be non-empty so
	// runPostDeployVerify takes the probe path rather than the
	// "no endpoint configured; skipping" early-return.
	c := newC(t, &postfix.Config{
		Mode:                     "dovecot",
		CertPath:                 certPath,
		KeyPath:                  keyPath,
		ReloadCommand:            "doveadm reload",
		ValidateCommand:          "doveconf -n",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify: &postfix.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "loadtest-target:993", // dovecot IMAPS — value unused by the test probe stub.
			Timeout:  100 * time.Millisecond,
		},
	})

	// Probe stub returns Success=false. runPostDeployVerify treats this
	// as a verify failure → DeployCertificate calls rollbackToBackups.
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: false, Error: "tls handshake failed"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err == nil {
		t.Fatal("expected verify-failure error")
	}
	if res != nil && res.Success {
		t.Fatal("expected Success=false on verify-failure")
	}
	// runPostDeployVerify wraps the probe failure as "TLS probe failed:
	// <error>"; assert that surfaces in the returned error so operators
	// see what failed instead of a generic "deploy failed" message.
	if !strings.Contains(err.Error(), "TLS probe failed") {
		t.Errorf("expected error to mention TLS probe failure, got: %v", err)
	}

	// Rollback must have restored the ORIGINAL cert + key bytes verbatim.
	// This is the load-bearing assertion Bundle 11 adds over the existing
	// Mode=postfix variant.
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert after rollback: %v", err)
	}
	if string(gotCert) != origCert {
		t.Errorf("rollback did not restore original cert bytes:\n  got:  %q\n  want: %q", gotCert, origCert)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key after rollback: %v", err)
	}
	if string(gotKey) != origKey {
		t.Errorf("rollback did not restore original key bytes:\n  got:  %q\n  want: %q", gotKey, origKey)
	}
}
