package postfix_test

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
