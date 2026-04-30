package traefik_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/traefik"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 7 of the deploy-hardening I master bundle: atomic + verify
// for Traefik. No reload command (Traefik watches via inotify);
// post-deploy TLS verify is the load-bearing safety check.

const certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
const keyA = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"

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

func newC(_ *testing.T, dir string) *traefik.Connector {
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	return c
}

func TestTraefik_Atomic_Happy(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_VerifyMatch(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(certA)}
	})
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_VerifyMismatch_Rollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD\n"), 0644)
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "0000"}
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if got, _ := os.ReadFile(cert); string(got) != "OLD\n" {
		t.Errorf("cert after rollback = %q, want OLD", got)
	}
}

func TestTraefik_Atomic_VerifyDialTimeout(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: false, Error: "timeout"}
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestTraefik_Atomic_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA+"\n"), 0644)
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	if res.Metadata["idempotent"] != "true" {
		t.Errorf("idempotent flag = %q", res.Metadata["idempotent"])
	}
}

func TestTraefik_Atomic_DefaultKeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestTraefik_Atomic_KeyModeOverride(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem", KeyFileMode: 0640,
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0640 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestTraefik_Atomic_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	c := newC(t, dir)
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

func TestTraefik_Atomic_NoChain(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_NoKey(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); err == nil {
		t.Error("key written despite empty KeyPEM")
	}
}

func TestTraefik_ValidateOnly_Sentinel(t *testing.T) {
	c := newC(t, t.TempDir())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestTraefik_Atomic_VerifyDisabled(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerify: &traefik.PostDeployVerifyConfig{Enabled: false, Endpoint: "h:443"},
	}, quietLogger())
	var n int32
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&n, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if n != 0 {
		t.Errorf("probe called %d times despite Enabled=false", n)
	}
}
