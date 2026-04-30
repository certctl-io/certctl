package envoy_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/envoy"
	"github.com/shankar0123/certctl/internal/deploy"
)

// Phase 7 of the deploy-hardening I master bundle: atomic-write
// retrofit for Envoy. Envoy file watcher (SDS) auto-reloads on
// rename, so the load-bearing change is the os.WriteFile ->
// deploy.AtomicWriteFile swap.

const certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
const keyA = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestEnvoy_Atomic_HappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file missing: %s", p)
		}
	}
}

func TestEnvoy_Atomic_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
		}
	}
	if !found {
		t.Error("no backup created")
	}
}

func TestEnvoy_Atomic_KeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestEnvoy_Atomic_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA+"\n"), 0644)
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Errorf("backup created on idempotent skip: %s", e.Name())
		}
	}
}

func TestEnvoy_ValidateOnly_Sentinel(t *testing.T) {
	cfg := envoy.Config{CertDir: t.TempDir(), CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}
