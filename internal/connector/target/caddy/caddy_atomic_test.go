package caddy_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/caddy"
	"github.com/certctl-io/certctl/internal/deploy"
)

// Phase 7 of the deploy-hardening I master bundle: atomic-write +
// ValidateOnly real impl + (where applicable) post-deploy verify
// for Caddy's API + file modes.

const certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
const keyA = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"

// newTestLogger returns a no-op slog logger so test runs stay readable.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestCaddy_FileMode_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := caddy.Config{Mode: "file", CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "cert.pem")); !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Errorf("cert not written: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "key.pem")); !strings.Contains(string(got), "BEGIN PRIVATE KEY") {
		t.Errorf("key not written: %q", got)
	}
}

func TestCaddy_FileMode_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	cfg := caddy.Config{Mode: "file", CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
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

func TestCaddy_FileMode_KeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	cfg := caddy.Config{Mode: "file", CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestCaddy_FileMode_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA+"\n"), 0644)
	cfg := caddy.Config{Mode: "file", CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	// Idempotent path: no backup created (only diff triggers backup).
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Errorf("backup created on idempotent skip: %s", e.Name())
		}
	}
}

func TestCaddy_ValidateOnly_FileMode_ReturnsSentinel(t *testing.T) {
	cfg := caddy.Config{Mode: "file", CertDir: t.TempDir(), CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestCaddy_ValidateOnly_APIMode_ProbesAdminAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := caddy.Config{Mode: "api", AdminAPI: srv.URL}
	c := caddy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestCaddy_ValidateOnly_APIMode_AdminUnreachable(t *testing.T) {
	cfg := caddy.Config{Mode: "api", AdminAPI: "http://localhost:9"} // closed port
	c := caddy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err == nil {
		t.Error("expected unreachable error")
	}
}

func TestCaddy_ValidateOnly_APIMode_AdminReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfg := caddy.Config{Mode: "api", AdminAPI: srv.URL}
	c := caddy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err == nil {
		t.Error("expected status-500 error")
	}
}

func TestCaddy_FileMode_NoKey(t *testing.T) {
	dir := t.TempDir()
	cfg := caddy.Config{Mode: "file", CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); err == nil {
		t.Error("key written despite empty KeyPEM")
	}
}

func TestCaddy_FileMode_BadDirError(t *testing.T) {
	cfg := caddy.Config{Mode: "file", CertDir: "/nonexistent-xyz", CertFile: "cert.pem", KeyFile: "key.pem"}
	c := caddy.New(&cfg, newTestLogger())
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Error("expected error on bad cert_dir")
	}
}
