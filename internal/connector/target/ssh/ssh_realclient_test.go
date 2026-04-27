package ssh

// Bundle M.SSH (Coverage Audit Closure) — SSH/SFTP target connector
// realclient failure-mode coverage. Closes finding H-002.
//
// The existing ssh_test.go tests the Connector layer via the SSHClient
// interface using a hand-rolled mockSSHClient. The realSSHClient
// implementation has 6 methods at 0% coverage (Connect, buildAuthMethods,
// WriteFile, Execute, StatFile, Close).
//
// Connect requires a live SSH server, so we don't test it here — the test
// for Connect is a manual deploy-time test (Part 44 in
// docs/testing-guide.md). Bundle M instead pins the testable surface:
//
//   - buildAuthMethods: every config branch (password, key from PEM, key
//     from path, key with passphrase, no auth, unsupported method, missing
//     key file)
//   - WriteFile / Execute / StatFile: not-connected guard (nil-client paths)
//   - Close: idempotent (multiple calls)
//   - New: constructor + applyDefaults

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// quietSSHLogger returns a slog.Logger writing to io.Discard at error level.
func quietSSHLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// generateTestPEM returns a PEM-encoded ECDSA P-256 private key suitable
// for ssh.ParsePrivateKey.
func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// ---------------------------------------------------------------------------
// New / applyDefaults
// ---------------------------------------------------------------------------

func TestNew_AppliesDefaults(t *testing.T) {
	cfg := &Config{Host: "h", User: "u"}
	conn, err := New(cfg, quietSSHLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if conn == nil {
		t.Fatal("New returned nil connector")
	}
	if cfg.Port != 22 {
		t.Errorf("Port default = %d; want 22", cfg.Port)
	}
	if cfg.AuthMethod != "key" {
		t.Errorf("AuthMethod default = %q; want 'key'", cfg.AuthMethod)
	}
	if cfg.CertMode != "0644" {
		t.Errorf("CertMode default = %q; want '0644'", cfg.CertMode)
	}
	if cfg.KeyMode != "0600" {
		t.Errorf("KeyMode default = %q; want '0600'", cfg.KeyMode)
	}
	if cfg.Timeout != 30 {
		t.Errorf("Timeout default = %d; want 30", cfg.Timeout)
	}
}

// ---------------------------------------------------------------------------
// buildAuthMethods
// ---------------------------------------------------------------------------

func TestBuildAuthMethods_Password(t *testing.T) {
	c := &realSSHClient{config: &Config{
		AuthMethod: "password",
		Password:   "secret",
	}}
	methods, err := c.buildAuthMethods()
	if err != nil {
		t.Fatalf("buildAuthMethods: %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 auth method, got %d", len(methods))
	}
}

func TestBuildAuthMethods_KeyInline(t *testing.T) {
	pemData := generateTestPEM(t)
	c := &realSSHClient{config: &Config{
		AuthMethod: "key",
		PrivateKey: string(pemData),
	}}
	methods, err := c.buildAuthMethods()
	if err != nil {
		t.Fatalf("buildAuthMethods: %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 auth method, got %d", len(methods))
	}
}

func TestBuildAuthMethods_KeyFromPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ecdsa")
	if err := os.WriteFile(keyPath, generateTestPEM(t), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	c := &realSSHClient{config: &Config{
		AuthMethod:     "key",
		PrivateKeyPath: keyPath,
	}}
	methods, err := c.buildAuthMethods()
	if err != nil {
		t.Fatalf("buildAuthMethods: %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 auth method, got %d", len(methods))
	}
}

func TestBuildAuthMethods_KeyFromPath_FileNotFound(t *testing.T) {
	c := &realSSHClient{config: &Config{
		AuthMethod:     "key",
		PrivateKeyPath: "/nonexistent/path/id_rsa",
	}}
	_, err := c.buildAuthMethods()
	if err == nil || !strings.Contains(err.Error(), "read private key") {
		t.Fatalf("expected file-not-found error, got: %v", err)
	}
}

func TestBuildAuthMethods_NoKeyConfigured(t *testing.T) {
	c := &realSSHClient{config: &Config{
		AuthMethod: "key",
		// neither PrivateKey nor PrivateKeyPath set
	}}
	_, err := c.buildAuthMethods()
	if err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Fatalf("expected missing-key error, got: %v", err)
	}
}

func TestBuildAuthMethods_KeyParseFailure(t *testing.T) {
	c := &realSSHClient{config: &Config{
		AuthMethod: "key",
		PrivateKey: "-----BEGIN PRIVATE KEY-----\nnot-actually-a-key\n-----END PRIVATE KEY-----",
	}}
	_, err := c.buildAuthMethods()
	if err == nil || !strings.Contains(err.Error(), "parse private key") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestBuildAuthMethods_UnsupportedMethod(t *testing.T) {
	c := &realSSHClient{config: &Config{
		AuthMethod: "kerberos",
	}}
	_, err := c.buildAuthMethods()
	if err == nil || !strings.Contains(err.Error(), "unsupported auth method") {
		t.Fatalf("expected unsupported-method error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WriteFile / Execute / StatFile — not-connected guards
// ---------------------------------------------------------------------------

func TestWriteFile_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	err := c.WriteFile("/tmp/test", []byte("data"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "SFTP client not connected") {
		t.Fatalf("expected not-connected error, got: %v", err)
	}
}

func TestExecute_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	_, err := c.Execute(t.Context(), "echo hi")
	if err == nil || !strings.Contains(err.Error(), "SSH client not connected") {
		t.Fatalf("expected not-connected error, got: %v", err)
	}
}

func TestStatFile_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	_, err := c.StatFile("/tmp/test")
	if err == nil || !strings.Contains(err.Error(), "SFTP client not connected") {
		t.Fatalf("expected not-connected error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Close — idempotent
// ---------------------------------------------------------------------------

func TestClose_NeverConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil clients should not error, got: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if err := c.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
