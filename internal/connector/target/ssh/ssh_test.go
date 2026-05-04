package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// stubFileInfo implements os.FileInfo for tests that need to return a
// FileInfo from the mock SSHClient's StatFile. Bundle 6 of the
// 2026-05-02 deployment-target audit evolved StatFile's signature from
// (int64, error) to (os.FileInfo, error) so the pre-deploy snapshot
// can capture the original mode for accurate rollback restoration.
type stubFileInfo struct {
	size int64
	mode os.FileMode
	name string
}

func (s *stubFileInfo) Name() string       { return s.name }
func (s *stubFileInfo) Size() int64        { return s.size }
func (s *stubFileInfo) Mode() os.FileMode  { return s.mode }
func (s *stubFileInfo) ModTime() time.Time { return time.Time{} }
func (s *stubFileInfo) IsDir() bool        { return false }
func (s *stubFileInfo) Sys() any           { return nil }

// testLogger returns a slog.Logger for test output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// --- Mock SSH Client ---

// mockSSHClient records all calls and returns configurable results.
//
// Bundle 6 of the 2026-05-02 deployment-target audit added per-path
// response maps (statByPath / readByPath / writeFileErrByPath) so the
// new snapshot/rollback tests can simulate (a) pre-existing remote
// files for the snapshot to read, (b) per-call WriteFile failures to
// inject restore-failure paths, and (c) sequenced Execute errors so
// the reload-then-retry-reload tests can drive both calls
// independently. The legacy global fields (statFileSize / statFileErr
// / writeFileErr / executeErr) are still honored when no per-path
// override matches, so existing tests remain green.
type mockSSHClient struct {
	connectCalls       int
	connectErr         error
	writeFileCalls     []writeFileCall
	writeFileErr       error
	writeFileErrByPath map[string]error // per-path WriteFile error overrides
	executeCalls       []string
	executeOutput      string
	executeErr         error
	executeErrSequence []error  // per-call Execute errors; falls back to executeErr after exhaustion
	executeOutSequence []string // per-call Execute outputs; mirrors executeErrSequence
	statFileCalls      []string
	statFileSize       int64
	statFileErr        error
	statByPath         map[string]statResponse // per-path StatFile responses
	readByPath         map[string][]byte       // per-path ReadFile bytes (existence implies success)
	readErrByPath      map[string]error        // per-path ReadFile error overrides
	removeCalls        []string
	removeErr          error
	removeErrByPath    map[string]error
	closeCalls         int
}

type writeFileCall struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type statResponse struct {
	info os.FileInfo
	err  error
}

func (m *mockSSHClient) Connect(ctx context.Context) error {
	m.connectCalls++
	return m.connectErr
}

func (m *mockSSHClient) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	m.writeFileCalls = append(m.writeFileCalls, writeFileCall{Path: remotePath, Data: data, Mode: mode})
	if m.writeFileErrByPath != nil {
		if err, ok := m.writeFileErrByPath[remotePath]; ok {
			return err
		}
	}
	return m.writeFileErr
}

func (m *mockSSHClient) Execute(ctx context.Context, command string) (string, error) {
	idx := len(m.executeCalls)
	m.executeCalls = append(m.executeCalls, command)
	if idx < len(m.executeErrSequence) {
		out := ""
		if idx < len(m.executeOutSequence) {
			out = m.executeOutSequence[idx]
		}
		return out, m.executeErrSequence[idx]
	}
	return m.executeOutput, m.executeErr
}

func (m *mockSSHClient) StatFile(remotePath string) (os.FileInfo, error) {
	m.statFileCalls = append(m.statFileCalls, remotePath)
	if m.statByPath != nil {
		if resp, ok := m.statByPath[remotePath]; ok {
			return resp.info, resp.err
		}
	}
	if m.statFileErr != nil {
		return nil, m.statFileErr
	}
	// Default: synthesise a FileInfo with the legacy size + a sane mode.
	return &stubFileInfo{size: m.statFileSize, mode: 0644, name: remotePath}, nil
}

func (m *mockSSHClient) ReadFile(remotePath string) ([]byte, error) {
	if m.readErrByPath != nil {
		if err, ok := m.readErrByPath[remotePath]; ok {
			return nil, err
		}
	}
	if m.readByPath != nil {
		if data, ok := m.readByPath[remotePath]; ok {
			return data, nil
		}
	}
	// Default: empty bytes, no error. Tests that don't exercise the
	// snapshot path see this fall-through (the read still succeeds so
	// the snapshot phase doesn't block their deploy hot path).
	return []byte{}, nil
}

func (m *mockSSHClient) Remove(remotePath string) error {
	m.removeCalls = append(m.removeCalls, remotePath)
	if m.removeErrByPath != nil {
		if err, ok := m.removeErrByPath[remotePath]; ok {
			return err
		}
	}
	return m.removeErr
}

func (m *mockSSHClient) Close() error {
	m.closeCalls++
	return nil
}

// --- ValidateConfig tests ---

func TestValidateConfig_Success_KeyAuth(t *testing.T) {
	// Create a temporary key file
	keyFile := createTempKeyFile(t)

	cfg := map[string]interface{}{
		"host":             "server.example.com",
		"user":             "deploy",
		"auth_method":      "key",
		"private_key_path": keyFile,
		"cert_path":        "/etc/ssl/certs/cert.pem",
		"key_path":         "/etc/ssl/private/key.pem",
	}

	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if c.config.Port != 22 {
		t.Errorf("expected default port 22, got %d", c.config.Port)
	}
	if c.config.CertMode != "0644" {
		t.Errorf("expected default cert_mode 0644, got %s", c.config.CertMode)
	}
	if c.config.KeyMode != "0600" {
		t.Errorf("expected default key_mode 0600, got %s", c.config.KeyMode)
	}
	if c.config.Timeout != 30 {
		t.Errorf("expected default timeout 30, got %d", c.config.Timeout)
	}
}

func TestValidateConfig_Success_InlineKey(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "10.0.0.5",
		"user":        "root",
		"auth_method": "key",
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
	}

	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateConfig_Success_PasswordAuth(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "server.local",
		"user":        "deploy",
		"auth_method": "password",
		"password":    "s3cret",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
	}

	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	err := c.ValidateConfig(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateConfig_MissingHost(t *testing.T) {
	cfg := map[string]interface{}{
		"user":      "deploy",
		"cert_path": "/etc/ssl/cert.pem",
		"key_path":  "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestValidateConfig_MissingUser(t *testing.T) {
	cfg := map[string]interface{}{
		"host":      "server.local",
		"cert_path": "/etc/ssl/cert.pem",
		"key_path":  "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestValidateConfig_MissingCertPath(t *testing.T) {
	cfg := map[string]interface{}{
		"host":     "server.local",
		"user":     "deploy",
		"key_path": "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing cert_path")
	}
}

func TestValidateConfig_MissingKeyPath(t *testing.T) {
	cfg := map[string]interface{}{
		"host":      "server.local",
		"user":      "deploy",
		"cert_path": "/etc/ssl/cert.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing key_path")
	}
}

func TestValidateConfig_KeyAuth_MissingKey(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "server.local",
		"user":        "deploy",
		"auth_method": "key",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for key auth missing both private_key and private_key_path")
	}
}

func TestValidateConfig_PasswordAuth_MissingPassword(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "server.local",
		"user":        "deploy",
		"auth_method": "password",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for password auth missing password")
	}
}

func TestValidateConfig_InvalidHost(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "server;rm -rf /",
		"user":        "deploy",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
		"private_key": "fake",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for host with shell metacharacters")
	}
}

func TestValidateConfig_InvalidPermissions(t *testing.T) {
	keyFile := createTempKeyFile(t)
	cfg := map[string]interface{}{
		"host":             "server.local",
		"user":             "deploy",
		"private_key_path": keyFile,
		"cert_path":        "/etc/ssl/cert.pem",
		"key_path":         "/etc/ssl/key.pem",
		"cert_mode":        "999",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for invalid cert_mode")
	}
}

func TestValidateConfig_ReloadCommandInjection(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"semicolon", "systemctl reload nginx; rm -rf /"},
		{"pipe", "systemctl reload nginx | cat"},
		{"backtick", "systemctl reload `malicious`"},
		{"command substitution", "systemctl reload $(evil)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := createTempKeyFile(t)
			cfg := map[string]interface{}{
				"host":             "server.local",
				"user":             "deploy",
				"private_key_path": keyFile,
				"cert_path":        "/etc/ssl/cert.pem",
				"key_path":         "/etc/ssl/key.pem",
				"reload_command":   tc.command,
			}
			c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
			raw, _ := json.Marshal(cfg)
			err := c.ValidateConfig(context.Background(), raw)
			if err == nil {
				t.Fatalf("expected error for reload command injection: %q", tc.command)
			}
		})
	}
}

func TestValidateConfig_InvalidAuthMethod(t *testing.T) {
	cfg := map[string]interface{}{
		"host":        "server.local",
		"user":        "deploy",
		"auth_method": "kerberos",
		"cert_path":   "/etc/ssl/cert.pem",
		"key_path":    "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for invalid auth method")
	}
}

func TestValidateConfig_KeyFileNotFound(t *testing.T) {
	cfg := map[string]interface{}{
		"host":             "server.local",
		"user":             "deploy",
		"auth_method":      "key",
		"private_key_path": "/nonexistent/key.pem",
		"cert_path":        "/etc/ssl/cert.pem",
		"key_path":         "/etc/ssl/key.pem",
	}
	c := NewWithClient(&Config{}, &mockSSHClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

// --- DeployCertificate tests ---

func TestDeployCertificate_Success_NoChainPath(t *testing.T) {
	mock := &mockSSHClient{statFileSize: 1024}
	cfg := &Config{
		Host:     "server.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got %s", result.Message)
	}

	// Should have 2 writes (cert with chain appended, key)
	if len(mock.writeFileCalls) != 2 {
		t.Fatalf("expected 2 write calls, got %d", len(mock.writeFileCalls))
	}

	// Cert should include chain (fullchain)
	certWrite := mock.writeFileCalls[0]
	if certWrite.Path != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert path /etc/ssl/cert.pem, got %s", certWrite.Path)
	}
	if certWrite.Mode != 0644 {
		t.Errorf("expected cert mode 0644, got %v", certWrite.Mode)
	}
	certContent := string(certWrite.Data)
	if len(certContent) == 0 {
		t.Error("cert data should not be empty")
	}

	// Key write
	keyWrite := mock.writeFileCalls[1]
	if keyWrite.Path != "/etc/ssl/key.pem" {
		t.Errorf("expected key path /etc/ssl/key.pem, got %s", keyWrite.Path)
	}
	if keyWrite.Mode != 0600 {
		t.Errorf("expected key mode 0600, got %v", keyWrite.Mode)
	}

	// Metadata
	if result.Metadata["host"] != "server.local" {
		t.Errorf("expected host metadata server.local, got %s", result.Metadata["host"])
	}
}

func TestDeployCertificate_Success_SeparateChain(t *testing.T) {
	mock := &mockSSHClient{}
	cfg := &Config{
		Host:      "server.local",
		Port:      22,
		CertPath:  "/etc/ssl/cert.pem",
		KeyPath:   "/etc/ssl/key.pem",
		ChainPath: "/etc/ssl/chain.pem",
		CertMode:  "0644",
		KeyMode:   "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM:  "cert-data",
		KeyPEM:   "key-data",
		ChainPEM: "chain-data",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got %s", result.Message)
	}

	// Should have 3 writes (cert, key, chain)
	if len(mock.writeFileCalls) != 3 {
		t.Fatalf("expected 3 write calls, got %d", len(mock.writeFileCalls))
	}

	// Chain should be separate
	chainWrite := mock.writeFileCalls[2]
	if chainWrite.Path != "/etc/ssl/chain.pem" {
		t.Errorf("expected chain path /etc/ssl/chain.pem, got %s", chainWrite.Path)
	}
}

func TestDeployCertificate_Success_WithReload(t *testing.T) {
	mock := &mockSSHClient{executeOutput: "ok"}
	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "cert",
		KeyPEM:  "key",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got %s", result.Message)
	}

	// Should have executed reload command
	if len(mock.executeCalls) != 1 {
		t.Fatalf("expected 1 execute call, got %d", len(mock.executeCalls))
	}
	if mock.executeCalls[0] != "systemctl reload nginx" {
		t.Errorf("expected reload command, got %s", mock.executeCalls[0])
	}
}

func TestDeployCertificate_MissingKeyPEM(t *testing.T) {
	mock := &mockSSHClient{}
	cfg := &Config{
		Host:     "server.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "cert",
		KeyPEM:  "", // Missing
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing KeyPEM")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestDeployCertificate_ConnectionFailure(t *testing.T) {
	mock := &mockSSHClient{connectErr: fmt.Errorf("connection refused")}
	cfg := &Config{
		Host:     "unreachable.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "cert",
		KeyPEM:  "key",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestDeployCertificate_WriteFailure(t *testing.T) {
	mock := &mockSSHClient{writeFileErr: fmt.Errorf("permission denied")}
	cfg := &Config{
		Host:     "server.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "cert",
		KeyPEM:  "key",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for write failure")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestDeployCertificate_ReloadFailure(t *testing.T) {
	mock := &mockSSHClient{executeErr: fmt.Errorf("reload failed: exit status 1"), executeOutput: "error"}
	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "cert",
		KeyPEM:  "key",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for reload failure")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

// --- Bundle 6: pre-deploy snapshot + reload-failure rollback ---
//
// These four tests pin the load-bearing rollback contract added in
// Bundle 6 of the 2026-05-02 deployment-target audit:
//   - happy rollback path: pre-existing remote bytes restored verbatim;
//   - first-time deploy partial-state cleanup via Remove;
//   - both reload AND rollback fail → operator-actionable wrapped error;
//   - rollback succeeds but the retry-reload after rollback fails →
//     daemon-state-unknown wrapped error.

func TestSSH_ReloadFails_FilesRestored(t *testing.T) {
	originalCert := []byte("-----BEGIN CERTIFICATE-----\nORIGINAL_CERT\n-----END CERTIFICATE-----\n")
	originalKey := []byte("-----BEGIN PRIVATE KEY-----\nORIGINAL_KEY\n-----END PRIVATE KEY-----\n")
	originalChain := []byte("-----BEGIN CERTIFICATE-----\nORIGINAL_CHAIN\n-----END CERTIFICATE-----\n")

	mock := &mockSSHClient{
		// Pre-existing files for all three paths; mode 0644 / 0600 / 0644.
		statByPath: map[string]statResponse{
			"/etc/ssl/cert.pem":  {info: &stubFileInfo{size: int64(len(originalCert)), mode: 0644}},
			"/etc/ssl/key.pem":   {info: &stubFileInfo{size: int64(len(originalKey)), mode: 0600}},
			"/etc/ssl/chain.pem": {info: &stubFileInfo{size: int64(len(originalChain)), mode: 0644}},
		},
		readByPath: map[string][]byte{
			"/etc/ssl/cert.pem":  originalCert,
			"/etc/ssl/key.pem":   originalKey,
			"/etc/ssl/chain.pem": originalChain,
		},
		// First Execute (reload) fails; second Execute (retry-reload after
		// restore) succeeds — clean recoverable failure.
		executeErrSequence: []error{fmt.Errorf("reload failed: exit status 1"), nil},
		executeOutSequence: []string{"reload error output", "ok"},
	}

	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		ChainPath:     "/etc/ssl/chain.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nNEW_CERT\n-----END CERTIFICATE-----\n",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nNEW_KEY\n-----END PRIVATE KEY-----\n",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nNEW_CHAIN\n-----END CERTIFICATE-----\n",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when reload fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Error must mention reload failure + rollback success.
	if !containsString(err.Error(), "reload command failed") && !containsString(err.Error(), "reload failed") {
		t.Errorf("expected error to mention reload failure, got: %v", err)
	}
	if !containsString(err.Error(), "rolled back") {
		t.Errorf("expected error to mention 'rolled back', got: %v", err)
	}

	// Build a path → bytes view of every WriteFile call for the assertions.
	// On the success path the deploy writes new bytes; on the rollback path
	// it writes the originals back. We expect each path to be written at
	// least twice (once with new bytes, once with originals).
	writesByPath := map[string][][]byte{}
	for _, w := range mock.writeFileCalls {
		writesByPath[w.Path] = append(writesByPath[w.Path], w.Data)
	}

	for _, path := range []string{"/etc/ssl/cert.pem", "/etc/ssl/key.pem", "/etc/ssl/chain.pem"} {
		writes := writesByPath[path]
		if len(writes) < 2 {
			t.Errorf("expected at least 2 WriteFile calls for %s (deploy + restore), got %d", path, len(writes))
			continue
		}
		// Last write to each path is the rollback restore — must equal
		// the pre-existing bytes captured in the snapshot.
		lastWrite := writes[len(writes)-1]
		var want []byte
		switch path {
		case "/etc/ssl/cert.pem":
			want = originalCert
		case "/etc/ssl/key.pem":
			want = originalKey
		case "/etc/ssl/chain.pem":
			want = originalChain
		}
		if string(lastWrite) != string(want) {
			t.Errorf("rollback for %s did not restore original bytes:\n  got:  %q\n  want: %q", path, lastWrite, want)
		}
	}

	// No Remove calls — every path had a pre-existing snapshot to restore from.
	if len(mock.removeCalls) != 0 {
		t.Errorf("expected 0 Remove calls (all paths had backups), got %d: %v", len(mock.removeCalls), mock.removeCalls)
	}

	// Both Execute calls (initial reload + retry-reload after rollback)
	// must have run.
	if len(mock.executeCalls) != 2 {
		t.Errorf("expected 2 Execute calls (reload + retry-reload), got %d", len(mock.executeCalls))
	}

	// Metadata reflects per-path snapshot status.
	if result.Metadata["backup_status_cert"] != "restored" {
		t.Errorf("expected backup_status_cert=restored, got %q", result.Metadata["backup_status_cert"])
	}
	if result.Metadata["backup_status_key"] != "restored" {
		t.Errorf("expected backup_status_key=restored, got %q", result.Metadata["backup_status_key"])
	}
	if result.Metadata["backup_status_chain"] != "restored" {
		t.Errorf("expected backup_status_chain=restored, got %q", result.Metadata["backup_status_chain"])
	}
	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true, got %q", result.Metadata["rolled_back"])
	}
}

func TestSSH_NoExistingCert_ReloadFails_NewCertRemoved(t *testing.T) {
	mock := &mockSSHClient{
		// All three paths report "no such file" — first-time deploy.
		statByPath: map[string]statResponse{
			"/etc/ssl/cert.pem":  {err: fmt.Errorf("stat: %w", os.ErrNotExist)},
			"/etc/ssl/key.pem":   {err: fmt.Errorf("stat: %w", os.ErrNotExist)},
			"/etc/ssl/chain.pem": {err: fmt.Errorf("stat: %w", os.ErrNotExist)},
		},
		// Reload fails; retry-reload after rollback succeeds.
		executeErrSequence: []error{fmt.Errorf("reload failed"), nil},
		executeOutSequence: []string{"reload error", "ok"},
	}

	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		ChainPath:     "/etc/ssl/chain.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nNEW_CERT\n-----END CERTIFICATE-----\n",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nNEW_KEY\n-----END PRIVATE KEY-----\n",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nNEW_CHAIN\n-----END CERTIFICATE-----\n",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when reload fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Rollback for first-time deploys must call Remove on every written path.
	expectedRemoves := map[string]bool{
		"/etc/ssl/cert.pem":  true,
		"/etc/ssl/key.pem":   true,
		"/etc/ssl/chain.pem": true,
	}
	if len(mock.removeCalls) != len(expectedRemoves) {
		t.Errorf("expected %d Remove calls, got %d: %v", len(expectedRemoves), len(mock.removeCalls), mock.removeCalls)
	}
	for _, p := range mock.removeCalls {
		if !expectedRemoves[p] {
			t.Errorf("unexpected Remove path: %s", p)
		}
	}

	// First-time deploy: WriteFile is called only during the initial
	// deploy, never during rollback (no backup to restore from).
	expectedWrites := 3 // cert + key + chain (all configured paths)
	if len(mock.writeFileCalls) != expectedWrites {
		t.Errorf("expected exactly %d WriteFile calls (deploy only, no restore), got %d", expectedWrites, len(mock.writeFileCalls))
	}

	// Metadata reflects "removed" status for all paths.
	if result.Metadata["backup_status_cert"] != "removed" {
		t.Errorf("expected backup_status_cert=removed, got %q", result.Metadata["backup_status_cert"])
	}
	if result.Metadata["backup_status_key"] != "removed" {
		t.Errorf("expected backup_status_key=removed, got %q", result.Metadata["backup_status_key"])
	}
	if result.Metadata["backup_status_chain"] != "removed" {
		t.Errorf("expected backup_status_chain=removed, got %q", result.Metadata["backup_status_chain"])
	}
}

func TestSSH_ReloadFails_RollbackAlsoFails_OperatorActionable(t *testing.T) {
	originalCert := []byte("ORIGINAL_CERT")
	originalKey := []byte("ORIGINAL_KEY")

	mock := &mockSSHClient{
		statByPath: map[string]statResponse{
			"/etc/ssl/cert.pem": {info: &stubFileInfo{size: int64(len(originalCert)), mode: 0644}},
			"/etc/ssl/key.pem":  {info: &stubFileInfo{size: int64(len(originalKey)), mode: 0600}},
		},
		readByPath: map[string][]byte{
			"/etc/ssl/cert.pem": originalCert,
			"/etc/ssl/key.pem":  originalKey,
		},
		// Initial deploy WriteFile calls succeed; rollback's WriteFile to
		// restore the cert FAILS. This injects the operator-actionable
		// case: reload failed AND the restore can't complete.
		writeFileErrByPath: map[string]error{},
		executeErrSequence: []error{fmt.Errorf("reload step failed")},
		executeOutSequence: []string{"reload error"},
	}
	// Track call count so we can fail only the SECOND WriteFile to
	// /etc/ssl/cert.pem (i.e. the restore call, not the initial deploy
	// write). Done via a wrapper because writeFileErrByPath is a flat map.
	wrapped := &writeOrderTrackingMock{base: mock}
	wrapped.failOnNthWriteForPath = map[string]int{
		"/etc/ssl/cert.pem": 2, // 1st = deploy write (succeed); 2nd = restore (fail)
	}

	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, wrapped, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "NEW_CERT",
		KeyPEM:  "NEW_KEY",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when both reload and rollback fail")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Wrapped error must mention BOTH the reload error and the rollback error.
	if !containsString(err.Error(), "reload failed") {
		t.Errorf("expected error to mention reload failure, got: %v", err)
	}
	if !containsString(err.Error(), "rollback also failed") {
		t.Errorf("expected error to mention 'rollback also failed', got: %v", err)
	}
	if !containsString(err.Error(), "manual operator inspection required") {
		t.Errorf("expected error to flag manual inspection, got: %v", err)
	}

	// Metadata must surface manual_action_required + both error strings.
	if result.Metadata["manual_action_required"] != "true" {
		t.Errorf("expected manual_action_required=true, got %q", result.Metadata["manual_action_required"])
	}
	if result.Metadata["rolled_back"] != "false" {
		t.Errorf("expected rolled_back=false, got %q", result.Metadata["rolled_back"])
	}
	if result.Metadata["rollback_error"] == "" {
		t.Error("expected rollback_error in metadata")
	}
}

func TestSSH_ReloadFails_RestoreThenSecondReloadFails(t *testing.T) {
	originalCert := []byte("ORIGINAL_CERT")
	originalKey := []byte("ORIGINAL_KEY")

	mock := &mockSSHClient{
		statByPath: map[string]statResponse{
			"/etc/ssl/cert.pem": {info: &stubFileInfo{size: int64(len(originalCert)), mode: 0644}},
			"/etc/ssl/key.pem":  {info: &stubFileInfo{size: int64(len(originalKey)), mode: 0600}},
		},
		readByPath: map[string][]byte{
			"/etc/ssl/cert.pem": originalCert,
			"/etc/ssl/key.pem":  originalKey,
		},
		// Both Execute calls (initial reload + retry-reload after rollback)
		// fail. The remote files are back to pre-deploy state but the
		// daemon may be in a stuck/partial state — operator needs to
		// know that.
		executeErrSequence: []error{fmt.Errorf("reload step 1 failed"), fmt.Errorf("reload step 2 failed")},
		executeOutSequence: []string{"out1", "out2"},
	}

	cfg := &Config{
		Host:          "server.local",
		Port:          22,
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		CertMode:      "0644",
		KeyMode:       "0600",
		ReloadCommand: "systemctl reload nginx",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.DeploymentRequest{
		CertPEM: "NEW_CERT",
		KeyPEM:  "NEW_KEY",
	}

	result, err := c.DeployCertificate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when retry-reload after rollback fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}

	// Wrapped error mentions reload failure, rollback success, and
	// retry-reload failure — operator must understand the daemon may
	// not be running the original config even though the files are back.
	if !containsString(err.Error(), "rolled back files") {
		t.Errorf("expected error to mention 'rolled back files', got: %v", err)
	}
	if !containsString(err.Error(), "retry-reload also failed") {
		t.Errorf("expected error to mention retry-reload failure, got: %v", err)
	}
	if !containsString(err.Error(), "daemon may need manual restart") {
		t.Errorf("expected error to flag daemon state, got: %v", err)
	}

	// Metadata flags daemon_state_unknown + rolled_back=true (files OK).
	if result.Metadata["daemon_state_unknown"] != "true" {
		t.Errorf("expected daemon_state_unknown=true, got %q", result.Metadata["daemon_state_unknown"])
	}
	if result.Metadata["rolled_back"] != "true" {
		t.Errorf("expected rolled_back=true, got %q", result.Metadata["rolled_back"])
	}

	// Both Execute calls happened; both WriteFile-on-restore calls
	// happened (cert + key restored).
	if len(mock.executeCalls) != 2 {
		t.Errorf("expected 2 Execute calls, got %d", len(mock.executeCalls))
	}
}

// writeOrderTrackingMock wraps mockSSHClient to fail the Nth WriteFile
// for a given path. Used by TestSSH_ReloadFails_RollbackAlsoFails_-
// OperatorActionable to fail the restore (2nd write) while letting the
// initial deploy (1st write) succeed for the same path.
type writeOrderTrackingMock struct {
	base                  *mockSSHClient
	writeCountByPath      map[string]int
	failOnNthWriteForPath map[string]int
}

func (w *writeOrderTrackingMock) Connect(ctx context.Context) error { return w.base.Connect(ctx) }
func (w *writeOrderTrackingMock) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	if w.writeCountByPath == nil {
		w.writeCountByPath = map[string]int{}
	}
	w.writeCountByPath[remotePath]++
	w.base.writeFileCalls = append(w.base.writeFileCalls, writeFileCall{Path: remotePath, Data: data, Mode: mode})
	if n, ok := w.failOnNthWriteForPath[remotePath]; ok {
		if w.writeCountByPath[remotePath] == n {
			return fmt.Errorf("injected write failure on call %d to %s", n, remotePath)
		}
	}
	return nil
}
func (w *writeOrderTrackingMock) Execute(ctx context.Context, cmd string) (string, error) {
	return w.base.Execute(ctx, cmd)
}
func (w *writeOrderTrackingMock) StatFile(remotePath string) (os.FileInfo, error) {
	return w.base.StatFile(remotePath)
}
func (w *writeOrderTrackingMock) ReadFile(remotePath string) ([]byte, error) {
	return w.base.ReadFile(remotePath)
}
func (w *writeOrderTrackingMock) Remove(remotePath string) error { return w.base.Remove(remotePath) }
func (w *writeOrderTrackingMock) Close() error                   { return w.base.Close() }

// --- ValidateDeployment tests ---

func TestValidateDeployment_Success(t *testing.T) {
	mock := &mockSSHClient{statFileSize: 2048}
	cfg := &Config{
		Host:     "server.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "ABC123",
	}

	result, err := c.ValidateDeployment(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid, got %s", result.Message)
	}

	// Should have stat'd both files
	if len(mock.statFileCalls) != 2 {
		t.Fatalf("expected 2 stat calls, got %d", len(mock.statFileCalls))
	}
	if mock.statFileCalls[0] != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert path, got %s", mock.statFileCalls[0])
	}
	if mock.statFileCalls[1] != "/etc/ssl/key.pem" {
		t.Errorf("expected key path, got %s", mock.statFileCalls[1])
	}
}

func TestValidateDeployment_CertNotFound(t *testing.T) {
	mock := &mockSSHClient{statFileErr: fmt.Errorf("file not found")}
	cfg := &Config{
		Host:     "server.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "ABC123",
	}

	result, err := c.ValidateDeployment(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
}

func TestValidateDeployment_ConnectionFailure(t *testing.T) {
	mock := &mockSSHClient{connectErr: fmt.Errorf("connection refused")}
	cfg := &Config{
		Host:     "unreachable.local",
		Port:     22,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		CertMode: "0644",
		KeyMode:  "0600",
	}
	c := NewWithClient(cfg, mock, testLogger())

	req := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "ABC123",
	}

	result, err := c.ValidateDeployment(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
}

// --- Helper tests ---

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		input    string
		expected os.FileMode
		wantErr  bool
	}{
		{"0644", 0644, false},
		{"0600", 0600, false},
		{"0755", 0755, false},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			mode, err := parsePermissions(tc.input)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && mode != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, mode)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.Port != 22 {
		t.Errorf("expected port 22, got %d", cfg.Port)
	}
	if cfg.AuthMethod != "key" {
		t.Errorf("expected auth_method key, got %s", cfg.AuthMethod)
	}
	if cfg.CertMode != "0644" {
		t.Errorf("expected cert_mode 0644, got %s", cfg.CertMode)
	}
	if cfg.KeyMode != "0600" {
		t.Errorf("expected key_mode 0600, got %s", cfg.KeyMode)
	}
	if cfg.Timeout != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.Timeout)
	}
}

// TestDeployCertificate_FullChainMode tests that when ChainPath is not set but
// ChainPEM is provided, the chain is appended to the certificate data before writing.
func TestDeployCertificate_FullChainMode(t *testing.T) {
	keyFile := createTempKeyFile(t)

	cfg := &Config{
		Host:           "example.com",
		Port:           22,
		User:           "deploy",
		AuthMethod:     "key",
		PrivateKeyPath: keyFile,
		CertPath:       "/etc/ssl/certs/cert.pem",
		KeyPath:        "/etc/ssl/private/key.pem",
		ChainPath:      "", // Not set, so chain should be appended to cert
		CertMode:       "0644",
		KeyMode:        "0600",
		Timeout:        30,
	}

	mock := &mockSSHClient{}
	connector := NewWithClient(cfg, mock, testLogger())

	deployReq := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBk...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIBj...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(context.Background(), deployReq)
	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("deployment result was not successful: %s", result.Message)
	}

	// Verify that the cert file received contains both cert and chain concatenated
	if len(mock.writeFileCalls) < 2 {
		t.Fatalf("expected at least 2 WriteFile calls, got %d", len(mock.writeFileCalls))
	}

	certWriteCall := mock.writeFileCalls[0]
	if certWriteCall.Path != "/etc/ssl/certs/cert.pem" {
		t.Errorf("expected cert path /etc/ssl/certs/cert.pem, got %s", certWriteCall.Path)
	}

	certData := string(certWriteCall.Data)
	if !containsString(certData, "BEGIN CERTIFICATE") || !containsString(certData, "END CERTIFICATE") {
		t.Errorf("cert data should contain combined cert and chain")
	}

	// Verify chain was not written separately (since ChainPath is empty)
	if len(mock.writeFileCalls) > 2 {
		t.Errorf("expected only 2 WriteFile calls (cert + key), got %d", len(mock.writeFileCalls))
	}
}

// TestDeployCertificate_Permissions tests that the correct file permissions are
// passed to WriteFile for both certificate and key files.
func TestDeployCertificate_Permissions(t *testing.T) {
	keyFile := createTempKeyFile(t)

	cfg := &Config{
		Host:           "example.com",
		Port:           22,
		User:           "deploy",
		AuthMethod:     "key",
		PrivateKeyPath: keyFile,
		CertPath:       "/etc/ssl/certs/cert.pem",
		KeyPath:        "/etc/ssl/private/key.pem",
		ChainPath:      "",
		CertMode:       "0644",
		KeyMode:        "0600",
		Timeout:        30,
	}

	mock := &mockSSHClient{}
	connector := NewWithClient(cfg, mock, testLogger())

	deployReq := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBk...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "",
	}

	_, err := connector.DeployCertificate(context.Background(), deployReq)
	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}

	if len(mock.writeFileCalls) < 2 {
		t.Fatalf("expected at least 2 WriteFile calls, got %d", len(mock.writeFileCalls))
	}

	// Check cert file permissions (0644 = rw-r--r--)
	certMode := mock.writeFileCalls[0].Mode
	expectedCertMode := os.FileMode(0644)
	if certMode != expectedCertMode {
		t.Errorf("expected cert mode 0644, got %o", certMode)
	}

	// Check key file permissions (0600 = rw-------)
	keyMode := mock.writeFileCalls[1].Mode
	expectedKeyMode := os.FileMode(0600)
	if keyMode != expectedKeyMode {
		t.Errorf("expected key mode 0600, got %o", keyMode)
	}
}

// TestValidateDeployment_KeyNotFound tests that ValidateDeployment fails when
// the key file is not found on the remote server.
func TestValidateDeployment_KeyNotFound(t *testing.T) {
	keyFile := createTempKeyFile(t)

	cfg := &Config{
		Host:           "example.com",
		Port:           22,
		User:           "deploy",
		AuthMethod:     "key",
		PrivateKeyPath: keyFile,
		CertPath:       "/etc/ssl/certs/cert.pem",
		KeyPath:        "/etc/ssl/private/key.pem",
		ChainPath:      "",
		CertMode:       "0644",
		KeyMode:        "0600",
		Timeout:        30,
	}

	// Create a custom mock that succeeds for cert but fails for key
	mock := &conditionalStatMockSSHClient{
		base: &mockSSHClient{},
	}

	connector := NewWithClient(cfg, mock, testLogger())

	valReq := target.ValidationRequest{
		Serial: "11111",
	}

	result, err := connector.ValidateDeployment(context.Background(), valReq)
	if err == nil {
		t.Error("expected validation to fail when key file is not found")
	}
	if result.Valid {
		t.Error("expected Valid=false when key file is missing")
	}
	if !containsString(result.Message, "key file not found") {
		t.Errorf("expected 'key file not found' in message, got: %s", result.Message)
	}
}

// conditionalStatMockSSHClient wraps mockSSHClient to fail on key path during StatFile.
type conditionalStatMockSSHClient struct {
	base      *mockSSHClient
	callCount int
}

func (m *conditionalStatMockSSHClient) Connect(ctx context.Context) error {
	return m.base.Connect(ctx)
}

func (m *conditionalStatMockSSHClient) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	return m.base.WriteFile(remotePath, data, mode)
}

func (m *conditionalStatMockSSHClient) Execute(ctx context.Context, command string) (string, error) {
	return m.base.Execute(ctx, command)
}

func (m *conditionalStatMockSSHClient) StatFile(remotePath string) (os.FileInfo, error) {
	m.callCount++
	// First call succeeds (cert), second call fails (key) — wrap
	// os.ErrNotExist so the connector's errors.Is check propagates the
	// "file not found" semantics through the Bundle 6 stat-error
	// handling.
	if m.callCount == 2 {
		return nil, fmt.Errorf("file not found: %w", os.ErrNotExist)
	}
	return &stubFileInfo{size: 1024, mode: 0644}, nil
}

func (m *conditionalStatMockSSHClient) ReadFile(remotePath string) ([]byte, error) {
	return m.base.ReadFile(remotePath)
}

func (m *conditionalStatMockSSHClient) Remove(remotePath string) error {
	return m.base.Remove(remotePath)
}

func (m *conditionalStatMockSSHClient) Close() error {
	return m.base.Close()
}

// --- Helpers ---

// createTempKeyFile creates a temporary file that simulates an SSH private key.
func createTempKeyFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyFile := dir + "/id_rsa"
	if err := os.WriteFile(keyFile, []byte("fake-key-data"), 0600); err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	return keyFile
}

// containsString is a helper to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && stringIndex(s, substr) != -1
}

// stringIndex returns the index of the first occurrence of substr in s, or -1 if not found.
func stringIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
