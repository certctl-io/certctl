package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// testLogger returns a slog.Logger for test output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// --- Mock SSH Client ---

// mockSSHClient records all calls and returns configurable results.
type mockSSHClient struct {
	connectCalls   int
	connectErr     error
	writeFileCalls []writeFileCall
	writeFileErr   error
	executeCalls   []string
	executeOutput  string
	executeErr     error
	statFileCalls  []string
	statFileSize   int64
	statFileErr    error
	closeCalls     int
}

type writeFileCall struct {
	Path string
	Data []byte
	Mode os.FileMode
}

func (m *mockSSHClient) Connect(ctx context.Context) error {
	m.connectCalls++
	return m.connectErr
}

func (m *mockSSHClient) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	m.writeFileCalls = append(m.writeFileCalls, writeFileCall{Path: remotePath, Data: data, Mode: mode})
	return m.writeFileErr
}

func (m *mockSSHClient) Execute(ctx context.Context, command string) (string, error) {
	m.executeCalls = append(m.executeCalls, command)
	return m.executeOutput, m.executeErr
}

func (m *mockSSHClient) StatFile(remotePath string) (int64, error) {
	m.statFileCalls = append(m.statFileCalls, remotePath)
	return m.statFileSize, m.statFileErr
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
