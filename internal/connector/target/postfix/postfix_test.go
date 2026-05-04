package postfix_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/postfix"
)

// --- Config Validation Tests ---

func TestPostfixConnector_ValidateConfig_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestPostfixConnector_ValidateConfig_DovecotMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "dovecot",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig for dovecot mode failed: %v", err)
	}
}

func TestPostfixConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := postfix.New(&postfix.Config{}, logger)
	err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPostfixConnector_ValidateConfig_InvalidMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := postfix.Config{
		Mode:          "nginx",
		CertPath:      "/tmp/cert.pem",
		ReloadCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("expected 'invalid mode' error, got: %v", err)
	}
}

func TestPostfixConnector_ValidateConfig_DirectoryNotExists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        "/nonexistent/directory/cert.pem",
		KeyPath:         "/nonexistent/directory/key.pem",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for non-existent cert directory")
	}
}

func TestPostfixConnector_ValidateConfig_MissingCertPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// An empty config with mode=postfix will get defaults applied.
	// The defaults point to /etc/postfix/certs/ which won't exist in test,
	// so this will fail at directory check — which is fine; it validates that
	// defaults are applied and path validation catches missing dirs.
	cfg := postfix.Config{
		Mode:            "postfix",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error when default cert directory doesn't exist")
	}
}

func TestPostfixConnector_ValidateConfig_DefaultsApplied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Create a directory matching the postfix default path structure
	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "postfix", "certs")
	os.MkdirAll(certDir, 0755)

	cfg := postfix.Config{
		Mode:     "postfix",
		CertPath: filepath.Join(certDir, "cert.pem"),
		KeyPath:  filepath.Join(certDir, "key.pem"),
		// Leave ReloadCommand and ValidateCommand empty to get defaults
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)

	// Defaults will be applied for reload/validate commands.
	// The validate command will be "postfix check" which won't exist in test env
	// but ValidateConfig only warns on validate command failure (doesn't error).
	// The reload command "postfix reload" will be validated by ValidateShellCommand.
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig with defaults failed: %v", err)
	}
}

// --- Deployment Tests ---

func TestPostfixConnector_DeployCertificate_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify cert file was written (just cert, not chain — since chain_path is set)
	certData, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	if string(certData) != req.CertPEM {
		t.Errorf("cert content mismatch: got %q", string(certData))
	}

	// Verify key file was written
	keyData, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if string(keyData) != req.KeyPEM {
		t.Errorf("key content mismatch")
	}

	// Verify chain file was written
	chainData, err := os.ReadFile(cfg.ChainPath)
	if err != nil {
		t.Fatalf("failed to read chain file: %v", err)
	}
	if string(chainData) != req.ChainPEM {
		t.Errorf("chain content mismatch")
	}

	// Verify cert has correct permissions (0644)
	info, err := os.Stat(cfg.CertPath)
	if err != nil {
		t.Fatalf("failed to stat cert file: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected cert permissions 0644, got %v", info.Mode().Perm())
	}

	// Verify key has correct permissions (0600)
	info, err = os.Stat(cfg.KeyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected key permissions 0600, got %v", info.Mode().Perm())
	}

	// Verify metadata
	if result.Metadata == nil {
		t.Fatal("expected metadata in result")
	}
	if result.Metadata["cert_path"] != cfg.CertPath {
		t.Errorf("expected cert_path in metadata")
	}
	if result.Metadata["mode"] != "postfix" {
		t.Errorf("expected mode=postfix in metadata, got %s", result.Metadata["mode"])
	}
	if _, ok := result.Metadata["duration_ms"]; !ok {
		t.Errorf("expected duration_ms in metadata")
	}
}

func TestPostfixConnector_DeployCertificate_ChainAppendedToCert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ChainPath:       "", // No chain_path — chain should be appended to cert
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	certPEM := "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
	chainPEM := "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"

	req := target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		ChainPEM: chainPEM,
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify cert file contains both cert and chain (fullchain)
	certData, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	expected := certPEM + "\n" + chainPEM
	if string(certData) != expected {
		t.Errorf("expected fullchain content, got: %q", string(certData))
	}
}

func TestPostfixConnector_DeployCertificate_CertWriteFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        "/nonexistent/directory/cert.pem",
		KeyPath:         "/nonexistent/directory/key.pem",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "cert",
		ChainPEM: "chain",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err == nil {
		t.Fatal("expected error when cert write fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestPostfixConnector_DeployCertificate_ValidateCommandFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "false", // Exits with code 1
	}

	connector := postfix.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "cert",
		ChainPEM: "chain",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err == nil {
		t.Fatal("expected error when validate command fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestPostfixConnector_DeployCertificate_ReloadCommandFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "false", // Exits with code 1
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "cert",
		ChainPEM: "chain",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err == nil {
		t.Fatal("expected error when reload command fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

// --- Validation Tests ---

func TestPostfixConnector_ValidateDeployment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)

	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        certPath,
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123",
	})
	if err != nil {
		t.Fatalf("ValidateDeployment failed: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid deployment")
	}
	if result.Metadata == nil {
		t.Fatal("expected metadata in result")
	}
	if result.Metadata["mode"] != "postfix" {
		t.Errorf("expected mode=postfix in metadata")
	}
}

func TestPostfixConnector_ValidateDeployment_CertNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := &postfix.Config{
		Mode:            "postfix",
		CertPath:        "/nonexistent/cert.pem",
		ValidateCommand: "true",
	}

	connector := postfix.New(cfg, logger)

	result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123",
	})
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
}

// --- Security Tests (Command Injection Prevention) ---

func TestPostfixConnector_ValidateConfig_RejectCommandInjectionSemicolon(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "postfix reload; rm -rf /",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command injection in reload_command")
	}
}

func TestPostfixConnector_ValidateConfig_RejectCommandInjectionPipe(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "postfix check | cat /etc/passwd",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command injection in validate_command")
	}
}

func TestPostfixConnector_ValidateConfig_RejectCommandSubstitution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "echo $(whoami)",
		ValidateCommand: "true",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command substitution in reload_command")
	}
}

func TestPostfixConnector_ValidateConfig_RejectBackticks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := postfix.Config{
		Mode:            "postfix",
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "postfix check `whoami`",
	}

	connector := postfix.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for backtick injection in validate_command")
	}
}
