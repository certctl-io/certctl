package nginx_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/nginx"
)

func TestNginxConnector_ValidateConfig_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestNginxConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := nginx.New(&nginx.Config{}, logger)
	err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNginxConnector_ValidateConfig_MissingCertPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for missing cert_path")
	}
}

func TestNginxConnector_ValidateConfig_MissingReloadCommand(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for missing reload_command")
	}
}

func TestNginxConnector_ValidateConfig_DirectoryNotExists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := nginx.Config{
		CertPath:        "/nonexistent/directory/cert.pem",
		ChainPath:       "/tmp/chain.pem",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for non-existent cert directory")
	}
}

func TestNginxConnector_DeployCertificate_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		KeyPath:         filepath.Join(tmpDir, "key.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify cert file was written
	certData, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	if string(certData) != req.CertPEM {
		t.Errorf("cert content mismatch")
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

	// Verify chain has correct permissions (0644)
	info, err = os.Stat(cfg.ChainPath)
	if err != nil {
		t.Fatalf("failed to stat chain file: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected chain permissions 0644, got %v", info.Mode().Perm())
	}

	// Verify metadata is populated
	if result.Metadata == nil {
		t.Fatal("expected metadata in result")
	}
	if result.Metadata["cert_path"] != cfg.CertPath {
		t.Errorf("expected cert_path in metadata")
	}
	if result.Metadata["chain_path"] != cfg.ChainPath {
		t.Errorf("expected chain_path in metadata")
	}
	if _, ok := result.Metadata["duration_ms"]; !ok {
		t.Errorf("expected duration_ms in metadata")
	}
}

func TestNginxConnector_DeployCertificate_CertWriteFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := &nginx.Config{
		CertPath:        "/nonexistent/directory/cert.pem",
		ChainPath:       "/tmp/chain.pem",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

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

func TestNginxConnector_DeployCertificate_ChainWriteFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       "/nonexistent/directory/chain.pem",
		ReloadCommand:   "true",
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

	req := target.DeploymentRequest{
		CertPEM:  "cert",
		ChainPEM: "chain",
	}

	result, err := connector.DeployCertificate(ctx, req)
	if err == nil {
		t.Fatal("expected error when chain write fails")
	}
	if result.Success {
		t.Fatal("expected failure result")
	}
}

func TestNginxConnector_DeployCertificate_ValidateCommandFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "false",
	}

	connector := nginx.New(cfg, logger)

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

func TestNginxConnector_DeployCertificate_ReloadCommandFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := &nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "false",
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

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

func TestNginxConnector_ValidateDeployment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)

	cfg := &nginx.Config{
		CertPath:        certPath,
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

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

	// Verify metadata is populated
	if result.Metadata == nil {
		t.Fatal("expected metadata in result")
	}
	if _, ok := result.Metadata["duration_ms"]; !ok {
		t.Errorf("expected duration_ms in metadata")
	}
}

func TestNginxConnector_ValidateDeployment_CertNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := &nginx.Config{
		CertPath:        "/nonexistent/cert.pem",
		ValidateCommand: "true",
	}

	connector := nginx.New(cfg, logger)

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

func TestNginxConnector_ValidateDeployment_ValidateCommandFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)

	cfg := &nginx.Config{
		CertPath:        certPath,
		ValidateCommand: "false",
	}

	connector := nginx.New(cfg, logger)

	result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123",
	})
	if err == nil {
		t.Fatal("expected error when validate command fails")
	}
	if result.Valid {
		t.Fatal("expected invalid result")
	}
}

// Security tests for command injection prevention

func TestNginxConnector_ValidateConfig_RejectCommandInjectionSemicolon(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "nginx; rm -rf /", // Command injection attempt
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command injection in reload_command")
	}
}

func TestNginxConnector_ValidateConfig_RejectCommandInjectionPipe(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "nginx -t | cat /etc/passwd", // Command injection attempt
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command injection in validate_command")
	}
}

func TestNginxConnector_ValidateConfig_RejectCommandSubstitution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "echo $(whoami)",
		ValidateCommand: "true",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for command substitution in reload_command")
	}
}

func TestNginxConnector_ValidateConfig_RejectBackticks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := nginx.Config{
		CertPath:        filepath.Join(tmpDir, "cert.pem"),
		ChainPath:       filepath.Join(tmpDir, "chain.pem"),
		ReloadCommand:   "true",
		ValidateCommand: "nginx -t `whoami`",
	}

	connector := nginx.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for backtick injection in validate_command")
	}
}
