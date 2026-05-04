package traefik_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/traefik"
)

func TestTraefikConnector_ValidateConfig_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestTraefikConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := traefik.New(&traefik.Config{}, logger)
	err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestTraefikConnector_ValidateConfig_MissingCertDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := traefik.Config{
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for missing cert_dir")
	}
}

func TestTraefikConnector_ValidateConfig_DirectoryNotExists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := traefik.Config{
		CertDir:  "/nonexistent/directory",
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

func TestTraefikConnector_DeployCertificate_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	// Verify certificate file was created
	certPath := filepath.Join(tmpDir, "cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("certificate file was not created: %s", certPath)
	}

	// Verify key file was created with correct permissions
	keyPath := filepath.Join(tmpDir, "key.pem")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("key file was not created: %s", keyPath)
	}

	// Check key file permissions (should be 0600)
	keyInfo, _ := os.Stat(keyPath)
	perms := keyInfo.Mode().Perm()
	if perms != 0600 {
		t.Fatalf("key file permissions are %o, expected 0600", perms)
	}
}

func TestTraefikConnector_DeployCertificate_WriteError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Use a non-existent directory to trigger write error
	cfg := traefik.Config{
		CertDir:  "/root/certctl/certs",
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err == nil {
		t.Fatal("expected error for write failure")
	}

	if result.Success {
		t.Fatal("deployment should fail")
	}
}

func TestTraefikConnector_ValidateDeployment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// First deploy a certificate
	deployRequest := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}
	connector.DeployCertificate(ctx, deployRequest)

	// Now validate
	validateRequest := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	}

	result, err := connector.ValidateDeployment(ctx, validateRequest)
	if err != nil {
		t.Fatalf("ValidateDeployment failed: %v", err)
	}

	if !result.Valid {
		t.Fatalf("validation should succeed, got: %s", result.Message)
	}

	if result.Serial != "123456" {
		t.Fatalf("serial mismatch: expected 123456, got %s", result.Serial)
	}
}

func TestTraefikConnector_ValidateDeployment_CertFileNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Don't deploy anything, just validate
	validateRequest := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	}

	result, err := connector.ValidateDeployment(ctx, validateRequest)
	if err == nil {
		t.Fatal("expected error for missing certificate file")
	}

	if result.Valid {
		t.Fatal("validation should fail")
	}
}

func TestTraefikConnector_DeployCertificate_WithoutChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Deploy without chain
	request := target.DeploymentRequest{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	// Verify certificate file exists
	certPath := filepath.Join(tmpDir, "cert.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}

	if string(data) != "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n" {
		t.Fatalf("certificate content mismatch")
	}
}

func TestTraefikConnector_DefaultFilenames(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := traefik.Config{
		CertDir: tmpDir,
		// Don't specify CertFile and KeyFile, use defaults
	}

	connector := traefik.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}
