package apache_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/apache"
)

func TestApacheConnector_ValidateConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := apache.Config{
			CertPath:        filepath.Join(tmpDir, "cert.pem"),
			KeyPath:         filepath.Join(tmpDir, "key.pem"),
			ChainPath:       filepath.Join(tmpDir, "chain.pem"),
			ReloadCommand:   "echo reload",
			ValidateCommand: "echo ok",
		}

		connector := apache.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("missing cert_path", func(t *testing.T) {
		cfg := apache.Config{
			ChainPath:       "/tmp/chain.pem",
			ReloadCommand:   "echo reload",
			ValidateCommand: "echo ok",
		}

		connector := apache.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("expected error for missing cert_path")
		}
	})

	t.Run("missing reload_command", func(t *testing.T) {
		cfg := apache.Config{
			CertPath:        "/tmp/cert.pem",
			ChainPath:       "/tmp/chain.pem",
			ValidateCommand: "echo ok",
		}

		connector := apache.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("expected error for missing reload_command")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		connector := apache.New(&apache.Config{}, logger)
		err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestApacheConnector_DeployCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("successful deployment", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &apache.Config{
			CertPath:        filepath.Join(tmpDir, "cert.pem"),
			KeyPath:         filepath.Join(tmpDir, "key.pem"),
			ChainPath:       filepath.Join(tmpDir, "chain.pem"),
			ReloadCommand:   "echo reload",
			ValidateCommand: "echo ok",
		}

		connector := apache.New(cfg, logger)

		req := target.DeploymentRequest{
			CertPEM:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			KeyPEM:   "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
			ChainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
		}

		result, err := connector.DeployCertificate(ctx, req)
		if err != nil {
			t.Fatalf("DeployCertificate failed: %v", err)
		}

		if !result.Success {
			t.Fatalf("expected success, got: %s", result.Message)
		}

		// Verify files were written
		certData, err := os.ReadFile(cfg.CertPath)
		if err != nil {
			t.Fatalf("failed to read cert file: %v", err)
		}
		if string(certData) != req.CertPEM {
			t.Errorf("cert content mismatch")
		}

		// Verify key has secure permissions
		info, err := os.Stat(cfg.KeyPath)
		if err != nil {
			t.Fatalf("failed to stat key file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected key permissions 0600, got %v", info.Mode().Perm())
		}
	})

	t.Run("validate command fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &apache.Config{
			CertPath:        filepath.Join(tmpDir, "cert.pem"),
			KeyPath:         filepath.Join(tmpDir, "key.pem"),
			ChainPath:       filepath.Join(tmpDir, "chain.pem"),
			ReloadCommand:   "echo reload",
			ValidateCommand: "false", // always fails
		}

		connector := apache.New(cfg, logger)

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
	})
}

func TestApacheConnector_ValidateDeployment(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("valid deployment", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")
		os.WriteFile(certPath, []byte("cert"), 0644)

		cfg := &apache.Config{
			CertPath:        certPath,
			ValidateCommand: "echo ok",
		}

		connector := apache.New(cfg, logger)

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
	})

	t.Run("missing cert file", func(t *testing.T) {
		cfg := &apache.Config{
			CertPath:        "/nonexistent/cert.pem",
			ValidateCommand: "echo ok",
		}

		connector := apache.New(cfg, logger)

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
	})
}
