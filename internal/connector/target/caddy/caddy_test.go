package caddy_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/caddy"
)

func TestCaddyConnector_ValidateConfig_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestCaddyConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := caddy.New(&caddy.Config{}, logger)
	err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCaddyConnector_ValidateConfig_InvalidMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		Mode:     "invalid",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestCaddyConnector_ValidateConfig_FileMode_MissingCertDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for missing cert_dir in file mode")
	}
}

func TestCaddyConnector_ValidateConfig_DefaultsApplied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		CertDir: tmpDir,
		Mode:    "file",
		// Don't specify AdminAPI, CertFile, KeyFile - should use defaults
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestCaddyConnector_DeployViaAPI_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Create a mock Caddy admin API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			// Verify POST request with JSON body
			if r.Method != "POST" {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			body, _ := io.ReadAll(r.Body)
			var payload map[string]string
			json.Unmarshal(body, &payload)
			if payload["cert"] == "" {
				t.Fatal("cert field missing in payload")
			}
			if payload["key"] == "" {
				t.Fatal("key field missing in payload")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := caddy.Config{
		AdminAPI: server.URL,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
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

	if !strings.Contains(result.Message, "API") {
		t.Fatalf("expected API deployment message, got: %s", result.Message)
	}
}

func TestCaddyConnector_DeployViaAPI_ServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Create a mock Caddy admin API server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid certificate"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: server.URL,
		CertDir:  tmpDir,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	// API fails and falls back to file mode - should succeed
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed via file fallback, got: %s", result.Message)
	}

	if !strings.Contains(result.Message, "file") {
		t.Fatalf("expected file deployment message after API failure, got: %s", result.Message)
	}
}

func TestCaddyConnector_DeployViaFile_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
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

	// Verify files were created
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("certificate file was not created: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("key file was not created: %s", keyPath)
	}

	// Verify key file has correct permissions
	keyInfo, _ := os.Stat(keyPath)
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("key file permissions are %o, expected 0600", keyInfo.Mode().Perm())
	}
}

func TestCaddyConnector_DeployViaFile_WriteError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  "/root/nonexistent",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)

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

func TestCaddyConnector_ValidateDeployment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Deploy a certificate
	deployRequest := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}
	connector.DeployCertificate(ctx, deployRequest)

	// Validate deployment
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

func TestCaddyConnector_ValidateDeployment_FileNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Don't deploy, just validate
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

func TestCaddyConnector_APIMode_NoChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := caddy.Config{
		AdminAPI: server.URL,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		// No ChainPEM
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}
}
