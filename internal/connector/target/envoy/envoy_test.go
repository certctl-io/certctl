package envoy_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/envoy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestEnvoyConnector_ValidateConfig_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{
		CertDir:      tmpDir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
	}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestEnvoyConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	connector := envoy.New(&envoy.Config{}, testLogger())
	if err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEnvoyConnector_ValidateConfig_MissingCertDir(t *testing.T) {
	ctx := context.Background()
	cfg := envoy.Config{CertFilename: "cert.pem", KeyFilename: "key.pem"}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err == nil {
		t.Fatal("expected error for missing cert_dir")
	}
}

func TestEnvoyConnector_ValidateConfig_DirectoryNotExists(t *testing.T) {
	ctx := context.Background()
	cfg := envoy.Config{CertDir: "/nonexistent/directory"}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

func TestEnvoyConnector_ValidateConfig_PathTraversal_CertFilename(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "../../../etc/passwd"}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err == nil {
		t.Fatal("expected error for path traversal in cert_filename")
	}
}

func TestEnvoyConnector_ValidateConfig_PathTraversal_KeyFilename(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	cfg := envoy.Config{CertDir: tmpDir, KeyFilename: "sub/key.pem"}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err == nil {
		t.Fatal("expected error for path traversal in key_filename")
	}
}

func TestEnvoyConnector_ValidateConfig_PathTraversal_ChainFilename(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	cfg := envoy.Config{CertDir: tmpDir, ChainFilename: "../chain.pem"}

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err == nil {
		t.Fatal("expected error for path traversal in chain_filename")
	}
}

func TestEnvoyConnector_ValidateConfig_DefaultFilenames(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	cfg := envoy.Config{CertDir: tmpDir} // No filenames — should use defaults

	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
		t.Fatalf("ValidateConfig with defaults failed: %v", err)
	}
}

func TestEnvoyConnector_DeployCertificate_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nCAcert...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	// Verify cert file was created with chain appended (no chain_filename set)
	certData, err := os.ReadFile(filepath.Join(tmpDir, "cert.pem"))
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	if got := string(certData); got != "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCAcert...\n-----END CERTIFICATE-----\n" {
		t.Fatalf("cert content mismatch: got %q", got)
	}

	// Verify key file created with correct permissions
	keyPath := filepath.Join(tmpDir, "key.pem")
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not found: %v", err)
	}
	if perms := keyInfo.Mode().Perm(); perms != 0600 {
		t.Fatalf("key permissions are %o, expected 0600", perms)
	}
}

func TestEnvoyConnector_DeployCertificate_WithoutChain(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

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

	// Cert file should only contain the leaf cert (no chain)
	certData, _ := os.ReadFile(filepath.Join(tmpDir, "cert.pem"))
	if got := string(certData); got != "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n" {
		t.Fatalf("cert content mismatch: got %q", got)
	}
}

func TestEnvoyConnector_DeployCertificate_SeparateChainFile(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{
		CertDir:       tmpDir,
		CertFilename:  "cert.pem",
		KeyFilename:   "key.pem",
		ChainFilename: "chain.pem",
	}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nleaf...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	// Cert file should only contain leaf (chain is separate)
	certData, _ := os.ReadFile(filepath.Join(tmpDir, "cert.pem"))
	if got := string(certData); got != "-----BEGIN CERTIFICATE-----\nleaf...\n-----END CERTIFICATE-----\n" {
		t.Fatalf("cert should not contain chain when chain_filename is set: got %q", got)
	}

	// Chain file should exist with chain data
	chainData, err := os.ReadFile(filepath.Join(tmpDir, "chain.pem"))
	if err != nil {
		t.Fatalf("chain file not found: %v", err)
	}
	if got := string(chainData); got != "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----\n" {
		t.Fatalf("chain content mismatch: got %q", got)
	}
}

func TestEnvoyConnector_DeployCertificate_WithSDSConfig(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{
		CertDir:      tmpDir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
		SDSConfig:    true,
	}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

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

	// Verify SDS JSON file was created
	sdsPath := filepath.Join(tmpDir, "sds.json")
	sdsData, err := os.ReadFile(sdsPath)
	if err != nil {
		t.Fatalf("SDS config file not found: %v", err)
	}

	// Parse and verify SDS JSON structure
	var sdsResource envoy.SDSResource
	if err := json.Unmarshal(sdsData, &sdsResource); err != nil {
		t.Fatalf("invalid SDS JSON: %v", err)
	}

	if len(sdsResource.Resources) != 1 {
		t.Fatalf("expected 1 SDS resource, got %d", len(sdsResource.Resources))
	}

	res := sdsResource.Resources[0]
	if res.Type != "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret" {
		t.Fatalf("wrong @type: %s", res.Type)
	}
	if res.Name != "server_cert" {
		t.Fatalf("wrong name: %s", res.Name)
	}

	expectedCertPath := filepath.Join(tmpDir, "cert.pem")
	expectedKeyPath := filepath.Join(tmpDir, "key.pem")
	if res.TLSCertificate.CertificateChain.Filename != expectedCertPath {
		t.Fatalf("cert chain path mismatch: got %s, want %s", res.TLSCertificate.CertificateChain.Filename, expectedCertPath)
	}
	if res.TLSCertificate.PrivateKey.Filename != expectedKeyPath {
		t.Fatalf("private key path mismatch: got %s, want %s", res.TLSCertificate.PrivateKey.Filename, expectedKeyPath)
	}

	// Verify SDS path is in metadata
	if result.Metadata["sds_config_path"] != sdsPath {
		t.Fatalf("SDS config path not in metadata")
	}
}

func TestEnvoyConnector_DeployCertificate_WriteError(t *testing.T) {
	ctx := context.Background()

	cfg := envoy.Config{
		CertDir:      "/root/envoy/certs",
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
	}
	connector := envoy.New(&cfg, testLogger())

	request := target.DeploymentRequest{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err == nil {
		t.Fatal("expected error for write failure")
	}
	if result.Success {
		t.Fatal("deployment should fail")
	}
}

func TestEnvoyConnector_ValidateDeployment_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// First deploy
	deployReq := target.DeploymentRequest{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
	}
	connector.DeployCertificate(ctx, deployReq)

	// Then validate
	validateReq := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	}

	result, err := connector.ValidateDeployment(ctx, validateReq)
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

func TestEnvoyConnector_ValidateDeployment_CertFileNotFound(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	validateReq := target.ValidationRequest{CertificateID: "mc-test", Serial: "123456"}
	result, err := connector.ValidateDeployment(ctx, validateReq)
	if err == nil {
		t.Fatal("expected error for missing certificate file")
	}
	if result.Valid {
		t.Fatal("validation should fail")
	}
}

func TestEnvoyConnector_ValidateDeployment_KeyFileNotFound(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	cfg := envoy.Config{CertDir: tmpDir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	connector := envoy.New(&cfg, testLogger())
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Write cert but not key
	os.WriteFile(filepath.Join(tmpDir, "cert.pem"), []byte("cert"), 0644)

	validateReq := target.ValidationRequest{CertificateID: "mc-test", Serial: "123456"}
	result, err := connector.ValidateDeployment(ctx, validateReq)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
	if result.Valid {
		t.Fatal("validation should fail")
	}
}
