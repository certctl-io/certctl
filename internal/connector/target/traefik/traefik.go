package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Config represents the Traefik deployment target configuration.
// Traefik uses a file provider that watches a directory for certificate files.
// When files change, Traefik automatically reloads without requiring a reload command.
type Config struct {
	CertDir  string `json:"cert_dir"`  // Directory where Traefik watches for certificate files
	CertFile string `json:"cert_file"` // Filename for certificate (default: cert.pem)
	KeyFile  string `json:"key_file"`  // Filename for private key (default: key.pem)
}

// Connector implements the target.Connector interface for Traefik servers.
// This connector runs on the AGENT side and handles local certificate deployment.
// Traefik watches the configured directory and automatically reloads when files change.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new Traefik target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// ValidateConfig checks that the certificate directory exists and is writable.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Traefik config: %w", err)
	}

	if cfg.CertDir == "" {
		return fmt.Errorf("Traefik cert_dir is required")
	}

	// Default filenames if not provided
	if cfg.CertFile == "" {
		cfg.CertFile = "cert.pem"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "key.pem"
	}

	c.logger.Info("validating Traefik configuration",
		"cert_dir", cfg.CertDir,
		"cert_file", cfg.CertFile,
		"key_file", cfg.KeyFile)

	// Verify directory exists and is writable
	if _, err := os.Stat(cfg.CertDir); os.IsNotExist(err) {
		return fmt.Errorf("Traefik cert directory does not exist: %s", cfg.CertDir)
	}

	// Try to write a test file to verify directory is writable
	testFile := filepath.Join(cfg.CertDir, ".certctl-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("Traefik cert directory is not writable: %s (%w)", cfg.CertDir, err)
	}
	// Clean up test file
	os.Remove(testFile)

	c.config = &cfg
	c.logger.Info("Traefik configuration validated")
	return nil
}

// DeployCertificate writes the certificate and key files to the configured directory.
// Traefik watches this directory and automatically reloads when files change.
//
// Steps:
// 1. Write certificate to cert_file with mode 0644 (readable by all)
// 2. Write private key to key_file with mode 0600 (private key permissions)
// 3. Traefik's file watcher automatically picks up the changes
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Traefik",
		"cert_dir", c.config.CertDir,
		"cert_file", c.config.CertFile,
		"key_file", c.config.KeyFile)

	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

	// Write certificate and chain combined with mode 0644 (readable by all)
	certData := request.CertPEM + "\n"
	if request.ChainPEM != "" {
		certData += request.ChainPEM + "\n"
	}
	if err := os.WriteFile(certPath, []byte(certData), 0644); err != nil {
		errMsg := fmt.Sprintf("failed to write certificate: %v", err)
		c.logger.Error("certificate deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: certPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Write private key with secure permissions (0600: rw-------)
	if request.KeyPEM != "" {
		if err := os.WriteFile(keyPath, []byte(request.KeyPEM), 0600); err != nil {
			errMsg := fmt.Sprintf("failed to write private key: %v", err)
			c.logger.Error("key deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: keyPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to Traefik successfully",
		"duration", deploymentDuration.String(),
		"cert_path", certPath,
		"key_path", keyPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("traefik-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Traefik (file watcher will auto-reload)",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path":   certPath,
			"key_path":    keyPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate files are readable.
// It checks that both the certificate and key files exist and are accessible.
//
// Steps:
// 1. Verify certificate file exists and is readable
// 2. Verify key file exists and is readable
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Traefik deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

	// Verify certificate file exists and is readable
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("certificate file not found: %s", certPath)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: certPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify key file exists and is readable
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("private key file not found: %s", keyPath)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: keyPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("Traefik deployment validated successfully",
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: certPath,
		Message:       "Certificate and key files accessible",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"cert_path":   certPath,
			"key_path":    keyPath,
			"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
