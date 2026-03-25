package apache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Config represents the Apache httpd deployment target configuration.
// This configuration is used on the agent side to deploy certificates to Apache.
type Config struct {
	CertPath        string `json:"cert_path"`        // Path where cert will be written (e.g., /etc/apache2/ssl/cert.pem)
	KeyPath         string `json:"key_path"`          // Path where private key will be written
	ChainPath       string `json:"chain_path"`        // Path where CA chain will be written
	ReloadCommand   string `json:"reload_command"`    // Command to reload Apache (e.g., "apachectl graceful" or "systemctl reload apache2")
	ValidateCommand string `json:"validate_command"`  // Command to validate Apache config (e.g., "apachectl configtest")
}

// Connector implements the target.Connector interface for Apache httpd servers.
// This connector runs on the AGENT side and handles local certificate deployment.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new Apache target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// ValidateConfig checks that all required configuration paths and commands are valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Apache config: %w", err)
	}

	if cfg.CertPath == "" || cfg.ChainPath == "" {
		return fmt.Errorf("Apache cert_path and chain_path are required")
	}

	if cfg.ReloadCommand == "" || cfg.ValidateCommand == "" {
		return fmt.Errorf("Apache reload_command and validate_command are required")
	}

	c.logger.Info("validating Apache configuration",
		"cert_path", cfg.CertPath,
		"chain_path", cfg.ChainPath)

	// Verify parent directory exists
	certDir := filepath.Dir(cfg.CertPath)
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("Apache cert directory does not exist: %s", certDir)
	}

	// Verify validate command works
	cmd := exec.CommandContext(ctx, "sh", "-c", cfg.ValidateCommand)
	if err := cmd.Run(); err != nil {
		c.logger.Warn("Apache config validation failed during config check",
			"error", err,
			"validate_command", cfg.ValidateCommand)
		// Don't fail; Apache might not be installed yet
	}

	c.config = &cfg
	c.logger.Info("Apache configuration validated")
	return nil
}

// DeployCertificate writes the certificate, key, and chain to configured paths
// and reloads Apache to pick up the new certificates.
//
// Steps:
// 1. Write certificate to cert_path with mode 0644
// 2. Write private key to key_path with mode 0600 (owner-only read)
// 3. Write chain to chain_path with mode 0644
// 4. Validate Apache configuration with configtest
// 5. Execute graceful reload command
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Apache httpd",
		"cert_path", c.config.CertPath,
		"chain_path", c.config.ChainPath)

	startTime := time.Now()

	// Write certificate (0644: rw-r--r--)
	if err := os.WriteFile(c.config.CertPath, []byte(request.CertPEM), 0644); err != nil {
		errMsg := fmt.Sprintf("failed to write certificate: %v", err)
		c.logger.Error("certificate deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Write private key with secure permissions (0600: rw-------)
	if c.config.KeyPath != "" && request.KeyPEM != "" {
		if err := os.WriteFile(c.config.KeyPath, []byte(request.KeyPEM), 0600); err != nil {
			errMsg := fmt.Sprintf("failed to write private key: %v", err)
			c.logger.Error("key deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: c.config.KeyPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Write chain (0644: rw-r--r--)
	if err := os.WriteFile(c.config.ChainPath, []byte(request.ChainPEM), 0644); err != nil {
		errMsg := fmt.Sprintf("failed to write chain: %v", err)
		c.logger.Error("chain deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.ChainPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Validate Apache configuration before reload
	c.logger.Debug("validating Apache configuration", "validate_command", c.config.ValidateCommand)
	validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
	if output, err := validateCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("Apache config validation failed: %v (output: %s)", err, string(output))
		c.logger.Error("Apache validation failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Graceful reload
	c.logger.Debug("reloading Apache", "reload_command", c.config.ReloadCommand)
	reloadCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ReloadCommand)
	if output, err := reloadCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("Apache reload failed: %v (output: %s)", err, string(output))
		c.logger.Error("Apache reload failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to Apache successfully",
		"duration", deploymentDuration.String(),
		"cert_path", c.config.CertPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.CertPath,
		DeploymentID:  fmt.Sprintf("apache-%d", time.Now().Unix()),
		Message:       "Certificate deployed and Apache reloaded successfully",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path":   c.config.CertPath,
			"chain_path":  c.config.ChainPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate is valid and accessible.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Apache deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	// Validate Apache configuration
	validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
	if output, err := validateCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("Apache config validation failed: %v (output: %s)", err, string(output))
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify certificate file exists and is readable
	if _, err := os.Stat(c.config.CertPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("certificate file not found: %s", c.config.CertPath)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("Apache deployment validated successfully",
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.CertPath,
		Message:       "Apache configuration valid and certificate accessible",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"validate_command": c.config.ValidateCommand,
			"duration_ms":      fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
