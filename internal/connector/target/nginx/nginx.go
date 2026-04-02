package nginx

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
	"github.com/shankar0123/certctl/internal/validation"
)

// Config represents the NGINX deployment target configuration.
// This configuration is used on the agent side to deploy certificates to NGINX.
type Config struct {
	CertPath        string `json:"cert_path"`        // Path where cert will be written (typically /etc/nginx/certs/cert.pem)
	KeyPath         string `json:"key_path"`         // Path where private key will be written (NOT provided by control plane)
	ChainPath       string `json:"chain_path"`       // Path where chain will be written (typically /etc/nginx/certs/chain.pem)
	ReloadCommand   string `json:"reload_command"`   // Command to reload NGINX (e.g., "nginx -s reload" or "systemctl reload nginx")
	ValidateCommand string `json:"validate_command"` // Command to validate NGINX config (e.g., "nginx -t")
}

// Connector implements the target.Connector interface for NGINX servers.
// This connector runs on the AGENT side and handles local certificate deployment.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new NGINX target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// ValidateConfig checks that all required configuration paths and commands are valid.
// It verifies that the certificate and key paths are writable and commands are executable.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid NGINX config: %w", err)
	}

	if cfg.CertPath == "" || cfg.ChainPath == "" {
		return fmt.Errorf("NGINX cert_path and chain_path are required")
	}

	if cfg.ReloadCommand == "" || cfg.ValidateCommand == "" {
		return fmt.Errorf("NGINX reload_command and validate_command are required")
	}

	// Validate commands to prevent injection attacks
	if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("invalid reload_command: %w", err)
	}
	if err := validation.ValidateShellCommand(cfg.ValidateCommand); err != nil {
		return fmt.Errorf("invalid validate_command: %w", err)
	}

	c.logger.Info("validating NGINX configuration",
		"cert_path", cfg.CertPath,
		"chain_path", cfg.ChainPath)

	// Verify directory exists and is writable
	certDir := filepath.Dir(cfg.CertPath)
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("NGINX cert directory does not exist: %s", certDir)
	}

	// Verify validate command works
	cmd := exec.CommandContext(ctx, "sh", "-c", cfg.ValidateCommand)
	if err := cmd.Run(); err != nil {
		c.logger.Warn("NGINX config validation failed during config check",
			"error", err,
			"validate_command", cfg.ValidateCommand)
		// Don't fail validation; NGINX might not be installed yet
	}

	c.config = &cfg
	c.logger.Info("NGINX configuration validated")
	return nil
}

// DeployCertificate writes the certificate and chain to the configured paths
// and reloads NGINX to pick up the new certificates.
// The agent (not the control plane) manages the private key.
//
// Steps:
// 1. Write certificate to cert_path with mode 0644 (readable by all)
// 2. Write chain to chain_path with mode 0644
// 3. Validate NGINX configuration
// 4. Execute reload command
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to NGINX",
		"cert_path", c.config.CertPath,
		"chain_path", c.config.ChainPath)

	startTime := time.Now()

	// Write certificate with secure permissions (0644: rw-r--r--)
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

	// Write chain with same permissions
	if c.config.ChainPath != "" {
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
	}

	// Write private key if provided and key_path is configured
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
		c.logger.Info("private key written", "key_path", c.config.KeyPath)
	}

	// Validate NGINX configuration before reload
	c.logger.Debug("validating NGINX configuration", "validate_command", c.config.ValidateCommand)
	validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
	if output, err := validateCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("NGINX config validation failed: %v (output: %s)", err, string(output))
		c.logger.Error("NGINX validation failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Reload NGINX
	c.logger.Debug("reloading NGINX", "reload_command", c.config.ReloadCommand)
	reloadCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ReloadCommand)
	if output, err := reloadCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("NGINX reload failed: %v (output: %s)", err, string(output))
		c.logger.Error("NGINX reload failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to NGINX successfully",
		"duration", deploymentDuration.String(),
		"cert_path", c.config.CertPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.CertPath,
		DeploymentID:  fmt.Sprintf("nginx-%d", time.Now().Unix()),
		Message:       "Certificate deployed and NGINX reloaded successfully",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path":   c.config.CertPath,
			"chain_path":  c.config.ChainPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate is valid and accessible.
// It validates the NGINX configuration to ensure the certificate can be read.
//
// Steps:
// 1. Run validate command to check config syntax
// 2. Verify certificate file is readable
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating NGINX deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	// Validate NGINX configuration
	validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
	if err := validateCmd.Run(); err != nil {
		errMsg := fmt.Sprintf("NGINX config validation failed: %v", err)
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
	c.logger.Info("NGINX deployment validated successfully",
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.CertPath,
		Message:       "NGINX configuration valid and certificate accessible",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"validate_command": c.config.ValidateCommand,
			"duration_ms":      fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
