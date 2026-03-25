package haproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Config represents the HAProxy deployment target configuration.
// HAProxy expects a combined PEM file containing the certificate, chain, and private key
// concatenated in a single file.
type Config struct {
	PEMPath         string `json:"pem_path"`          // Path for combined PEM (cert + chain + key)
	ReloadCommand   string `json:"reload_command"`     // Command to reload HAProxy (e.g., "systemctl reload haproxy")
	ValidateCommand string `json:"validate_command"`   // Command to validate config (e.g., "haproxy -c -f /etc/haproxy/haproxy.cfg")
}

// Connector implements the target.Connector interface for HAProxy servers.
// This connector runs on the AGENT side and handles local certificate deployment.
// HAProxy uses a combined PEM file (cert + chain + key) unlike NGINX/Apache which use
// separate files.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new HAProxy target connector with the given configuration and logger.
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
		return fmt.Errorf("invalid HAProxy config: %w", err)
	}

	if cfg.PEMPath == "" {
		return fmt.Errorf("HAProxy pem_path is required")
	}

	if cfg.ReloadCommand == "" {
		return fmt.Errorf("HAProxy reload_command is required")
	}

	c.logger.Info("validating HAProxy configuration",
		"pem_path", cfg.PEMPath)

	// Verify validate command works if provided
	if cfg.ValidateCommand != "" {
		cmd := exec.CommandContext(ctx, "sh", "-c", cfg.ValidateCommand)
		if err := cmd.Run(); err != nil {
			c.logger.Warn("HAProxy config validation failed during config check",
				"error", err,
				"validate_command", cfg.ValidateCommand)
			// Don't fail; HAProxy might not be installed yet
		}
	}

	c.config = &cfg
	c.logger.Info("HAProxy configuration validated")
	return nil
}

// DeployCertificate creates a combined PEM file (cert + chain + key) and reloads HAProxy.
//
// HAProxy requires all TLS material in a single file, concatenated in this order:
// 1. Server certificate
// 2. Intermediate/chain certificates
// 3. Private key
//
// Steps:
// 1. Build combined PEM (cert + chain + key)
// 2. Write to pem_path with mode 0600 (contains private key)
// 3. Optionally validate HAProxy configuration
// 4. Execute reload command
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to HAProxy",
		"pem_path", c.config.PEMPath)

	startTime := time.Now()

	// Build combined PEM: cert + chain + key
	combinedPEM := request.CertPEM + "\n"
	if request.ChainPEM != "" {
		combinedPEM += request.ChainPEM + "\n"
	}
	if request.KeyPEM != "" {
		combinedPEM += request.KeyPEM + "\n"
	}

	// Write combined PEM with secure permissions (0600: contains private key)
	if err := os.WriteFile(c.config.PEMPath, []byte(combinedPEM), 0600); err != nil {
		errMsg := fmt.Sprintf("failed to write combined PEM: %v", err)
		c.logger.Error("PEM deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.PEMPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Validate HAProxy configuration if validate command is configured
	if c.config.ValidateCommand != "" {
		c.logger.Debug("validating HAProxy configuration", "validate_command", c.config.ValidateCommand)
		validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
		if output, err := validateCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("HAProxy config validation failed: %v (output: %s)", err, string(output))
			c.logger.Error("HAProxy validation failed", "error", err, "output", string(output))
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: c.config.PEMPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Reload HAProxy
	c.logger.Debug("reloading HAProxy", "reload_command", c.config.ReloadCommand)
	reloadCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ReloadCommand)
	if output, err := reloadCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("HAProxy reload failed: %v (output: %s)", err, string(output))
		c.logger.Error("HAProxy reload failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.PEMPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to HAProxy successfully",
		"duration", deploymentDuration.String(),
		"pem_path", c.config.PEMPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.PEMPath,
		DeploymentID:  fmt.Sprintf("haproxy-%d", time.Now().Unix()),
		Message:       "Combined PEM deployed and HAProxy reloaded successfully",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"pem_path":    c.config.PEMPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate is valid and accessible.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating HAProxy deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	// Validate HAProxy configuration if command provided
	if c.config.ValidateCommand != "" {
		validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
		if output, err := validateCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("HAProxy config validation failed: %v (output: %s)", err, string(output))
			c.logger.Error("validation failed", "error", err)
			return &target.ValidationResult{
				Valid:         false,
				Serial:        request.Serial,
				TargetAddress: c.config.PEMPath,
				Message:       errMsg,
				ValidatedAt:   time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Verify combined PEM file exists and is readable
	if _, err := os.Stat(c.config.PEMPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("combined PEM file not found: %s", c.config.PEMPath)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.PEMPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("HAProxy deployment validated successfully",
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.PEMPath,
		Message:       "HAProxy configuration valid and PEM accessible",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"pem_path":    c.config.PEMPath,
			"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
