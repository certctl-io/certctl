package postfix

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

// Config represents the Postfix/Dovecot deployment target configuration.
// This connector supports dual-mode operation: "postfix" for Postfix MTA
// and "dovecot" for Dovecot IMAP/POP3. The mode determines default file
// paths and reload commands. Both modes write cert/key/chain files and
// reload the mail service.
type Config struct {
	Mode            string `json:"mode"`              // "postfix" (default) or "dovecot"
	CertPath        string `json:"cert_path"`         // Path where cert will be written
	KeyPath         string `json:"key_path"`           // Path where private key will be written
	ChainPath       string `json:"chain_path"`         // Path where CA chain will be written (optional — if empty, chain appended to cert)
	ReloadCommand   string `json:"reload_command"`     // Command to reload service
	ValidateCommand string `json:"validate_command"`   // Optional command to validate config before reload
}

// Connector implements the target.Connector interface for Postfix and Dovecot
// mail servers. This connector runs on the AGENT side and handles local
// certificate deployment for mail server TLS (STARTTLS, SMTPS, IMAPS, POP3S).
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new Postfix/Dovecot target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// applyDefaults sets mode-specific default values for any unconfigured fields.
func applyDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = "postfix"
	}

	switch cfg.Mode {
	case "dovecot":
		if cfg.CertPath == "" {
			cfg.CertPath = "/etc/dovecot/certs/cert.pem"
		}
		if cfg.KeyPath == "" {
			cfg.KeyPath = "/etc/dovecot/certs/key.pem"
		}
		if cfg.ReloadCommand == "" {
			cfg.ReloadCommand = "doveadm reload"
		}
		if cfg.ValidateCommand == "" {
			cfg.ValidateCommand = "doveconf -n"
		}
	default: // "postfix"
		if cfg.CertPath == "" {
			cfg.CertPath = "/etc/postfix/certs/cert.pem"
		}
		if cfg.KeyPath == "" {
			cfg.KeyPath = "/etc/postfix/certs/key.pem"
		}
		if cfg.ReloadCommand == "" {
			cfg.ReloadCommand = "postfix reload"
		}
		if cfg.ValidateCommand == "" {
			cfg.ValidateCommand = "postfix check"
		}
	}
}

// ValidateConfig checks that the configuration is valid for the selected mode.
// It applies mode-specific defaults, validates shell commands against injection,
// and verifies the certificate directory exists.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid mail server config: %w", err)
	}

	// Validate mode
	if cfg.Mode != "" && cfg.Mode != "postfix" && cfg.Mode != "dovecot" {
		return fmt.Errorf("invalid mode %q: must be \"postfix\" or \"dovecot\"", cfg.Mode)
	}

	// Apply mode-specific defaults
	applyDefaults(&cfg)

	// Validate commands to prevent injection attacks
	if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("invalid reload_command: %w", err)
	}
	if cfg.ValidateCommand != "" {
		if err := validation.ValidateShellCommand(cfg.ValidateCommand); err != nil {
			return fmt.Errorf("invalid validate_command: %w", err)
		}
	}

	c.logger.Info("validating mail server configuration",
		"mode", cfg.Mode,
		"cert_path", cfg.CertPath,
		"key_path", cfg.KeyPath,
		"chain_path", cfg.ChainPath)

	// Verify certificate directory exists
	certDir := filepath.Dir(cfg.CertPath)
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("%s cert directory does not exist: %s", cfg.Mode, certDir)
	}

	// Verify validate command works (best-effort — service might not be installed yet)
	if cfg.ValidateCommand != "" {
		cmd := exec.CommandContext(ctx, "sh", "-c", cfg.ValidateCommand)
		if err := cmd.Run(); err != nil {
			c.logger.Warn("config validation command failed during config check",
				"error", err,
				"mode", cfg.Mode,
				"validate_command", cfg.ValidateCommand)
		}
	}

	c.config = &cfg
	c.logger.Info("mail server configuration validated", "mode", cfg.Mode)
	return nil
}

// DeployCertificate writes the certificate, key, and chain to the configured paths
// and reloads the mail service to pick up the new certificates.
//
// Steps:
// 1. Write certificate to cert_path with mode 0644 (if chain_path empty, append chain)
// 2. Write private key to key_path with mode 0600
// 3. If chain_path is set, write chain separately with mode 0644
// 4. Validate configuration (if validate_command is set)
// 5. Reload service
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to mail server",
		"mode", c.config.Mode,
		"cert_path", c.config.CertPath,
		"key_path", c.config.KeyPath)

	startTime := time.Now()

	// Build certificate data: if chain_path is set, write chain separately;
	// otherwise append chain to cert file (fullchain behavior)
	certData := request.CertPEM
	if request.ChainPEM != "" && c.config.ChainPath == "" {
		certData += "\n" + request.ChainPEM
	}

	// Write certificate with mode 0644 (rw-r--r--)
	if err := os.WriteFile(c.config.CertPath, []byte(certData), 0644); err != nil {
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
		c.logger.Info("private key written", "key_path", c.config.KeyPath)
	}

	// Write chain separately if chain_path is configured
	if c.config.ChainPath != "" && request.ChainPEM != "" {
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

	// Validate configuration before reload
	if c.config.ValidateCommand != "" {
		c.logger.Debug("validating configuration", "validate_command", c.config.ValidateCommand)
		validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
		if output, err := validateCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("%s config validation failed: %v (output: %s)", c.config.Mode, err, string(output))
			c.logger.Error("config validation failed", "error", err, "output", string(output))
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: c.config.CertPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Reload service
	c.logger.Debug("reloading service", "reload_command", c.config.ReloadCommand)
	reloadCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ReloadCommand)
	if output, err := reloadCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("%s reload failed: %v (output: %s)", c.config.Mode, err, string(output))
		c.logger.Error("service reload failed", "error", err, "output", string(output))
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to mail server successfully",
		"mode", c.config.Mode,
		"duration", deploymentDuration.String(),
		"cert_path", c.config.CertPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.CertPath,
		DeploymentID:  fmt.Sprintf("%s-%d", c.config.Mode, time.Now().Unix()),
		Message:       fmt.Sprintf("Certificate deployed and %s reloaded successfully", c.config.Mode),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path":   c.config.CertPath,
			"key_path":    c.config.KeyPath,
			"mode":        c.config.Mode,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate is valid and accessible.
// It runs the validate command (if configured) and checks that the cert file exists.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating mail server deployment",
		"mode", c.config.Mode,
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	// Validate configuration if validate command is set
	if c.config.ValidateCommand != "" {
		validateCmd := exec.CommandContext(ctx, "sh", "-c", c.config.ValidateCommand)
		if output, err := validateCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("%s config validation failed: %v (output: %s)", c.config.Mode, err, string(output))
			c.logger.Error("validation failed", "error", err)
			return &target.ValidationResult{
				Valid:         false,
				Serial:        request.Serial,
				TargetAddress: c.config.CertPath,
				Message:       errMsg,
				ValidatedAt:   time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
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
	c.logger.Info("mail server deployment validated successfully",
		"mode", c.config.Mode,
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.CertPath,
		Message:       fmt.Sprintf("%s configuration valid and certificate accessible", c.config.Mode),
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"mode":             c.config.Mode,
			"validate_command": c.config.ValidateCommand,
			"duration_ms":      fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
