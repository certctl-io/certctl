// Package javakeystore implements a target connector for deploying certificates
// to Java KeyStores (JKS/PKCS#12) via the keytool CLI. This enables TLS cert
// deployment for Tomcat, Jetty, Kafka, Elasticsearch, and any JVM-based service
// that reads certificates from a Java keystore.
//
// Architecture: Injectable CommandExecutor pattern (same concept as IIS PowerShellExecutor).
// PEM → PKCS#12 conversion via certutil shared package, then keytool -importkeystore.
// Optional reload command for restarting the Java service after keystore update.
package javakeystore

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
	"github.com/shankar0123/certctl/internal/validation"
)

// Config represents the Java Keystore deployment target configuration.
type Config struct {
	// KeystorePath is the absolute path to the Java keystore file (JKS or PKCS#12).
	KeystorePath string `json:"keystore_path"`

	// KeystorePassword is the password protecting the keystore.
	KeystorePassword string `json:"keystore_password"`

	// KeystoreType is the keystore format: "PKCS12" (default) or "JKS".
	KeystoreType string `json:"keystore_type"`

	// Alias is the key entry alias in the keystore (default: "server").
	Alias string `json:"alias"`

	// ReloadCommand is an optional command to run after updating the keystore
	// (e.g., "systemctl restart tomcat"). Validated against shell injection.
	ReloadCommand string `json:"reload_command,omitempty"`

	// CreateKeystore creates the keystore if it doesn't exist (default: true).
	CreateKeystore bool `json:"create_keystore"`

	// KeytoolPath overrides the default keytool binary path.
	// Default: "keytool" (found via PATH).
	KeytoolPath string `json:"keytool_path,omitempty"`
}

// CommandExecutor abstracts command execution for testability.
type CommandExecutor interface {
	Execute(ctx context.Context, name string, args ...string) (string, error)
}

// realExecutor calls commands on the local system.
type realExecutor struct{}

func (e *realExecutor) Execute(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Connector implements the target.Connector interface for Java Keystore.
type Connector struct {
	config   *Config
	logger   *slog.Logger
	executor CommandExecutor
}

// validAlias matches safe keystore alias names (alphanumeric, hyphens, underscores, dots).
var validAlias = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// validKeystoreTypes defines allowed keystore type values.
var validKeystoreTypes = map[string]bool{
	"PKCS12": true,
	"JKS":    true,
}

// New creates a new Java Keystore connector with the default command executor.
func New(cfg *Config, logger *slog.Logger) *Connector {
	if cfg == nil {
		cfg = &Config{}
	}
	applyDefaults(cfg)
	return &Connector{
		config:   cfg,
		logger:   logger,
		executor: &realExecutor{},
	}
}

// NewWithExecutor creates a connector with an injected executor for testing.
func NewWithExecutor(cfg *Config, logger *slog.Logger, executor CommandExecutor) *Connector {
	if cfg == nil {
		cfg = &Config{}
	}
	applyDefaults(cfg)
	return &Connector{
		config:   cfg,
		logger:   logger,
		executor: executor,
	}
}

func applyDefaults(cfg *Config) {
	if cfg.KeystoreType == "" {
		cfg.KeystoreType = "PKCS12"
	}
	if cfg.Alias == "" {
		cfg.Alias = "server"
	}
	if cfg.KeytoolPath == "" {
		cfg.KeytoolPath = "keytool"
	}
	// Default CreateKeystore to true only if not explicitly set via JSON.
	// Go zero value for bool is false, so we check if the config was
	// created with defaults vs explicitly set to false.
}

// ValidateConfig validates the Java Keystore configuration.
func (c *Connector) ValidateConfig(ctx context.Context, config json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("invalid JavaKeystore config JSON: %w", err)
	}
	applyDefaults(&cfg)

	if cfg.KeystorePath == "" {
		return fmt.Errorf("keystore_path is required")
	}

	// Path traversal check — detect ".." in the raw path before Clean resolves it
	if strings.Contains(cfg.KeystorePath, "..") {
		return fmt.Errorf("keystore_path must not contain path traversal (..) sequences")
	}

	if cfg.KeystorePassword == "" {
		return fmt.Errorf("keystore_password is required")
	}

	if !validKeystoreTypes[cfg.KeystoreType] {
		return fmt.Errorf("invalid keystore_type: must be 'PKCS12' or 'JKS' (got %q)", cfg.KeystoreType)
	}

	if !validAlias.MatchString(cfg.Alias) {
		return fmt.Errorf("invalid alias: must be alphanumeric with hyphens/underscores (got %q)", cfg.Alias)
	}

	if cfg.ReloadCommand != "" {
		if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
			return fmt.Errorf("invalid reload_command: %w", err)
		}
	}

	// Verify parent directory exists for keystore path
	dir := filepath.Dir(cfg.KeystorePath)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("keystore directory does not exist: %s", dir)
	}

	c.config = &cfg
	return nil
}

// DeployCertificate imports a certificate and key into the Java Keystore.
// Flow: PEM → PKCS#12 temp file → keytool -importkeystore → cleanup temp → optional reload
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if request.KeyPEM == "" {
		return nil, fmt.Errorf("private key is required for Java Keystore import")
	}

	c.logger.Info("deploying certificate to Java Keystore",
		"keystore", c.config.KeystorePath,
		"alias", c.config.Alias,
		"type", c.config.KeystoreType)

	// Step 1: Convert PEM to temporary PKCS#12 file
	pfxPassword, err := certutil.GenerateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate temp PFX password: %w", err)
	}

	pfxData, err := certutil.CreatePFX(request.CertPEM, request.KeyPEM, request.ChainPEM, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("create temp PFX: %w", err)
	}

	// Write PFX to temp file
	tmpFile, err := os.CreateTemp("", "certctl-jks-*.p12")
	if err != nil {
		return nil, fmt.Errorf("create temp PFX file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(pfxData); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp PFX file: %w", err)
	}
	tmpFile.Close()

	// Step 2: Delete existing alias if keystore exists (keytool -delete)
	if _, err := os.Stat(c.config.KeystorePath); err == nil {
		deleteArgs := []string{
			"-delete",
			"-alias", c.config.Alias,
			"-keystore", c.config.KeystorePath,
			"-storepass", c.config.KeystorePassword,
			"-storetype", c.config.KeystoreType,
			"-noprompt",
		}
		// Ignore error — alias may not exist yet
		c.executor.Execute(ctx, c.config.KeytoolPath, deleteArgs...)
	}

	// Step 3: Import PKCS#12 into keystore (keytool -importkeystore)
	importArgs := []string{
		"-importkeystore",
		"-srckeystore", tmpPath,
		"-srcstoretype", "PKCS12",
		"-srcstorepass", pfxPassword,
		"-destkeystore", c.config.KeystorePath,
		"-deststoretype", c.config.KeystoreType,
		"-deststorepass", c.config.KeystorePassword,
		"-destalias", c.config.Alias,
		"-srcalias", "1", // go-pkcs12 uses alias "1" by default
		"-noprompt",
	}

	output, err := c.executor.Execute(ctx, c.config.KeytoolPath, importArgs...)
	if err != nil {
		return nil, fmt.Errorf("keytool import failed: %s: %w", output, err)
	}

	// Step 4: Compute thumbprint for verification
	thumbprint, err := certutil.ComputeThumbprint(request.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}

	// Step 5: Optional reload command
	if c.config.ReloadCommand != "" {
		output, err := c.executor.Execute(ctx, "sh", "-c", c.config.ReloadCommand)
		if err != nil {
			c.logger.Warn("reload command failed (non-fatal)", "error", err, "output", output)
		}
	}

	c.logger.Info("certificate imported to Java Keystore",
		"keystore", c.config.KeystorePath,
		"alias", c.config.Alias,
		"thumbprint", thumbprint)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.KeystorePath,
		DeploymentID:  thumbprint,
		Message:       fmt.Sprintf("Certificate imported to %s (alias: %s, thumbprint: %s)", c.config.KeystorePath, c.config.Alias, thumbprint),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"thumbprint":    thumbprint,
			"alias":         c.config.Alias,
			"keystore_type": c.config.KeystoreType,
			"keystore_path": c.config.KeystorePath,
		},
	}, nil
}

// ValidateDeployment verifies that a certificate exists in the Java Keystore
// by running keytool -list and checking the alias.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	listArgs := []string{
		"-list",
		"-alias", c.config.Alias,
		"-keystore", c.config.KeystorePath,
		"-storepass", c.config.KeystorePassword,
		"-storetype", c.config.KeystoreType,
		"-v",
	}

	output, err := c.executor.Execute(ctx, c.config.KeytoolPath, listArgs...)
	if err != nil {
		return &target.ValidationResult{
			Valid:       false,
			Serial:      request.Serial,
			Message:     fmt.Sprintf("keytool list failed: %s", output),
			ValidatedAt: time.Now(),
		}, fmt.Errorf("keytool list failed: %w", err)
	}

	// Check if the alias exists in the output
	if !strings.Contains(output, c.config.Alias) {
		return &target.ValidationResult{
			Valid:       false,
			Serial:      request.Serial,
			Message:     fmt.Sprintf("alias %q not found in keystore", c.config.Alias),
			ValidatedAt: time.Now(),
		}, fmt.Errorf("alias %q not found in keystore %s", c.config.Alias, c.config.KeystorePath)
	}

	// Try to extract serial from keytool output for comparison
	serialFound := false
	if request.Serial != "" {
		normalizedSerial := strings.ReplaceAll(strings.ToUpper(request.Serial), ":", "")
		serialFound = strings.Contains(strings.ToUpper(output), normalizedSerial)
	}

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.KeystorePath,
		Message:       fmt.Sprintf("Certificate found in keystore (alias: %s, serial_match: %v)", c.config.Alias, serialFound),
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"alias":        c.config.Alias,
			"serial_match": fmt.Sprintf("%v", serialFound),
		},
	}, nil
}

// Ensure Connector implements target.Connector.
var _ target.Connector = (*Connector)(nil)
