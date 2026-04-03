package envoy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Config represents the Envoy deployment target configuration.
// Envoy uses file-based certificate delivery — the agent writes cert/key files
// to a directory that Envoy watches via its SDS (Secret Discovery Service)
// file-based configuration or static filename references in the bootstrap config.
type Config struct {
	CertDir       string `json:"cert_dir"`        // Directory where Envoy watches for cert files (required)
	CertFilename  string `json:"cert_filename"`   // Filename for certificate (default: cert.pem)
	KeyFilename   string `json:"key_filename"`    // Filename for private key (default: key.pem)
	ChainFilename string `json:"chain_filename"`  // Optional filename for chain (if set, chain written separately)
	SDSConfig     bool   `json:"sds_config"`      // If true, write an SDS discovery JSON file for file-based SDS
}

// SDSResource represents an Envoy SDS tls_certificate resource for file-based SDS.
// This matches Envoy's expected format for file-based Secret Discovery Service.
type SDSResource struct {
	Resources []SDSTLSCertificate `json:"resources"`
}

// SDSTLSCertificate represents a single SDS tls_certificate entry.
type SDSTLSCertificate struct {
	Type            string         `json:"@type"`
	Name            string         `json:"name"`
	TLSCertificate  TLSCertificate `json:"tls_certificate"`
}

// TLSCertificate contains the file paths for cert and key in Envoy's SDS format.
type TLSCertificate struct {
	CertificateChain DataSource `json:"certificate_chain"`
	PrivateKey       DataSource `json:"private_key"`
}

// DataSource represents an Envoy data source pointing to a file path.
type DataSource struct {
	Filename string `json:"filename"`
}

// Connector implements the target.Connector interface for Envoy proxy servers.
// This connector runs on the AGENT side and handles local certificate deployment.
// Envoy watches the configured directory via its file-based SDS or static config
// and automatically picks up certificate changes without an explicit reload.
type Connector struct {
	config *Config
	logger *slog.Logger
}

// New creates a new Envoy target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
	}
}

// ValidateConfig checks that the certificate directory is configured and valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Envoy config: %w", err)
	}

	if cfg.CertDir == "" {
		return fmt.Errorf("Envoy cert_dir is required")
	}

	// Default filenames if not provided
	if cfg.CertFilename == "" {
		cfg.CertFilename = "cert.pem"
	}
	if cfg.KeyFilename == "" {
		cfg.KeyFilename = "key.pem"
	}

	// Validate filenames don't contain path separators (prevent path traversal)
	if strings.Contains(cfg.CertFilename, "/") || strings.Contains(cfg.CertFilename, "\\") {
		return fmt.Errorf("Envoy cert_filename must not contain path separators")
	}
	if strings.Contains(cfg.KeyFilename, "/") || strings.Contains(cfg.KeyFilename, "\\") {
		return fmt.Errorf("Envoy key_filename must not contain path separators")
	}
	if cfg.ChainFilename != "" && (strings.Contains(cfg.ChainFilename, "/") || strings.Contains(cfg.ChainFilename, "\\")) {
		return fmt.Errorf("Envoy chain_filename must not contain path separators")
	}

	c.logger.Info("validating Envoy configuration",
		"cert_dir", cfg.CertDir,
		"cert_filename", cfg.CertFilename,
		"key_filename", cfg.KeyFilename,
		"chain_filename", cfg.ChainFilename,
		"sds_config", cfg.SDSConfig)

	// Verify directory exists and is writable
	if _, err := os.Stat(cfg.CertDir); os.IsNotExist(err) {
		return fmt.Errorf("Envoy cert directory does not exist: %s", cfg.CertDir)
	}

	// Try to write a test file to verify directory is writable
	testFile := filepath.Join(cfg.CertDir, ".certctl-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("Envoy cert directory is not writable: %s (%w)", cfg.CertDir, err)
	}
	os.Remove(testFile)

	c.config = &cfg
	c.logger.Info("Envoy configuration validated")
	return nil
}

// DeployCertificate writes the certificate and key files to the configured directory.
// Envoy watches this directory via file-based SDS or static config references
// and automatically picks up changes without requiring a reload command.
//
// Steps:
// 1. Write certificate (+ chain if chain_filename not set) to cert_filename with mode 0644
// 2. Write private key to key_filename with mode 0600
// 3. If chain_filename set and chain provided, write chain separately with mode 0644
// 4. If sds_config is true, write SDS JSON file pointing to cert/key paths
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Envoy",
		"cert_dir", c.config.CertDir,
		"cert_filename", c.config.CertFilename,
		"key_filename", c.config.KeyFilename)

	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFilename)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFilename)

	// Build certificate data: if chain_filename is set, write chain separately;
	// otherwise append chain to cert file (standard fullchain behavior)
	certData := request.CertPEM + "\n"
	if request.ChainPEM != "" && c.config.ChainFilename == "" {
		certData += request.ChainPEM + "\n"
	}

	// Write certificate with mode 0644 (readable by Envoy process)
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

	// Write chain separately if chain_filename is configured
	if c.config.ChainFilename != "" && request.ChainPEM != "" {
		chainPath := filepath.Join(c.config.CertDir, c.config.ChainFilename)
		if err := os.WriteFile(chainPath, []byte(request.ChainPEM+"\n"), 0644); err != nil {
			errMsg := fmt.Sprintf("failed to write chain: %v", err)
			c.logger.Error("chain deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: chainPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Write SDS JSON file if configured
	if c.config.SDSConfig {
		if err := c.writeSDSConfig(); err != nil {
			errMsg := fmt.Sprintf("failed to write SDS config: %v", err)
			c.logger.Error("SDS config deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: certPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to Envoy successfully",
		"duration", deploymentDuration.String(),
		"cert_path", certPath,
		"key_path", keyPath,
		"sds_config", c.config.SDSConfig)

	metadata := map[string]string{
		"cert_path":   certPath,
		"key_path":    keyPath,
		"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
	}
	if c.config.SDSConfig {
		metadata["sds_config_path"] = filepath.Join(c.config.CertDir, "sds.json")
	}

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("envoy-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Envoy (file-based SDS will auto-reload)",
		DeployedAt:    time.Now(),
		Metadata:      metadata,
	}, nil
}

// writeSDSConfig writes an Envoy SDS JSON file that references the cert/key file paths.
// This file is consumed by Envoy's file-based SDS provider (path_config_source).
func (c *Connector) writeSDSConfig() error {
	certPath := filepath.Join(c.config.CertDir, c.config.CertFilename)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFilename)

	sdsResource := SDSResource{
		Resources: []SDSTLSCertificate{
			{
				Type: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
				Name: "server_cert",
				TLSCertificate: TLSCertificate{
					CertificateChain: DataSource{Filename: certPath},
					PrivateKey:       DataSource{Filename: keyPath},
				},
			},
		},
	}

	sdsJSON, err := json.MarshalIndent(sdsResource, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SDS config: %w", err)
	}

	sdsPath := filepath.Join(c.config.CertDir, "sds.json")
	if err := os.WriteFile(sdsPath, sdsJSON, 0644); err != nil {
		return fmt.Errorf("failed to write SDS config file: %w", err)
	}

	c.logger.Info("SDS config file written", "path", sdsPath)
	return nil
}

// ValidateDeployment verifies that the deployed certificate files are readable.
// It checks that both the certificate and key files exist and are accessible.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Envoy deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFilename)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFilename)

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
	c.logger.Info("Envoy deployment validated successfully",
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
