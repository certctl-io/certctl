package caddy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
	"github.com/shankar0123/certctl/internal/deploy"
)

// Config represents the Caddy deployment target configuration.
// Caddy supports both API-based and file-based certificate deployment.
// In API mode, certificates are posted to the Caddy admin API.
// In file mode, certificates are written to a directory and Caddy reloads.
type Config struct {
	AdminAPI string `json:"admin_api"` // Caddy admin API URL (e.g., http://localhost:2019, default: http://localhost:2019)
	CertDir  string `json:"cert_dir"`  // Directory for file-based deployment (used if API fails or mode=file)
	CertFile string `json:"cert_file"` // Filename for certificate in file mode (default: cert.pem)
	KeyFile  string `json:"key_file"`  // Filename for private key in file mode (default: key.pem)
	Mode     string `json:"mode"`      // Deployment mode: "api" (default) or "file"
}

// Connector implements the target.Connector interface for Caddy servers.
// This connector runs on the AGENT side and handles local certificate deployment.
// It supports both API-based hot reload and file-based deployment.
type Connector struct {
	config *Config
	logger *slog.Logger
	client *http.Client
}

// New creates a new Caddy target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// ValidateConfig checks that the Caddy configuration is valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Caddy config: %w", err)
	}

	// Set defaults
	if cfg.AdminAPI == "" {
		cfg.AdminAPI = "http://localhost:2019"
	}
	if cfg.Mode == "" {
		cfg.Mode = "api"
	}
	if cfg.CertFile == "" {
		cfg.CertFile = "cert.pem"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "key.pem"
	}

	// Validate mode
	if cfg.Mode != "api" && cfg.Mode != "file" {
		return fmt.Errorf("Caddy mode must be 'api' or 'file', got: %s", cfg.Mode)
	}

	c.logger.Info("validating Caddy configuration",
		"admin_api", cfg.AdminAPI,
		"mode", cfg.Mode)

	// For file mode, verify directory exists
	if cfg.Mode == "file" {
		if cfg.CertDir == "" {
			return fmt.Errorf("Caddy cert_dir is required in file mode")
		}
		if _, err := os.Stat(cfg.CertDir); os.IsNotExist(err) {
			return fmt.Errorf("Caddy cert directory does not exist: %s", cfg.CertDir)
		}
		// Test write access
		testFile := filepath.Join(cfg.CertDir, ".certctl-write-test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("Caddy cert directory is not writable: %s (%w)", cfg.CertDir, err)
		}
		os.Remove(testFile)
	}

	c.config = &cfg
	c.logger.Info("Caddy configuration validated")
	return nil
}

// DeployCertificate deploys a certificate to Caddy using the configured mode.
// In API mode, it posts the certificate to Caddy's admin API.
// In file mode, it writes the certificate files and relies on Caddy's file watcher.
//
// Steps:
// 1. If mode="api": POST to Caddy admin API endpoint with certificate data
// 2. If mode="file" or API fails: Write certificate and key files to cert_dir
// 3. Log deployment status
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Caddy",
		"mode", c.config.Mode,
		"admin_api", c.config.AdminAPI)

	startTime := time.Now()

	// Try API mode if configured
	if c.config.Mode == "api" {
		result, err := c.deployViaAPI(ctx, request, startTime)
		if err == nil {
			c.logger.Info("certificate deployed to Caddy via API",
				"duration", time.Since(startTime).String())
			return result, nil
		}
		c.logger.Warn("API deployment failed, falling back to file mode", "error", err)
	}

	// Fall back to file mode
	return c.deployViaFile(ctx, request, startTime)
}

// deployViaAPI deploys a certificate using Caddy's admin API.
//
// Bundle 9 of the 2026-05-02 deployment-target audit:
//   - Fix 1: duration_ms metric uses the caller-passed startTime (was
//     time.Since(time.Now()) which always rounded to ~0ms).
//   - Fix 3: SHA-256 idempotency short-circuit — GET the current loaded
//     certs and compare to the deploy payload's cert bytes; skip the POST
//     when they match. Conservative: any GET failure (network, non-200,
//     parse error, hash mismatch) falls through to today's POST behavior.
func (c *Connector) deployViaAPI(ctx context.Context, request target.DeploymentRequest, startTime time.Time) (*target.DeploymentResult, error) {
	c.logger.Debug("attempting API deployment", "url", c.config.AdminAPI)

	// Build the certificate payload with combined cert and chain
	certData := request.CertPEM + "\n"
	if request.ChainPEM != "" {
		certData += request.ChainPEM + "\n"
	}

	apiURL := c.config.AdminAPI + "/config/apps/tls/certificates/load"

	// Bundle 9 Fix 3: idempotency short-circuit. GET the current loaded
	// certs and SHA-256 compare to the deploy payload — if they match,
	// skip the POST and return success with metadata.idempotent=true.
	// Caddy's response shape varies between operators / config versions;
	// handle BOTH the array-of-objects and single-object shapes. Any
	// failure during the GET (network, non-200, JSON parse error, hash
	// mismatch) silently falls through to the POST below — false
	// negatives are safe; false positives are dangerous.
	deployHash := sha256.Sum256([]byte(certData))
	if c.idempotencySkipPOST(ctx, apiURL, deployHash) {
		c.logger.Debug("Caddy already has this certificate loaded; skipping POST",
			"admin_url", c.config.AdminAPI)
		return &target.DeploymentResult{
			Success:       true,
			TargetAddress: c.config.AdminAPI,
			DeploymentID:  fmt.Sprintf("caddy-api-idem-%d", time.Now().Unix()),
			Message:       "Caddy already has this certificate loaded (idempotent skip)",
			DeployedAt:    time.Now(),
			Metadata: map[string]string{
				"method":      "api",
				"admin_url":   c.config.AdminAPI,
				"idempotent":  "true",
				"duration_ms": fmt.Sprintf("%d", time.Since(startTime).Milliseconds()),
			},
		}, nil
	}

	payload := map[string]string{
		"cert": certData,
		"key":  request.KeyPEM,
	}

	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach Caddy API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("Caddy API returned status %d: %s", resp.StatusCode, string(body))
	}

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.AdminAPI,
		DeploymentID:  fmt.Sprintf("caddy-api-%d", time.Now().Unix()),
		Message:       "Certificate deployed via Caddy admin API",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"method":      "api",
			"admin_url":   c.config.AdminAPI,
			"duration_ms": fmt.Sprintf("%d", time.Since(startTime).Milliseconds()),
		},
	}, nil
}

// idempotencySkipPOST returns true iff GET-ing the Caddy admin API at the
// same path returns a cert whose SHA-256 matches the deploy payload's
// SHA-256. The function is best-effort: it returns false (= "fall through
// to the POST") on any error along the way (network, non-200, JSON parse,
// no matching entry, hash mismatch).
//
// Caddy's response shape can be either:
//   - a single object: {"cert": "...", "key": "..."}
//   - an array of objects: [{"cert": "...", "key": "..."}, ...]
//
// We try both shapes; the first that decodes AND has a matching hash wins.
//
// Bundle 9 Fix 3 of the 2026-05-02 deployment-target audit.
func (c *Connector) idempotencySkipPOST(ctx context.Context, apiURL string, deployHash [32]byte) bool {
	getReq, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false
	}
	getReq.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(getReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// Try array-of-objects shape first.
	var asArray []map[string]string
	if err := json.Unmarshal(body, &asArray); err == nil {
		for _, entry := range asArray {
			if entry["cert"] == "" {
				continue
			}
			if sha256.Sum256([]byte(entry["cert"])) == deployHash {
				return true
			}
		}
		return false
	}
	// Fall back to single-object shape.
	var asObject map[string]string
	if err := json.Unmarshal(body, &asObject); err == nil {
		if asObject["cert"] != "" && sha256.Sum256([]byte(asObject["cert"])) == deployHash {
			return true
		}
	}
	return false
}

// deployViaFile deploys a certificate by writing files to the cert directory.
func (c *Connector) deployViaFile(ctx context.Context, request target.DeploymentRequest, startTime time.Time) (*target.DeploymentResult, error) {
	c.logger.Debug("deploying via file mode", "cert_dir", c.config.CertDir)

	if c.config.CertDir == "" {
		return &target.DeploymentResult{
			Success:    false,
			Message:    "cert_dir required for file mode deployment",
			DeployedAt: time.Now(),
		}, fmt.Errorf("cert_dir not configured for file mode")
	}

	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

	// Write certificate with chain — Phase 7 (deploy-hardening I):
	// atomic-write via deploy.AtomicWriteFile so cert/key swap
	// atomically and have backup files for rollback (Caddy's file
	// watcher picks up the rename atomically, no torn config).
	certData := request.CertPEM + "\n"
	if request.ChainPEM != "" {
		certData += request.ChainPEM + "\n"
	}
	if _, err := deploy.AtomicWriteFile(ctx, certPath, []byte(certData), deploy.WriteOptions{
		Mode: 0644,
	}); err != nil {
		errMsg := fmt.Sprintf("failed to write certificate: %v", err)
		c.logger.Error("certificate deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: certPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Write private key — atomic + 0600 default.
	if request.KeyPEM != "" {
		if _, err := deploy.AtomicWriteFile(ctx, keyPath, []byte(request.KeyPEM), deploy.WriteOptions{
			Mode: 0600,
		}); err != nil {
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
	c.logger.Info("certificate deployed to Caddy via file mode",
		"duration", deploymentDuration.String(),
		"cert_path", certPath,
		"key_path", keyPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("caddy-file-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Caddy (file-based)",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"method":      "file",
			"cert_path":   certPath,
			"key_path":    keyPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate is valid and accessible.
// For API mode, it doesn't perform additional validation.
// For file mode, it checks that the certificate and key files exist and are readable.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Caddy deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial,
		"mode", c.config.Mode)

	startTime := time.Now()

	// For file mode, verify files exist AND the cert is valid PEM/x509.
	//
	// Bundle 9 Fix 2 of the 2026-05-02 deployment-target audit: pre-fix,
	// this branch checked file existence only (os.Stat). A cert file that
	// existed but contained malformed bytes passed validation; Caddy's
	// file-watcher silently failed to load it; operators saw "validation
	// green" + "TLS handshake fails" with no obvious connection. Post-fix,
	// the cert file is read and parsed via certutil.ParseCertificatePEM so
	// only files that Caddy can actually load pass validation.
	if c.config.Mode == "file" || c.config.CertDir != "" {
		certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
		keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

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

		// Bundle 9 Fix 2: PEM-parse the cert file. A malformed cert that
		// Caddy's watcher would silently reject must fail validation here
		// instead of bubbling up as a confusing "TLS handshake fails"
		// later.
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			errMsg := fmt.Sprintf("failed to read certificate file %s: %v", certPath, err)
			c.logger.Error("validation failed", "error", err)
			return &target.ValidationResult{
				Valid:         false,
				Serial:        request.Serial,
				TargetAddress: certPath,
				Message:       errMsg,
				ValidatedAt:   time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		if _, err := certutil.ParseCertificatePEM(string(certBytes)); err != nil {
			errMsg := fmt.Sprintf("certificate file %s is not valid PEM/x509: %v", certPath, err)
			c.logger.Error("validation failed", "error", err)
			return &target.ValidationResult{
				Valid:         false,
				Serial:        request.Serial,
				TargetAddress: certPath,
				Message:       errMsg,
				ValidatedAt:   time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("Caddy deployment validated successfully",
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.AdminAPI,
		Message:       "Caddy certificate deployment validated",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"mode":        c.config.Mode,
			"admin_api":   c.config.AdminAPI,
			"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}
