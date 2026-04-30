// Package apache implements the Apache httpd target connector.
// As of the deploy-hardening I master bundle Phase 5, Apache
// follows the canonical pattern established by NGINX (Phase 4):
// atomic-write all files via internal/deploy.Apply, run
// `apachectl configtest` as PreCommit, run `apachectl graceful` as
// PostCommit, post-deploy TLS handshake to verify the new cert is
// being served, rollback on any failure.
//
// Apache-specific quirks codified here:
//
//   - Validate command is `apachectl configtest` (NOT `apachectl -t`
//     — that flag exists but the operator-facing convention is
//     configtest).
//   - Reload command is `apachectl graceful` for zero-downtime
//     reload (NOT `apachectl restart` which drops in-flight TLS
//     sessions).
//   - Separate cert / chain / key files (vs HAProxy's combined
//     PEM blob).
package apache

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
	"github.com/shankar0123/certctl/internal/validation"
)

// Config represents the Apache httpd deployment target
// configuration. Phase 5 (deploy-hardening I) added the
// CertFileMode/KeyFileMode/...-Owner/-Group overrides + the
// PostDeployVerify config + BackupRetention. Pre-existing fields
// (CertPath/KeyPath/ChainPath/ReloadCommand/ValidateCommand)
// preserved for back-compat.
type Config struct {
	CertPath        string `json:"cert_path"`
	KeyPath         string `json:"key_path,omitempty"`
	ChainPath       string `json:"chain_path,omitempty"`
	ReloadCommand   string `json:"reload_command"`
	ValidateCommand string `json:"validate_command"`

	// Phase 5: file ownership + mode overrides.
	CertFileMode   os.FileMode `json:"cert_file_mode,omitempty"`
	ChainFileMode  os.FileMode `json:"chain_file_mode,omitempty"`
	KeyFileMode    os.FileMode `json:"key_file_mode,omitempty"`
	CertFileOwner  string      `json:"cert_file_owner,omitempty"`
	CertFileGroup  string      `json:"cert_file_group,omitempty"`
	ChainFileOwner string      `json:"chain_file_owner,omitempty"`
	ChainFileGroup string      `json:"chain_file_group,omitempty"`
	KeyFileOwner   string      `json:"key_file_owner,omitempty"`
	KeyFileGroup   string      `json:"key_file_group,omitempty"`

	// Phase 5: post-deploy TLS verification (frozen-decision-0.3
	// default ON).
	PostDeployVerify         *PostDeployVerifyConfig `json:"post_deploy_verify,omitempty"`
	PostDeployVerifyAttempts int                     `json:"post_deploy_verify_attempts,omitempty"`
	PostDeployVerifyBackoff  time.Duration           `json:"post_deploy_verify_backoff,omitempty"`

	// Phase 5: backup retention (default 3, -1 to disable).
	BackupRetention int `json:"backup_retention,omitempty"`
}

// PostDeployVerifyConfig matches the NGINX shape for cross-
// connector consistency.
type PostDeployVerifyConfig struct {
	Enabled  bool          `json:"enabled"`
	Endpoint string        `json:"endpoint,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// Connector implements the target.Connector interface for Apache
// httpd. Test seams (runValidate / runReload / probe) mirror NGINX.
type Connector struct {
	config *Config
	logger *slog.Logger

	runValidate func(ctx context.Context, command string) ([]byte, error)
	runReload   func(ctx context.Context, command string) ([]byte, error)
	probe       func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult
}

// New constructs an Apache connector with default test seams
// pointing to the production exec / tlsprobe paths.
func New(config *Config, logger *slog.Logger) *Connector {
	c := &Connector{config: config, logger: logger}
	c.runValidate = defaultRunCommand
	c.runReload = defaultRunCommand
	c.probe = tlsprobe.ProbeTLS
	return c
}

func defaultRunCommand(ctx context.Context, command string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	return cmd.CombinedOutput()
}

// SetTestRunValidate / SetTestRunReload / SetTestProbe — test-only
// hooks mirroring nginx package; allow tests to skip exec without
// `apachectl` on PATH.
func (c *Connector) SetTestRunValidate(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runValidate = fn
}
func (c *Connector) SetTestRunReload(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runReload = fn
}
func (c *Connector) SetTestProbe(fn func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult) {
	c.probe = fn
}

// ValidateConfig — preserved verbatim from pre-Phase-5 implementation.
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
	if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("invalid reload_command: %w", err)
	}
	if err := validation.ValidateShellCommand(cfg.ValidateCommand); err != nil {
		return fmt.Errorf("invalid validate_command: %w", err)
	}
	c.logger.Info("validating Apache configuration",
		"cert_path", cfg.CertPath,
		"chain_path", cfg.ChainPath)
	certDir := filepath.Dir(cfg.CertPath)
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("Apache cert directory does not exist: %s", certDir)
	}
	c.config = &cfg
	c.logger.Info("Apache configuration validated")
	return nil
}

// DeployCertificate — Phase 5 atomic + verify + rollback. Mirrors
// the NGINX template; differences are operator-facing command
// names (`apachectl configtest`, `apachectl graceful`).
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Apache httpd",
		"cert_path", c.config.CertPath,
		"chain_path", c.config.ChainPath)
	startTime := time.Now()

	plan := c.buildPlan(request)
	plan.PreCommit = func(pcCtx context.Context, _ map[string]string) error {
		out, err := c.runValidate(pcCtx, c.config.ValidateCommand)
		if err != nil {
			return fmt.Errorf("apachectl configtest failed: %w (output: %s)", err, string(out))
		}
		return nil
	}
	plan.PostCommit = func(pcCtx context.Context) error {
		out, err := c.runReload(pcCtx, c.config.ReloadCommand)
		if err != nil {
			return fmt.Errorf("apachectl graceful failed: %w (output: %s)", err, string(out))
		}
		return nil
	}

	res, err := deploy.Apply(ctx, plan)
	if err != nil {
		return c.failureResult(c.config.CertPath, "deploy.Apply", err, startTime), err
	}

	if !res.SkippedAsIdempotent {
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back",
				"error", vErr, "cert_path", c.config.CertPath)
			rbErr := c.rollbackToBackups(ctx, res.BackupPaths)
			if rbErr != nil {
				return c.failureResult(c.config.CertPath, "verify+rollback both failed",
					fmt.Errorf("verify: %w; rollback: %v", vErr, rbErr), startTime), rbErr
			}
			return c.failureResult(c.config.CertPath, "post-deploy verify failed; rolled back", vErr, startTime), vErr
		}
	}

	dur := time.Since(startTime)
	idemNote := ""
	if res.SkippedAsIdempotent {
		idemNote = " (idempotent skip — bytes unchanged)"
	}
	c.logger.Info("certificate deployed to Apache successfully",
		"duration", dur.String(), "cert_path", c.config.CertPath, "idempotent", res.SkippedAsIdempotent)
	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.CertPath,
		DeploymentID:  fmt.Sprintf("apache-%d", time.Now().Unix()),
		Message:       "Certificate deployed and Apache reloaded successfully" + idemNote,
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path":   c.config.CertPath,
			"chain_path":  c.config.ChainPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
			"idempotent":  fmt.Sprintf("%t", res.SkippedAsIdempotent),
		},
	}, nil
}

// ValidateOnly — Phase 5 real impl replacing the stub.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.config == nil || c.config.ValidateCommand == "" {
		return target.ErrValidateOnlyNotSupported
	}
	out, err := c.runValidate(ctx, c.config.ValidateCommand)
	if err != nil {
		return fmt.Errorf("apachectl configtest (ValidateOnly): %w (output: %s)", err, string(out))
	}
	return nil
}

// buildPlan — Apache assembles the same cert+chain+key Plan shape
// as NGINX. Defaults follow Apache's distro conventions:
// Debian/Ubuntu apache2 user, RHEL/CentOS apache user.
func (c *Connector) buildPlan(request target.DeploymentRequest) deploy.Plan {
	files := []deploy.File{{
		Path:  c.config.CertPath,
		Bytes: []byte(request.CertPEM),
		Mode:  c.config.CertFileMode,
		Owner: c.config.CertFileOwner,
		Group: c.config.CertFileGroup,
	}}
	if c.config.ChainPath != "" && request.ChainPEM != "" {
		files = append(files, deploy.File{
			Path:  c.config.ChainPath,
			Bytes: []byte(request.ChainPEM),
			Mode:  c.config.ChainFileMode,
			Owner: c.config.ChainFileOwner,
			Group: c.config.ChainFileGroup,
		})
	}
	if c.config.KeyPath != "" && request.KeyPEM != "" {
		// Key file default mode is 0600 (owner-only read) — locked
		// down even when no override + destination doesn't exist.
		// FileDefaults.Mode (0644 — for cert/chain) does NOT apply
		// to keys; per-File explicit mode wins over Defaults.
		keyMode := c.config.KeyFileMode
		if keyMode == 0 {
			keyMode = 0600
		}
		files = append(files, deploy.File{
			Path:  c.config.KeyPath,
			Bytes: []byte(request.KeyPEM),
			Mode:  keyMode,
			Owner: c.config.KeyFileOwner,
			Group: c.config.KeyFileGroup,
		})
	}
	return deploy.Plan{
		Files: files,
		Defaults: deploy.FileDefaults{
			Mode:  0644,
			Owner: pickFirstExistingUser("apache", "www-data", "httpd"),
			Group: pickFirstExistingGroup("apache", "www-data", "httpd"),
		},
		BackupRetention: c.config.BackupRetention,
	}
}

// runPostDeployVerify mirrors the NGINX implementation; we don't
// share via package because the per-connector retry knobs differ.
func (c *Connector) runPostDeployVerify(ctx context.Context, deployedCertPEM string) error {
	verify := c.config.PostDeployVerify
	if verify != nil && !verify.Enabled {
		c.logger.Info("post-deploy TLS verify disabled per config")
		return nil
	}
	endpoint := ""
	timeout := 10 * time.Second
	if verify != nil {
		endpoint = verify.Endpoint
		if verify.Timeout > 0 {
			timeout = verify.Timeout
		}
	}
	if endpoint == "" {
		c.logger.Warn("post-deploy verify enabled but no endpoint configured; skipping",
			"hint", "set Config.PostDeployVerify.Endpoint = host:port")
		return nil
	}
	want, err := certPEMToFingerprint(deployedCertPEM)
	if err != nil {
		return fmt.Errorf("compute deployed cert fingerprint: %w", err)
	}
	attempts := c.config.PostDeployVerifyAttempts
	if attempts <= 0 {
		attempts = 3
	}
	backoff := c.config.PostDeployVerifyBackoff
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		res := c.probe(ctx, endpoint, timeout)
		if !res.Success {
			lastErr = fmt.Errorf("TLS probe failed: %s", res.Error)
			continue
		}
		got := strings.ToLower(res.Fingerprint)
		want = strings.ToLower(want)
		if got == want {
			c.logger.Info("post-deploy TLS verify succeeded",
				"endpoint", endpoint, "fingerprint", got, "attempt", i+1)
			return nil
		}
		lastErr = fmt.Errorf("post-deploy TLS verify SHA-256 mismatch: got %s, want %s", got, want)
	}
	return lastErr
}

func (c *Connector) rollbackToBackups(ctx context.Context, backupPaths map[string]string) error {
	for finalPath, backupPath := range backupPaths {
		if backupPath == "" {
			if err := os.Remove(finalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rollback remove %s: %w", finalPath, err)
			}
			continue
		}
		bytes, err := os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("rollback read backup %s: %w", backupPath, err)
		}
		if _, err := deploy.AtomicWriteFile(ctx, finalPath, bytes, deploy.WriteOptions{
			SkipIdempotent:  true,
			BackupRetention: -1,
		}); err != nil {
			return fmt.Errorf("rollback write %s: %w", finalPath, err)
		}
	}
	out, err := c.runReload(ctx, c.config.ReloadCommand)
	if err != nil {
		return fmt.Errorf("rollback reload failed: %w (output: %s)", err, string(out))
	}
	return nil
}

func (c *Connector) failureResult(addr, stage string, err error, startTime time.Time) *target.DeploymentResult {
	return &target.DeploymentResult{
		Success:       false,
		TargetAddress: addr,
		Message:       fmt.Sprintf("%s: %v", stage, err),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"stage":       stage,
			"duration_ms": fmt.Sprintf("%d", time.Since(startTime).Milliseconds()),
		},
	}
}

func certPEMToFingerprint(pemBytes string) (string, error) {
	begin := "-----BEGIN CERTIFICATE-----"
	end := "-----END CERTIFICATE-----"
	beginIdx := strings.Index(pemBytes, begin)
	if beginIdx < 0 {
		return "", fmt.Errorf("no CERTIFICATE PEM block")
	}
	rest := pemBytes[beginIdx+len(begin):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return "", fmt.Errorf("PEM block not terminated")
	}
	body := strings.TrimSpace(rest[:endIdx])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, " ", "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

func pickFirstExistingUser(candidates ...string) string {
	for _, name := range candidates {
		if _, err := user.Lookup(name); err == nil {
			return name
		}
	}
	return ""
}
func pickFirstExistingGroup(candidates ...string) string {
	for _, name := range candidates {
		if _, err := user.LookupGroup(name); err == nil {
			return name
		}
	}
	return ""
}

// ValidateDeployment — preserved from pre-Phase-5; switched to use
// the test seam runValidate so tests don't need apachectl on PATH.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Apache deployment",
		"certificate_id", request.CertificateID, "serial", request.Serial)
	startTime := time.Now()
	if _, err := c.runValidate(ctx, c.config.ValidateCommand); err != nil {
		errMsg := fmt.Sprintf("Apache config validation failed: %v", err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.CertPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
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
	dur := time.Since(startTime)
	c.logger.Info("Apache deployment validated successfully", "duration", dur.String())
	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.CertPath,
		Message:       "Apache configuration valid and certificate accessible",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"validate_command": c.config.ValidateCommand,
			"duration_ms":      fmt.Sprintf("%d", dur.Milliseconds()),
		},
	}, nil
}
