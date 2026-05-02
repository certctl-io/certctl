// Package haproxy implements the HAProxy target connector.
//
// HAProxy expects all TLS material concatenated in a single PEM
// file (cert + chain + key in that order). Phase 6 of the
// deploy-hardening I master bundle adds atomic-deploy + post-deploy
// TLS verify + rollback + ValidateOnly to the connector following
// the canonical NGINX template.
//
// HAProxy quirks:
//
//   - Single combined-PEM file (vs NGINX/Apache's separate
//     cert/chain/key files).
//   - Validate command is `haproxy -c -f <config>` (NOT a separate
//     subcommand).
//   - Reload via `systemctl reload haproxy` is preferred over
//     `restart` because reload uses socket activation to drain
//     in-flight connections gracefully (the old worker hands off
//     to the new worker via the master socket).
//   - Combined PEM file mode default 0600 (contains private key).
package haproxy

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
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
	"github.com/shankar0123/certctl/internal/validation"
)

// Config — Phase 6 (deploy-hardening I) added per-target file
// ownership + mode overrides + post-deploy verify + backup
// retention.
type Config struct {
	PEMPath         string `json:"pem_path"`
	ReloadCommand   string `json:"reload_command"`
	ValidateCommand string `json:"validate_command,omitempty"`

	PEMFileMode  os.FileMode `json:"pem_file_mode,omitempty"`
	PEMFileOwner string      `json:"pem_file_owner,omitempty"`
	PEMFileGroup string      `json:"pem_file_group,omitempty"`

	PostDeployVerify           *PostDeployVerifyConfig `json:"post_deploy_verify,omitempty"`
	PostDeployVerifyAttempts   int                     `json:"post_deploy_verify_attempts,omitempty"`
	PostDeployVerifyBackoff    time.Duration           `json:"post_deploy_verify_backoff,omitempty"`
	PostDeployVerifyMaxBackoff time.Duration           `json:"post_deploy_verify_max_backoff,omitempty"`

	BackupRetention int `json:"backup_retention,omitempty"`
}

type PostDeployVerifyConfig struct {
	Enabled  bool          `json:"enabled"`
	Endpoint string        `json:"endpoint,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

type Connector struct {
	config *Config
	logger *slog.Logger

	runValidate func(ctx context.Context, command string) ([]byte, error)
	runReload   func(ctx context.Context, command string) ([]byte, error)
	probe       func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult
}

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

func (c *Connector) SetTestRunValidate(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runValidate = fn
}
func (c *Connector) SetTestRunReload(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runReload = fn
}
func (c *Connector) SetTestProbe(fn func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult) {
	c.probe = fn
}

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
	if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("invalid reload_command: %w", err)
	}
	if cfg.ValidateCommand != "" {
		if err := validation.ValidateShellCommand(cfg.ValidateCommand); err != nil {
			return fmt.Errorf("invalid validate_command: %w", err)
		}
	}
	c.logger.Info("validating HAProxy configuration", "pem_path", cfg.PEMPath)
	c.config = &cfg
	c.logger.Info("HAProxy configuration validated")
	return nil
}

// DeployCertificate Phase 6 atomic + verify + rollback. Combined
// PEM file (cert + chain + key) written via deploy.Apply.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to HAProxy", "pem_path", c.config.PEMPath)
	startTime := time.Now()

	combinedPEM := buildCombinedPEM(request)
	plan := c.buildPlan([]byte(combinedPEM))
	if c.config.ValidateCommand != "" {
		plan.PreCommit = func(pcCtx context.Context, _ map[string]string) error {
			out, err := c.runValidate(pcCtx, c.config.ValidateCommand)
			if err != nil {
				return fmt.Errorf("haproxy -c -f failed: %w (output: %s)", err, string(out))
			}
			return nil
		}
	}
	plan.PostCommit = func(pcCtx context.Context) error {
		out, err := c.runReload(pcCtx, c.config.ReloadCommand)
		if err != nil {
			return fmt.Errorf("haproxy reload failed: %w (output: %s)", err, string(out))
		}
		return nil
	}

	res, err := deploy.Apply(ctx, plan)
	if err != nil {
		return c.failureResult(c.config.PEMPath, "deploy.Apply", err, startTime), err
	}

	if !res.SkippedAsIdempotent {
		// Use the cert (first PEM block) for fingerprint match,
		// not the full combined PEM. The wire serves leaf cert.
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back", "error", vErr)
			rbErr := c.rollbackToBackups(ctx, res.BackupPaths)
			if rbErr != nil {
				return c.failureResult(c.config.PEMPath, "verify+rollback both failed",
					fmt.Errorf("verify: %w; rollback: %v", vErr, rbErr), startTime), rbErr
			}
			return c.failureResult(c.config.PEMPath, "post-deploy verify failed; rolled back", vErr, startTime), vErr
		}
	}

	dur := time.Since(startTime)
	idemNote := ""
	if res.SkippedAsIdempotent {
		idemNote = " (idempotent skip — bytes unchanged)"
	}
	c.logger.Info("certificate deployed to HAProxy successfully",
		"duration", dur.String(), "pem_path", c.config.PEMPath, "idempotent", res.SkippedAsIdempotent)
	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.PEMPath,
		DeploymentID:  fmt.Sprintf("haproxy-%d", time.Now().Unix()),
		Message:       "Certificate deployed and HAProxy reloaded successfully" + idemNote,
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"pem_path":    c.config.PEMPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
			"idempotent":  fmt.Sprintf("%t", res.SkippedAsIdempotent),
		},
	}, nil
}

// ValidateOnly real impl — Phase 6 replaces the stub.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.config == nil || c.config.ValidateCommand == "" {
		return target.ErrValidateOnlyNotSupported
	}
	out, err := c.runValidate(ctx, c.config.ValidateCommand)
	if err != nil {
		return fmt.Errorf("haproxy -c -f (ValidateOnly): %w (output: %s)", err, string(out))
	}
	return nil
}

// buildCombinedPEM concatenates cert + chain + key in the order
// HAProxy requires.
func buildCombinedPEM(request target.DeploymentRequest) string {
	var b strings.Builder
	b.WriteString(request.CertPEM)
	b.WriteString("\n")
	if request.ChainPEM != "" {
		b.WriteString(request.ChainPEM)
		b.WriteString("\n")
	}
	if request.KeyPEM != "" {
		b.WriteString(request.KeyPEM)
		b.WriteString("\n")
	}
	return b.String()
}

func (c *Connector) buildPlan(combined []byte) deploy.Plan {
	mode := c.config.PEMFileMode
	if mode == 0 {
		mode = 0600 // combined file contains the private key
	}
	return deploy.Plan{
		Files: []deploy.File{{
			Path:  c.config.PEMPath,
			Bytes: combined,
			Mode:  mode,
			Owner: c.config.PEMFileOwner,
			Group: c.config.PEMFileGroup,
		}},
		Defaults: deploy.FileDefaults{
			Mode:  0600,
			Owner: pickFirstExistingUser("haproxy"),
			Group: pickFirstExistingGroup("haproxy"),
		},
		BackupRetention: c.config.BackupRetention,
	}
}

func (c *Connector) runPostDeployVerify(ctx context.Context, deployedCertPEM string) error {
	verify := c.config.PostDeployVerify
	if verify != nil && !verify.Enabled {
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
		c.logger.Warn("post-deploy verify enabled but no endpoint configured; skipping")
		return nil
	}
	want, err := certPEMToFingerprint(deployedCertPEM)
	if err != nil {
		return fmt.Errorf("compute deployed cert fingerprint: %w", err)
	}

	retryCfg := tlsprobe.RetryConfig{
		Attempts:       c.config.PostDeployVerifyAttempts,
		InitialBackoff: c.config.PostDeployVerifyBackoff,
		MaxBackoff:     c.config.PostDeployVerifyMaxBackoff,
	}

	probe := func(probectx context.Context) error {
		res := c.probe(probectx, endpoint, timeout)
		if !res.Success {
			return fmt.Errorf("TLS probe failed: %s", res.Error)
		}
		got := strings.ToLower(res.Fingerprint)
		wantLower := strings.ToLower(want)
		if got != wantLower {
			return fmt.Errorf("post-deploy TLS verify SHA-256 mismatch: got %s, want %s", got, wantLower)
		}
		c.logger.Info("post-deploy TLS verify succeeded",
			"endpoint", endpoint, "fingerprint", got)
		return nil
	}

	return tlsprobe.VerifyWithExponentialBackoff(ctx, retryCfg, probe)
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

func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating HAProxy deployment",
		"certificate_id", request.CertificateID, "serial", request.Serial)
	startTime := time.Now()
	if c.config.ValidateCommand != "" {
		if _, err := c.runValidate(ctx, c.config.ValidateCommand); err != nil {
			errMsg := fmt.Sprintf("HAProxy config validation failed: %v", err)
			return &target.ValidationResult{
				Valid:         false,
				Serial:        request.Serial,
				TargetAddress: c.config.PEMPath,
				Message:       errMsg,
				ValidatedAt:   time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}
	if _, err := os.Stat(c.config.PEMPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("PEM file not found: %s", c.config.PEMPath)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.PEMPath,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	dur := time.Since(startTime)
	c.logger.Info("HAProxy deployment validated successfully", "duration", dur.String())
	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.PEMPath,
		Message:       "HAProxy PEM file present and config valid",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"validate_command": c.config.ValidateCommand,
			"duration_ms":      fmt.Sprintf("%d", dur.Milliseconds()),
		},
	}, nil
}
