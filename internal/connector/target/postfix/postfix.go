// Package postfix implements the Postfix + Dovecot mail-server
// target connector. As of the deploy-hardening I master bundle
// Phase 7, both modes follow the canonical NGINX template:
// atomic-write via internal/deploy.Apply, validate-with-the-target
// PreCommit, reload PostCommit, post-deploy TLS verify, rollback
// on failure.
package postfix

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

type Config struct {
	Mode            string `json:"mode"`
	CertPath        string `json:"cert_path"`
	KeyPath         string `json:"key_path"`
	ChainPath       string `json:"chain_path"`
	ReloadCommand   string `json:"reload_command"`
	ValidateCommand string `json:"validate_command"`

	// Phase 7: file ownership + mode + verify + retention.
	CertFileMode               os.FileMode             `json:"cert_file_mode,omitempty"`
	KeyFileMode                os.FileMode             `json:"key_file_mode,omitempty"`
	ChainFileMode              os.FileMode             `json:"chain_file_mode,omitempty"`
	CertFileOwner              string                  `json:"cert_file_owner,omitempty"`
	CertFileGroup              string                  `json:"cert_file_group,omitempty"`
	KeyFileOwner               string                  `json:"key_file_owner,omitempty"`
	KeyFileGroup               string                  `json:"key_file_group,omitempty"`
	PostDeployVerify           *PostDeployVerifyConfig `json:"post_deploy_verify,omitempty"`
	PostDeployVerifyAttempts   int                     `json:"post_deploy_verify_attempts,omitempty"`
	PostDeployVerifyBackoff    time.Duration           `json:"post_deploy_verify_backoff,omitempty"`
	PostDeployVerifyMaxBackoff time.Duration           `json:"post_deploy_verify_max_backoff,omitempty"`
	BackupRetention            int                     `json:"backup_retention,omitempty"`
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
	return exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
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
	default:
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

func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid mail server config: %w", err)
	}
	if cfg.Mode != "" && cfg.Mode != "postfix" && cfg.Mode != "dovecot" {
		return fmt.Errorf("invalid mode %q: must be \"postfix\" or \"dovecot\"", cfg.Mode)
	}
	applyDefaults(&cfg)
	if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("invalid reload_command: %w", err)
	}
	if cfg.ValidateCommand != "" {
		if err := validation.ValidateShellCommand(cfg.ValidateCommand); err != nil {
			return fmt.Errorf("invalid validate_command: %w", err)
		}
	}
	c.logger.Info("validating mail server configuration",
		"mode", cfg.Mode, "cert_path", cfg.CertPath, "key_path", cfg.KeyPath, "chain_path", cfg.ChainPath)
	certDir := filepath.Dir(cfg.CertPath)
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("%s cert directory does not exist: %s", cfg.Mode, certDir)
	}
	c.config = &cfg
	c.logger.Info("mail server configuration validated", "mode", cfg.Mode)
	return nil
}

// DeployCertificate atomic + verify + rollback. Mail-specific
// quirk preserved: if ChainPath is empty, the chain is appended to
// the cert (Postfix/Dovecot's "no separate chain" mode).
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to mail server",
		"mode", c.config.Mode, "cert_path", c.config.CertPath)
	startTime := time.Now()

	plan := c.buildPlan(request)
	if c.config.ValidateCommand != "" {
		plan.PreCommit = func(pcCtx context.Context, _ map[string]string) error {
			out, err := c.runValidate(pcCtx, c.config.ValidateCommand)
			if err != nil {
				return fmt.Errorf("%s validate failed: %w (output: %s)", c.config.Mode, err, string(out))
			}
			return nil
		}
	}
	plan.PostCommit = func(pcCtx context.Context) error {
		out, err := c.runReload(pcCtx, c.config.ReloadCommand)
		if err != nil {
			return fmt.Errorf("%s reload failed: %w (output: %s)", c.config.Mode, err, string(out))
		}
		return nil
	}

	res, err := deploy.Apply(ctx, plan)
	if err != nil {
		return c.failureResult(c.config.CertPath, "deploy.Apply", err, startTime), err
	}

	if !res.SkippedAsIdempotent {
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back", "error", vErr)
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
	c.logger.Info("certificate deployed to mail server successfully",
		"duration", dur.String(), "mode", c.config.Mode, "idempotent", res.SkippedAsIdempotent)
	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: c.config.CertPath,
		DeploymentID:  fmt.Sprintf("%s-%d", c.config.Mode, time.Now().Unix()),
		Message:       fmt.Sprintf("Certificate deployed and %s reloaded successfully%s", c.config.Mode, idemNote),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"mode":        c.config.Mode,
			"cert_path":   c.config.CertPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
			"idempotent":  fmt.Sprintf("%t", res.SkippedAsIdempotent),
		},
	}, nil
}

func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.config == nil || c.config.ValidateCommand == "" {
		return target.ErrValidateOnlyNotSupported
	}
	out, err := c.runValidate(ctx, c.config.ValidateCommand)
	if err != nil {
		return fmt.Errorf("%s validate (ValidateOnly): %w (output: %s)", c.config.Mode, err, string(out))
	}
	return nil
}

func (c *Connector) buildPlan(request target.DeploymentRequest) deploy.Plan {
	// Postfix/Dovecot quirk: if ChainPath is empty, append chain
	// to cert for serving as a single-file bundle.
	certBytes := []byte(request.CertPEM)
	if c.config.ChainPath == "" && request.ChainPEM != "" {
		certBytes = append(certBytes, []byte("\n"+request.ChainPEM)...)
	}
	files := []deploy.File{{
		Path:  c.config.CertPath,
		Bytes: certBytes,
		Mode:  c.config.CertFileMode,
		Owner: c.config.CertFileOwner,
		Group: c.config.CertFileGroup,
	}}
	if c.config.ChainPath != "" && request.ChainPEM != "" {
		files = append(files, deploy.File{
			Path:  c.config.ChainPath,
			Bytes: []byte(request.ChainPEM),
			Mode:  c.config.ChainFileMode,
		})
	}
	if c.config.KeyPath != "" && request.KeyPEM != "" {
		mode := c.config.KeyFileMode
		if mode == 0 {
			mode = 0600 // back-compat: Postfix keys 0600
		}
		files = append(files, deploy.File{
			Path:  c.config.KeyPath,
			Bytes: []byte(request.KeyPEM),
			Mode:  mode,
			Owner: c.config.KeyFileOwner,
			Group: c.config.KeyFileGroup,
		})
	}
	defaultUser := pickFirstExistingUser("postfix", "dovecot", "_postfix")
	defaultGroup := pickFirstExistingGroup("postfix", "dovecot", "_postfix")
	return deploy.Plan{
		Files:           files,
		Defaults:        deploy.FileDefaults{Mode: 0644, Owner: defaultUser, Group: defaultGroup},
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
	c.logger.Info("validating mail server deployment",
		"mode", c.config.Mode, "certificate_id", request.CertificateID, "serial", request.Serial)
	startTime := time.Now()
	if c.config.ValidateCommand != "" {
		if _, err := c.runValidate(ctx, c.config.ValidateCommand); err != nil {
			errMsg := fmt.Sprintf("%s config validation failed: %v", c.config.Mode, err)
			return &target.ValidationResult{
				Valid: false, Serial: request.Serial, TargetAddress: c.config.CertPath,
				Message: errMsg, ValidatedAt: time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}
	if _, err := os.Stat(c.config.CertPath); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("certificate file not found: %s", c.config.CertPath)
		return &target.ValidationResult{
			Valid: false, Serial: request.Serial, TargetAddress: c.config.CertPath,
			Message: errMsg, ValidatedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	dur := time.Since(startTime)
	return &target.ValidationResult{
		Valid: true, Serial: request.Serial, TargetAddress: c.config.CertPath,
		Message: fmt.Sprintf("%s configuration valid", c.config.Mode), ValidatedAt: time.Now(),
		Metadata: map[string]string{
			"mode": c.config.Mode, "validate_command": c.config.ValidateCommand,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
		},
	}, nil
}
