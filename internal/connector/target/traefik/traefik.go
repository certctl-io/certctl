// Package traefik implements the Traefik file-provider target
// connector. Bundle 4 of the 2026-05-02 deployment-target audit:
// upgraded from two separate deploy.AtomicWriteFile calls (cert,
// key) to a single deploy.Apply Plan with all-files atomicity.
// Traefik has no PreCommit (no `nginx -t` equivalent) and no
// PostCommit (file watcher auto-reloads on rename). Post-deploy
// TLS verify (optional) confirms the watcher picked up the new
// cert; on verify failure, restoreFromBackups rewrites every File
// path from its backup so the watcher reloads to the prior state.
package traefik

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
	"path/filepath"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

type Config struct {
	CertDir  string `json:"cert_dir"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`

	// Phase 7: per-file mode/owner overrides + post-deploy verify
	// + backup retention.
	CertFileMode             os.FileMode             `json:"cert_file_mode,omitempty"`
	KeyFileMode              os.FileMode             `json:"key_file_mode,omitempty"`
	CertFileOwner            string                  `json:"cert_file_owner,omitempty"`
	CertFileGroup            string                  `json:"cert_file_group,omitempty"`
	KeyFileOwner             string                  `json:"key_file_owner,omitempty"`
	KeyFileGroup             string                  `json:"key_file_group,omitempty"`
	PostDeployVerify         *PostDeployVerifyConfig `json:"post_deploy_verify,omitempty"`
	PostDeployVerifyAttempts int                     `json:"post_deploy_verify_attempts,omitempty"`
	PostDeployVerifyBackoff  time.Duration           `json:"post_deploy_verify_backoff,omitempty"`
	BackupRetention          int                     `json:"backup_retention,omitempty"`
}

type PostDeployVerifyConfig struct {
	Enabled  bool          `json:"enabled"`
	Endpoint string        `json:"endpoint,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

type Connector struct {
	config *Config
	logger *slog.Logger
	probe  func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult
}

func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{config: config, logger: logger, probe: tlsprobe.ProbeTLS}
}

func (c *Connector) SetTestProbe(fn func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult) {
	c.probe = fn
}

func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Traefik config: %w", err)
	}
	if cfg.CertDir == "" {
		return fmt.Errorf("Traefik cert_dir is required")
	}
	if cfg.CertFile == "" {
		cfg.CertFile = "cert.pem"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "key.pem"
	}
	c.logger.Info("validating Traefik configuration", "cert_dir", cfg.CertDir,
		"cert_file", cfg.CertFile, "key_file", cfg.KeyFile)
	if _, err := os.Stat(cfg.CertDir); os.IsNotExist(err) {
		return fmt.Errorf("Traefik cert directory does not exist: %s", cfg.CertDir)
	}
	testFile := filepath.Join(cfg.CertDir, ".certctl-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("Traefik cert directory is not writable: %s (%w)", cfg.CertDir, err)
	}
	os.Remove(testFile)
	c.config = &cfg
	c.logger.Info("Traefik configuration validated")
	return nil
}

// DeployCertificate writes cert + chain (combined) and key via a
// single deploy.Apply Plan. Bundle 4 of the 2026-05-02 deployment-
// target audit replaced the prior two-AtomicWriteFile approach,
// which broke all-files atomicity (a key-write failure after a
// successful cert write left an orphaned cert and the dedicated
// rollback helper only restored the cert).
//
// Traefik has no PreCommit (no validate-with-target command) and
// no PostCommit (inotify watcher auto-reloads on rename). Apply
// gives us SHA-256 idempotency over both files and rollback
// semantics if the rename loop ever fails mid-stream.
//
// Post-deploy TLS verify (optional via PostDeployVerify) confirms
// the watcher picked up the new bytes; on mismatch, restoreFromBackups
// rewrites both files from their backups and the watcher will
// auto-reload to the prior state on its next tick.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Traefik",
		"cert_dir", c.config.CertDir, "cert_file", c.config.CertFile, "key_file", c.config.KeyFile)
	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

	plan := c.buildPlan(request, certPath, keyPath)

	res, err := deploy.Apply(ctx, plan)
	if err != nil {
		return c.failureResult(certPath, "deploy.Apply", err, startTime), err
	}

	// Post-deploy TLS verify (skip when nothing changed).
	if !res.SkippedAsIdempotent {
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back", "error", vErr)
			rbErr := c.restoreFromBackups(ctx, res.BackupPaths)
			if rbErr != nil {
				return c.failureResult(certPath, "verify+rollback both failed",
					fmt.Errorf("verify: %w; rollback: %v", vErr, rbErr), startTime), rbErr
			}
			return c.failureResult(certPath, "post-deploy verify failed; rolled back", vErr, startTime), vErr
		}
	}

	dur := time.Since(startTime)
	idemNote := ""
	if res.SkippedAsIdempotent {
		idemNote = " (idempotent skip — bytes unchanged)"
	}
	c.logger.Info("certificate deployed to Traefik successfully",
		"duration", dur.String(), "cert_path", certPath, "idempotent", res.SkippedAsIdempotent)
	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("traefik-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Traefik (file watcher will auto-reload)" + idemNote,
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path": certPath, "key_path": keyPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
			"idempotent":  fmt.Sprintf("%t", res.SkippedAsIdempotent),
		},
	}, nil
}

// buildPlan assembles the deploy.Plan for one cert+(optional)key
// deployment. Cert and key are separate Files in the same Plan so
// Apply runs SHA-256 idempotency all-files and produces all-or-
// nothing atomicity. The combined-PEM (cert + "\n" + chain + "\n")
// shape is preserved for byte-equal compatibility with pre-Bundle-4
// deploys.
func (c *Connector) buildPlan(request target.DeploymentRequest, certPath, keyPath string) deploy.Plan {
	combined := request.CertPEM + "\n"
	if request.ChainPEM != "" {
		combined = combined + request.ChainPEM + "\n"
	}
	certMode := c.config.CertFileMode
	if certMode == 0 {
		certMode = 0644
	}
	keyMode := c.config.KeyFileMode
	if keyMode == 0 {
		keyMode = 0600
	}

	files := []deploy.File{{
		Path:  certPath,
		Bytes: []byte(combined),
		Mode:  certMode,
		Owner: c.config.CertFileOwner,
		Group: c.config.CertFileGroup,
	}}
	if request.KeyPEM != "" {
		files = append(files, deploy.File{
			Path:  keyPath,
			Bytes: []byte(request.KeyPEM),
			Mode:  keyMode,
			Owner: c.config.KeyFileOwner,
			Group: c.config.KeyFileGroup,
		})
	}
	return deploy.Plan{
		Files:           files,
		BackupRetention: c.config.BackupRetention,
	}
}

// ValidateOnly returns ErrValidateOnlyNotSupported. Traefik has no
// validate-with-the-target command (the file watcher just picks up
// changes); there is no way to dry-run a cert deploy without
// touching the live files.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	return target.ErrValidateOnlyNotSupported
}

func (c *Connector) runPostDeployVerify(ctx context.Context, deployedCertPEM string) error {
	verify := c.config.PostDeployVerify
	if verify == nil || !verify.Enabled || verify.Endpoint == "" {
		return nil
	}
	timeout := verify.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	want, err := certPEMToFingerprint(deployedCertPEM)
	if err != nil {
		return fmt.Errorf("compute fingerprint: %w", err)
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
		res := c.probe(ctx, verify.Endpoint, timeout)
		if !res.Success {
			lastErr = fmt.Errorf("TLS probe failed: %s", res.Error)
			continue
		}
		if strings.EqualFold(res.Fingerprint, want) {
			return nil
		}
		lastErr = fmt.Errorf("post-deploy TLS verify SHA-256 mismatch: got %s, want %s", res.Fingerprint, want)
	}
	return lastErr
}

// restoreFromBackups iterates the BackupPaths returned by deploy.Apply
// and rewrites every destination from its backup via AtomicWriteFile
// {SkipIdempotent:true, BackupRetention:-1}. The -1 prevents
// backup-of-the-backup pollution when a rollback fires.
//
// For files that did not exist before the deploy (BackupPath == ""),
// restore = remove. Mirrors nginx.go::rollbackToBackups (L487-515)
// with the reload step elided — Traefik's inotify watcher will
// pick up the restored bytes on its next tick.
//
// Bundle 4 of the 2026-05-02 deployment-target audit. Replaces the
// pre-fix rollbackCertAndKey helper which only restored the cert
// (key was orphaned on verify failure).
func (c *Connector) restoreFromBackups(ctx context.Context, backupPaths map[string]string) error {
	for finalPath, backupPath := range backupPaths {
		if backupPath == "" {
			// File didn't exist pre-deploy → restore = remove.
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
			BackupRetention: -1, // don't backup the rollback
		}); err != nil {
			return fmt.Errorf("rollback write %s: %w", finalPath, err)
		}
	}
	return nil
}

func (c *Connector) failureResult(addr, stage string, err error, startTime time.Time) *target.DeploymentResult {
	return &target.DeploymentResult{
		Success: false, TargetAddress: addr,
		Message: fmt.Sprintf("%s: %v", stage, err), DeployedAt: time.Now(),
		Metadata: map[string]string{
			"stage": stage, "duration_ms": fmt.Sprintf("%d", time.Since(startTime).Milliseconds()),
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
		return "", fmt.Errorf("PEM not terminated")
	}
	body := strings.TrimSpace(rest[:endIdx])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, " ", "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Traefik deployment", "certificate_id", request.CertificateID, "serial", request.Serial)
	startTime := time.Now()
	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return &target.ValidationResult{
			Valid: false, Serial: request.Serial, TargetAddress: certPath,
			Message: fmt.Sprintf("certificate file not found: %s", certPath), ValidatedAt: time.Now(),
		}, fmt.Errorf("certificate file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return &target.ValidationResult{
			Valid: false, Serial: request.Serial, TargetAddress: keyPath,
			Message: fmt.Sprintf("private key file not found: %s", keyPath), ValidatedAt: time.Now(),
		}, fmt.Errorf("private key file not found: %s", keyPath)
	}
	dur := time.Since(startTime)
	return &target.ValidationResult{
		Valid: true, Serial: request.Serial, TargetAddress: certPath,
		Message: "Certificate and key files accessible", ValidatedAt: time.Now(),
		Metadata: map[string]string{
			"cert_path": certPath, "key_path": keyPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
		},
	}, nil
}
