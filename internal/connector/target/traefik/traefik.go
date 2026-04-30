// Package traefik implements the Traefik file-provider target
// connector. As of deploy-hardening I Phase 7: atomic-write via
// internal/deploy.AtomicWriteFile + optional post-deploy TLS
// verify. No PreCommit/PostCommit because Traefik watches the
// directory via inotify and auto-reloads on file change.
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

// DeployCertificate writes cert + chain (combined) and key as
// separate files via deploy.AtomicWriteFile. Traefik's inotify
// watcher picks up the changes and auto-reloads. Post-deploy
// verify (if enabled) handshakes against the configured endpoint.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to Traefik",
		"cert_dir", c.config.CertDir, "cert_file", c.config.CertFile, "key_file", c.config.KeyFile)
	startTime := time.Now()

	certPath := filepath.Join(c.config.CertDir, c.config.CertFile)
	keyPath := filepath.Join(c.config.CertDir, c.config.KeyFile)

	// Preserve the pre-Phase-7 trailing-newline convention so
	// existing operator deploys + tests don't break on byte-equal
	// comparisons.
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

	certRes, err := deploy.AtomicWriteFile(ctx, certPath, []byte(combined), deploy.WriteOptions{
		Mode: certMode, Owner: c.config.CertFileOwner, Group: c.config.CertFileGroup,
		BackupRetention: c.config.BackupRetention,
	})
	if err != nil {
		return c.failureResult(certPath, "write cert", err, startTime), err
	}
	if request.KeyPEM != "" {
		_, err := deploy.AtomicWriteFile(ctx, keyPath, []byte(request.KeyPEM), deploy.WriteOptions{
			Mode: keyMode, Owner: c.config.KeyFileOwner, Group: c.config.KeyFileGroup,
			BackupRetention: c.config.BackupRetention,
		})
		if err != nil {
			// Cert already written; try to roll back the cert too.
			if certRes.BackupPath != "" {
				if bytes, rErr := os.ReadFile(certRes.BackupPath); rErr == nil {
					_, _ = deploy.AtomicWriteFile(ctx, certPath, bytes, deploy.WriteOptions{SkipIdempotent: true, BackupRetention: -1})
				}
			}
			return c.failureResult(keyPath, "write key", err, startTime), err
		}
	}

	// Post-deploy TLS verify.
	if !certRes.Idempotent {
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back", "error", vErr)
			rbErr := c.rollbackCertAndKey(ctx, certPath, certRes.BackupPath, keyPath)
			if rbErr != nil {
				return c.failureResult(certPath, "verify+rollback both failed",
					fmt.Errorf("verify: %w; rollback: %v", vErr, rbErr), startTime), rbErr
			}
			return c.failureResult(certPath, "post-deploy verify failed; rolled back", vErr, startTime), vErr
		}
	}

	dur := time.Since(startTime)
	idemNote := ""
	if certRes.Idempotent {
		idemNote = " (idempotent skip — bytes unchanged)"
	}
	c.logger.Info("certificate deployed to Traefik successfully",
		"duration", dur.String(), "cert_path", certPath, "idempotent", certRes.Idempotent)
	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("traefik-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Traefik (file watcher will auto-reload)" + idemNote,
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"cert_path": certPath, "key_path": keyPath,
			"duration_ms": fmt.Sprintf("%d", dur.Milliseconds()),
			"idempotent":  fmt.Sprintf("%t", certRes.Idempotent),
		},
	}, nil
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

func (c *Connector) rollbackCertAndKey(ctx context.Context, certPath, certBackup, keyPath string) error {
	if certBackup == "" {
		if err := os.Remove(certPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		bytes, err := os.ReadFile(certBackup)
		if err != nil {
			return fmt.Errorf("read cert backup: %w", err)
		}
		if _, err := deploy.AtomicWriteFile(ctx, certPath, bytes, deploy.WriteOptions{SkipIdempotent: true, BackupRetention: -1}); err != nil {
			return err
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
