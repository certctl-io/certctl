package envoy

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

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/deploy"
	"github.com/certctl-io/certctl/internal/tlsprobe"
)

// Config represents the Envoy deployment target configuration.
// Envoy uses file-based certificate delivery — the agent writes cert/key files
// to a directory that Envoy watches via its SDS (Secret Discovery Service)
// file-based configuration or static filename references in the bootstrap config.
type Config struct {
	CertDir       string `json:"cert_dir"`       // Directory where Envoy watches for cert files (required)
	CertFilename  string `json:"cert_filename"`  // Filename for certificate (default: cert.pem)
	KeyFilename   string `json:"key_filename"`   // Filename for private key (default: key.pem)
	ChainFilename string `json:"chain_filename"` // Optional filename for chain (if set, chain written separately)
	SDSConfig     bool   `json:"sds_config"`     // If true, write an SDS discovery JSON file for file-based SDS

	// Bundle 3 (deployment-target audit 2026-05-02): post-deploy TLS
	// verification. Defends against Envoy's SDS file watcher's natural
	// pickup latency — without this, DeployCertificate returned the
	// moment file writes completed and a caller running post-deploy
	// verify could see Envoy still serving the old cert (watcher
	// hadn't reloaded yet, load-balanced replica hit one that hadn't
	// reloaded yet, etc.). Same shape as nginx.go::PostDeployVerify.
	// Default behavior is opt-in: nil PostDeployVerify or
	// PostDeployVerify.Enabled=false skips the verify step entirely.
	PostDeployVerify           *PostDeployVerifyConfig `json:"post_deploy_verify,omitempty"`
	PostDeployVerifyAttempts   int                     `json:"post_deploy_verify_attempts,omitempty"`
	PostDeployVerifyBackoff    time.Duration           `json:"post_deploy_verify_backoff,omitempty"`
	PostDeployVerifyMaxBackoff time.Duration           `json:"post_deploy_verify_max_backoff,omitempty"`

	// Bundle 3: backup retention. Zero =
	// deploy.DefaultBackupRetention (3); -1 = disable backups. Mirrors
	// the per-Plan setting on file-write connectors that already use
	// deploy.Apply (nginx/apache/haproxy/postfix). Envoy uses
	// AtomicWriteFile per file so this gets passed via WriteOptions.
	BackupRetention int `json:"backup_retention,omitempty"`
}

// PostDeployVerifyConfig controls the post-deploy TLS handshake verification
// step. Mirrors nginx.PostDeployVerifyConfig so the Envoy + NGINX shapes are
// interchangeable for operators reading docs.
type PostDeployVerifyConfig struct {
	// Enabled toggles the verify; false = skip even when the struct
	// is non-nil.
	Enabled bool `json:"enabled"`

	// Endpoint is the host:port to dial for the TLS handshake. When
	// empty, the connector logs a warning and skips verify (V2:
	// operator-explicit configuration required; no defaulting to
	// localhost which would be wrong for sidecar deployments).
	Endpoint string `json:"endpoint,omitempty"`

	// Timeout caps each individual probe attempt. Zero defaults to
	// 10s (matches nginx default).
	Timeout time.Duration `json:"timeout,omitempty"`
}

// SDSResource represents an Envoy SDS tls_certificate resource for file-based SDS.
// This matches Envoy's expected format for file-based Secret Discovery Service.
type SDSResource struct {
	Resources []SDSTLSCertificate `json:"resources"`
}

// SDSTLSCertificate represents a single SDS tls_certificate entry.
type SDSTLSCertificate struct {
	Type           string         `json:"@type"`
	Name           string         `json:"name"`
	TLSCertificate TLSCertificate `json:"tls_certificate"`
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

	// Bundle 3: probe seam for post-deploy TLS verify. Same shape NGINX
	// uses (nginx.go:130) — tlsprobe.ProbeTLS in production; tests
	// inject a stub via SetTestProbe.
	probe func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult
}

// New creates a new Envoy target connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
		probe:  tlsprobe.ProbeTLS,
	}
}

// SetTestProbe overrides the post-deploy TLS probe for tests. Production code
// gets tlsprobe.ProbeTLS via New; tests inject a stub that returns canned
// ProbeResults to exercise watcher-pickup retry/backoff paths without standing
// up a real TLS server.
func (c *Connector) SetTestProbe(fn func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult) {
	c.probe = fn
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
//  1. Atomic-write certificate (+ chain if chain_filename not set) to
//     cert_filename with mode 0644.
//  2. Atomic-write private key to key_filename with mode 0600.
//  3. If chain_filename set and chain provided, atomic-write chain
//     separately with mode 0644.
//  4. If sds_config is true, atomic-write SDS JSON file pointing to
//     cert/key paths (Bundle 3: previously os.WriteFile, now
//     deploy.AtomicWriteFile so the JSON itself is atomic — torn JSON
//     mid-write would make Envoy refuse to load any cert).
//  5. If PostDeployVerify enabled, dial the configured TLS endpoint and
//     poll until the served leaf-cert SHA-256 matches the deployed
//     fingerprint, with retry/backoff to absorb watcher latency. On
//     mismatch after all attempts, restore from the WriteResults'
//     BackupPaths and return a wrapped error (Bundle 3).
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

	// Bundle 3 contract: track WriteResults for every atomic write so
	// the post-deploy-verify rollback path can restore from backups
	// across all four files (cert, key, chain, SDS JSON) — not just
	// the cert.
	results := make([]*deploy.WriteResult, 0, 4)

	writeOpts := func(mode os.FileMode) deploy.WriteOptions {
		return deploy.WriteOptions{Mode: mode, BackupRetention: c.config.BackupRetention}
	}

	// 1. Cert (+ inline chain if no separate chain filename).
	certRes, err := deploy.AtomicWriteFile(ctx, certPath, []byte(certData), writeOpts(0644))
	if err != nil {
		errMsg := fmt.Sprintf("failed to write certificate: %v", err)
		c.logger.Error("certificate deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: certPath,
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	results = append(results, certRes)

	// 2. Key (mode 0600 — private material).
	if request.KeyPEM != "" {
		keyRes, err := deploy.AtomicWriteFile(ctx, keyPath, []byte(request.KeyPEM), writeOpts(0600))
		if err != nil {
			errMsg := fmt.Sprintf("failed to write private key: %v", err)
			c.logger.Error("key deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: keyPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		results = append(results, keyRes)
	}

	// 3. Optional separate chain file.
	if c.config.ChainFilename != "" && request.ChainPEM != "" {
		chainPath := filepath.Join(c.config.CertDir, c.config.ChainFilename)
		chainRes, err := deploy.AtomicWriteFile(ctx, chainPath, []byte(request.ChainPEM+"\n"), writeOpts(0644))
		if err != nil {
			errMsg := fmt.Sprintf("failed to write chain: %v", err)
			c.logger.Error("chain deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: chainPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		results = append(results, chainRes)
	}

	// 4. SDS JSON (Bundle 3: was os.WriteFile, now atomic).
	if c.config.SDSConfig {
		sdsRes, err := c.writeSDSConfig(ctx)
		if err != nil {
			errMsg := fmt.Sprintf("failed to write SDS config: %v", err)
			c.logger.Error("SDS config deployment failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: certPath,
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		results = append(results, sdsRes)
	}

	// 5. Post-deploy TLS verify (Bundle 3). Skip when all four files
	// were idempotent (no actual change to verify) — same gate NGINX
	// uses on res.SkippedAsIdempotent.
	if c.shouldRunVerify(results) {
		if vErr := c.runPostDeployVerify(ctx, request.CertPEM); vErr != nil {
			c.logger.Error("post-deploy TLS verify failed; rolling back", "error", vErr)
			rbErr := c.restoreFromBackups(ctx, results)
			if rbErr != nil {
				return c.failureResult(certPath, "post-deploy verify + rollback both failed",
					fmt.Errorf("verify: %w; rollback: %v", vErr, rbErr), startTime), rbErr
			}
			return c.failureResult(certPath, "post-deploy verify failed; rolled back",
				vErr, startTime), vErr
		}
	}

	deploymentDuration := time.Since(startTime)
	allIdempotent := true
	for _, r := range results {
		if !r.Idempotent {
			allIdempotent = false
			break
		}
	}
	idemNote := ""
	if allIdempotent {
		idemNote = " (idempotent skip — all bytes unchanged)"
	}

	c.logger.Info("certificate deployed to Envoy successfully",
		"duration", deploymentDuration.String(),
		"cert_path", certPath,
		"key_path", keyPath,
		"sds_config", c.config.SDSConfig,
		"idempotent", allIdempotent)

	metadata := map[string]string{
		"cert_path":   certPath,
		"key_path":    keyPath,
		"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		"idempotent":  fmt.Sprintf("%t", allIdempotent),
	}
	if c.config.SDSConfig {
		metadata["sds_config_path"] = filepath.Join(c.config.CertDir, "sds.json")
	}

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: certPath,
		DeploymentID:  fmt.Sprintf("envoy-%d", time.Now().Unix()),
		Message:       "Certificate deployed to Envoy (file-based SDS will auto-reload)" + idemNote,
		DeployedAt:    time.Now(),
		Metadata:      metadata,
	}, nil
}

// shouldRunVerify reports whether the post-deploy verify step should fire.
// Returns false when every WriteResult was idempotent (nothing actually
// changed; the operator's prior deploy already succeeded), mirroring
// NGINX's res.SkippedAsIdempotent gate.
func (c *Connector) shouldRunVerify(results []*deploy.WriteResult) bool {
	for _, r := range results {
		if !r.Idempotent {
			return true
		}
	}
	return false
}

// writeSDSConfig writes an Envoy SDS JSON file that references the cert/key
// file paths. The write goes through deploy.AtomicWriteFile (Bundle 3) so
// power loss / OOM mid-write cannot leave a torn JSON file — Envoy's SDS
// watcher refuses to load any cert against a malformed JSON.
func (c *Connector) writeSDSConfig(ctx context.Context) (*deploy.WriteResult, error) {
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
		return nil, fmt.Errorf("failed to marshal SDS config: %w", err)
	}

	sdsPath := filepath.Join(c.config.CertDir, "sds.json")
	res, err := deploy.AtomicWriteFile(ctx, sdsPath, sdsJSON, deploy.WriteOptions{
		Mode:            0644,
		BackupRetention: c.config.BackupRetention,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write SDS config file: %w", err)
	}

	c.logger.Info("SDS config file written", "path", sdsPath)
	return res, nil
}

// runPostDeployVerify dials the configured endpoint, performs a TLS handshake,
// and asserts the leaf cert's SHA-256 matches the SHA-256 of the bytes we just
// deployed. Retries with backoff per PostDeployVerifyAttempts to absorb the
// natural latency between SDS file write and Envoy's watcher picking up the
// change.
//
// Returns nil on match; returns a wrapped error on any failure mode (mismatch
// after all attempts, dial timeout, handshake failure, DNS resolution failure).
// The caller decides whether to roll back. Same shape as nginx.go:416.
//
// Bundle 3 of the 2026-05-02 deployment-target audit.
func (c *Connector) runPostDeployVerify(ctx context.Context, deployedCertPEM string) error {
	verify := c.config.PostDeployVerify
	if verify == nil || !verify.Enabled {
		return nil
	}

	endpoint := verify.Endpoint
	timeout := verify.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
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
	want = strings.ToLower(want)

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
		if got != want {
			return fmt.Errorf("post-deploy TLS verify SHA-256 mismatch: got %s, want %s", got, want)
		}
		c.logger.Info("post-deploy TLS verify succeeded",
			"endpoint", endpoint,
			"fingerprint", got)
		return nil
	}

	return tlsprobe.VerifyWithExponentialBackoff(ctx, retryCfg, probe)
}

// restoreFromBackups iterates the WriteResults from a successful per-file
// AtomicWriteFile pass and rewrites each destination from its BackupPath. Used
// when post-deploy TLS verify fails — the writes already succeeded, so we undo
// them by rewriting the backup bytes via AtomicWriteFile{SkipIdempotent:true,
// BackupRetention:-1}.
//
// Traefik has no PostCommit reload to retry — Envoy's SDS file watcher will
// pick up the restored bytes naturally on its next tick. The verify retry/
// backoff in this same DeployCertificate call would have absorbed that watcher
// cycle; on rollback we trust the watcher and return.
//
// Mirrors nginx.go::rollbackToBackups (L487-515) with the reload step elided.
//
// Bundle 3 of the 2026-05-02 deployment-target audit.
func (c *Connector) restoreFromBackups(ctx context.Context, results []*deploy.WriteResult) error {
	for _, r := range results {
		if r == nil || r.Idempotent {
			// Idempotent writes did not modify the destination, so
			// there is nothing to restore.
			continue
		}
		if r.BackupPath == "" {
			// File did not exist before this deploy — restore = remove.
			if err := os.Remove(r.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rollback remove %s: %w", r.Path, err)
			}
			continue
		}
		bytes, err := os.ReadFile(r.BackupPath)
		if err != nil {
			return fmt.Errorf("rollback read backup %s: %w", r.BackupPath, err)
		}
		if _, err := deploy.AtomicWriteFile(ctx, r.Path, bytes, deploy.WriteOptions{
			SkipIdempotent:  true,
			BackupRetention: -1, // don't backup the rollback (no chain explosion)
		}); err != nil {
			return fmt.Errorf("rollback write %s: %w", r.Path, err)
		}
	}
	return nil
}

// failureResult builds a target.DeploymentResult for the various error paths.
// Centralized so the field set stays consistent. Same shape as nginx.go:519.
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

// certPEMToFingerprint extracts the SHA-256 hex fingerprint of the first
// certificate block in a PEM bundle. Mirrors nginx.go's helper of the same
// name (and tlsprobe.CertFingerprint's output format) so equality compare
// works against the probe's served fingerprint.
func certPEMToFingerprint(pemBytes string) (string, error) {
	der, err := firstPEMBlock(pemBytes, "CERTIFICATE")
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

// firstPEMBlock pulls the bytes of the first PEM block of the requested type.
// Mirrors nginx.go:548 (kept inline rather than a shared helper because the
// nginx version is package-private; cross-package import would force exposure).
func firstPEMBlock(pemBytes, blockType string) ([]byte, error) {
	begin := "-----BEGIN " + blockType + "-----"
	end := "-----END " + blockType + "-----"
	beginIdx := strings.Index(pemBytes, begin)
	if beginIdx < 0 {
		return nil, fmt.Errorf("no %s PEM block found", blockType)
	}
	rest := pemBytes[beginIdx+len(begin):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return nil, fmt.Errorf("PEM block not terminated")
	}
	body := strings.TrimSpace(rest[:endIdx])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, " ", "")
	return base64.StdEncoding.DecodeString(body)
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
