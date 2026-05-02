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
	"sort"
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

	// BackupRetention controls how many .certctl-bak.<unix-nanos>.p12 backup
	// files to keep after a successful deploy. Bundle 8 (2026-05-02
	// deployment-target audit) introduced these backups for on-import-failure
	// rollback; without retention, every deploy adds another file and disks
	// fill up over time. Values:
	//   0  → use default of 3 (keep most recent 3 backups).
	//   N  → keep most recent N backups.
	//   -1 → opt out of pruning entirely (operators that wire their own
	//        archival/rotation logic).
	BackupRetention int `json:"backup_retention,omitempty"`

	// BackupDir overrides the directory where .certctl-bak.* files are
	// written and pruned from. Default: filepath.Dir(KeystorePath) — same
	// filesystem as the keystore itself, so backup writes are atomic-ish
	// and a full disk fails fast at snapshot time rather than mid-deploy.
	BackupDir string `json:"backup_dir,omitempty"`
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
//
// Bundle 8 of the 2026-05-02 deployment-target audit added a pre-delete
// snapshot + on-import-failure rollback wrapper around the original
// keytool flow:
//  1. Convert PEM to PKCS#12 temp file (transient password, never logged).
//  2. If the keystore exists, run `keytool -exportkeystore` to a sibling
//     `.certctl-bak.<unix-nanos>.p12` BEFORE the irreversible -delete.
//     Backup path persisted in a local variable for the rollback path.
//  3. Run the existing -delete (best-effort; alias may not exist).
//  4. Run keytool -importkeystore.
//  5. On import failure with a backup in hand, rollbackImport runs
//     keytool -delete (clean up the alias the failed import may have
//     created) + keytool -importkeystore from the backup PFX.
//  6. On success: compute thumbprint, run optional reload command,
//     prune old backup files per Config.BackupRetention.
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

	// Bundle 8: pre-delete snapshot. When the keystore exists, run
	// keytool -exportkeystore to capture the prior alias state into a
	// sibling PKCS#12 backup file BEFORE the irreversible -delete step.
	// Backup path is held in a local variable for the rollback path;
	// snapshot failure aborts the deploy entirely (no mutation has
	// happened yet, so the keystore is untouched).
	//
	// Empty backupPath = first-time deploy (keystore file doesn't exist
	// yet) — rollback in that case has nothing to restore from; the
	// failure path returns the import error verbatim.
	var backupPath string
	if _, err := os.Stat(c.config.KeystorePath); err == nil {
		var snapErr error
		backupPath, snapErr = c.snapshotKeystore(ctx)
		if snapErr != nil {
			return nil, fmt.Errorf("pre-deploy snapshot failed: %w", snapErr)
		}
		c.logger.Debug("pre-deploy snapshot captured", "backup_path", backupPath)

		// Step 2: Delete existing alias (keytool -delete). Best-effort —
		// the alias may not exist in this keystore.
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
		// Bundle 8: import failed. Roll back if we have a backup; otherwise
		// surface the import error verbatim (first-time deploy — nothing
		// to restore from, the failed import didn't write anything we can
		// undo at the alias level).
		if backupPath != "" {
			c.logger.Error("keytool import failed; attempting rollback",
				"error", err,
				"output", output,
				"backup_path", backupPath)
			rbErr := c.rollbackImport(ctx, backupPath)
			if rbErr != nil {
				// Operator-actionable: import AND rollback both failed.
				// Surface BOTH errors AND the backup path so the operator
				// can manually keytool -importkeystore from the .p12 file
				// to recover.
				combined := fmt.Errorf("keytool import failed (%w) AND rollback also failed (%v); manual operator inspection required (backup at %s)", err, rbErr, backupPath)
				c.logger.Error("JavaKeystore rollback also failed",
					"import_error", err,
					"rollback_error", rbErr,
					"backup_path", backupPath)
				return nil, combined
			}
			return nil, fmt.Errorf("keytool import failed; rolled back from %s: %s: %w", backupPath, output, err)
		}
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

	// Bundle 8: prune old backups on the success path so operator filesystems
	// don't accumulate .certctl-bak.* files indefinitely. Failure here is
	// non-fatal (debug log only) — the deploy succeeded, retention cleanup
	// is housekeeping.
	c.pruneBackups()

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

// --- Bundle 8: pre-delete snapshot + on-import-failure rollback ---

// backupFilePrefix is the literal prefix on rollback-snapshot files.
// Centralised here so the snapshot writer, the rollback reader, and the
// retention pruner all agree on the naming convention.
//
// Bundle 8 of the 2026-05-02 deployment-target audit.
const backupFilePrefix = ".certctl-bak."

// backupFileSuffix is the literal suffix on rollback-snapshot files. Always
// PKCS#12 regardless of the source keystore type — `keytool -exportkeystore`
// destinations are PKCS#12 by convention because every JVM can read PKCS#12,
// while JKS is OpenJDK-specific.
const backupFileSuffix = ".p12"

// backupDir returns the directory rollback snapshots are written to.
// Operators can override via Config.BackupDir; default = same dir as the
// keystore so snapshots land on the same filesystem (atomic-ish writes,
// disk-full failures surface at snapshot time rather than mid-deploy).
func (c *Connector) backupDir() string {
	if c.config.BackupDir != "" {
		return c.config.BackupDir
	}
	return filepath.Dir(c.config.KeystorePath)
}

// snapshotKeystore runs `keytool -exportkeystore` to copy the existing alias
// into a new PKCS#12 file at <backupDir>/.certctl-bak.<unix-nanos>.p12.
// Returns the backup path on success; the caller persists it for the
// rollback path.
//
// The export password mirrors the keystore password — it's the same secret
// the operator already trusts the connector with, and avoiding a second
// transient password keeps the rollback's matching `-srcstorepass` simple.
//
// Bundle 8 of the 2026-05-02 deployment-target audit.
func (c *Connector) snapshotKeystore(ctx context.Context) (string, error) {
	backupPath := filepath.Join(
		c.backupDir(),
		fmt.Sprintf("%s%d%s", backupFilePrefix, time.Now().UnixNano(), backupFileSuffix),
	)
	exportArgs := []string{
		"-exportkeystore",
		"-srckeystore", c.config.KeystorePath,
		"-srcstoretype", c.config.KeystoreType,
		"-srcstorepass", c.config.KeystorePassword,
		"-srcalias", c.config.Alias,
		"-destkeystore", backupPath,
		"-deststoretype", "PKCS12",
		"-deststorepass", c.config.KeystorePassword,
		"-noprompt",
	}
	output, err := c.executor.Execute(ctx, c.config.KeytoolPath, exportArgs...)
	if err != nil {
		// keytool -exportkeystore returns non-zero when the alias isn't
		// present in the source keystore. That's a normal first-time-on-
		// existing-keystore signal, NOT an outage. Treat it as "no
		// snapshot to roll back to" and proceed cleanly — the import
		// will create the alias from scratch, and rollback (if the
		// import then fails) will be the no-backup path.
		lowerOut := strings.ToLower(output)
		if strings.Contains(lowerOut, "does not exist") || strings.Contains(lowerOut, "alias <") {
			c.logger.Debug("snapshot found no existing alias to export — first-time-on-keystore deploy",
				"alias", c.config.Alias,
				"output", output)
			return "", nil
		}
		return "", fmt.Errorf("keytool -exportkeystore: %s: %w", output, err)
	}
	return backupPath, nil
}

// rollbackImport restores the previous alias state from a snapshot PFX. Two
// keytool calls in order:
//  1. -delete the alias (best-effort — the failed import may or may not have
//     created an alias entry; we don't know which, so we always try).
//  2. -importkeystore from the backup PFX, restoring the original cert + key
//     under the original alias.
//
// Returns nil on success; wrapped error on rollback-script failure. The
// caller surfaces the wrapped error to the operator alongside the import
// error and the backup path so manual recovery is possible.
//
// Bundle 8 of the 2026-05-02 deployment-target audit.
func (c *Connector) rollbackImport(ctx context.Context, backupPath string) error {
	// Step 1: best-effort delete (alias may not exist after a failed import).
	deleteArgs := []string{
		"-delete",
		"-alias", c.config.Alias,
		"-keystore", c.config.KeystorePath,
		"-storepass", c.config.KeystorePassword,
		"-storetype", c.config.KeystoreType,
		"-noprompt",
	}
	c.executor.Execute(ctx, c.config.KeytoolPath, deleteArgs...)

	// Step 2: re-import from the backup PKCS#12 to restore the previous state.
	importArgs := []string{
		"-importkeystore",
		"-srckeystore", backupPath,
		"-srcstoretype", "PKCS12",
		"-srcstorepass", c.config.KeystorePassword,
		"-destkeystore", c.config.KeystorePath,
		"-deststoretype", c.config.KeystoreType,
		"-deststorepass", c.config.KeystorePassword,
		"-srcalias", c.config.Alias,
		"-destalias", c.config.Alias,
		"-noprompt",
	}
	output, err := c.executor.Execute(ctx, c.config.KeytoolPath, importArgs...)
	if err != nil {
		return fmt.Errorf("rollback re-import: %s: %w", output, err)
	}
	c.logger.Info("JavaKeystore rollback completed", "backup_path", backupPath)
	return nil
}

// pruneBackups removes older `.certctl-bak.*.p12` files beyond the configured
// retention count so operator filesystems don't accumulate snapshots
// indefinitely. Best-effort: any error during the readdir / remove cycle
// is swallowed at debug level — the deploy already succeeded, retention
// cleanup is housekeeping.
//
// Retention semantics (per Config.BackupRetention):
//   - 0  → default of 3 (keep most recent 3 backups).
//   - N  → keep most recent N backups.
//   - -1 → opt out entirely (no pruning).
//
// "Most recent" is determined by file ModTime, not by the unix-nanos in the
// filename — ModTime is robust against system-clock changes between deploys
// and aligns with the actual filesystem ordering operators see in `ls -lt`.
//
// Bundle 8 of the 2026-05-02 deployment-target audit.
func (c *Connector) pruneBackups() {
	keep := c.config.BackupRetention
	if keep == 0 {
		keep = 3
	}
	if keep < 0 {
		return // operator opted out
	}
	dir := c.backupDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.logger.Debug("backup retention prune skipped: ReadDir failed",
			"dir", dir, "error", err)
		return
	}
	type backupFile struct {
		name    string
		modTime time.Time
	}
	var backups []backupFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, backupFilePrefix) || !strings.HasSuffix(name, backupFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupFile{name: name, modTime: info.ModTime()})
	}
	if len(backups) <= keep {
		return
	}
	// Sort newest-first by ModTime; older entries (the tail) get pruned.
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})
	for _, b := range backups[keep:] {
		path := filepath.Join(dir, b.name)
		if err := os.Remove(path); err != nil {
			c.logger.Debug("backup retention prune: Remove failed",
				"path", path, "error", err)
		}
	}
}
