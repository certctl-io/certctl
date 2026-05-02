// Package wincertstore implements a target connector for deploying certificates
// to the Windows Certificate Store via PowerShell. Unlike the IIS connector,
// this connector only imports certificates into the store — it does not manage
// IIS site bindings. Use this for non-IIS Windows services that read certs
// from the Windows cert store (e.g., Exchange, RDP, SQL Server, ADFS).
//
// Architecture: Same injectable PowerShellExecutor pattern as the IIS connector.
// Supports agent-local PowerShell or WinRM proxy agent modes.
package wincertstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
)

// Config represents the Windows Certificate Store deployment target configuration.
type Config struct {
	// StoreName is the Windows certificate store name (e.g., "My", "Root", "WebHosting").
	StoreName string `json:"store_name"`

	// StoreLocation is the store location: "LocalMachine" (default) or "CurrentUser".
	StoreLocation string `json:"store_location"`

	// FriendlyName is an optional friendly name assigned to the imported certificate.
	FriendlyName string `json:"friendly_name,omitempty"`

	// RemoveExpired controls whether expired certificates with the same CN are removed
	// after successful import. Default false.
	RemoveExpired bool `json:"remove_expired,omitempty"`

	// Mode is the deployment mode: "local" (default) or "winrm".
	Mode string `json:"mode"`

	// WinRM settings (only used when Mode is "winrm").
	WinRMHost     string `json:"winrm_host,omitempty"`
	WinRMPort     int    `json:"winrm_port,omitempty"`
	WinRMUsername string `json:"winrm_username,omitempty"`
	WinRMPassword string `json:"winrm_password,omitempty"`
	WinRMHTTPS    bool   `json:"winrm_https,omitempty"`
	WinRMInsecure bool   `json:"winrm_insecure,omitempty"`
}

// PowerShellExecutor abstracts PowerShell command execution for testability.
type PowerShellExecutor interface {
	Execute(ctx context.Context, script string) (string, error)
}

// realExecutor calls powershell.exe on the local system.
type realExecutor struct{}

func (e *realExecutor) Execute(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Connector implements the target.Connector interface for Windows Certificate Store.
type Connector struct {
	config   *Config
	logger   *slog.Logger
	executor PowerShellExecutor
}

// validStoreName matches safe Windows certificate store names (alphanumeric, spaces, hyphens, dots).
var validStoreName = regexp.MustCompile(`^[a-zA-Z0-9 _\-\.]+$`)

// validStoreLocation matches allowed store locations.
var validStoreLocations = map[string]bool{
	"LocalMachine": true,
	"CurrentUser":  true,
}

// New creates a new Windows Certificate Store connector with the default PowerShell executor.
func New(cfg *Config, logger *slog.Logger) (*Connector, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	applyDefaults(cfg)
	return &Connector{
		config:   cfg,
		logger:   logger,
		executor: &realExecutor{},
	}, nil
}

// NewWithExecutor creates a connector with an injected executor for testing.
func NewWithExecutor(cfg *Config, logger *slog.Logger, executor PowerShellExecutor) *Connector {
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
	if cfg.StoreName == "" {
		cfg.StoreName = "My"
	}
	if cfg.StoreLocation == "" {
		cfg.StoreLocation = "LocalMachine"
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
}

// ValidateConfig validates the Windows Certificate Store configuration.
func (c *Connector) ValidateConfig(ctx context.Context, config json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("invalid WinCertStore config JSON: %w", err)
	}
	applyDefaults(&cfg)

	if !validStoreName.MatchString(cfg.StoreName) {
		return fmt.Errorf("invalid store_name: must be alphanumeric (got %q)", cfg.StoreName)
	}

	if !validStoreLocations[cfg.StoreLocation] {
		return fmt.Errorf("invalid store_location: must be 'LocalMachine' or 'CurrentUser' (got %q)", cfg.StoreLocation)
	}

	if cfg.FriendlyName != "" && !validStoreName.MatchString(cfg.FriendlyName) {
		return fmt.Errorf("invalid friendly_name: must be alphanumeric (got %q)", cfg.FriendlyName)
	}

	if cfg.Mode != "local" && cfg.Mode != "winrm" {
		return fmt.Errorf("invalid mode: must be 'local' or 'winrm' (got %q)", cfg.Mode)
	}

	if cfg.Mode == "winrm" {
		if cfg.WinRMHost == "" {
			return fmt.Errorf("winrm_host is required when mode is 'winrm'")
		}
		if cfg.WinRMUsername == "" {
			return fmt.Errorf("winrm_username is required when mode is 'winrm'")
		}
		if cfg.WinRMPassword == "" {
			return fmt.Errorf("winrm_password is required when mode is 'winrm'")
		}
	}

	c.config = &cfg
	return nil
}

// snapshotEntry captures one cert in the target store with the SAME Subject
// as the new cert — i.e. a cert that may be displaced by Import-PfxCertificate
// and must be re-imported on rollback. The PfxPath is a temp file on the
// remote host populated by Export-PfxCertificate during the snapshot phase.
//
// Bundle 7 of the 2026-05-02 deployment-target audit.
type snapshotEntry struct {
	Thumbprint string
	PfxPath    string
}

// snapshotState is the parsed output of the pre-deploy Get-ChildItem snapshot
// PowerShell script. AllThumbprints is every cert in the store at deploy
// time (used by the post-rollback verify phase to confirm the store is
// back to pre-deploy state). Entries is the subset whose Subject matches
// the new cert and was Export-PfxCertificate'd into TempDir for restore.
// ExportPassword is the transient password used for both Export and
// rollback Import; it is held in memory only and never logged or
// persisted in metadata.
//
// Bundle 7 of the 2026-05-02 deployment-target audit.
type snapshotState struct {
	Entries        []snapshotEntry
	AllThumbprints []string
	TempDir        string
	ExportPassword string
}

// DeployCertificate imports a certificate into the Windows Certificate Store.
//
// Bundle 7 of the 2026-05-02 deployment-target audit added a pre-deploy
// snapshot + on-import-failure rollback wrapper around the original single
// PowerShell import script:
//  1. Parse the new cert's Subject DN from CertPEM (used by the snapshot to
//     decide which existing certs may be displaced).
//  2. Run the snapshot script: Get-ChildItem the store; for every cert with
//     the same Subject as the new one, Export-PfxCertificate to a tempdir
//     using a transient export password. Captures every thumbprint for
//     post-rollback verification.
//  3. Run the original import script (unchanged contract: PFX import +
//     optional FriendlyName + optional RemoveExpired).
//  4. On import-script failure: run the rollback script (Remove-Item the
//     new cert if it landed; Import-PfxCertificate every snapshot entry;
//     clean up the tempdir) and a verify script (assert all original
//     thumbprints are back). Return wrapped error to the operator.
//  5. On success: best-effort cleanup of the snapshot tempdir.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if request.KeyPEM == "" {
		return nil, fmt.Errorf("private key is required for Windows Certificate Store import")
	}

	c.logger.Info("deploying certificate to Windows Certificate Store",
		"store_name", c.config.StoreName,
		"store_location", c.config.StoreLocation)

	// Bundle 7: parse the new cert's Subject DN. The snapshot phase uses
	// this to decide which existing certs to Export-PfxCertificate for
	// the rollback path. Cert PEM parse errors fail the deploy before
	// any cert-store mutation.
	newCert, err := certutil.ParseCertificatePEM(request.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse new cert for snapshot: %w", err)
	}
	newSubject := newCert.Subject.String()

	// Bundle 7: pre-deploy snapshot. A separate transient export password
	// from the import PFX password — different lifecycle, different
	// PowerShell script. Held in memory only; never logged or persisted.
	exportPassword, err := certutil.GenerateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate snapshot export password: %w", err)
	}

	snapshotScript := c.buildSnapshotScript(newSubject, exportPassword)
	snapshotOut, err := c.executor.Execute(ctx, snapshotScript)
	if err != nil {
		// Snapshot failure is a real outage signal — bail out before any
		// cert-store mutation. The rollback path requires snapshot data;
		// we have none.
		return nil, fmt.Errorf("pre-deploy snapshot failed: %s: %w", snapshotOut, err)
	}
	state := parseSnapshotOutput(snapshotOut, exportPassword)
	c.logger.Debug("pre-deploy snapshot captured",
		"snapshot_entries", len(state.Entries),
		"total_thumbprints", len(state.AllThumbprints),
		"tempdir", state.TempDir)

	// Generate transient PFX password for the import.
	pfxPassword, err := certutil.GenerateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate PFX password: %w", err)
	}

	// Convert PEM to PFX
	pfxData, err := certutil.CreatePFX(request.CertPEM, request.KeyPEM, request.ChainPEM, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("create PFX: %w", err)
	}

	// Compute thumbprint for verification
	thumbprint, err := certutil.ComputeThumbprint(request.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}

	// Build the PowerShell import script
	pfxB64 := base64.StdEncoding.EncodeToString(pfxData)
	script := c.buildImportScript(pfxB64, pfxPassword, thumbprint)

	output, err := c.executor.Execute(ctx, script)
	if err != nil {
		// Bundle 7: import failed. Roll back — Remove-Item the new cert
		// if it landed, Import-PfxCertificate each snapshotted PFX, clean
		// up the tempdir. Then verify the rollback by re-reading
		// Get-ChildItem.
		c.logger.Error("PowerShell import failed; attempting rollback",
			"error", err,
			"output", output,
			"snapshot_entries", len(state.Entries))
		rbErr := c.rollbackImport(ctx, state, thumbprint)
		if rbErr != nil {
			// Both import AND rollback failed — operator-actionable.
			combined := fmt.Errorf("PowerShell import failed (%w) AND rollback also failed (%v); manual operator inspection required", err, rbErr)
			c.logger.Error("WinCertStore rollback also failed",
				"import_error", err,
				"rollback_error", rbErr,
				"new_thumbprint", thumbprint,
				"snapshot_entries", len(state.Entries))
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("cert:\\%s\\%s", c.config.StoreLocation, c.config.StoreName),
				Message:       combined.Error(),
				DeployedAt:    time.Now(),
				Metadata: map[string]string{
					"thumbprint":             thumbprint,
					"store_name":             c.config.StoreName,
					"store_location":         c.config.StoreLocation,
					"import_error":           output,
					"rollback_error":         rbErr.Error(),
					"rolled_back":            "false",
					"manual_action_required": "true",
				},
			}, combined
		}

		// Rollback succeeded. Best-effort verification — re-read
		// Get-ChildItem and assert every original thumbprint is back.
		// Skipped when the snapshot was empty (first-time deploy with
		// no prior thumbprints to verify against).
		verifyNote := ""
		if len(state.AllThumbprints) > 0 {
			if vErr := c.verifyRollback(ctx, state); vErr != nil {
				verifyNote = fmt.Sprintf(" (warning: %v)", vErr)
				c.logger.Warn("WinCertStore rollback verification disagreed",
					"error", vErr)
			}
		}

		errMsg := fmt.Sprintf("PowerShell import failed; rolled back%s: %v (output: %s)", verifyNote, err, output)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("cert:\\%s\\%s", c.config.StoreLocation, c.config.StoreName),
			Message:       errMsg,
			DeployedAt:    time.Now(),
			Metadata: map[string]string{
				"thumbprint":     thumbprint,
				"store_name":     c.config.StoreName,
				"store_location": c.config.StoreLocation,
				"import_error":   output,
				"rolled_back":    "true",
			},
		}, fmt.Errorf("%s", errMsg)
	}

	// Success path: clean up the snapshot tempdir on a best-effort basis.
	// Failure here is non-fatal — operators don't need their deploy to
	// fail because of leftover temp files; surface as a debug log.
	if state.TempDir != "" {
		if cleanupErr := c.cleanupSnapshot(ctx, state); cleanupErr != nil {
			c.logger.Debug("snapshot tempdir cleanup failed (non-fatal)",
				"error", cleanupErr,
				"tempdir", state.TempDir)
		}
	}

	c.logger.Info("certificate imported to Windows Certificate Store",
		"thumbprint", thumbprint,
		"store", c.config.StoreName,
		"location", c.config.StoreLocation)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: fmt.Sprintf("cert:\\%s\\%s", c.config.StoreLocation, c.config.StoreName),
		DeploymentID:  thumbprint,
		Message:       fmt.Sprintf("Certificate imported to %s\\%s (thumbprint: %s)", c.config.StoreLocation, c.config.StoreName, thumbprint),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"thumbprint":     thumbprint,
			"store_name":     c.config.StoreName,
			"store_location": c.config.StoreLocation,
		},
	}, nil
}

// buildImportScript creates the PowerShell script to import a PFX into the cert store.
func (c *Connector) buildImportScript(pfxB64, pfxPassword, thumbprint string) string {
	var sb strings.Builder

	// Decode PFX from base64 and write to temp file
	sb.WriteString(fmt.Sprintf("$pfxBytes = [System.Convert]::FromBase64String('%s')\n", pfxB64))
	sb.WriteString("$pfxPath = [System.IO.Path]::GetTempFileName() + '.pfx'\n")
	sb.WriteString("try {\n")
	sb.WriteString("  [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)\n")

	// Import PFX to cert store
	sb.WriteString(fmt.Sprintf("  $secPwd = ConvertTo-SecureString -String '%s' -Force -AsPlainText\n", pfxPassword))
	sb.WriteString(fmt.Sprintf("  $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\\%s\\%s' -Password $secPwd -Exportable\n",
		c.config.StoreLocation, c.config.StoreName))

	// Set friendly name if configured
	if c.config.FriendlyName != "" {
		sb.WriteString(fmt.Sprintf("  $cert.FriendlyName = '%s'\n", c.config.FriendlyName))
	}

	// Verify import
	sb.WriteString(fmt.Sprintf("  $imported = Get-ChildItem 'Cert:\\%s\\%s\\%s' -ErrorAction SilentlyContinue\n",
		c.config.StoreLocation, c.config.StoreName, thumbprint))
	sb.WriteString("  if (-not $imported) { throw 'Certificate import verification failed' }\n")

	// Remove expired certs with same subject (optional)
	if c.config.RemoveExpired {
		sb.WriteString("  $subject = $cert.Subject\n")
		sb.WriteString(fmt.Sprintf("  Get-ChildItem 'Cert:\\%s\\%s' | Where-Object { $_.Subject -eq $subject -and $_.NotAfter -lt (Get-Date) -and $_.Thumbprint -ne '%s' } | Remove-Item -Force\n",
			c.config.StoreLocation, c.config.StoreName, thumbprint))
	}

	sb.WriteString(fmt.Sprintf("  Write-Output 'SUCCESS:%s'\n", thumbprint))
	sb.WriteString("} finally {\n")
	sb.WriteString("  if (Test-Path $pfxPath) { Remove-Item $pfxPath -Force }\n")
	sb.WriteString("}\n")

	return sb.String()
}

// ValidateDeployment verifies that a certificate exists in the Windows Certificate Store.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	// Get thumbprint from metadata if available, otherwise query by serial
	thumbprint := ""
	if request.Metadata != nil {
		thumbprint = request.Metadata["thumbprint"]
	}

	var script string
	if thumbprint != "" {
		script = fmt.Sprintf("$cert = Get-ChildItem 'Cert:\\%s\\%s\\%s' -ErrorAction SilentlyContinue; if ($cert) { Write-Output ('FOUND:' + $cert.Thumbprint + ':' + $cert.NotAfter.ToString('o')) } else { Write-Output 'NOT_FOUND' }",
			c.config.StoreLocation, c.config.StoreName, thumbprint)
	} else {
		// Fallback: search by serial number
		script = fmt.Sprintf("$cert = Get-ChildItem 'Cert:\\%s\\%s' | Where-Object { $_.SerialNumber -eq '%s' } | Select-Object -First 1; if ($cert) { Write-Output ('FOUND:' + $cert.Thumbprint + ':' + $cert.NotAfter.ToString('o')) } else { Write-Output 'NOT_FOUND' }",
			c.config.StoreLocation, c.config.StoreName, request.Serial)
	}

	output, err := c.executor.Execute(ctx, script)
	if err != nil {
		return &target.ValidationResult{
			Valid:       false,
			Serial:      request.Serial,
			Message:     fmt.Sprintf("PowerShell query failed: %s", output),
			ValidatedAt: time.Now(),
		}, fmt.Errorf("validation query failed: %w", err)
	}

	if strings.HasPrefix(output, "FOUND:") {
		parts := strings.SplitN(output, ":", 3)
		foundThumb := ""
		if len(parts) >= 2 {
			foundThumb = parts[1]
		}
		return &target.ValidationResult{
			Valid:         true,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("cert:\\%s\\%s", c.config.StoreLocation, c.config.StoreName),
			Message:       fmt.Sprintf("Certificate found in store (thumbprint: %s)", foundThumb),
			ValidatedAt:   time.Now(),
			Metadata: map[string]string{
				"thumbprint": foundThumb,
			},
		}, nil
	}

	return &target.ValidationResult{
		Valid:       false,
		Serial:      request.Serial,
		Message:     "Certificate not found in Windows Certificate Store",
		ValidatedAt: time.Now(),
	}, fmt.Errorf("certificate not found in %s\\%s", c.config.StoreLocation, c.config.StoreName)
}

// Ensure Connector implements target.Connector.
var _ target.Connector = (*Connector)(nil)

// --- Bundle 7: pre-deploy snapshot + on-import-failure rollback ---

// escapePowerShellSingleQuoted escapes a string for safe embedding inside a
// single-quoted PowerShell literal. PowerShell single-quoted strings have no
// escape sequences other than the apostrophe-doubling rule: a literal
// apostrophe inside the string is written as two consecutive apostrophes.
// Subject DN strings can contain apostrophes (e.g. CN=O'Reilly) so this is
// load-bearing for the snapshot script's -eq Subject comparison.
func escapePowerShellSingleQuoted(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// buildSnapshotScript builds the pre-deploy Get-ChildItem snapshot PowerShell.
// Output format (one line per cert plus a trailing TEMPDIR line):
//
//	SNAPSHOT:<thumbprint>:<pfxPath>     -- same-Subject cert, exported for restore
//	THUMB:<thumbprint>                  -- different Subject; track for verify only
//	TEMPDIR:<path>                      -- tempdir created for the snapshot exports
//
// The export password is embedded as a single-quoted literal. GenerateRandomPassword
// returns alphanumeric chars only so it cannot break the literal.
//
// Bundle 7 of the 2026-05-02 deployment-target audit. The "# CERTCTL_SNAPSHOT"
// comment tag identifies the script to test mocks deterministically.
func (c *Connector) buildSnapshotScript(newSubject, exportPassword string) string {
	escapedSubject := escapePowerShellSingleQuoted(newSubject)
	var sb strings.Builder
	sb.WriteString("# CERTCTL_SNAPSHOT\n")
	fmt.Fprintf(&sb, "$store = 'Cert:\\%s\\%s'\n", c.config.StoreLocation, c.config.StoreName)
	sb.WriteString("$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'certctl-snapshot-' + [System.Guid]::NewGuid().ToString())\n")
	sb.WriteString("New-Item -ItemType Directory -Path $tempDir -Force | Out-Null\n")
	fmt.Fprintf(&sb, "$pwd = ConvertTo-SecureString -String '%s' -Force -AsPlainText\n", exportPassword)
	fmt.Fprintf(&sb, "$newSubject = '%s'\n", escapedSubject)
	sb.WriteString("Get-ChildItem $store -ErrorAction SilentlyContinue | ForEach-Object {\n")
	sb.WriteString("  if ($_.Subject -eq $newSubject) {\n")
	sb.WriteString("    $pfx = [System.IO.Path]::Combine($tempDir, $_.Thumbprint + '.pfx')\n")
	sb.WriteString("    try {\n")
	sb.WriteString("      Export-PfxCertificate -Cert $_ -FilePath $pfx -Password $pwd -ChainOption EndEntityCertOnly | Out-Null\n")
	sb.WriteString("      Write-Output ('SNAPSHOT:' + $_.Thumbprint + ':' + $pfx)\n")
	sb.WriteString("    } catch {\n")
	sb.WriteString("      Write-Output ('THUMB:' + $_.Thumbprint)\n")
	sb.WriteString("    }\n")
	sb.WriteString("  } else {\n")
	sb.WriteString("    Write-Output ('THUMB:' + $_.Thumbprint)\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	sb.WriteString("Write-Output ('TEMPDIR:' + $tempDir)\n")
	return sb.String()
}

// parseSnapshotOutput consumes the output of buildSnapshotScript and returns
// a populated snapshotState. Lines that don't match the expected prefixes
// are tolerated (logged at debug level) so transient PowerShell warnings
// don't fail the parse.
func parseSnapshotOutput(output, exportPassword string) *snapshotState {
	state := &snapshotState{ExportPassword: exportPassword}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SNAPSHOT:"):
			rest := strings.TrimPrefix(line, "SNAPSHOT:")
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) != 2 {
				continue
			}
			state.Entries = append(state.Entries, snapshotEntry{
				Thumbprint: parts[0],
				PfxPath:    parts[1],
			})
			state.AllThumbprints = append(state.AllThumbprints, parts[0])
		case strings.HasPrefix(line, "THUMB:"):
			state.AllThumbprints = append(state.AllThumbprints, strings.TrimPrefix(line, "THUMB:"))
		case strings.HasPrefix(line, "TEMPDIR:"):
			state.TempDir = strings.TrimPrefix(line, "TEMPDIR:")
		}
	}
	return state
}

// rollbackImport runs the rollback PowerShell script that:
//  1. Removes the new cert from the store if it landed (Test-Path guard).
//  2. Re-imports each snapshot entry's PFX from the tempdir.
//  3. Cleans up the tempdir.
//
// Returns nil on success, wrapped error on rollback-script failure.
//
// Bundle 7 of the 2026-05-02 deployment-target audit. The "# CERTCTL_ROLLBACK"
// comment tag identifies the script to test mocks deterministically.
func (c *Connector) rollbackImport(ctx context.Context, state *snapshotState, newThumbprint string) error {
	var sb strings.Builder
	sb.WriteString("# CERTCTL_ROLLBACK\n")
	fmt.Fprintf(&sb, "$store = 'Cert:\\%s\\%s'\n", c.config.StoreLocation, c.config.StoreName)
	fmt.Fprintf(&sb, "$pwd = ConvertTo-SecureString -String '%s' -Force -AsPlainText\n", state.ExportPassword)

	// Remove the new cert if it landed.
	fmt.Fprintf(&sb, "$newCertPath = '%s\\%s\\%s'\n",
		fmt.Sprintf("Cert:\\%s", c.config.StoreLocation),
		c.config.StoreName,
		newThumbprint)
	sb.WriteString("if (Test-Path $newCertPath) { Remove-Item $newCertPath -Force -ErrorAction SilentlyContinue }\n")

	// Re-import each snapshot entry.
	for _, entry := range state.Entries {
		fmt.Fprintf(&sb,
			"Import-PfxCertificate -FilePath '%s' -CertStoreLocation $store -Password $pwd -Exportable | Out-Null\n",
			entry.PfxPath)
	}

	// Clean up the snapshot tempdir.
	if state.TempDir != "" {
		fmt.Fprintf(&sb,
			"Remove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue\n",
			state.TempDir)
	}

	sb.WriteString("Write-Output 'ROLLBACK_OK'\n")

	output, err := c.executor.Execute(ctx, sb.String())
	if err != nil {
		return fmt.Errorf("rollback script: %w (output: %s)", err, strings.TrimSpace(output))
	}
	c.logger.Info("WinCertStore rollback completed",
		"snapshot_entries", len(state.Entries),
		"new_thumbprint", newThumbprint,
		"output", strings.TrimSpace(output))
	return nil
}

// verifyRollback re-reads Get-ChildItem on the store and asserts every
// pre-deploy thumbprint is back. Returns nil on full match; returns a
// non-fatal warning error when one or more thumbprints are missing
// (the rollback's Remove-Item / Import-PfxCertificate ran but the store
// is in an unexpected state — operator inspection recommended).
//
// Bundle 7 of the 2026-05-02 deployment-target audit. The "# CERTCTL_VERIFY"
// comment tag identifies the script to test mocks deterministically.
func (c *Connector) verifyRollback(ctx context.Context, state *snapshotState) error {
	if len(state.AllThumbprints) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(state.AllThumbprints))
	for _, t := range state.AllThumbprints {
		quoted = append(quoted, "'"+t+"'")
	}
	var sb strings.Builder
	sb.WriteString("# CERTCTL_VERIFY\n")
	fmt.Fprintf(&sb, "$store = 'Cert:\\%s\\%s'\n", c.config.StoreLocation, c.config.StoreName)
	sb.WriteString("$found = Get-ChildItem $store -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint\n")
	fmt.Fprintf(&sb, "$want = @(%s)\n", strings.Join(quoted, ","))
	sb.WriteString("$missing = $want | Where-Object { $_ -notin $found }\n")
	sb.WriteString("if ($missing.Count -eq 0) { Write-Output 'VERIFY_OK' } else { Write-Output ('VERIFY_FAILED:' + ($missing -join ',')) }\n")

	output, err := c.executor.Execute(ctx, sb.String())
	if err != nil {
		return fmt.Errorf("verify probe: %w", err)
	}
	out := strings.TrimSpace(output)
	if out == "VERIFY_OK" {
		return nil
	}
	return fmt.Errorf("rollback verification disagreed: %s", out)
}

// cleanupSnapshot best-effort removes the snapshot tempdir on the success
// path so operators' filesystems don't accumulate `certctl-snapshot-*`
// directories. Failure is non-fatal (caller logs at debug level).
//
// Bundle 7 of the 2026-05-02 deployment-target audit. The "# CERTCTL_CLEANUP"
// comment tag identifies the script to test mocks deterministically.
func (c *Connector) cleanupSnapshot(ctx context.Context, state *snapshotState) error {
	if state.TempDir == "" {
		return nil
	}
	script := fmt.Sprintf(
		"# CERTCTL_CLEANUP\nRemove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue\nWrite-Output 'CLEANUP_OK'\n",
		state.TempDir)
	if _, err := c.executor.Execute(ctx, script); err != nil {
		return fmt.Errorf("cleanup script: %w", err)
	}
	return nil
}
