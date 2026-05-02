package iis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
)

// Config represents the IIS deployment target configuration.
// Supports two modes:
//   - "local" (default): runs PowerShell locally on a Windows agent
//   - "winrm": connects to a remote Windows server via WinRM (proxy agent pattern)
type Config struct {
	Hostname    string `json:"hostname"`     // Target hostname or IP
	SiteName    string `json:"site_name"`    // IIS site name (e.g., "Default Web Site")
	CertStore   string `json:"cert_store"`   // Windows cert store (e.g., "My", "WebHosting")
	BindingInfo string `json:"binding_info"` // Binding info (e.g., "*.example.com")
	Port        int    `json:"port"`         // HTTPS port (default 443)
	SNI         bool   `json:"sni"`          // Enable Server Name Indication
	IPAddress   string `json:"ip_address"`   // Bind to specific IP (default "*")
	Mode        string `json:"mode"`         // "local" (default) or "winrm"

	// WinRM settings (only used when Mode is "winrm")
	WinRM WinRMConfig `json:"winrm"`
}

// PowerShellExecutor abstracts PowerShell command execution for testability.
// On real Windows deployments, the realExecutor calls powershell.exe directly.
// Tests inject a mock executor to verify command construction without Windows.
type PowerShellExecutor interface {
	Execute(ctx context.Context, script string) (string, error)
}

// realExecutor calls powershell.exe on the local system.
type realExecutor struct{}

func (e *realExecutor) Execute(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Connector implements the target.Connector interface for IIS (Internet Information Services).
// This connector runs on Windows agents and manages certificate deployment via PowerShell.
//
// IIS certificate management requires:
//   - Windows Server with IIS installed
//   - PowerShell execution available
//   - Administrative privileges
//
// Deployment flow:
//  1. Convert PEM cert+key to PFX (PKCS#12) format via go-pkcs12
//  2. Import PFX to Windows certificate store via Import-PfxCertificate
//  3. Compute SHA-1 thumbprint (IIS certificate identifier)
//  4. Update IIS HTTPS binding via New-WebBinding + AddSslCertificate
//  5. Verify binding is active via Get-WebBinding
type Connector struct {
	config   *Config
	logger   *slog.Logger
	executor PowerShellExecutor
}

// New creates a new IIS target connector with the given configuration and logger.
// In "local" mode (default), uses the real PowerShell executor.
// In "winrm" mode, creates a WinRM client for remote execution.
func New(config *Config, logger *slog.Logger) (*Connector, error) {
	mode := config.Mode
	if mode == "" {
		mode = "local"
	}

	var executor PowerShellExecutor
	switch mode {
	case "local":
		executor = &realExecutor{}
	case "winrm":
		winrmExec, err := newWinRMExecutor(&config.WinRM)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WinRM executor: %w", err)
		}
		executor = winrmExec
	default:
		return nil, fmt.Errorf("unsupported IIS connector mode %q (must be 'local' or 'winrm')", mode)
	}

	return &Connector{
		config:   config,
		logger:   logger,
		executor: executor,
	}, nil
}

// NewWithExecutor creates a new IIS target connector with an injected executor.
// Used in tests to mock PowerShell execution on non-Windows platforms.
func NewWithExecutor(config *Config, logger *slog.Logger, executor PowerShellExecutor) *Connector {
	return &Connector{
		config:   config,
		logger:   logger,
		executor: executor,
	}
}

// validIISName matches safe IIS site names and cert store names.
// Allows alphanumeric, spaces, underscores, hyphens, and dots.
var validIISName = regexp.MustCompile(`^[a-zA-Z0-9 _\-\.]+$`)

// validateIISName checks that an IIS name field contains only safe characters.
// This prevents PowerShell injection via malicious site or store names.
func validateIISName(name, field string) error {
	if name == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(name) > 256 {
		return fmt.Errorf("%s exceeds maximum length (256 characters)", field)
	}
	if !validIISName.MatchString(name) {
		return fmt.Errorf("%s contains invalid characters (allowed: alphanumeric, space, underscore, hyphen, dot)", field)
	}
	return nil
}

// validIPOrWildcard matches valid IP addresses or the wildcard "*".
var validIPOrWildcard = regexp.MustCompile(`^(\*|(\d{1,3}\.){3}\d{1,3})$`)

// ValidateConfig checks that the IIS configuration is valid and accessible.
// It verifies field values, PowerShell availability, and optionally checks that
// the IIS site exists and the cert store is accessible.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid IIS config: %w", err)
	}

	// Validate required fields
	if err := validateIISName(cfg.SiteName, "site_name"); err != nil {
		return err
	}
	if err := validateIISName(cfg.CertStore, "cert_store"); err != nil {
		return err
	}

	// Apply defaults
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.IPAddress == "" {
		cfg.IPAddress = "*"
	}

	// Validate port range
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	// Validate IP address format
	if !validIPOrWildcard.MatchString(cfg.IPAddress) {
		return fmt.Errorf("ip_address must be a valid IPv4 address or '*', got %q", cfg.IPAddress)
	}

	// Validate binding_info if provided (safe characters only)
	if cfg.BindingInfo != "" {
		if len(cfg.BindingInfo) > 512 {
			return fmt.Errorf("binding_info exceeds maximum length (512 characters)")
		}
		// Allow typical binding chars: alphanumeric, *, :, ., -
		validBinding := regexp.MustCompile(`^[a-zA-Z0-9\*\:\.\-]+$`)
		if !validBinding.MatchString(cfg.BindingInfo) {
			return fmt.Errorf("binding_info contains invalid characters")
		}
	}

	// Apply mode default
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	if cfg.Mode != "local" && cfg.Mode != "winrm" {
		return fmt.Errorf("unsupported mode %q (must be 'local' or 'winrm')", cfg.Mode)
	}

	c.logger.Info("validating IIS configuration",
		"site_name", cfg.SiteName,
		"cert_store", cfg.CertStore,
		"hostname", cfg.Hostname,
		"port", cfg.Port,
		"mode", cfg.Mode)

	// Verify PowerShell is available (only in local mode — WinRM handles this remotely)
	if cfg.Mode == "local" {
		if _, err := exec.LookPath("powershell.exe"); err != nil {
			return fmt.Errorf("powershell.exe not found in PATH: %w", err)
		}
	}

	// Verify IIS site exists
	siteCheckScript := fmt.Sprintf(`Get-Website -Name '%s' | Select-Object -ExpandProperty Name`, cfg.SiteName)
	output, err := c.executor.Execute(ctx, siteCheckScript)
	if err != nil {
		return fmt.Errorf("IIS site %q not found or inaccessible: %s (error: %w)", cfg.SiteName, strings.TrimSpace(output), err)
	}

	// Verify cert store is accessible
	storeCheckScript := fmt.Sprintf(`Test-Path 'Cert:\LocalMachine\%s'`, cfg.CertStore)
	output, err = c.executor.Execute(ctx, storeCheckScript)
	if err != nil || !strings.Contains(strings.TrimSpace(output), "True") {
		return fmt.Errorf("certificate store %q is not accessible: %s", cfg.CertStore, strings.TrimSpace(output))
	}

	c.config = &cfg
	c.logger.Info("IIS configuration validated",
		"site_name", cfg.SiteName,
		"cert_store", cfg.CertStore)
	return nil
}

// DeployCertificate imports a certificate to the Windows certificate store and updates
// the IIS binding to use the new certificate.
//
// Deployment flow:
//  1. Snapshot the existing binding's SSL cert thumbprint via Get-WebBinding
//     (Bundle 5: enables rollback on binding-update failure)
//  2. Convert PEM cert+key+chain to PFX format (go-pkcs12 with random password)
//  3. Write PFX to temp file (cleaned up on exit, even on error)
//  4. Compute SHA-1 thumbprint from DER cert (matches Windows certutil output)
//  5. Import PFX to Windows cert store via Import-PfxCertificate
//  6. Update IIS HTTPS binding via New-WebBinding + AddSslCertificate
//  7. On binding failure (Bundle 5): rollback — remove new cert from store
//     and re-bind old thumbprint (if any); verify rollback via Get-WebBinding
//  8. Return result with thumbprint in metadata
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to IIS",
		"site_name", c.config.SiteName,
		"cert_store", c.config.CertStore)

	startTime := time.Now()

	// Validate we have a private key (required for PFX creation)
	if request.KeyPEM == "" {
		errMsg := "private key (KeyPEM) is required for IIS deployment"
		c.logger.Error("deployment failed", "error", errMsg)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Bundle 5 (2026-05-02 deployment-target audit): pre-deploy snapshot
	// of the existing binding's SSL thumbprint so a binding-update failure
	// can roll back to the pre-deploy state. Empty oldThumbprint means
	// there is no existing binding (first-time deploy) — rollback removes
	// the new cert but does not re-bind anything.
	oldThumbprint, err := c.snapshotOldBinding(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("pre-deploy binding snapshot failed: %v", err)
		c.logger.Error("deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	if oldThumbprint != "" {
		c.logger.Debug("pre-deploy binding snapshot captured", "old_thumbprint", oldThumbprint)
	} else {
		c.logger.Debug("pre-deploy snapshot: no existing binding (first-time deploy)")
	}

	// Step 1: Create PFX from PEM inputs
	pfxPassword, err := certutil.GenerateRandomPassword(32)
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate PFX password: %v", err)
		c.logger.Error("deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	pfxData, err := certutil.CreatePFX(request.CertPEM, request.KeyPEM, request.ChainPEM, pfxPassword)
	if err != nil {
		errMsg := fmt.Sprintf("failed to create PFX: %v", err)
		c.logger.Error("PFX creation failed", "error", err)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Step 2+3: Compute thumbprint and import PFX
	// In local mode: write PFX to temp file, import via file path
	// In WinRM mode: base64-encode PFX, decode on remote side to temp file, import, clean up
	thumbprint, err := certutil.ComputeThumbprint(request.CertPEM)
	if err != nil {
		errMsg := fmt.Sprintf("failed to compute certificate thumbprint: %v", err)
		c.logger.Error("deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	c.logger.Debug("certificate thumbprint computed", "thumbprint", thumbprint)

	// Step 4: Import PFX to Windows certificate store
	var importScript string
	mode := c.config.Mode
	if mode == "" {
		mode = "local"
	}

	if mode == "winrm" {
		// WinRM mode: base64-encode PFX, decode on remote, import, cleanup
		pfxBase64 := base64.StdEncoding.EncodeToString(pfxData)
		importScript = fmt.Sprintf(
			`$pfxPath = [System.IO.Path]::GetTempFileName() + '.pfx'; `+
				`[System.IO.File]::WriteAllBytes($pfxPath, [System.Convert]::FromBase64String('%s')); `+
				`try { `+
				`$password = ConvertTo-SecureString -String '%s' -AsPlainText -Force; `+
				`Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\LocalMachine\%s' -Password $password `+
				`} finally { Remove-Item -Path $pfxPath -Force -ErrorAction SilentlyContinue }`,
			pfxBase64, pfxPassword, c.config.CertStore,
		)
	} else {
		// Local mode: write PFX to local temp file
		tmpFile, fileErr := os.CreateTemp("", "certctl-*.pfx")
		if fileErr != nil {
			errMsg := fmt.Sprintf("failed to create temp PFX file: %v", fileErr)
			c.logger.Error("deployment failed", "error", fileErr)
			return &target.DeploymentResult{
				Success:    false,
				Message:    errMsg,
				DeployedAt: time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		pfxPath := tmpFile.Name()
		defer os.Remove(pfxPath) // Always clean up temp PFX

		if _, writeErr := tmpFile.Write(pfxData); writeErr != nil {
			tmpFile.Close()
			errMsg := fmt.Sprintf("failed to write temp PFX file: %v", writeErr)
			c.logger.Error("deployment failed", "error", writeErr)
			return &target.DeploymentResult{
				Success:    false,
				Message:    errMsg,
				DeployedAt: time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		tmpFile.Close()

		importScript = fmt.Sprintf(
			`$password = ConvertTo-SecureString -String '%s' -AsPlainText -Force; `+
				`Import-PfxCertificate -FilePath '%s' -CertStoreLocation 'Cert:\LocalMachine\%s' -Password $password`,
			pfxPassword, pfxPath, c.config.CertStore,
		)
	}

	output, err := c.executor.Execute(ctx, importScript)
	if err != nil {
		errMsg := fmt.Sprintf("PFX import failed: %v (output: %s)", err, strings.TrimSpace(output))
		c.logger.Error("PFX import failed",
			"error", err,
			"output", strings.TrimSpace(output),
			"cert_store", c.config.CertStore)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	c.logger.Info("PFX imported to certificate store",
		"cert_store", c.config.CertStore,
		"thumbprint", thumbprint)

	// Step 5: Update IIS HTTPS binding
	port := c.config.Port
	if port == 0 {
		port = 443
	}
	ipAddress := c.config.IPAddress
	if ipAddress == "" {
		ipAddress = "*"
	}
	hostHeader := c.config.BindingInfo
	sniFlag := 0
	if c.config.SNI {
		sniFlag = 1
	}

	bindingScript := fmt.Sprintf(
		// Remove existing HTTPS binding on this port (if any), then create new one
		`$existing = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d -ErrorAction SilentlyContinue; `+
			`if ($existing) { $existing | Remove-WebBinding }; `+
			`New-WebBinding -Name '%s' -Protocol 'https' -Port %d -IPAddress '%s' -HostHeader '%s' -SslFlags %d; `+
			`$binding = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d; `+
			`$binding.AddSslCertificate('%s', '%s')`,
		c.config.SiteName, port,
		c.config.SiteName, port, ipAddress, hostHeader, sniFlag,
		c.config.SiteName, port,
		thumbprint, c.config.CertStore,
	)

	output, err = c.executor.Execute(ctx, bindingScript)
	if err != nil {
		bindingErr := err
		bindingOutput := strings.TrimSpace(output)
		c.logger.Error("IIS binding update failed; attempting rollback",
			"error", bindingErr,
			"output", bindingOutput,
			"site_name", c.config.SiteName,
			"new_thumbprint", thumbprint,
			"old_thumbprint", oldThumbprint)

		// Bundle 5: roll back. Remove the freshly-imported cert from the
		// store; if there was an old binding, re-bind the old thumbprint.
		// Then verify the rollback by re-reading Get-WebBinding.
		rbErr := c.rollbackBinding(ctx, oldThumbprint, thumbprint)
		if rbErr != nil {
			// Operator-actionable: binding update AND rollback both failed.
			// The cert store may contain the orphaned new cert AND the
			// binding may be in an indeterminate state. Surface both
			// errors and flag for manual inspection.
			c.logger.Error("IIS rollback also failed",
				"binding_error", bindingErr,
				"rollback_error", rbErr,
				"new_thumbprint", thumbprint,
				"old_thumbprint", oldThumbprint)
			combined := fmt.Errorf("binding update failed (%w) AND rollback also failed (%v); manual operator inspection required", bindingErr, rbErr)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
				Message:       combined.Error(),
				DeployedAt:    time.Now(),
				Metadata: map[string]string{
					"thumbprint":             thumbprint,
					"old_thumbprint":         oldThumbprint,
					"cert_store":             c.config.CertStore,
					"binding_error":          bindingOutput,
					"rollback_error":         rbErr.Error(),
					"rolled_back":            "false",
					"manual_action_required": "true",
				},
			}, combined
		}

		// Rollback succeeded. Best-effort verification — non-fatal warning
		// if the verify probe disagrees (only fires when there was an old
		// thumbprint to verify against).
		verifyNote := ""
		if oldThumbprint != "" {
			if vErr := c.verifyRollback(ctx, oldThumbprint); vErr != nil {
				verifyNote = fmt.Sprintf(" (warning: %v)", vErr)
				c.logger.Warn("IIS rollback verification disagreed",
					"error", vErr,
					"old_thumbprint", oldThumbprint)
			}
		}

		errMsg := fmt.Sprintf("IIS binding update failed; rolled back%s: %v (output: %s)", verifyNote, bindingErr, bindingOutput)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			DeployedAt:    time.Now(),
			Metadata: map[string]string{
				"thumbprint":     thumbprint,
				"old_thumbprint": oldThumbprint,
				"cert_store":     c.config.CertStore,
				"binding_error":  bindingOutput,
				"rolled_back":    "true",
			},
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to IIS successfully",
		"duration", deploymentDuration.String(),
		"site_name", c.config.SiteName,
		"thumbprint", thumbprint)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
		DeploymentID:  fmt.Sprintf("iis-%s-%d", thumbprint[:8], time.Now().Unix()),
		Message:       "Certificate imported and IIS binding updated successfully",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"hostname":    c.config.Hostname,
			"site_name":   c.config.SiteName,
			"cert_store":  c.config.CertStore,
			"thumbprint":  thumbprint,
			"port":        fmt.Sprintf("%d", port),
			"sni":         fmt.Sprintf("%t", c.config.SNI),
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the certificate is properly deployed in IIS.
// It checks the IIS binding to ensure it's active with the correct certificate thumbprint.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating IIS deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial,
		"site_name", c.config.SiteName)

	startTime := time.Now()

	port := c.config.Port
	if port == 0 {
		port = 443
	}

	// Query IIS binding for HTTPS on the configured port
	bindingScript := fmt.Sprintf(
		`$binding = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d -ErrorAction SilentlyContinue; `+
			`if ($binding) { $binding.certificateHash } else { 'NO_BINDING' }`,
		c.config.SiteName, port,
	)

	output, err := c.executor.Execute(ctx, bindingScript)
	if err != nil {
		errMsg := fmt.Sprintf("failed to query IIS binding: %v (output: %s)", err, strings.TrimSpace(output))
		c.logger.Error("validation failed", "error", err, "output", strings.TrimSpace(output))
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	bindingHash := strings.TrimSpace(output)
	if bindingHash == "NO_BINDING" || bindingHash == "" {
		errMsg := fmt.Sprintf("no HTTPS binding found on IIS site %q port %d", c.config.SiteName, port)
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify the certificate exists in the store
	certCheckScript := fmt.Sprintf(
		`$cert = Get-ChildItem -Path 'Cert:\LocalMachine\%s\%s' -ErrorAction SilentlyContinue; `+
			`if ($cert -and $cert.NotAfter -gt (Get-Date)) { 'VALID' } `+
			`elseif ($cert) { 'EXPIRED' } `+
			`else { 'NOT_FOUND' }`,
		c.config.CertStore, bindingHash,
	)

	output, err = c.executor.Execute(ctx, certCheckScript)
	if err != nil {
		errMsg := fmt.Sprintf("failed to verify certificate in store: %v", err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	certStatus := strings.TrimSpace(output)
	validationDuration := time.Since(startTime)

	switch certStatus {
	case "VALID":
		c.logger.Info("IIS deployment validated successfully",
			"duration", validationDuration.String(),
			"thumbprint", bindingHash)
		return &target.ValidationResult{
			Valid:         true,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       "Certificate is bound to IIS site and valid",
			ValidatedAt:   time.Now(),
			Metadata: map[string]string{
				"thumbprint":  bindingHash,
				"site_name":   c.config.SiteName,
				"cert_store":  c.config.CertStore,
				"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
			},
		}, nil

	case "EXPIRED":
		errMsg := fmt.Sprintf("certificate %s is expired in store %q", bindingHash, c.config.CertStore)
		c.logger.Error("validation failed: certificate expired", "thumbprint", bindingHash)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
			Metadata: map[string]string{
				"thumbprint": bindingHash,
				"status":     "expired",
			},
		}, fmt.Errorf("%s", errMsg)

	default: // NOT_FOUND or unexpected
		errMsg := fmt.Sprintf("certificate %s not found in store %q", bindingHash, c.config.CertStore)
		c.logger.Error("validation failed: certificate not in store", "thumbprint", bindingHash)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s (IIS: %s)", c.config.Hostname, c.config.SiteName),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
			Metadata: map[string]string{
				"thumbprint": bindingHash,
				"status":     "not_found",
			},
		}, fmt.Errorf("%s", errMsg)
	}
}

// snapshotOldBinding returns the SSL certificate thumbprint currently bound to
// the configured (site, port). Returns "" + nil if there is no existing
// binding (first-time deploy — rollback removes the new cert but does not
// re-bind anything). Returns "" + error if the snapshot script itself fails;
// the caller bails out of the deploy entirely (no cert-store mutation has
// happened yet).
//
// Bundle 5 of the 2026-05-02 deployment-target audit.
func (c *Connector) snapshotOldBinding(ctx context.Context) (string, error) {
	port := c.config.Port
	if port == 0 {
		port = 443
	}
	// The "# CERTCTL_SNAPSHOT" comment tag makes the script uniquely
	// identifiable to test mocks via strings.Contains, isolating it from
	// the binding-update / rollback / verify scripts which all also call
	// Get-WebBinding.
	script := fmt.Sprintf(
		"# CERTCTL_SNAPSHOT\n"+
			"$existing = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d -ErrorAction SilentlyContinue; "+
			"if ($existing -and $existing.certificateHash) { Write-Output ('OLD_THUMBPRINT:' + $existing.certificateHash) } "+
			"else { Write-Output 'NO_OLD_BINDING' }",
		c.config.SiteName, port)
	output, err := c.executor.Execute(ctx, script)
	if err != nil {
		return "", fmt.Errorf("Get-WebBinding snapshot: %w (output: %s)", err, strings.TrimSpace(output))
	}
	out := strings.TrimSpace(output)
	if strings.HasPrefix(out, "OLD_THUMBPRINT:") {
		return strings.TrimSpace(strings.TrimPrefix(out, "OLD_THUMBPRINT:")), nil
	}
	// "NO_OLD_BINDING" or any other unexpected output — treat as
	// first-time deploy (no rollback target).
	return "", nil
}

// rollbackBinding removes the freshly-imported cert (newThumbprint) from the
// configured store and, if oldThumbprint is non-empty, re-binds the old cert
// via AddSslCertificate. Falls through to New-WebBinding + AddSslCertificate
// when the old binding entry has been removed (e.g. by the failed binding
// script's Remove-WebBinding step).
//
// Bundle 5 of the 2026-05-02 deployment-target audit. The "# CERTCTL_ROLLBACK"
// comment tag identifies the script to test mocks.
func (c *Connector) rollbackBinding(ctx context.Context, oldThumbprint, newThumbprint string) error {
	port := c.config.Port
	if port == 0 {
		port = 443
	}
	ipAddress := c.config.IPAddress
	if ipAddress == "" {
		ipAddress = "*"
	}
	hostHeader := c.config.BindingInfo
	sniFlag := 0
	if c.config.SNI {
		sniFlag = 1
	}

	var b strings.Builder
	b.WriteString("# CERTCTL_ROLLBACK\n")
	// Always remove the freshly-imported cert. Even when oldThumbprint is
	// empty (first-time deploy), the new cert must come out so the store
	// is left in pre-deploy state.
	fmt.Fprintf(&b,
		"Remove-Item -Path 'Cert:\\LocalMachine\\%s\\%s' -Force -ErrorAction SilentlyContinue; ",
		c.config.CertStore, newThumbprint)
	if oldThumbprint != "" {
		// Re-bind the old cert. Two branches: if Get-WebBinding still
		// returns a binding (the failed bindingScript's Remove-WebBinding
		// either ran and a new binding was partially created, or didn't
		// run), AddSslCertificate against it. If no binding exists,
		// recreate via New-WebBinding + AddSslCertificate.
		fmt.Fprintf(&b,
			"$binding = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d -ErrorAction SilentlyContinue; "+
				"if ($binding) { $binding.AddSslCertificate('%s', '%s'); Write-Output 'REBOUND_EXISTING' } "+
				"else { New-WebBinding -Name '%s' -Protocol 'https' -Port %d -IPAddress '%s' -HostHeader '%s' -SslFlags %d; "+
				"$nb = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d; "+
				"$nb.AddSslCertificate('%s', '%s'); Write-Output 'REBOUND_NEW' }",
			c.config.SiteName, port,
			oldThumbprint, c.config.CertStore,
			c.config.SiteName, port, ipAddress, hostHeader, sniFlag,
			c.config.SiteName, port,
			oldThumbprint, c.config.CertStore)
	} else {
		b.WriteString("Write-Output 'CERT_REMOVED_NO_REBIND'")
	}

	output, err := c.executor.Execute(ctx, b.String())
	if err != nil {
		return fmt.Errorf("rollback script: %w (output: %s)", err, strings.TrimSpace(output))
	}
	c.logger.Info("IIS rollback completed",
		"old_thumbprint", oldThumbprint,
		"new_thumbprint", newThumbprint,
		"output", strings.TrimSpace(output))
	return nil
}

// verifyRollback re-reads Get-WebBinding and confirms the bound thumbprint
// matches oldThumbprint. Returns nil on match; returns a non-fatal warning
// error on mismatch (the rollback's Remove-Item already ran; the verify is
// best-effort confirmation that the rebind succeeded).
//
// Bundle 5 of the 2026-05-02 deployment-target audit.
func (c *Connector) verifyRollback(ctx context.Context, oldThumbprint string) error {
	port := c.config.Port
	if port == 0 {
		port = 443
	}
	script := fmt.Sprintf(
		"# CERTCTL_VERIFY\n"+
			"$check = Get-WebBinding -Name '%s' -Protocol 'https' -Port %d -ErrorAction SilentlyContinue; "+
			"if ($check -and $check.certificateHash -eq '%s') { Write-Output 'VERIFY_OK' } "+
			"elseif ($check) { Write-Output ('VERIFY_FAILED:' + $check.certificateHash) } "+
			"else { Write-Output 'VERIFY_FAILED:NO_BINDING' }",
		c.config.SiteName, port, oldThumbprint)
	output, err := c.executor.Execute(ctx, script)
	if err != nil {
		return fmt.Errorf("verify probe: %w", err)
	}
	out := strings.TrimSpace(output)
	if out == "VERIFY_OK" {
		return nil
	}
	return fmt.Errorf("rollback verification disagreed: %s", out)
}

// NOTE: PFX creation, key parsing, thumbprint computation, and password generation
// have been extracted to the shared certutil package (internal/connector/target/certutil)
// for reuse by WinCertStore and JavaKeystore connectors.
