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
	"os"
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

// DeployCertificate imports a certificate into the Windows Certificate Store.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if request.KeyPEM == "" {
		return nil, fmt.Errorf("private key is required for Windows Certificate Store import")
	}

	c.logger.Info("deploying certificate to Windows Certificate Store",
		"store_name", c.config.StoreName,
		"store_location", c.config.StoreLocation)

	// Generate transient PFX password
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
		return nil, fmt.Errorf("PowerShell import failed: %s: %w", output, err)
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
		sb.WriteString(fmt.Sprintf("  $subject = $cert.Subject\n"))
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

// tempFileForPFX is a helper used only in WinRM mode — writes PFX to temp file.
// In WinRM mode, the PFX is base64-encoded and transferred in the PowerShell script
// (same pattern as IIS WinRM deployment).
func tempFileForPFX(pfxData []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "certctl-pfx-*.pfx")
	if err != nil {
		return "", nil, fmt.Errorf("create temp PFX file: %w", err)
	}
	if _, err := f.Write(pfxData); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("write temp PFX file: %w", err)
	}
	f.Close()
	cleanup := func() { os.Remove(f.Name()) }
	return f.Name(), cleanup, nil
}
