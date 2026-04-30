package iis

import (
	"context"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMConfig holds WinRM connection settings for remote IIS management.
// Used when Mode is "winrm" — the proxy agent connects to a remote Windows
// server over WinRM and executes PowerShell commands remotely.
type WinRMConfig struct {
	Host     string `json:"winrm_host"`     // WinRM target hostname or IP (required)
	Port     int    `json:"winrm_port"`     // WinRM port (default 5985 for HTTP, 5986 for HTTPS)
	Username string `json:"winrm_username"` // Windows user (e.g., "Administrator")
	Password string `json:"winrm_password"` // Windows password
	UseHTTPS bool   `json:"winrm_https"`    // Use HTTPS (port 5986) instead of HTTP (port 5985)
	Insecure bool   `json:"winrm_insecure"` // Skip TLS certificate verification (for self-signed certs)
	Timeout  int    `json:"winrm_timeout"`  // Operation timeout in seconds (default 60)
}

// winrmExecutor implements PowerShellExecutor by running PowerShell commands
// on a remote Windows server via WinRM. This enables the proxy agent pattern:
// a Linux agent in the same network zone manages Windows IIS servers remotely.
type winrmExecutor struct {
	client *winrm.Client
}

// newWinRMExecutor creates a WinRM client and returns a PowerShellExecutor.
func newWinRMExecutor(cfg *WinRMConfig) (*winrmExecutor, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("winrm_host is required for WinRM mode")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("winrm_username is required for WinRM mode")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("winrm_password is required for WinRM mode")
	}

	port := cfg.Port
	if port == 0 {
		if cfg.UseHTTPS {
			port = 5986
		} else {
			port = 5985
		}
	}

	timeout := time.Duration(cfg.Timeout) * time.Second
	if cfg.Timeout == 0 {
		timeout = 60 * time.Second
	}

	endpoint := winrm.NewEndpoint(
		cfg.Host,
		port,
		cfg.UseHTTPS,
		cfg.Insecure,
		nil, // CA cert
		nil, // Client cert
		nil, // Client key
		timeout,
	)

	client, err := winrm.NewClient(endpoint, cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create WinRM client: %w", err)
	}

	return &winrmExecutor{client: client}, nil
}

// Execute runs a PowerShell script on the remote Windows server via WinRM.
// The script is wrapped in powershell.exe invocation on the remote side.
func (e *winrmExecutor) Execute(ctx context.Context, script string) (string, error) {
	// RunPSWithContext returns (stdout, stderr, exitCode, error)
	stdout, stderr, exitCode, err := e.client.RunPSWithContext(ctx, script)
	if err != nil {
		return stdout + stderr, fmt.Errorf("WinRM command failed: %w", err)
	}
	if exitCode != 0 {
		return stdout + stderr, fmt.Errorf("PowerShell exited with code %d: %s", exitCode, stdout+stderr)
	}

	return stdout, nil
}
