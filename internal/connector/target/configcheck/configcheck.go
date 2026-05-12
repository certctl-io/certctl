// Package configcheck provides server-side syntactic validation of target
// connector configurations.
//
// Bundle 1 / RT-C1 closure (2026-05-12). Before this package existed, the API
// path (POST/PUT /api/v1/targets) accepted arbitrary `config` JSON without
// invoking any connector's ValidateConfig method. The agent then fetched the
// stored config and executed reload_command / validate_command strings via
// `sh -c` (see internal/connector/target/{nginx,apache,postfix,haproxy,javakeystore,ssh}/...go).
// Net result: an actor with `target.edit` (default on r-operator role per
// migrations/000029_rbac.up.sql:196) could store a shell-injecting config
// and pop the agent host on next deploy.
//
// This package fixes the SERVER side. It is intentionally narrow:
//
//   - It only validates fields that are dangerous at execution time:
//     reload_command, validate_command, restart_command, and equivalent.
//   - It runs validation.ValidateShellCommand on those fields and rejects
//     any shell metacharacter ; | & $ ` ( ) { } < > \ " ' \n \r \x00 .
//   - It does NOT do filesystem checks (cert directory exists, etc.).
//     Those live on the agent in each connector's ValidateConfig method
//     because the relevant filesystem lives on the agent, not the server.
//
// The agent-side defense in depth remains: cmd/agent/main.go calls
// connector.ValidateConfig(ctx, configJSON) after createTargetConnector
// returns and before DeployCertificate. So even if server-side validation
// were bypassed, the agent would still reject the shell-injecting config
// before executing it.
package configcheck

import (
	"encoding/json"
	"fmt"

	"github.com/certctl-io/certctl/internal/validation"
)

// Validate runs server-side syntactic validation against the supplied
// target-config JSON. It returns nil for any unknown targetType (the type
// validity gate is owned by service.isValidTargetType — this function is
// only responsible for the dangerous-field check on known shell-using types).
//
// targetType must match the canonical type strings used by the agent's
// createTargetConnector switch in cmd/agent/main.go (NGINX, Apache, HAProxy,
// Postfix, JavaKeystore, SSH). Other types (F5, IIS, Caddy, Traefik, Envoy,
// AWSACM, AzureKeyVault, KubernetesSecrets, WinCertStore) do not accept
// operator-supplied command strings in their config and are no-ops here.
//
// Per-connector struct shapes are intentionally duplicated as minimal
// anonymous structs here to avoid importing every connector package into
// the service layer. The full Config structs live in the per-connector
// packages and are loaded by the agent at deploy time.
func Validate(targetType string, configJSON json.RawMessage) error {
	if len(configJSON) == 0 {
		return nil
	}

	switch targetType {
	case "NGINX":
		return validateNginx(configJSON)
	case "Apache":
		return validateApache(configJSON)
	case "HAProxy":
		return validateHAProxy(configJSON)
	case "Postfix", "Dovecot":
		return validatePostfix(configJSON)
	case "JavaKeystore":
		return validateJavaKeystore(configJSON)
	case "SSH":
		return validateSSH(configJSON)
	}
	// Other target types do not accept operator-supplied command strings.
	return nil
}

// shellCmdConfig captures the dangerous fields shared by every shell-using
// connector. Specific connector configs may have additional fields not
// listed here; we only validate the subset that flows into sh -c.
type shellCmdConfig struct {
	ReloadCommand   string `json:"reload_command,omitempty"`
	ValidateCommand string `json:"validate_command,omitempty"`
	RestartCommand  string `json:"restart_command,omitempty"`
}

func (c *shellCmdConfig) checkAll(targetType string) error {
	if c.ReloadCommand != "" {
		if err := validation.ValidateShellCommand(c.ReloadCommand); err != nil {
			return fmt.Errorf("%s reload_command: %w", targetType, err)
		}
	}
	if c.ValidateCommand != "" {
		if err := validation.ValidateShellCommand(c.ValidateCommand); err != nil {
			return fmt.Errorf("%s validate_command: %w", targetType, err)
		}
	}
	if c.RestartCommand != "" {
		if err := validation.ValidateShellCommand(c.RestartCommand); err != nil {
			return fmt.Errorf("%s restart_command: %w", targetType, err)
		}
	}
	return nil
}

func validateNginx(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("NGINX config: invalid JSON: %w", err)
	}
	return c.checkAll("NGINX")
}

func validateApache(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("Apache config: invalid JSON: %w", err)
	}
	return c.checkAll("Apache")
}

func validateHAProxy(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("HAProxy config: invalid JSON: %w", err)
	}
	return c.checkAll("HAProxy")
}

func validatePostfix(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("Postfix/Dovecot config: invalid JSON: %w", err)
	}
	return c.checkAll("Postfix/Dovecot")
}

func validateJavaKeystore(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("JavaKeystore config: invalid JSON: %w", err)
	}
	return c.checkAll("JavaKeystore")
}

func validateSSH(b []byte) error {
	var c shellCmdConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("SSH config: invalid JSON: %w", err)
	}
	return c.checkAll("SSH")
}
