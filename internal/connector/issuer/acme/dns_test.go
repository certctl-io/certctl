package acme_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	acmeissuer "github.com/shankar0123/certctl/internal/connector/issuer/acme"
)

func TestScriptDNSSolver(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("Present_Success", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "dns-record.txt")

		// Create a script that writes the DNS record to a file
		scriptPath := filepath.Join(tmpDir, "present.sh")
		script := `#!/bin/sh
echo "DOMAIN=$CERTCTL_DNS_DOMAIN FQDN=$CERTCTL_DNS_FQDN VALUE=$CERTCTL_DNS_VALUE TOKEN=$CERTCTL_DNS_TOKEN" > ` + outputFile + `
`
		if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
			t.Fatalf("Failed to create script: %v", err)
		}

		solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
		err := solver.Present(ctx, "example.com", "test-token", "test-key-auth")
		if err != nil {
			t.Fatalf("Present failed: %v", err)
		}

		// Verify the script was executed with correct env vars
		output, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		expected := "DOMAIN=example.com FQDN=_acme-challenge.example.com VALUE=test-key-auth TOKEN=test-token\n"
		if string(output) != expected {
			t.Errorf("Script output mismatch:\ngot:  %q\nwant: %q", string(output), expected)
		}
	})

	t.Run("Present_ScriptFailure", func(t *testing.T) {
		tmpDir := t.TempDir()
		scriptPath := filepath.Join(tmpDir, "fail.sh")
		script := `#!/bin/sh
echo "error: something went wrong" >&2
exit 1
`
		os.WriteFile(scriptPath, []byte(script), 0755)

		solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
		err := solver.Present(ctx, "example.com", "token", "keyauth")
		if err == nil {
			t.Fatal("Expected error from failing script")
		}
		t.Logf("Correctly got error: %v", err)
	})

	t.Run("Present_NoScript", func(t *testing.T) {
		solver := acmeissuer.NewScriptDNSSolver("", "", logger)
		err := solver.Present(ctx, "example.com", "token", "keyauth")
		if err == nil {
			t.Fatal("Expected error when no script is configured")
		}
	})

	t.Run("CleanUp_Success", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "cleanup.txt")

		scriptPath := filepath.Join(tmpDir, "cleanup.sh")
		script := `#!/bin/sh
echo "cleaned $CERTCTL_DNS_FQDN" > ` + outputFile + `
`
		os.WriteFile(scriptPath, []byte(script), 0755)

		solver := acmeissuer.NewScriptDNSSolver("", scriptPath, logger)
		err := solver.CleanUp(ctx, "example.com", "token", "keyauth")
		if err != nil {
			t.Fatalf("CleanUp failed: %v", err)
		}

		output, _ := os.ReadFile(outputFile)
		expected := "cleaned _acme-challenge.example.com\n"
		if string(output) != expected {
			t.Errorf("Cleanup output mismatch: got %q, want %q", string(output), expected)
		}
	})

	t.Run("CleanUp_NoScript_Noop", func(t *testing.T) {
		solver := acmeissuer.NewScriptDNSSolver("", "", logger)
		// Should not error — cleanup without a script is a no-op
		err := solver.CleanUp(ctx, "example.com", "token", "keyauth")
		if err != nil {
			t.Fatalf("CleanUp without script should not error: %v", err)
		}
	})

	t.Run("Present_NonexistentScript", func(t *testing.T) {
		solver := acmeissuer.NewScriptDNSSolver("/nonexistent/script.sh", "", logger)
		err := solver.Present(ctx, "example.com", "token", "keyauth")
		if err == nil {
			t.Fatal("Expected error for nonexistent script")
		}
	})
}

func TestScriptDNSSolver_PresentPersist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("PresentPersist_Success", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "persist-record.txt")

		scriptPath := filepath.Join(tmpDir, "present.sh")
		script := `#!/bin/sh
echo "DOMAIN=$CERTCTL_DNS_DOMAIN FQDN=$CERTCTL_DNS_FQDN VALUE=$CERTCTL_DNS_VALUE TOKEN=$CERTCTL_DNS_TOKEN" > ` + outputFile + `
`
		if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
			t.Fatalf("Failed to create script: %v", err)
		}

		solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
		err := solver.PresentPersist(ctx, "example.com", "test-token", "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123")
		if err != nil {
			t.Fatalf("PresentPersist failed: %v", err)
		}

		output, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		// Verify _validation-persist prefix (not _acme-challenge)
		expected := "DOMAIN=example.com FQDN=_validation-persist.example.com VALUE=letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123 TOKEN=test-token\n"
		if string(output) != expected {
			t.Errorf("Script output mismatch:\ngot:  %q\nwant: %q", string(output), expected)
		}
	})

	t.Run("PresentPersist_NoScript", func(t *testing.T) {
		solver := acmeissuer.NewScriptDNSSolver("", "", logger)
		err := solver.PresentPersist(ctx, "example.com", "token", "letsencrypt.org; accounturi=https://example.com/acct/1")
		if err == nil {
			t.Fatal("Expected error when no script is configured")
		}
	})

	t.Run("PresentPersist_ScriptFailure", func(t *testing.T) {
		tmpDir := t.TempDir()
		scriptPath := filepath.Join(tmpDir, "fail.sh")
		script := `#!/bin/sh
echo "error: DNS API failure" >&2
exit 1
`
		os.WriteFile(scriptPath, []byte(script), 0755)

		solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
		err := solver.PresentPersist(ctx, "example.com", "token", "letsencrypt.org; accounturi=https://example.com/acct/1")
		if err == nil {
			t.Fatal("Expected error from failing script")
		}
	})

	t.Run("PresentPersist_WildcardDomain", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "persist-wildcard.txt")

		scriptPath := filepath.Join(tmpDir, "present.sh")
		script := `#!/bin/sh
echo "FQDN=$CERTCTL_DNS_FQDN" > ` + outputFile + `
`
		os.WriteFile(scriptPath, []byte(script), 0755)

		solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
		// For *.example.com, the persist record should be at _validation-persist.example.com
		err := solver.PresentPersist(ctx, "example.com", "token", "letsencrypt.org; accounturi=https://example.com/acct/1")
		if err != nil {
			t.Fatalf("PresentPersist failed for wildcard base domain: %v", err)
		}

		output, _ := os.ReadFile(outputFile)
		expected := "FQDN=_validation-persist.example.com\n"
		if string(output) != expected {
			t.Errorf("FQDN mismatch: got %q, want %q", string(output), expected)
		}
	})
}

// Security tests for DNS injection prevention

func TestScriptDNSSolver_Present_RejectInvalidDomain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "present.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0"), 0755)

	tests := []struct {
		name   string
		domain string
	}{
		{
			name:   "domain with command injection semicolon",
			domain: "example.com; rm -rf /",
		},
		{
			name:   "domain with backtick injection",
			domain: "example.com`whoami`",
		},
		{
			name:   "domain with command substitution",
			domain: "example.com$(whoami)",
		},
		{
			name:   "domain with pipe injection",
			domain: "example.com | cat /etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
			err := solver.Present(ctx, tt.domain, "test-token", "test-key-auth")
			if err == nil {
				t.Fatalf("expected error for invalid domain: %s", tt.domain)
			}
		})
	}
}

func TestScriptDNSSolver_Present_RejectInvalidToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "present.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0"), 0755)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "token with command injection",
			token: "token$(whoami)",
		},
		{
			name:  "token with backtick injection",
			token: "token`id`",
		},
		{
			name:  "token with semicolon",
			token: "token;malicious",
		},
		{
			name:  "token with pipe",
			token: "token|cat",
		},
		{
			name:  "token with space",
			token: "token value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
			err := solver.Present(ctx, "example.com", tt.token, "test-key-auth")
			if err == nil {
				t.Fatalf("expected error for invalid token: %s", tt.token)
			}
		})
	}
}

func TestScriptDNSSolver_CleanUp_RejectInvalidDomain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "cleanup.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0"), 0755)

	solver := acmeissuer.NewScriptDNSSolver("", scriptPath, logger)
	err := solver.CleanUp(ctx, "example.com; rm -rf /", "test-token", "test-key-auth")
	if err == nil {
		t.Fatal("expected error for command injection in domain")
	}
}

func TestScriptDNSSolver_PresentPersist_RejectInvalidDomain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "present.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0"), 0755)

	solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
	err := solver.PresentPersist(ctx, "example.com`whoami`", "test-token", "letsencrypt.org; accounturi=https://example.com/acct/1")
	if err == nil {
		t.Fatal("expected error for command injection in domain")
	}
}

func TestScriptDNSSolver_PresentPersist_RejectInvalidToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "present.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0"), 0755)

	solver := acmeissuer.NewScriptDNSSolver(scriptPath, "", logger)
	err := solver.PresentPersist(ctx, "example.com", "token$(whoami)", "letsencrypt.org; accounturi=https://example.com/acct/1")
	if err == nil {
		t.Fatal("expected error for command injection in token")
	}
}
