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
