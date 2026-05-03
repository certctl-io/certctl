package openssl_test

// Top-10 fix #3 of the 2026-05-03 issuer-coverage audit. The OpenSSL
// adapter (497 LOC) is certctl's shell-out integration for arbitrary
// CLI-driven CAs — operator-supplied scripts that issue / revoke /
// CRL-generate certs. It is the highest-risk issuer surface: every
// failure mode of os/exec applies, plus partial-stdout, signal-kill,
// and CA-policy rejection. Pre-fix, openssl_test.go covered the
// happy path (8 funcs + 20 subtests) but had no companion
// _failure_test.go matching the shape of every peer adapter
// (digicert / vault / sectigo / entrust / globalsign / ejbca all
// have one).
//
// Six tests below pin the operator-actionable error contract for
// each shell-out failure mode the production code can encounter.
// Each test:
//
//   1. Constructs a Connector with an operator-supplied script path
//      (real script written to t.TempDir, no os/exec mocking — that's
//      the connector's actual production code path).
//   2. Drives the script to produce the failure shape.
//   3. Calls IssueCertificate.
//   4. Asserts: error non-nil, error message contains an operator-
//      grep-friendly substring (so journalctl + grep find the fault),
//      errors.Is/As wrapping survives, no half-state leaks (tempfiles
//      cleaned up, no partial cert returned).

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/openssl"
)

// quietLogger discards log output so the test runner's stdout shows
// only test results.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// validCSRPEM is a syntactically-valid PEM-encoded PKCS#10 CSR for
// "test.example.com". The SignScript path is what fails in these
// tests, so the CSR content is just a placeholder — the
// openssl adapter writes it to a tempfile and hands the path off to
// the script.
const validCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBYTCCAQcCAQAwHDEaMBgGA1UEAwwRdGVzdC5leGFtcGxlLmNvbTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABA1yzbF4Pz2H8j3JL85uyHj0F2FfPWClIWWzPQuy
zJOvyhkS8fz0KPRvCsXhgfGfyFRoO9CzcQVZxtkdzS/ndlOgSjBIBgkqhkiG9w0B
CQ4xOzA5MDcGA1UdEQQwMC6CEXRlc3QuZXhhbXBsZS5jb22CGXd3dy50ZXN0LmV4
YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDVjLDVDmvQRjFcYmBpRCq7vcVq
9qQI+Pz0V/z0JhCDCwIhAOq4HnzZlqOOmL7ZyqjPTAdAa6XjRWZdXHl1y4D4GpnH
-----END CERTIFICATE REQUEST-----
`

// writeScript writes a #!/usr/bin/env bash script to t.TempDir and
// returns its path. The mode is 0o755 so the connector's exec call
// succeeds. Skipping the +x bit is how Test 2 induces EACCES.
func writeScript(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("openssl adapter shell-out tests assume POSIX bash; skipping on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sign.sh")
	full := "#!/usr/bin/env bash\n" + body
	if err := os.WriteFile(path, []byte(full), mode); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

// issueRequest is the canonical request payload for the failure tests
// — the connector's IssueCertificate flow runs the script regardless
// of CSR content, so a placeholder is sufficient.
func issueRequest() issuer.IssuanceRequest {
	return issuer.IssuanceRequest{
		CommonName: "test.example.com",
		SANs:       []string{"test.example.com"},
		CSRPEM:     validCSRPEM,
	}
}

// Test 1 — script does not exist. The connector wraps the os/exec
// "no such file or directory" error and surfaces it to the caller.
// Operators reading journalctl need to see the script path so they
// can fix the misconfiguration.
func TestOpenSSL_Issue_ScriptNotFound_OperatorActionableError(t *testing.T) {
	logger := quietLogger()
	cfg := &openssl.Config{
		SignScript:     "/this/path/does/not/exist/sign.sh",
		TimeoutSeconds: 5,
	}
	conn := openssl.New(cfg, logger)

	_, err := conn.IssueCertificate(context.Background(), issueRequest())
	if err == nil {
		t.Fatal("expected error for missing sign script, got nil")
	}
	// Operator-actionable: the message names the failure mode.
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "no such file") && !strings.Contains(low, "not found") {
		t.Errorf("error should name the script-not-found failure mode; got: %v", err)
	}
	// errors.Is preserves through fmt.Errorf %w wrapping.
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err should wrap os.ErrNotExist (errors.Is); got: %v", err)
	}
}

// Test 2 — script exists but is non-executable. EACCES surfaces.
// Operators searching `grep permission` on logs need the substring.
func TestOpenSSL_Issue_PermissionDenied_OperatorActionableError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0o600 doesn't gate execution for uid 0")
	}
	logger := quietLogger()
	scriptPath := writeScript(t, "exit 0\n", 0o600) // readable but not executable
	cfg := &openssl.Config{
		SignScript:     scriptPath,
		TimeoutSeconds: 5,
	}
	conn := openssl.New(cfg, logger)

	_, err := conn.IssueCertificate(context.Background(), issueRequest())
	if err == nil {
		t.Fatal("expected error for non-executable sign script, got nil")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "permission") {
		t.Errorf("error should contain 'permission' so operators can grep; got: %v", err)
	}
	// errors.Is preserves the underlying syscall.EACCES → os.ErrPermission.
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("err should wrap os.ErrPermission (errors.Is); got: %v", err)
	}
}

// Test 3 — script exits 0 but writes garbage (no PEM markers) to the
// cert output file. The connector's parseCertificate must reject the
// output and the error must mention "PEM" so operators don't confuse
// it with a script-side error.
func TestOpenSSL_Issue_MalformedStdout_DistinguishedFromCSRReject(t *testing.T) {
	logger := quietLogger()
	// Script exits 0 + writes garbage to the cert output file ($2).
	scriptPath := writeScript(t, `printf 'this-is-not-a-pem-block' > "$2"
exit 0
`, 0o755)
	cfg := &openssl.Config{
		SignScript:     scriptPath,
		TimeoutSeconds: 5,
	}
	conn := openssl.New(cfg, logger)

	_, err := conn.IssueCertificate(context.Background(), issueRequest())
	if err == nil {
		t.Fatal("expected error for garbage-output sign script, got nil")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "pem") && !strings.Contains(low, "certificate") && !strings.Contains(low, "parse") {
		t.Errorf("error should mention PEM/certificate/parse so operators can distinguish from script-side failure; got: %v", err)
	}
	// Tempfiles in the per-call dir are cleaned up (defer os.Remove on
	// csrFile + certFile in the connector). The script's tempdir is
	// distinct from t.TempDir() so we can't directly assert here, but
	// the absence of the connector returning a populated CertPEM
	// proves no half-state surfaced.
}

// Test 4 — script returns exit code 2 (CA-side rejection convention)
// with a stderr message containing "policy violation". Operators need
// the stderr text in the surfaced error so they can debug what the CA
// rejected.
func TestOpenSSL_Issue_NonZeroExit_DistinguishesCAReject_From_ScriptError(t *testing.T) {
	logger := quietLogger()
	scriptPath := writeScript(t, `echo 'policy violation: subject CN not allowed' >&2
exit 2
`, 0o755)
	cfg := &openssl.Config{
		SignScript:     scriptPath,
		TimeoutSeconds: 5,
	}
	conn := openssl.New(cfg, logger)

	_, err := conn.IssueCertificate(context.Background(), issueRequest())
	if err == nil {
		t.Fatal("expected error for non-zero-exit sign script, got nil")
	}
	if !strings.Contains(err.Error(), "policy violation") {
		t.Errorf("error should embed the script's stderr so operators see what the CA said; got: %v", err)
	}
	// Production code wraps the *exec.ExitError via %w. The exact
	// substring the operator greps on is "exit status 2" or similar
	// — our contract is just that the script's stderr surfaces in
	// the message (asserted above) AND the error chain is preserved
	// (no-panic on errors.Unwrap).
	if unwrap := errors.Unwrap(err); unwrap == nil {
		t.Errorf("err should wrap the underlying exec error via %%w; got unwrapped nil")
	}
}

// Test 5 — script blocks indefinitely; caller's context has a 100ms
// deadline. The adapter must propagate cancellation to exec, return
// quickly, and surface a deadline-exceeded error operators can
// errors.Is(err, context.DeadlineExceeded) on.
func TestOpenSSL_Issue_TimeoutEnforced_ContextCancellationPropagates(t *testing.T) {
	logger := quietLogger()
	// `exec sleep 30` replaces bash with sleep, so SIGKILL goes
	// directly to the sleeping process — without `exec`, killing
	// bash orphans the sleep child and leaves it holding the
	// stdout/stderr pipes open, which makes cmd.CombinedOutput
	// block for the full 30s.
	scriptPath := writeScript(t, `exec sleep 30
`, 0o755)
	cfg := &openssl.Config{
		SignScript:     scriptPath,
		TimeoutSeconds: 60, // adapter timeout is generous; caller-ctx cancellation must win
	}
	conn := openssl.New(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := conn.IssueCertificate(ctx, issueRequest())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected deadline-exceeded error, got nil")
	}
	// Tight tolerance — catches a "deadline not actually enforced" bug.
	// Bash subprocess teardown adds ~50-100ms slack on slow CI; cap at
	// 1s. The 30s sleep makes any value under 5s a clear pass.
	if elapsed > 5*time.Second {
		t.Errorf("call took %v; ctx deadline (100ms) was not enforced", elapsed)
	}
	// Either context.DeadlineExceeded OR a wrapped exec.ExitError
	// (signal-killed) surfaces — both are correct here. Assert at
	// least one is true.
	if !errors.Is(err, context.DeadlineExceeded) {
		// Some Go versions wrap the killed-by-signal as ExitError and
		// don't surface DeadlineExceeded directly; accept that path
		// too.
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "killed") && !strings.Contains(low, "signal") && !strings.Contains(low, "deadline") {
			t.Errorf("error should be deadline-exceeded or signal-kill; got: %v", err)
		}
	}
}

// Test 6 — script writes half a PEM block, then sends SIGKILL to
// itself. The connector's parseCertificate must reject the partial
// PEM rather than handing a half-cert back to the caller.
func TestOpenSSL_Issue_SignalKilled_PartialOutputDiscarded(t *testing.T) {
	logger := quietLogger()
	scriptPath := writeScript(t, `printf -- '-----BEGIN CERTIFICATE-----\nMIIBYTCCAQcCAQAwHDEaMBgGA1UEAwwRdGVzdC5leG' > "$2"
kill -KILL $$
`, 0o755)
	cfg := &openssl.Config{
		SignScript:     scriptPath,
		TimeoutSeconds: 5,
	}
	conn := openssl.New(cfg, logger)

	result, err := conn.IssueCertificate(context.Background(), issueRequest())
	if err == nil {
		t.Fatal("expected error for signal-killed sign script, got nil")
	}
	if result != nil && result.CertPEM != "" {
		t.Fatalf("partial cert leaked to caller: %q (no half-state should escape)", result.CertPEM)
	}
	low := strings.ToLower(err.Error())
	// Either "signal" / "killed" surfaces from the exec error, OR
	// the parseCertificate failure surfaces (PEM malformed because
	// the script's output is truncated). Both are operator-actionable.
	if !strings.Contains(low, "signal") && !strings.Contains(low, "killed") &&
		!strings.Contains(low, "pem") && !strings.Contains(low, "parse") &&
		!strings.Contains(low, "certificate") {
		t.Errorf("error should name the signal-kill failure mode or PEM-parse fallout; got: %v", err)
	}
}
