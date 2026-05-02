package envoy_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/envoy"
	"github.com/shankar0123/certctl/internal/deploy"
	"github.com/shankar0123/certctl/internal/tlsprobe"
)

// Phase 7 of the deploy-hardening I master bundle: atomic-write
// retrofit for Envoy. Envoy file watcher (SDS) auto-reloads on
// rename, so the load-bearing change is the os.WriteFile ->
// deploy.AtomicWriteFile swap.

const certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
const keyA = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestEnvoy_Atomic_HappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file missing: %s", p)
		}
	}
}

func TestEnvoy_Atomic_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
		}
	}
	if !found {
		t.Error("no backup created")
	}
}

func TestEnvoy_Atomic_KeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestEnvoy_Atomic_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA+"\n"), 0644)
	cfg := envoy.Config{CertDir: dir, CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			t.Errorf("backup created on idempotent skip: %s", e.Name())
		}
	}
}

func TestEnvoy_ValidateOnly_Sentinel(t *testing.T) {
	cfg := envoy.Config{CertDir: t.TempDir(), CertFilename: "cert.pem", KeyFilename: "key.pem"}
	c := envoy.New(&cfg, newTestLogger())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bundle 3 (deployment-target audit 2026-05-02): SDS atomicity + post-deploy
// watcher pickup confirmation.
// ---------------------------------------------------------------------------

// certPEMFingerprint mirrors envoy.certPEMToFingerprint (which is package-
// private). Computes SHA-256 of the first PEM block's DER bytes; matches what
// tlsprobe.CertFingerprint emits for a served leaf cert.
func certPEMFingerprint(t *testing.T, pemBytes string) string {
	t.Helper()
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	bi := strings.Index(pemBytes, begin)
	if bi < 0 {
		t.Fatalf("no CERTIFICATE block in PEM")
	}
	rest := pemBytes[bi+len(begin):]
	ei := strings.Index(rest, end)
	if ei < 0 {
		t.Fatalf("no END CERTIFICATE in PEM")
	}
	body := strings.TrimSpace(rest[:ei])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// TestEnvoy_Atomic_SDSConfigWriteIsAtomic pins the wiring change at envoy.go's
// writeSDSConfig — pre-Bundle-3 the SDS JSON went through os.WriteFile (no
// backup, torn-write hazard). Post-fix it goes through deploy.AtomicWriteFile,
// which produces a sibling backup with deploy.BackupSuffix when an existing
// SDS JSON is replaced.
func TestEnvoy_Atomic_SDSConfigWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	sdsPath := filepath.Join(dir, "sds.json")
	// Pre-write a sentinel SDS JSON so the connector's write produces
	// a backup we can assert on.
	if err := os.WriteFile(sdsPath, []byte(`{"resources":[{"name":"old"}]}`), 0644); err != nil {
		t.Fatalf("seed sds: %v", err)
	}
	cfg := envoy.Config{
		CertDir:      dir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
		SDSConfig:    true,
	}
	c := envoy.New(&cfg, newTestLogger())
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err != nil || !res.Success {
		t.Fatalf("deploy: err=%v success=%v", err, res != nil && res.Success)
	}

	// SDS JSON should be the new bytes (i.e. NOT match the sentinel).
	got, err := os.ReadFile(sdsPath)
	if err != nil {
		t.Fatalf("read sds: %v", err)
	}
	if strings.Contains(string(got), `"old"`) {
		t.Errorf("SDS JSON not replaced; still contains sentinel")
	}
	if !strings.Contains(string(got), "server_cert") {
		t.Errorf("SDS JSON missing expected resource name; got %s", string(got))
	}

	// AtomicWriteFile produces a backup file with deploy.BackupSuffix
	// when replacing an existing destination. Pre-Bundle-3 (os.WriteFile
	// path) no backup would exist for sds.json.
	entries, _ := os.ReadDir(dir)
	foundBak := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sds.json"+deploy.BackupSuffix) {
			foundBak = true
		}
	}
	if !foundBak {
		t.Errorf("no SDS JSON backup created — atomic-write wiring missing? entries=%v", entryNames(entries))
	}
}

// TestEnvoy_Atomic_WatcherPickupRetries pins the retry/backoff loop in the
// post-deploy verify path. Stub the probe so attempts 1+2 return the wrong
// fingerprint and attempt 3 returns the correct one — DeployCertificate must
// succeed and the probe must have been called exactly 3 times.
func TestEnvoy_Atomic_WatcherPickupRetries(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{
		CertDir:      dir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
		PostDeployVerify: &envoy.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "envoy.test.invalid:443",
			Timeout:  100 * time.Millisecond,
		},
		PostDeployVerifyAttempts: 3,
		PostDeployVerifyBackoff:  time.Millisecond, // tight loop for tests
	}
	c := envoy.New(&cfg, newTestLogger())

	want := certPEMFingerprint(t, certA)
	var calls atomic.Int64
	c.SetTestProbe(func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		n := calls.Add(1)
		if n < 3 {
			return tlsprobe.ProbeResult{Success: true, Fingerprint: "deadbeef"}
		}
		return tlsprobe.ProbeResult{Success: true, Fingerprint: want}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err != nil {
		t.Fatalf("deploy returned error after retries should have succeeded: %v", err)
	}
	if !res.Success {
		t.Fatalf("deploy.Success=false; message=%s", res.Message)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("probe called %d times, want 3", got)
	}
}

// TestEnvoy_Atomic_WatcherPickupAllAttemptsFail_RollsBack pins the verify-
// failure rollback path. Pre-write sentinel cert + key; stub probe to always
// return the wrong fingerprint; assert DeployCertificate returns a wrapped
// error AND the destination files contain the sentinel bytes (restored from
// backups).
func TestEnvoy_Atomic_WatcherPickupAllAttemptsFail_RollsBack(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	sentCert := []byte("SENTINEL-CERT-BYTES")
	sentKey := []byte("SENTINEL-KEY-BYTES")
	if err := os.WriteFile(certPath, sentCert, 0644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(keyPath, sentKey, 0600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	cfg := envoy.Config{
		CertDir:      dir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
		PostDeployVerify: &envoy.PostDeployVerifyConfig{
			Enabled:  true,
			Endpoint: "envoy.test.invalid:443",
			Timeout:  100 * time.Millisecond,
		},
		PostDeployVerifyAttempts: 2,
		PostDeployVerifyBackoff:  time.Millisecond,
	}
	c := envoy.New(&cfg, newTestLogger())
	c.SetTestProbe(func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "deadbeef"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err == nil {
		t.Fatalf("expected verify-mismatch error, got nil; res=%+v", res)
	}
	if res.Success {
		t.Errorf("expected Success=false on verify failure")
	}
	if !strings.Contains(strings.ToLower(res.Message), "verify") {
		t.Errorf("expected message to mention verify; got %q", res.Message)
	}

	// Both files must be restored to sentinel bytes.
	gotCert, _ := os.ReadFile(certPath)
	if string(gotCert) != string(sentCert) {
		t.Errorf("cert not restored on rollback; got %q want %q", string(gotCert), string(sentCert))
	}
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != string(sentKey) {
		t.Errorf("key not restored on rollback; got %q want %q", string(gotKey), string(sentKey))
	}
}

// TestEnvoy_Atomic_PostDeployVerifyDisabledByDefault pins the opt-in default.
// A Config with no PostDeployVerify set must NOT call the probe — preserving
// pre-Bundle-3 behaviour for callers that don't opt in.
func TestEnvoy_Atomic_PostDeployVerifyDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := envoy.Config{
		CertDir:      dir,
		CertFilename: "cert.pem",
		KeyFilename:  "key.pem",
		// PostDeployVerify intentionally nil.
	}
	c := envoy.New(&cfg, newTestLogger())
	var calls atomic.Int64
	c.SetTestProbe(func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult {
		calls.Add(1)
		return tlsprobe.ProbeResult{Success: false, Error: "probe should not be called"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err != nil || !res.Success {
		t.Fatalf("deploy: err=%v success=%v", err, res != nil && res.Success)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("probe called %d times when PostDeployVerify is nil; want 0", got)
	}
}

// entryNames is a tiny helper for log-friendly directory listings in test
// failure messages.
func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
