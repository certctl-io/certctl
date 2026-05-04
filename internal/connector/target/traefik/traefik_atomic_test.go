package traefik_test

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

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/traefik"
	"github.com/certctl-io/certctl/internal/deploy"
	"github.com/certctl-io/certctl/internal/tlsprobe"
)

// Phase 7 of the deploy-hardening I master bundle: atomic + verify
// for Traefik. No reload command (Traefik watches via inotify);
// post-deploy TLS verify is the load-bearing safety check.

const certA = "-----BEGIN CERTIFICATE-----\nQUxQSEEtQ0VSVA==\n-----END CERTIFICATE-----\n"
const keyA = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func fingerprintOfPEM(pem string) string {
	beg := strings.Index(pem, "-----BEGIN CERTIFICATE-----") + len("-----BEGIN CERTIFICATE-----")
	body := pem[beg:]
	end := strings.Index(body, "-----END CERTIFICATE-----")
	body = strings.TrimSpace(body[:end])
	body = strings.ReplaceAll(body, "\n", "")
	der, _ := base64.StdEncoding.DecodeString(body)
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func newC(_ *testing.T, dir string) *traefik.Connector {
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	return c
}

func TestTraefik_Atomic_Happy(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_VerifyMatch(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(certA)}
	})
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_VerifyMismatch_Rollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD\n"), 0644)
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "0000"}
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if got, _ := os.ReadFile(cert); string(got) != "OLD\n" {
		t.Errorf("cert after rollback = %q, want OLD", got)
	}
}

func TestTraefik_Atomic_VerifyDialTimeout(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: false, Error: "timeout"}
	})
	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestTraefik_Atomic_Idempotency(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte(certA+"\n"), 0644)
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
	if res.Metadata["idempotent"] != "true" {
		t.Errorf("idempotent flag = %q", res.Metadata["idempotent"])
	}
}

func TestTraefik_Atomic_DefaultKeyMode_0600(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0600 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestTraefik_Atomic_KeyModeOverride(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem", KeyFileMode: 0640,
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA, KeyPEM: keyA})
	stat, _ := os.Stat(filepath.Join(dir, "key.pem"))
	if stat.Mode().Perm() != 0640 {
		t.Errorf("key mode = %#o", stat.Mode().Perm())
	}
}

func TestTraefik_Atomic_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("OLD"), 0644)
	c := newC(t, dir)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), deploy.BackupSuffix) {
			found = true
		}
	}
	if !found {
		t.Error("no backup")
	}
}

func TestTraefik_Atomic_NoChain(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if err != nil || !res.Success {
		t.Fatal(err)
	}
}

func TestTraefik_Atomic_NoKey(t *testing.T) {
	dir := t.TempDir()
	c := newC(t, dir)
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); err == nil {
		t.Error("key written despite empty KeyPEM")
	}
}

func TestTraefik_ValidateOnly_Sentinel(t *testing.T) {
	c := newC(t, t.TempDir())
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestTraefik_Atomic_VerifyDisabled(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerify: &traefik.PostDeployVerifyConfig{Enabled: false, Endpoint: "h:443"},
	}, quietLogger())
	var n int32
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		atomic.AddInt32(&n, 1)
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
	})
	c.DeployCertificate(context.Background(), target.DeploymentRequest{CertPEM: certA})
	if n != 0 {
		t.Errorf("probe called %d times despite Enabled=false", n)
	}
}

// ---------------------------------------------------------------------------
// Bundle 4 (deployment-target audit 2026-05-02): single-Plan deploy.Apply
// refactor regression guards.
// ---------------------------------------------------------------------------

// TestTraefik_Atomic_KeyWriteFails_CertRollsBack is the regression guard for
// the original two-AtomicWriteFile bug. Pre-Bundle-4, a key-write failure
// after a successful cert write left the cert orphaned (the inline best-
// effort cert rollback was incomplete; the dedicated rollbackCertAndKey
// only restored the cert). Post-Bundle-4, deploy.Apply makes both writes
// all-or-nothing — if the key path is unwritable, Apply rejects the plan
// before any disk mutation OR rolls back the cert mid-rename.
//
// We trigger the failure via a key path inside a read-only subdirectory.
// The cert path is in the writable root — pre-fix the cert would land,
// post-fix Apply backs out atomically.
func TestTraefik_Atomic_KeyWriteFails_CertRollsBack(t *testing.T) {
	dir := t.TempDir()

	// Pre-write sentinel cert bytes. After a failed deploy these
	// must remain unchanged.
	certPath := filepath.Join(dir, "cert.pem")
	const sentinel = "SENTINEL-CERT\n"
	if err := os.WriteFile(certPath, []byte(sentinel), 0644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	// Make the key destination unwritable: a read-only subdir.
	keyDir := filepath.Join(dir, "ro-keys")
	if err := os.Mkdir(keyDir, 0500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	defer os.Chmod(keyDir, 0700) // restore so t.TempDir cleanup can rm

	c := traefik.New(&traefik.Config{
		CertDir:  dir,
		CertFile: "cert.pem",
		KeyFile:  "ro-keys/key.pem", // unwritable target
	}, quietLogger())

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err == nil {
		t.Fatalf("expected error from unwritable key path; res=%+v", res)
	}

	// Cert on disk must still be the sentinel — Apply's all-files
	// atomicity guarantee. Pre-Bundle-4 this assertion would have
	// failed because cert was already written before the key error.
	got, _ := os.ReadFile(certPath)
	if string(got) != sentinel {
		t.Errorf("cert clobbered despite key-write failure: got %q want %q", string(got), sentinel)
	}
}

// TestTraefik_Atomic_AllFilesIdempotent pins the all-files SHA-256 short-
// circuit. Pre-Bundle-4 idempotency was per-file (certRes.Idempotent only)
// — a cert that matched but a key that was new would get reported as
// idempotent skip even though the key actually changed. Post-fix
// res.SkippedAsIdempotent is true only when EVERY File matched; the
// negative case (cert match, key new) flips it to false and still runs
// the verify path.
func TestTraefik_Atomic_AllFilesIdempotent(t *testing.T) {
	t.Run("both_match_skips", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		// Pre-write bytes that match exactly what Traefik would write
		// (cert + "\n").
		if err := os.WriteFile(certPath, []byte(certA+"\n"), 0644); err != nil {
			t.Fatalf("seed cert: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte(keyA), 0600); err != nil {
			t.Fatalf("seed key: %v", err)
		}

		var probeCalls int32
		c := traefik.New(&traefik.Config{
			CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
			PostDeployVerify: &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
		}, quietLogger())
		c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
			atomic.AddInt32(&probeCalls, 1)
			return tlsprobe.ProbeResult{Success: true, Fingerprint: "x"}
		})

		res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
			CertPEM: certA,
			KeyPEM:  keyA,
		})
		if err != nil || !res.Success {
			t.Fatalf("deploy: err=%v success=%v", err, res != nil && res.Success)
		}
		if res.Metadata["idempotent"] != "true" {
			t.Errorf("expected idempotent=true when both files match; got %q", res.Metadata["idempotent"])
		}
		if probeCalls != 0 {
			t.Errorf("probe called %d times on idempotent skip; want 0", probeCalls)
		}
	})

	t.Run("cert_match_key_new_runs_verify", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		// Pre-write cert matching what Traefik would write; do NOT
		// pre-write key — it'll be new.
		if err := os.WriteFile(certPath, []byte(certA+"\n"), 0644); err != nil {
			t.Fatalf("seed cert: %v", err)
		}

		var probeCalls int32
		c := traefik.New(&traefik.Config{
			CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
			PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
			PostDeployVerifyAttempts: 1,
		}, quietLogger())
		c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
			atomic.AddInt32(&probeCalls, 1)
			return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(certA)}
		})

		res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
			CertPEM: certA,
			KeyPEM:  keyA,
		})
		if err != nil || !res.Success {
			t.Fatalf("deploy: err=%v success=%v", err, res != nil && res.Success)
		}
		if res.Metadata["idempotent"] == "true" {
			t.Errorf("expected idempotent=false when key is new; got true (per-file idempotency leaked through?)")
		}
		if probeCalls != 1 {
			t.Errorf("probe should fire when key is new; called %d times want 1", probeCalls)
		}
	})
}

// TestTraefik_Atomic_VerifyMismatch_BothFilesRollBack pins all-files rollback
// on verify failure. Pre-Bundle-4 rollbackCertAndKey only restored the cert;
// the key was left in whatever state the deploy reached. Post-fix
// restoreFromBackups iterates res.BackupPaths and rewrites EVERY destination
// from its backup.
func TestTraefik_Atomic_VerifyMismatch_BothFilesRollBack(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	const sentinelCert = "SENTINEL-CERT\n"
	const sentinelKey = "SENTINEL-KEY\n"
	if err := os.WriteFile(certPath, []byte(sentinelCert), 0644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(sentinelKey), 0600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts: 1,
		PostDeployVerify:         &traefik.PostDeployVerifyConfig{Enabled: true, Endpoint: "h:443"},
	}, quietLogger())
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		return tlsprobe.ProbeResult{Success: true, Fingerprint: "deadbeef"}
	})

	_, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA,
		KeyPEM:  keyA,
	})
	if err == nil {
		t.Fatal("expected verify-mismatch error")
	}

	// Both files must be restored to sentinel bytes — pre-Bundle-4
	// rollbackCertAndKey only restored the cert; the key would still
	// be the new bytes.
	gotCert, _ := os.ReadFile(certPath)
	if string(gotCert) != sentinelCert {
		t.Errorf("cert not restored on rollback: got %q want %q", string(gotCert), sentinelCert)
	}
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != sentinelKey {
		t.Errorf("key not restored on rollback (Bundle 4 regression: pre-fix this would fail because rollbackCertAndKey ignored the key): got %q want %q", string(gotKey), sentinelKey)
	}
}

// TestTraefik_VerifyExponentialBackoff_GrowsBetweenAttempts: post-deploy verify
// retries with exponential backoff (Top-10 fix #8). 4 attempts, 10ms initial,
// 80ms cap; expected gaps 10ms, 20ms, 40ms.
func TestTraefik_VerifyExponentialBackoff_GrowsBetweenAttempts(t *testing.T) {
	dir := t.TempDir()
	c := traefik.New(&traefik.Config{
		CertDir: dir, CertFile: "cert.pem", KeyFile: "key.pem",
		PostDeployVerifyAttempts:   4,
		PostDeployVerifyBackoff:    10 * time.Millisecond,
		PostDeployVerifyMaxBackoff: 80 * time.Millisecond,
		PostDeployVerify: &traefik.PostDeployVerifyConfig{
			Enabled: true, Endpoint: "h:443", Timeout: 100 * time.Millisecond,
		},
	}, quietLogger())

	var callTimes []time.Time
	probeCallCount := atomic.Int32{}
	c.SetTestProbe(func(_ context.Context, _ string, _ time.Duration) tlsprobe.ProbeResult {
		callTimes = append(callTimes, time.Now())
		count := probeCallCount.Add(1)
		if count == 4 {
			return tlsprobe.ProbeResult{Success: true, Fingerprint: fingerprintOfPEM(certA)}
		}
		return tlsprobe.ProbeResult{Success: false, Error: "cert not yet deployed"}
	})

	res, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM: certA, KeyPEM: keyA,
	})
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}
	if !res.Success {
		t.Fatal("expected Success=true")
	}
	if len(callTimes) != 4 {
		t.Fatalf("expected 4 probe calls, got %d", len(callTimes))
	}
	const tolerance = 25 * time.Millisecond
	expectedGaps := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
	}
	for i := 0; i < len(expectedGaps); i++ {
		gap := callTimes[i+1].Sub(callTimes[i])
		expected := expectedGaps[i]
		if gap < expected-tolerance || gap > expected+tolerance {
			t.Errorf("gap[%d]: expected ~%v, got %v", i, expected, gap)
		}
	}
}
