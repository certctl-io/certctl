package intune

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// silentLogger returns a logger that drops everything; the SIGHUP watcher
// path emits Info logs we don't want fouling test output.
func silentTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// writeTestBundle writes a PEM bundle of the given certs at path with mode 0600.
func writeTestBundle(t *testing.T, path string, certs []*x509.Certificate) {
	t.Helper()
	body := []byte{}
	for _, c := range certs {
		body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// freshHolderCert is a small factory for a self-signed EC cert with a
// caller-controlled CN + lifetime. Used by Reload tests that swap the
// on-disk pool between calls.
func freshHolderCert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

func TestTrustAnchorHolder_NewLoadsBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intune-trust.pem")
	cert := freshHolderCert(t, "initial-conn", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{cert})

	holder, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatalf("NewTrustAnchorHolder: %v", err)
	}
	got := holder.Get()
	if len(got) != 1 || got[0].Subject.CommonName != "initial-conn" {
		t.Fatalf("Get returned %#v, want one cert with CN=initial-conn", got)
	}
	if holder.Path() != path {
		t.Errorf("Path = %q, want %q", holder.Path(), path)
	}
}

func TestTrustAnchorHolder_NewRequiresLogger(t *testing.T) {
	if _, err := NewTrustAnchorHolder("/nonexistent", nil); err == nil {
		t.Fatal("nil logger must error")
	}
}

func TestTrustAnchorHolder_NewSurfacesLoadError(t *testing.T) {
	if _, err := NewTrustAnchorHolder("/path/that/does/not/exist.pem", silentTestLogger()); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestTrustAnchorHolder_ReloadHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	c1 := freshHolderCert(t, "rev-1", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c1})

	h, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Rotate on disk and call Reload.
	c2 := freshHolderCert(t, "rev-2", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c2})
	if err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got := h.Get()
	if len(got) != 1 || got[0].Subject.CommonName != "rev-2" {
		t.Errorf("after Reload Get = %#v, want one cert CN=rev-2", got)
	}
}

func TestTrustAnchorHolder_ReloadKeepsOldOnFailure(t *testing.T) {
	// Mid-rotation half-file: operator overwrites the bundle with garbage
	// → Reload errors → holder must still serve the OLD pool. Without this
	// fail-safe a single typo would take Intune enrollment down for the
	// whole window until a re-rotate.
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	good := freshHolderCert(t, "stable", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{good})

	h, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite with content that LoadTrustAnchor will reject (no PEM blocks).
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(); err == nil {
		t.Fatal("Reload from garbage file must error")
	}

	// Old pool still served.
	got := h.Get()
	if len(got) != 1 || got[0].Subject.CommonName != "stable" {
		t.Errorf("after failed Reload Get should still be the pre-Reload pool; got %#v", got)
	}
}

func TestTrustAnchorHolder_ReloadKeepsOldOnExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	good := freshHolderCert(t, "still-valid", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{good})

	h, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Operator rotates to a cert that's already expired (their script
	// pulled an old bundle by mistake). Reload should error AND the holder
	// should retain the previous good pool — exactly the fail-safe semantics
	// LoadTrustAnchor enforces at startup.
	expired := freshHolderCert(t, "expired-conn", time.Now().Add(-1*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{expired})

	if err := h.Reload(); err == nil {
		t.Fatal("Reload with expired cert must error")
	}
	if !strings.Contains(h.Get()[0].Subject.CommonName, "still-valid") {
		t.Errorf("after expired-cert Reload, holder should retain old pool")
	}
}

func TestTrustAnchorHolder_WatchSIGHUPReloadsPool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	c1 := freshHolderCert(t, "rev-pre-sighup", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c1})

	h, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	stop := h.WatchSIGHUP()
	defer stop()

	// Rotate on disk, then send SIGHUP to our own process and poll for the swap.
	c2 := freshHolderCert(t, "rev-post-sighup", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c2})
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	// Poll for up to 2 seconds.
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.Get()
		if len(got) == 1 && got[0].Subject.CommonName == "rev-post-sighup" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("post-SIGHUP pool not swapped in 2s; current CN=%q", got[0].Subject.CommonName)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTrustAnchorHolder_WatchSIGHUPStopIsClean(t *testing.T) {
	// Mirrors cmd/server/tls_test.go::TestCertHolder_WatchSIGHUP_StopExits:
	// we do NOT fire a SIGHUP after stop(), because once signal.Stop has
	// removed our handler the kernel's default action on SIGHUP is to
	// terminate the process — it would kill the test runner. The contract
	// we need to pin is "stop() is synchronous and safe", which we
	// demonstrate by closing the watcher and verifying the holder still
	// serves the original cert without panic.
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	writeTestBundle(t, path, []*x509.Certificate{
		freshHolderCert(t, "stop-test", time.Now().Add(30*24*time.Hour)),
	})

	h, err := NewTrustAnchorHolder(path, silentTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	stop := h.WatchSIGHUP()
	stop()
	time.Sleep(50 * time.Millisecond) // let the goroutine fully exit

	if cn := h.Get()[0].Subject.CommonName; cn != "stop-test" {
		t.Errorf("after stop CN = %q, want unchanged stop-test", cn)
	}
}
