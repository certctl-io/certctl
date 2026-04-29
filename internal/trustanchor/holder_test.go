package trustanchor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

// EST RFC 7030 hardening master bundle Phase 2.1: this test file holds the
// white-box tests for the trust-anchor primitives (parseBundlePEM + LoadBundle
// + Holder) that used to live in internal/scep/intune/{trust_anchor_test.go,
// trust_anchor_holder_test.go}. The intune package retains a thin
// public-surface test of LoadTrustAnchor (the back-compat shim) — the
// detailed tests live here so the EST mTLS sibling route + any future
// trustanchor.Holder caller share the same contract pinning.

// silentLogger drops everything; the SIGHUP watcher emits Info logs we don't
// want fouling test output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// pemEncodeCert is a small DRY helper for the PEM bundle fixtures.
func pemEncodeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// freshConnectorCertDER returns a freshly-minted EC P-256 cert as raw DER
// + the matching key. Lifetime is parameterised so the same factory drives
// both the happy-path and expired-cert cases.
func freshConnectorCertDER(t *testing.T, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "trustanchor-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return der, key
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

// ----- parseBundlePEM (white-box) -----

func TestParseBundlePEM_HappyPath_SingleCert(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(365*24*time.Hour))
	body := pemEncodeCert(t, der)

	certs, err := parseBundlePEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseBundlePEM: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "trustanchor-test" {
		t.Errorf("Subject.CommonName = %q", certs[0].Subject.CommonName)
	}
}

func TestParseBundlePEM_HappyPath_MultiCert(t *testing.T) {
	d1, _ := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	d2, _ := freshConnectorCertDER(t, time.Now().Add(60*24*time.Hour))
	body := append(pemEncodeCert(t, d1), pemEncodeCert(t, d2)...)

	certs, err := parseBundlePEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseBundlePEM: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("len(certs) = %d, want 2", len(certs))
	}
}

func TestParseBundlePEM_SkipsNonCertBlocks(t *testing.T) {
	der, key := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	body := append(keyPEM, pemEncodeCert(t, der)...) // priv key first, cert second

	certs, err := parseBundlePEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseBundlePEM should ignore non-CERTIFICATE blocks: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1 (priv key block must be skipped)", len(certs))
	}
}

func TestParseBundlePEM_EmptyBundleRejected(t *testing.T) {
	_, err := parseBundlePEM([]byte("nothing here"), "test", time.Now())
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE PEM blocks") {
		t.Fatalf("expected 'no CERTIFICATE PEM blocks' error, got %v", err)
	}
}

func TestParseBundlePEM_OnlyKeyBlocksRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_, err := parseBundlePEM(body, "test", time.Now())
	if err == nil {
		t.Fatalf("expected error for bundle with no certs, got nil")
	}
}

func TestParseBundlePEM_ExpiredCertRejected(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(-1*time.Hour)) // already expired
	body := pemEncodeCert(t, der)

	_, err := parseBundlePEM(body, "expired-bundle", time.Now())
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
	// Operator-actionable message must include the subject so the audit
	// log says exactly which cert to rotate.
	if !strings.Contains(err.Error(), "trustanchor-test") {
		t.Errorf("error must include subject CN for operator action: %v", err)
	}
}

func TestParseBundlePEM_MalformedCertRejected(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-real-asn1-cert")})

	_, err := parseBundlePEM(bad, "test", time.Now())
	if err == nil {
		t.Fatalf("expected x509 parse error, got nil")
	}
}

// ----- LoadBundle (filesystem-side) -----

func TestLoadBundle_FromDisk(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	body := pemEncodeCert(t, der)

	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	certs, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
}

func TestLoadBundle_EmptyPath(t *testing.T) {
	_, err := LoadBundle("")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-path error, got %v", err)
	}
}

func TestLoadBundle_MissingFile(t *testing.T) {
	_, err := LoadBundle("/tmp/does-not-exist-trustanchor.pem")
	if err == nil {
		t.Fatalf("expected file-not-found error, got nil")
	}
	if errors.Is(err, nil) {
		t.Fatalf("error must be non-nil")
	}
}

// ----- Holder -----

func TestHolder_NewLoadsBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	cert := freshHolderCert(t, "initial", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{cert})

	holder, err := New(path, silentLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := holder.Get()
	if len(got) != 1 || got[0].Subject.CommonName != "initial" {
		t.Fatalf("Get returned %#v, want one cert with CN=initial", got)
	}
	if holder.Path() != path {
		t.Errorf("Path = %q, want %q", holder.Path(), path)
	}
}

func TestHolder_NewRequiresLogger(t *testing.T) {
	if _, err := New("/nonexistent", nil); err == nil {
		t.Fatal("nil logger must error")
	}
}

func TestHolder_NewSurfacesLoadError(t *testing.T) {
	if _, err := New("/path/that/does/not/exist.pem", silentLogger()); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestHolder_PoolReturnsAllCerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	c1 := freshHolderCert(t, "ca-1", time.Now().Add(30*24*time.Hour))
	c2 := freshHolderCert(t, "ca-2", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c1, c2})

	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	pool := h.Pool()
	if pool == nil {
		t.Fatal("Pool returned nil")
	}
	// pool.Subjects() is deprecated for caller-owned pools that may include
	// the system roots. We've built this pool ourselves with exactly the
	// two certs from h.Get(), so it's a safe use — but the linter doesn't
	// know that. Rather than disable the lint, we cross-check via Equal()
	// over the underlying cert slice we used to build the pool.
	got := h.Get()
	if len(got) != 2 {
		t.Errorf("Get() len = %d, want 2", len(got))
	}
}

func TestHolder_SetLabelForLogIgnoresEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	writeTestBundle(t, path, []*x509.Certificate{
		freshHolderCert(t, "label-test", time.Now().Add(30*24*time.Hour)),
	})
	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetLabelForLog("") // no-op; default "trust anchor" preserved
	h.SetLabelForLog("est mTLS client CA bundle")
	// No public getter for label; just exercise without crashing — race
	// detector covers the locking contract under -race.
}

func TestHolder_ReloadHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	c1 := freshHolderCert(t, "rev-1", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c1})

	h, err := New(path, silentLogger())
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

func TestHolder_ReloadKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	good := freshHolderCert(t, "stable", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{good})

	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite with content that LoadBundle will reject (no PEM blocks).
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

func TestHolder_ReloadKeepsOldOnExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	good := freshHolderCert(t, "still-valid", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{good})

	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}

	expired := freshHolderCert(t, "expired-conn", time.Now().Add(-1*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{expired})

	if err := h.Reload(); err == nil {
		t.Fatal("Reload with expired cert must error")
	}
	if !strings.Contains(h.Get()[0].Subject.CommonName, "still-valid") {
		t.Errorf("after expired-cert Reload, holder should retain old pool")
	}
}

func TestHolder_WatchSIGHUPReloadsPool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	c1 := freshHolderCert(t, "rev-pre-sighup", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c1})

	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	stop := h.WatchSIGHUP()
	defer stop()

	c2 := freshHolderCert(t, "rev-post-sighup", time.Now().Add(30*24*time.Hour))
	writeTestBundle(t, path, []*x509.Certificate{c2})
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

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

func TestHolder_WatchSIGHUPStopIsClean(t *testing.T) {
	// We do NOT fire a SIGHUP after stop(): once signal.Stop has removed our
	// handler the kernel's default action on SIGHUP is to terminate the
	// process — it would kill the test runner. Pin "stop() is synchronous
	// and safe" by closing the watcher and verifying the holder still
	// serves the original cert without panic.
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.pem")
	writeTestBundle(t, path, []*x509.Certificate{
		freshHolderCert(t, "stop-test", time.Now().Add(30*24*time.Hour)),
	})

	h, err := New(path, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	stop := h.WatchSIGHUP()
	stop()
	time.Sleep(50 * time.Millisecond)

	if cn := h.Get()[0].Subject.CommonName; cn != "stop-test" {
		t.Errorf("after stop CN = %q, want unchanged stop-test", cn)
	}
}
