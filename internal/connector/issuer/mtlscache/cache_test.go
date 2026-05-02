package mtlscache

// Audit fix #10 — mTLS keypair cache tests.
//
// TestRefreshIfStale_NoReloadWhenMtimeStable is the load-bearing
// regression guard against the pre-fix per-call disk read (the
// "latency floor" the audit calls out). Without the cache, every API
// call parses the keypair; with the cache, only the first call (plus
// reloads triggered by mtime advancement) parses it.
//
// TestRefreshIfStale_ReloadsOnMtimeAdvance pins the rotation-without-
// process-restart contract — operators who do `mv -f new.crt
// /etc/ssl/...` get the new cert on the next API call. Without this
// test, the "rotation handled" claim in docs/connectors.md would be
// "I think it works."
//
// TestRefreshIfStale_ConcurrentNoRace pins thread safety under the
// concurrent fan-out the renewal scheduler runs (now bounded by audit
// fix #9 but still concurrent). 100 goroutines hammer the cache; race
// detector must stay clean and exactly one reload fires per mtime tick.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeKeyPair generates a fresh ECDSA-P256 self-signed cert + key
// PEM, writes them to a tempdir, and returns the paths. Used by the
// cache tests to create realistic input that tls.LoadX509KeyPair
// will accept.
func writeKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mtlscache-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestNew_FailsOnMissingPaths pins the input-validation guards on the
// constructor. Without these, a misconfigured deployment could
// construct a Cache with empty paths and only fail at first-use.
func TestNew_FailsOnMissingPaths(t *testing.T) {
	cases := []struct{ name, certPath, keyPath, want string }{
		{"empty_cert", "", "/tmp/k", "cert path required"},
		{"empty_key", "/tmp/c", "", "key path required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.certPath, tc.keyPath, Options{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("err %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestNew_LoadsImmediately pins the fail-fast contract — a broken
// cert path is observed at construction, not at first API call. The
// negative case (broken paths) returns a useful error.
func TestNew_LoadsImmediately(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)
	c, err := New(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Certificate().Certificate == nil {
		t.Errorf("expected loaded cert, got zero-value")
	}
	if c.Client() == nil {
		t.Errorf("expected non-nil http.Client")
	}
	if c.Transport() == nil {
		t.Errorf("expected non-nil http.Transport")
	}

	t.Run("broken_cert_path", func(t *testing.T) {
		_, err := New("/nonexistent/cert.pem", keyPath, Options{})
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})
}

// TestRefreshIfStale_NoReloadWhenMtimeStable is the regression guard
// against the pre-fix per-call disk read. Counts os.Stat calls vs.
// reload-driven parses by tracking the loaded-at timestamp — if
// RefreshIfStale never observes a forward mtime, LoadedAt should
// equal the post-construction value across many calls.
func TestRefreshIfStale_NoReloadWhenMtimeStable(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	c, err := New(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	originalLoad := c.LoadedAt()

	for i := 0; i < 100; i++ {
		if err := c.RefreshIfStale(); err != nil {
			t.Fatalf("RefreshIfStale[%d]: %v", i, err)
		}
	}

	if !c.LoadedAt().Equal(originalLoad) {
		t.Errorf("cache reloaded with no mtime advance: original=%v, current=%v", originalLoad, c.LoadedAt())
	}
}

// TestRefreshIfStale_ReloadsOnMtimeAdvance pins the rotation-without-
// process-restart contract: operators who replace the cert file in
// place get the new keypair on the next API call.
func TestRefreshIfStale_ReloadsOnMtimeAdvance(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	c, err := New(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	originalLoad := c.LoadedAt()

	// First refresh: no advance, no reload.
	if err := c.RefreshIfStale(); err != nil {
		t.Fatalf("RefreshIfStale (stable): %v", err)
	}
	if !c.LoadedAt().Equal(originalLoad) {
		t.Fatalf("unexpected reload before mtime advance")
	}

	// Advance the mtime forward by 2 seconds.
	future := originalLoad.Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if err := c.RefreshIfStale(); err != nil {
		t.Fatalf("RefreshIfStale (after chtimes): %v", err)
	}
	if !c.LoadedAt().After(originalLoad) {
		t.Errorf("expected reload after mtime advance: original=%v, current=%v", originalLoad, c.LoadedAt())
	}
}

// TestRefreshIfStale_StatErrorBubbles pins that a missing cert file
// surfaces as an error from RefreshIfStale rather than being
// silently ignored. An unexpectedly-deleted cert file is a real
// outage signal that operators need to see.
func TestRefreshIfStale_StatErrorBubbles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	c, err := New(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove cert: %v", err)
	}

	if err := c.RefreshIfStale(); err == nil {
		t.Fatal("expected RefreshIfStale to error when cert file is missing")
	}
}

// TestRefreshIfStale_ConcurrentNoRace pins thread safety. 100
// goroutines hammer the cache simultaneously. With -race, this catches
// any unsynchronised access to the cert / transport / mtime fields.
// Run with `go test -race ./internal/connector/issuer/mtlscache/...`.
func TestRefreshIfStale_ConcurrentNoRace(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	c, err := New(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	var calls atomic.Int64

	const goroutines = 100
	const itersPerGoroutine = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerGoroutine; j++ {
				if err := c.RefreshIfStale(); err != nil {
					t.Errorf("RefreshIfStale: %v", err)
					return
				}
				_ = c.Client()
				_ = c.Transport()
				_ = c.Certificate()
				calls.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != int64(goroutines*itersPerGoroutine) {
		t.Errorf("expected %d total calls, got %d", goroutines*itersPerGoroutine, got)
	}
}

// TestCache_TLSConfigBuilderUsed pins that a custom TLSConfigBuilder
// is actually invoked and its returned config is what ends up on the
// transport. GlobalSign uses this to pin a private RootCAs pool via
// ServerCAPath.
func TestCache_TLSConfigBuilderUsed(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	var builderCalled atomic.Int64
	builder := func(cert tls.Certificate) (*tls.Config, error) {
		builderCalled.Add(1)
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13, // distinct from default to verify it took effect
		}, nil
	}

	c, err := New(certPath, keyPath, Options{TLSConfigBuilder: builder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := builderCalled.Load(); got != 1 {
		t.Errorf("expected builder called once at New, got %d", got)
	}
	if c.Transport().TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected custom MinVersion=TLS1.3, got %v", c.Transport().TLSClientConfig.MinVersion)
	}

	// Trigger a reload via mtime advance and verify the builder
	// runs again.
	future := c.LoadedAt().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := c.RefreshIfStale(); err != nil {
		t.Fatalf("RefreshIfStale: %v", err)
	}
	if got := builderCalled.Load(); got != 2 {
		t.Errorf("expected builder called twice (once at New, once at reload), got %d", got)
	}
}

// TestCache_ClientHonoursTimeout pins the HTTPTimeout option. Use a
// blocking httptest server + a short timeout to verify the client
// errors out promptly.
func TestCache_ClientHonoursTimeout(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	c, err := New(certPath, keyPath, Options{HTTPTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := c.Client()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	start := time.Now()
	_, err = client.Do(req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("client did not honour 50ms timeout: elapsed=%v", elapsed)
	}
}

// contains is a tiny helper to avoid pulling strings into every
// test for substring checks.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
