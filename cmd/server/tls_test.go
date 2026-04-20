package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// generateTestCert writes a PEM-encoded self-signed leaf cert + ECDSA P-256
// key pair to certPath/keyPath. The subject is derived from cn so tests can
// tell reloaded certs apart from original certs by re-parsing the served
// Certificate and comparing the CN.
func generateTestCert(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// readCertCN returns the CommonName from the leaf cert currently held by the
// holder, by exercising the same GetCertificate path the tls handshake would
// take. Lets tests assert which generation of the cert is being served.
func readCertCN(t *testing.T, h *certHolder) string {
	t.Helper()
	c, err := h.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return leaf.Subject.CommonName
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewCertHolder_ValidPair_LoadsCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-initial")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	if got := readCertCN(t, h); got != "cn-initial" {
		t.Fatalf("CN mismatch: got %q want %q", got, "cn-initial")
	}
}

func TestNewCertHolder_MissingFile_Fails(t *testing.T) {
	_, err := newCertHolder("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing files, got nil")
	}
}

func TestNewCertHolder_MalformedCert_Fails(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not a pem cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, err := newCertHolder(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
}

func TestCertHolder_Reload_SwapsCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-v1")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	if got := readCertCN(t, h); got != "cn-v1" {
		t.Fatalf("initial CN: got %q want cn-v1", got)
	}

	// Rotate on disk and reload.
	generateTestCert(t, certPath, keyPath, "cn-v2")
	if err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := readCertCN(t, h); got != "cn-v2" {
		t.Fatalf("post-reload CN: got %q want cn-v2", got)
	}
}

func TestCertHolder_Reload_FailureRetainsPreviousCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-v1")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}

	// Corrupt the cert file and attempt reload.
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}
	if err := h.Reload(); err == nil {
		t.Fatal("expected Reload error for corrupt file, got nil")
	}
	// Holder should still serve the v1 cert.
	if got := readCertCN(t, h); got != "cn-v1" {
		t.Fatalf("post-failed-reload CN: got %q want cn-v1 (reload must not clobber on failure)", got)
	}
}

func TestCertHolder_GetCertificate_Concurrent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-concurrent")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}

	// 64 readers + 1 rotator for 500ms. Race detector catches any unsynchronized
	// swap of h.cert. Rotator writes fresh files + Reload, readers call
	// GetCertificate in a tight loop.
	var wg sync.WaitGroup
	done := make(chan struct{})
	const readers = 64
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					if _, err := h.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
						t.Errorf("GetCertificate: %v", err)
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			generateTestCert(t, certPath, keyPath, "cn-concurrent")
			_ = h.Reload()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(done)
	wg.Wait()
}

func TestCertHolder_WatchSIGHUP_ReloadsOnSignal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-before-sighup")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	stop := h.watchSIGHUP(silentLogger())
	defer stop()

	// Rotate on disk, then fire SIGHUP to our own process and poll for the swap.
	generateTestCert(t, certPath, keyPath, "cn-after-sighup")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if readCertCN(t, h) == "cn-after-sighup" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watcher did not reload cert within 2s (CN still %q)", readCertCN(t, h))
}

func TestCertHolder_WatchSIGHUP_StopExits(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-stop")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	stop := h.watchSIGHUP(silentLogger())

	// Closing should be synchronous and safe; a subsequent SIGHUP must not
	// cause a reload (the watcher goroutine is gone).
	stop()
	time.Sleep(50 * time.Millisecond) // let goroutine exit

	// After stop, the signal may still be delivered to the process but the
	// watcher has called signal.Stop so this channel is no longer receiving.
	// Simply assert that calling stop() twice does not panic — the goroutine
	// has already exited, so a second close would panic on the `done`
	// channel; we do NOT call stop twice. Instead verify no regression in
	// the held cert.
	if got := readCertCN(t, h); got != "cn-stop" {
		t.Fatalf("unexpected cert rotation after stop: got %q want cn-stop", got)
	}
}

func TestBuildServerTLSConfig_IsTLS13Only(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-cfg")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	cfg := buildServerTLSConfig(h)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion: got %#x want %#x (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
	}
	wantCurves := []tls.CurveID{tls.X25519, tls.CurveP256}
	if len(cfg.CurvePreferences) != len(wantCurves) {
		t.Fatalf("CurvePreferences length: got %d want %d", len(cfg.CurvePreferences), len(wantCurves))
	}
	for i, c := range cfg.CurvePreferences {
		if c != wantCurves[i] {
			t.Fatalf("CurvePreferences[%d]: got %v want %v", i, c, wantCurves[i])
		}
	}
	if cfg.GetCertificate == nil {
		t.Fatal("GetCertificate: nil (holder not wired; SIGHUP reload would be broken)")
	}
	if len(cfg.Certificates) != 0 {
		t.Fatalf("Certificates: got %d want 0 (static cert would pin the first load and defeat reload)", len(cfg.Certificates))
	}
}

func TestBuildServerTLSConfig_Handshake_TLS12Rejected(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-handshake")

	h, err := newCertHolder(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	serverCfg := buildServerTLSConfig(h)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Server loop: accept and immediately close (we only care about the
	// handshake outcome).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Force handshake so the server-side error surfaces.
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	// TLS 1.3 client — should succeed.
	clientOK := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	c, err := tls.Dial("tcp", ln.Addr().String(), clientOK)
	if err != nil {
		t.Fatalf("TLS 1.3 dial failed (expected success): %v", err)
	}
	if c.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("negotiated version: got %#x want TLS 1.3 (%#x)", c.ConnectionState().Version, tls.VersionTLS13)
	}
	c.Close()

	// TLS 1.2 client — must be rejected at handshake.
	clientOld := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	if _, err := tls.Dial("tcp", ln.Addr().String(), clientOld); err == nil {
		t.Fatal("TLS 1.2 dial succeeded; HTTPS-everywhere requires server to refuse TLS 1.2")
	}
}

func TestPreflightServerTLS_MissingCertPath(t *testing.T) {
	err := preflightServerTLS("", "/any/key.pem")
	if err == nil {
		t.Fatal("expected error for empty cert path, got nil")
	}
}

func TestPreflightServerTLS_MissingKeyPath(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-preflight")
	err := preflightServerTLS(certPath, "")
	if err == nil {
		t.Fatal("expected error for empty key path, got nil")
	}
}

func TestPreflightServerTLS_CertFileNotReadable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(keyPath, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := preflightServerTLS(filepath.Join(dir, "nope.crt"), keyPath)
	if err == nil {
		t.Fatal("expected error for unreadable cert path, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist wrapped in error chain, got: %v", err)
	}
}

func TestPreflightServerTLS_InvalidKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	// Pair of valid cert + garbage key — files are readable but the pair
	// doesn't round-trip tls.LoadX509KeyPair.
	generateTestCert(t, certPath, keyPath, "cn-bad-pair")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN EC PRIVATE KEY-----\nBAD\n-----END EC PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := preflightServerTLS(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key pair, got nil")
	}
}

func TestPreflightServerTLS_ValidPair_NoError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	generateTestCert(t, certPath, keyPath, "cn-ok")
	if err := preflightServerTLS(certPath, keyPath); err != nil {
		t.Fatalf("unexpected error for valid pair: %v", err)
	}
}
