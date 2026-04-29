package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SCEP RFC 8894 Phase 1: preflightSCEPRACertKey covers the six failure
// modes spelled out in the helper's docblock plus the no-op-when-disabled
// path. Mirrors TestPreflightEnrollmentIssuer's table-driven shape so the
// suite stays uniform for the next reviewer.
//
// Each test materialises a real ECDSA P-256 cert/key pair on disk (rather
// than mocking) so the tls.X509KeyPair path is exercised end-to-end —
// catches drift in stdlib cert-parsing semantics that a mock would hide.

func TestPreflightSCEPRACertKey_Disabled_NoOp(t *testing.T) {
	// Enabled=false short-circuits before any path validation; should pass
	// even with empty paths (mirrors preflightSCEPChallengePassword).
	if err := preflightSCEPRACertKey(false, "", ""); err != nil {
		t.Fatalf("disabled SCEP returned error: %v", err)
	}
}

func TestPreflightSCEPRACertKey_EnabledMissingPaths_Refuses(t *testing.T) {
	// Validate() also catches this; preflight reports the specific failure
	// with a more actionable error string + os.Exit(1) at the call site.
	cases := []struct {
		name     string
		certPath string
		keyPath  string
	}{
		{"both_empty", "", ""},
		{"cert_only", "/tmp/ra.crt", ""},
		{"key_only", "", "/tmp/ra.key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightSCEPRACertKey(true, tc.certPath, tc.keyPath)
			if err == nil {
				t.Fatalf("expected error for missing paths, got nil")
			}
			if !strings.Contains(err.Error(), "RA pair missing") {
				t.Errorf("error should mention RA pair missing, got: %v", err)
			}
		})
	}
}

func TestPreflightSCEPRACertKey_KeyWorldReadable_Refuses(t *testing.T) {
	// Defense-in-depth: even a perfectly-valid RA pair must be rejected if
	// the key file is mode 0644 (world-readable). The deploy convention is
	// 0600 — owner read/write only.
	dir := t.TempDir()
	certPath, keyPath := writeECDSARAPair(t, dir, time.Now().Add(30*24*time.Hour))
	// Re-chmod the key to 0644 to trigger the gate.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	err := preflightSCEPRACertKey(true, certPath, keyPath)
	if err == nil {
		t.Fatalf("expected error for world-readable key, got nil")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Errorf("error should mention insecure permissions, got: %v", err)
	}
}

func TestPreflightSCEPRACertKey_ValidPair_Accepts(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeECDSARAPair(t, dir, time.Now().Add(30*24*time.Hour))
	if err := preflightSCEPRACertKey(true, certPath, keyPath); err != nil {
		t.Fatalf("valid RA pair rejected: %v", err)
	}
}

func TestPreflightSCEPRACertKey_ExpiredCert_Refuses(t *testing.T) {
	// An RA cert past NotAfter would cause every conformant SCEP client to
	// reject the CertRep signature. Catch it at startup.
	dir := t.TempDir()
	certPath, keyPath := writeECDSARAPair(t, dir, time.Now().Add(-1*time.Hour))
	err := preflightSCEPRACertKey(true, certPath, keyPath)
	if err == nil {
		t.Fatalf("expected error for expired cert, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired, got: %v", err)
	}
}

func TestPreflightSCEPRACertKey_MismatchedPair_Refuses(t *testing.T) {
	// tls.X509KeyPair detects the cert/key mismatch; preflight should
	// surface it with an actionable error (cert + key are halves of
	// different RA pairs — common multi-profile typo).
	dir := t.TempDir()
	certPath, _ := writeECDSARAPair(t, dir, time.Now().Add(30*24*time.Hour))
	_, keyPath := writeECDSARAPair(t, dir, time.Now().Add(30*24*time.Hour))
	// Re-write the key path under a unique name to avoid collision with
	// the first pair's file (writeECDSARAPair would have overwritten).
	err := preflightSCEPRACertKey(true, certPath, keyPath)
	if err == nil {
		t.Fatalf("expected error for mismatched pair, got nil")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention invalid pair, got: %v", err)
	}
}

func TestPreflightSCEPRACertKey_MissingFiles_Refuses(t *testing.T) {
	// Both files referenced but neither exists — a typo or a fresh deploy
	// where the operator forgot to mount the secret. Cert-path failure mode
	// is checked first because key-path stat is the first os call after
	// the empty-string check.
	dir := t.TempDir()
	missingCert := filepath.Join(dir, "ra.crt")
	missingKey := filepath.Join(dir, "ra.key")
	err := preflightSCEPRACertKey(true, missingCert, missingKey)
	if err == nil {
		t.Fatalf("expected error for missing files, got nil")
	}
	if !strings.Contains(err.Error(), "stat failed") && !strings.Contains(err.Error(), "read failed") {
		t.Errorf("error should mention stat/read failure, got: %v", err)
	}
}

func TestPreflightSCEPRACertKey_UnsupportedAlg_Refuses(t *testing.T) {
	// Ed25519 isn't supported by the CMS signature path RFC 8894 §3.5.2
	// advertises. Catch this at startup to avoid runtime failures the
	// first time a client sends a real PKIMessage.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ra.crt")
	keyPath := filepath.Join(dir, "ra.key")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ra-ed25519"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	err = preflightSCEPRACertKey(true, certPath, keyPath)
	if err == nil {
		t.Fatalf("expected error for ed25519 RA cert, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported public-key algorithm") &&
		!strings.Contains(err.Error(), "invalid") {
		// tls.X509KeyPair may reject ed25519 SCEP-signing keys earlier
		// than our explicit alg gate; accept either failure path so the
		// test is robust against stdlib changes.
		t.Errorf("error should mention algorithm/invalid, got: %v", err)
	}
}

// writeECDSARAPair generates a fresh ECDSA P-256 self-signed cert + key,
// writes them to dir/ra-<rand>.crt + ra-<rand>.key with the cert at 0644
// and the key at 0600 (the production deploy mode). Returns the two paths.
func writeECDSARAPair(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ra-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Use a unique suffix so successive calls within the same test don't
	// overwrite each other (the mismatched-pair test relies on this).
	suffix := tmpl.SerialNumber.String()
	certPath = filepath.Join(dir, "ra-"+suffix+".crt")
	keyPath = filepath.Join(dir, "ra-"+suffix+".key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}
