package intune

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// EST RFC 7030 hardening master bundle Phase 2.1: the white-box parser
// tests (TestParseTrustAnchorPEM_*) moved to internal/trustanchor/holder_test.go
// where parseBundlePEM now lives. The intune package retains a thin
// public-surface test of LoadTrustAnchor — the back-compat shim that
// existing intune callers use — so a future refactor that breaks the
// shim's wire-up to trustanchor.LoadBundle is caught here.

// pemEncodeCert is a small DRY helper for the PEM bundle fixtures.
func pemEncodeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// freshConnectorCertDER returns a freshly-minted EC P-256 cert as raw DER
// + the matching key. Lifetime is parameterised so the same factory drives
// both happy-path and expired-cert cases. Kept in this file (not deleted with
// the white-box tests) because trust_anchor_holder_test.go's freshHolderCert
// returns *x509.Certificate while LoadTrustAnchor tests need raw DER + key.
func freshConnectorCertDER(t *testing.T, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "intune-connector-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return der, key
}

func TestLoadTrustAnchor_FromDisk(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	body := pemEncodeCert(t, der)

	dir := t.TempDir()
	path := filepath.Join(dir, "intune-trust.pem")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	certs, err := LoadTrustAnchor(path)
	if err != nil {
		t.Fatalf("LoadTrustAnchor: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "intune-connector-test" {
		t.Errorf("Subject.CommonName = %q", certs[0].Subject.CommonName)
	}
}

func TestLoadTrustAnchor_EmptyPath(t *testing.T) {
	_, err := LoadTrustAnchor("")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-path error, got %v", err)
	}
}

func TestLoadTrustAnchor_MissingFile(t *testing.T) {
	_, err := LoadTrustAnchor("/tmp/does-not-exist-intune-trust.pem")
	if err == nil {
		t.Fatalf("expected file-not-found error, got nil")
	}
	if errors.Is(err, nil) {
		t.Fatalf("error must be non-nil")
	}
}
