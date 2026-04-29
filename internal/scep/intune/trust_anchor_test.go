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

func TestParseTrustAnchorPEM_HappyPath_SingleCert(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(365*24*time.Hour))
	body := pemEncodeCert(t, der)

	certs, err := parseTrustAnchorPEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseTrustAnchorPEM: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "intune-connector-test" {
		t.Errorf("Subject.CommonName = %q", certs[0].Subject.CommonName)
	}
}

func TestParseTrustAnchorPEM_HappyPath_MultiCert(t *testing.T) {
	d1, _ := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	d2, _ := freshConnectorCertDER(t, time.Now().Add(60*24*time.Hour))
	body := append(pemEncodeCert(t, d1), pemEncodeCert(t, d2)...)

	certs, err := parseTrustAnchorPEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseTrustAnchorPEM: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("len(certs) = %d, want 2", len(certs))
	}
}

func TestParseTrustAnchorPEM_SkipsNonCertBlocks(t *testing.T) {
	der, key := freshConnectorCertDER(t, time.Now().Add(30*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	body := append(keyPEM, pemEncodeCert(t, der)...) // priv key first, cert second

	certs, err := parseTrustAnchorPEM(body, "test", time.Now())
	if err != nil {
		t.Fatalf("parseTrustAnchorPEM should ignore non-CERTIFICATE blocks: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1 (priv key block must be skipped)", len(certs))
	}
}

func TestParseTrustAnchorPEM_EmptyBundleRejected(t *testing.T) {
	_, err := parseTrustAnchorPEM([]byte("nothing here"), "test", time.Now())
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE PEM blocks") {
		t.Fatalf("expected 'no CERTIFICATE PEM blocks' error, got %v", err)
	}
}

func TestParseTrustAnchorPEM_OnlyKeyBlocksRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_, err := parseTrustAnchorPEM(body, "test", time.Now())
	if err == nil {
		t.Fatalf("expected error for bundle with no certs, got nil")
	}
}

func TestParseTrustAnchorPEM_ExpiredCertRejected(t *testing.T) {
	der, _ := freshConnectorCertDER(t, time.Now().Add(-1*time.Hour)) // already expired
	body := pemEncodeCert(t, der)

	_, err := parseTrustAnchorPEM(body, "expired-bundle", time.Now())
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
	// Operator-actionable message must include the subject so the audit
	// log says exactly which cert to rotate.
	if !strings.Contains(err.Error(), "intune-connector-test") {
		t.Errorf("error must include subject CN for operator action: %v", err)
	}
}

func TestParseTrustAnchorPEM_MalformedCertRejected(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-real-asn1-cert")})

	_, err := parseTrustAnchorPEM(bad, "test", time.Now())
	if err == nil {
		t.Fatalf("expected x509 parse error, got nil")
	}
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
	// Don't string-assert on the OS error — just make sure it's surfaced.
	if errors.Is(err, nil) {
		t.Fatalf("error must be non-nil")
	}
}
