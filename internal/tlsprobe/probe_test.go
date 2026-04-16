package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProbeTLS_ConnectionRefused tests probing an unavailable endpoint.
func TestProbeTLS_ConnectionRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := ProbeTLS(ctx, "127.0.0.1:1", 1*time.Second)

	if result.Success {
		t.Errorf("expected Success=false for unavailable endpoint, got %v", result.Success)
	}
	if result.Error == "" {
		t.Errorf("expected Error to be set for unavailable endpoint, got empty")
	}
	// ResponseTimeMs might be 0 on very fast systems, so just check it's set
	if result.ResponseTimeMs < 0 {
		t.Errorf("expected ResponseTimeMs >= 0, got %d", result.ResponseTimeMs)
	}
}

// TestProbeTLS_Success tests probing a live TLS server.
func TestProbeTLS_Success(t *testing.T) {
	// Create a test HTTPS server with a self-signed certificate
	server := httptest.NewTLSServer(nil)
	defer server.Close()

	// Extract the server address (remove https://)
	u := server.Listener.Addr().(*net.TCPAddr)
	address := net.JoinHostPort(u.IP.String(), fmt.Sprintf("%d", u.Port))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := ProbeTLS(ctx, address, 5*time.Second)

	if !result.Success {
		t.Errorf("expected Success=true, got false. Error: %s", result.Error)
	}
	if result.Fingerprint == "" {
		t.Errorf("expected Fingerprint to be set, got empty")
	}
	if result.TLSVersion == "" {
		t.Errorf("expected TLSVersion to be set, got empty")
	}
	if result.ResponseTimeMs == 0 {
		t.Errorf("expected ResponseTimeMs > 0, got 0")
	}
}

// TestCertFingerprint_SHA256 tests SHA-256 fingerprint computation.
func TestCertFingerprint_SHA256(t *testing.T) {
	cert, _ := createTestCertWithKey(t, "test.example.com", "rsa")
	fp := CertFingerprint(cert)

	if fp == "" {
		t.Errorf("expected non-empty fingerprint, got empty")
	}
	if len(fp) != 64 {
		t.Errorf("expected fingerprint length 64 (hex SHA-256), got %d", len(fp))
	}

	// Verify it's valid hex
	for _, ch := range fp {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			t.Errorf("expected lowercase hex fingerprint, got invalid char: %c", ch)
		}
	}

	// Verify consistency (same cert should produce same fingerprint)
	fp2 := CertFingerprint(cert)
	if fp != fp2 {
		t.Errorf("fingerprint not consistent: %s vs %s", fp, fp2)
	}
}

// TestCertKeyInfo_RSA tests RSA key info extraction.
func TestCertKeyInfo_RSA(t *testing.T) {
	cert, _ := createTestCertWithKey(t, "test.example.com", "rsa")

	alg, size := CertKeyInfo(cert)

	if alg != "RSA" {
		t.Errorf("expected algorithm 'RSA', got '%s'", alg)
	}
	if size != 2048 {
		t.Errorf("expected RSA key size 2048, got %d", size)
	}
}

// TestCertKeyInfo_ECDSA tests ECDSA key info extraction.
func TestCertKeyInfo_ECDSA(t *testing.T) {
	cert, _ := createTestCertWithKey(t, "test.example.com", "ecdsa")

	alg, size := CertKeyInfo(cert)

	if alg != "ECDSA" {
		t.Errorf("expected algorithm 'ECDSA', got '%s'", alg)
	}
	if size != 256 {
		t.Errorf("expected ECDSA P-256 key size 256, got %d", size)
	}
}

// Helper: createTestCert creates a self-signed test certificate with RSA key.
func createTestCert(t *testing.T, cn string) *x509.Certificate {
	cert, _ := createTestCertWithKey(t, cn, "rsa")
	return cert
}

// Helper: createTestCertWithKey creates a test certificate with specified key type.
func createTestCertWithKey(t *testing.T, cn, keyType string) (*x509.Certificate, interface{}) {
	var privKey interface{}
	var pubKey interface{}

	if keyType == "rsa" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
	} else if keyType == "ecdsa" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
	} else {
		t.Fatalf("unsupported key type: %s", keyType)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{cn},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, privKey
}
