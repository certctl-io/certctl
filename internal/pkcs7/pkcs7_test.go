package pkcs7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestBuildCertsOnlyPKCS7(t *testing.T) {
	dummyCert := []byte{0x30, 0x82, 0x01, 0x00}
	result, err := BuildCertsOnlyPKCS7([][]byte{dummyCert})
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7 failed: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty PKCS#7 output")
	}
	if result[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag (0x30), got 0x%02x", result[0])
	}
}

func TestBuildCertsOnlyPKCS7_MultipleCerts(t *testing.T) {
	cert1 := []byte{0x30, 0x82, 0x01, 0x00}
	cert2 := []byte{0x30, 0x82, 0x02, 0x00}
	result, err := BuildCertsOnlyPKCS7([][]byte{cert1, cert2})
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7 failed: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty PKCS#7 output")
	}
}

func TestPEMToDERChain_Success(t *testing.T) {
	pemData := generateTestCertPEM(t)
	certs, err := PEMToDERChain(pemData)
	if err != nil {
		t.Fatalf("PEMToDERChain failed: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestPEMToDERChain_NoCerts(t *testing.T) {
	_, err := PEMToDERChain("not a PEM")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestASN1EncodeLength(t *testing.T) {
	tests := []struct {
		length   int
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, tt := range tests {
		result := ASN1EncodeLength(tt.length)
		if len(result) != len(tt.expected) {
			t.Errorf("ASN1EncodeLength(%d): expected %d bytes, got %d", tt.length, len(tt.expected), len(result))
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("ASN1EncodeLength(%d): byte %d: expected 0x%02x, got 0x%02x", tt.length, i, tt.expected[i], result[i])
			}
		}
	}
}
