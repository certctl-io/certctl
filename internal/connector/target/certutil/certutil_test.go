package certutil

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

// generateTestCertAndKey creates a self-signed certificate and key for testing.
func generateTestCertAndKey() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}

func TestCreatePFX_Success(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	pfx, err := CreatePFX(certPEM, keyPEM, "", "test-password")
	if err != nil {
		t.Fatalf("CreatePFX failed: %v", err)
	}
	if len(pfx) == 0 {
		t.Error("expected non-empty PFX data")
	}
}

func TestCreatePFX_WithChain(t *testing.T) {
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	// Use the same cert as chain for testing purposes
	pfx, err := CreatePFX(certPEM, keyPEM, certPEM, "test-password")
	if err != nil {
		t.Fatalf("CreatePFX with chain failed: %v", err)
	}
	if len(pfx) == 0 {
		t.Error("expected non-empty PFX data")
	}
}

func TestCreatePFX_InvalidCert(t *testing.T) {
	_, err := CreatePFX("not-a-cert", "not-a-key", "", "pw")
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestCreatePFX_InvalidKey(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	_, err = CreatePFX(certPEM, "not-a-key", "", "pw")
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
}

func TestParsePrivateKey_PKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	parsed, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKey_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	parsed, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKey_Invalid(t *testing.T) {
	_, err := ParsePrivateKey([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for invalid key bytes")
	}
}

func TestComputeThumbprint_Success(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	thumb, err := ComputeThumbprint(certPEM)
	if err != nil {
		t.Fatalf("ComputeThumbprint failed: %v", err)
	}
	if len(thumb) != 40 {
		t.Errorf("expected 40-char hex thumbprint, got %d chars", len(thumb))
	}
	// Verify uppercase hex
	for _, c := range thumb {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Errorf("thumbprint contains non-uppercase-hex char: %c", c)
		}
	}
}

func TestComputeThumbprint_InvalidPEM(t *testing.T) {
	_, err := ComputeThumbprint("not a cert")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	pw, err := GenerateRandomPassword(32)
	if err != nil {
		t.Fatalf("GenerateRandomPassword failed: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("expected 32-char password, got %d", len(pw))
	}
}

func TestGenerateRandomPassword_Uniqueness(t *testing.T) {
	pw1, _ := GenerateRandomPassword(32)
	pw2, _ := GenerateRandomPassword(32)
	if pw1 == pw2 {
		t.Error("two generated passwords should not be identical")
	}
}

func TestParseCertificatePEM_Success(t *testing.T) {
	certPEM, _, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN test.example.com, got %s", cert.Subject.CommonName)
	}
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	_, err := ParseCertificatePEM("not a cert")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
