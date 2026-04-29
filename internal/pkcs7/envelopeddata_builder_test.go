package pkcs7

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// freshRSARecipient produces a self-signed RSA-2048 cert + matching key
// usable as both EnvelopedData recipient (BUILDER input) and EnvelopedData
// decryptor (Decrypt input). RSA-2048 is the minimum the parser supports
// for keyTrans.
func freshRSARecipient(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "envelopeddata-builder-test"},
		Issuer:       pkix.Name{CommonName: "envelopeddata-builder-test-issuer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func TestBuildEnvelopedData_RoundTrip(t *testing.T) {
	cert, key := freshRSARecipient(t)
	plaintext := []byte("the eagle has landed at coordinate 47.6062N 122.3321W; key zeroize at exit")

	wire, err := BuildEnvelopedData(plaintext, cert, nil)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("empty wire bytes")
	}

	parsed, err := ParseEnvelopedData(wire)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	got, err := parsed.Decrypt(key, cert)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch:\n got = %q\nwant = %q", got, plaintext)
	}
}

func TestBuildEnvelopedData_AlgorithmIsAES256CBC(t *testing.T) {
	cert, _ := freshRSARecipient(t)
	wire, err := BuildEnvelopedData([]byte("alg-id pin"), cert, nil)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	parsed, err := ParseEnvelopedData(wire)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	if !parsed.ContentEncryptionAlg.Algorithm.Equal(OIDAES256CBC) {
		t.Errorf("alg = %v, want OIDAES256CBC %v", parsed.ContentEncryptionAlg.Algorithm, OIDAES256CBC)
	}
}

func TestBuildEnvelopedData_RecipientMatchesIssuerAndSerial(t *testing.T) {
	cert, _ := freshRSARecipient(t)
	wire, err := BuildEnvelopedData([]byte("rid pin"), cert, nil)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	parsed, err := ParseEnvelopedData(wire)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	if len(parsed.RecipientInfos) != 1 {
		t.Fatalf("recipient count = %d, want 1", len(parsed.RecipientInfos))
	}
	rid := parsed.RecipientInfos[0].IssuerAndSerial
	if !bytes.Equal(rid.IssuerRaw.FullBytes, cert.RawIssuer) {
		t.Errorf("issuer mismatch:\n got = %x\nwant = %x", rid.IssuerRaw.FullBytes, cert.RawIssuer)
	}
	if rid.SerialNumber == nil || rid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: got %v, want %v", rid.SerialNumber, cert.SerialNumber)
	}
}

func TestBuildEnvelopedData_RejectsNonRSARecipient(t *testing.T) {
	// EnvelopedData keyTrans requires RSA per the parser's contract; ECDSA
	// recipient certs MUST be rejected at build time so an operator never
	// ships a serverkeygen response that no client can decrypt.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "ecdsa-recipient-reject-test"},
		Issuer:       pkix.Name{CommonName: "ecdsa-recipient-reject-test-issuer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := BuildEnvelopedData([]byte("test"), cert, nil); err == nil {
		t.Fatal("expected error for non-RSA recipient cert")
	}
}

func TestBuildEnvelopedData_RejectsEmptyPlaintext(t *testing.T) {
	cert, _ := freshRSARecipient(t)
	_, err := BuildEnvelopedData(nil, cert, nil)
	if err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

func TestBuildEnvelopedData_RejectsNilCert(t *testing.T) {
	_, err := BuildEnvelopedData([]byte("x"), nil, nil)
	if err == nil {
		t.Fatal("expected error for nil recipient cert")
	}
}

func TestBuildEnvelopedData_LargePlaintextRoundTrip(t *testing.T) {
	// PKCS#7 padding + AES-256-CBC works for arbitrary plaintext lengths.
	// Pin the contract for a 4KiB-aligned key blob (typical PKCS#8 RSA-2048
	// is ~1.2KB; ECDSA P-384 is ~250B).
	cert, key := freshRSARecipient(t)
	big := bytes.Repeat([]byte("ABCDEFGH"), 512) // 4 KiB
	wire, err := BuildEnvelopedData(big, cert, nil)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	parsed, err := ParseEnvelopedData(wire)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	got, err := parsed.Decrypt(key, cert)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Errorf("4KiB round-trip mismatch")
	}
}
