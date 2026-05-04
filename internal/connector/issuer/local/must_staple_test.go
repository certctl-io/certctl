package local

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// SCEP RFC 8894 + Intune master bundle Phase 5.6: must-staple per-profile
// policy field (RFC 7633).
//
// Pins the contract that:
//
//  1. When the IssuanceRequest carries MustStaple=true, the issued cert
//     contains the id-pe-tlsfeature extension with the canonical
//     wire bytes (SEQUENCE OF INTEGER {5} per RFC 7633 §6).
//
//  2. When MustStaple=false (or unset), the extension is OMITTED — adding
//     it by default would break customer deployments where the TLS path
//     doesn't staple.
//
//  3. The OID + DER bytes match RFC 7633 §6 verbatim:
//     OID 1.3.6.1.5.5.7.1.24, value 0x30 0x03 0x02 0x01 0x05.
//
// The test exercises the local issuer end-to-end (CSR → CreateCertificate
// → ParseCertificate → walk Extensions) so any drift in the extension-
// injection path is caught.

func TestGenerateCertificate_MustStapleProfile_AddsExtension(t *testing.T) {
	conn, _ := newLocalIssuerForMustStapleTest(t)
	csrPEM := buildMustStapleCSR(t, "must-staple.example.com")

	result, err := conn.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName:    "must-staple.example.com",
		SANs:          []string{"must-staple.example.com"},
		CSRPEM:        csrPEM,
		EKUs:          []string{"serverAuth"},
		MaxTTLSeconds: 86400,
		MustStaple:    true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert := parsePEMCertForTest(t, result.CertPEM)
	ext := findExtensionByOID(cert, oidMustStaple)
	if ext == nil {
		t.Fatal("issued cert is missing id-pe-tlsfeature extension despite MustStaple=true")
	}
	if ext.Critical {
		t.Errorf("must-staple extension Critical = true, want false (RFC 7633 §6 says non-critical)")
	}
	if !bytes.Equal(ext.Value, mustStapleExtensionValue) {
		t.Errorf("must-staple extension Value = %x, want %x (RFC 7633 §6 SEQUENCE OF INTEGER {5})",
			ext.Value, mustStapleExtensionValue)
	}
}

func TestGenerateCertificate_NoMustStaple_OmitsExtension(t *testing.T) {
	conn, _ := newLocalIssuerForMustStapleTest(t)
	csrPEM := buildMustStapleCSR(t, "no-staple.example.com")

	result, err := conn.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName:    "no-staple.example.com",
		SANs:          []string{"no-staple.example.com"},
		CSRPEM:        csrPEM,
		EKUs:          []string{"serverAuth"},
		MaxTTLSeconds: 86400,
		// MustStaple intentionally unset — defaults to false.
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert := parsePEMCertForTest(t, result.CertPEM)
	if ext := findExtensionByOID(cert, oidMustStaple); ext != nil {
		t.Errorf("issued cert has id-pe-tlsfeature extension despite MustStaple=false (would break non-stapling deploys)")
	}
}

// TestMustStapleConstants_PinExactRFC7633Bytes locks down the exact OID +
// DER bytes against RFC 7633 §6. If a future refactor changes the
// pre-encoded value in any way, this test fails — catches drift before
// it reaches a real cert.
func TestMustStapleConstants_PinExactRFC7633Bytes(t *testing.T) {
	wantOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24} // id-pe-tlsfeature
	if !oidMustStaple.Equal(wantOID) {
		t.Errorf("oidMustStaple = %v, want %v (RFC 7633 §6)", oidMustStaple, wantOID)
	}

	// The TLS Feature for status_request is INTEGER 5 (per the IANA TLS
	// ExtensionType registry). RFC 7633 §6 wraps that in SEQUENCE OF.
	wantBytes := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	if !bytes.Equal(mustStapleExtensionValue, wantBytes) {
		t.Errorf("mustStapleExtensionValue = %x, want %x (SEQUENCE OF INTEGER {5})",
			mustStapleExtensionValue, wantBytes)
	}

	// Sanity: the bytes round-trip through asn1.Unmarshal as the
	// expected structure.
	var parsed []int
	if _, err := asn1.Unmarshal(mustStapleExtensionValue, &parsed); err != nil {
		t.Fatalf("mustStapleExtensionValue does not parse as SEQUENCE OF INTEGER: %v", err)
	}
	if len(parsed) != 1 || parsed[0] != 5 {
		t.Errorf("parsed mustStaple = %v, want [5]", parsed)
	}
}

// --- helpers -------------------------------------------------------------

// newLocalIssuerForMustStapleTest builds a self-signed local CA Connector
// using the package's standard New + ensureCA path — same constructor
// production uses, so any drift in the cert-template-injection code path
// is exercised faithfully.
func newLocalIssuerForMustStapleTest(t *testing.T) (*Connector, *x509.Certificate) {
	t.Helper()
	c := New(&Config{ValidityDays: 7}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.ensureCA(context.Background()); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	return c, c.caCert
}

func buildMustStapleCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey CSR: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parsePEMCertForTest(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("PEM decode returned nil")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func findExtensionByOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oid) {
			return &cert.Extensions[i]
		}
	}
	return nil
}
