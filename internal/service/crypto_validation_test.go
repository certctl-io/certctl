package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// generateTestCSR creates a valid CSR PEM for testing purposes.
func generateTestCSR(t *testing.T, keyType string, keySize int) string {
	t.Helper()

	var privKey interface{}
	var err error

	switch keyType {
	case "RSA":
		privKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		default:
			t.Fatalf("unsupported ECDSA key size: %d", keySize)
		}
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames: []string{"test.example.com", "www.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM)
}

func TestValidateCSRAgainstProfile_NilProfile(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 256)

	result, err := ValidateCSRAgainstProfile(csrPEM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", result.KeyAlgorithm)
	}
	if result.KeySize != 256 {
		t.Errorf("expected 256, got %d", result.KeySize)
	}
}

func TestValidateCSRAgainstProfile_ECDSA256_Allowed(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 256)

	profile := &domain.CertificateProfile{
		Name: "Standard TLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
			{Algorithm: "RSA", MinSize: 2048},
		},
	}

	result, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", result.KeyAlgorithm)
	}
	if result.KeySize != 256 {
		t.Errorf("expected 256, got %d", result.KeySize)
	}
}

func TestValidateCSRAgainstProfile_ECDSA384_Allowed(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 384)

	profile := &domain.CertificateProfile{
		Name: "High Security",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 384},
		},
	}

	result, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeySize != 384 {
		t.Errorf("expected 384, got %d", result.KeySize)
	}
}

func TestValidateCSRAgainstProfile_RSA2048_Allowed(t *testing.T) {
	csrPEM := generateTestCSR(t, "RSA", 2048)

	profile := &domain.CertificateProfile{
		Name: "Standard TLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "RSA", MinSize: 2048},
		},
	}

	result, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "RSA" {
		t.Errorf("expected RSA, got %s", result.KeyAlgorithm)
	}
	if result.KeySize != 2048 {
		t.Errorf("expected 2048, got %d", result.KeySize)
	}
}

func TestValidateCSRAgainstProfile_ECDSA256_RejectedByHighSecurity(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 256)

	profile := &domain.CertificateProfile{
		Name: "High Security",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 384},
			{Algorithm: "RSA", MinSize: 4096},
		},
	}

	_, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err == nil {
		t.Fatal("expected rejection, got nil error")
	}
	if !containsSubstring(err.Error(), "does not match any allowed algorithm") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateCSRAgainstProfile_RSA_RejectedByECDSAOnly(t *testing.T) {
	csrPEM := generateTestCSR(t, "RSA", 2048)

	profile := &domain.CertificateProfile{
		Name: "ECDSA Only",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
		},
	}

	_, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err == nil {
		t.Fatal("expected rejection, got nil error")
	}
}

func TestValidateCSRAgainstProfile_EmptyAlgorithmRules(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 256)

	profile := &domain.CertificateProfile{
		Name:                 "Permissive",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{}, // empty = allow anything
	}

	result, err := ValidateCSRAgainstProfile(csrPEM, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", result.KeyAlgorithm)
	}
}

func TestValidateCSRAgainstProfile_InvalidPEM(t *testing.T) {
	_, err := ValidateCSRAgainstProfile("not a pem", nil)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
	if !containsSubstring(err.Error(), "failed to decode CSR PEM") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestValidateCSRAgainstProfile_InvalidCSRContent(t *testing.T) {
	// Valid PEM block but garbage content
	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nTm90IGEgcmVhbCBDU1I=\n-----END CERTIFICATE REQUEST-----"

	_, err := ValidateCSRAgainstProfile(csrPEM, nil)
	if err == nil {
		t.Fatal("expected error for invalid CSR content, got nil")
	}
}

func TestExtractCSRKeyInfo_ECDSA(t *testing.T) {
	csrPEM := generateTestCSR(t, "ECDSA", 256)

	result, err := extractCSRKeyInfo(csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", result.KeyAlgorithm)
	}
	if result.KeySize != 256 {
		t.Errorf("expected 256, got %d", result.KeySize)
	}
}

func TestExtractCSRKeyInfo_RSA(t *testing.T) {
	csrPEM := generateTestCSR(t, "RSA", 2048)

	result, err := extractCSRKeyInfo(csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyAlgorithm != "RSA" {
		t.Errorf("expected RSA, got %s", result.KeyAlgorithm)
	}
	if result.KeySize != 2048 {
		t.Errorf("expected 2048, got %d", result.KeySize)
	}
}
