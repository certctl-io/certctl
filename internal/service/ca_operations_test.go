// Tests for CAOperationsSvc, the focused sub-service that handles CRL generation
// and OCSP response signing extracted from CertificateService (TICKET-007).
package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to create a CAOperationsSvc for testing
func newCAOperationsSvcTest() (*CAOperationsSvc, *mockRevocationRepo, *mockCertRepo) {
	revocationRepo := newMockRevocationRepository()
	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()

	caSvc := NewCAOperationsSvc(revocationRepo, certRepo, profileRepo)
	registry := NewIssuerRegistry(slog.Default())
	registry.Set("iss-local", &mockIssuerConnector{})
	caSvc.SetIssuerRegistry(registry)

	return caSvc, revocationRepo, certRepo
}

func TestCAOperationsSvc_GenerateDERCRL_Success(t *testing.T) {
	caSvc, revocationRepo, _ := newCAOperationsSvcTest()

	// Add some revoked certificates to the repo
	now := time.Now()
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{
			SerialNumber:  "SERIAL-001",
			CertificateID: "cert-1",
			IssuerID:      "iss-local",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-24 * time.Hour),
			RevokedBy:     "admin",
		},
		{
			SerialNumber:  "SERIAL-002",
			CertificateID: "cert-2",
			IssuerID:      "iss-local",
			Reason:        "superseded",
			RevokedAt:     now.Add(-12 * time.Hour),
			RevokedBy:     "admin",
		},
	}

	crl, err := caSvc.GenerateDERCRL(context.Background(), "iss-local")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}

	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL")
	}

	t.Logf("DER CRL generated successfully: %d bytes", len(crl))
}

func TestCAOperationsSvc_GenerateDERCRL_EmptyCRL(t *testing.T) {
	caSvc, revocationRepo, _ := newCAOperationsSvcTest()

	// No revoked certs for this issuer
	revocationRepo.Revocations = []*domain.CertificateRevocation{}

	crl, err := caSvc.GenerateDERCRL(context.Background(), "iss-local")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL even when empty")
	}

	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL bytes (at least the CRL structure)")
	}

	t.Logf("Empty DER CRL generated successfully: %d bytes", len(crl))
}

func TestCAOperationsSvc_GetOCSPResponse_Good(t *testing.T) {
	caSvc, _, certRepo := newCAOperationsSvcTest()

	// Add a non-revoked certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-ocsp-good",
		CommonName: "good.example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}
	certRepo.AddCert(cert)

	version := &domain.CertificateVersion{
		ID:            "ver-ocsp-good",
		CertificateID: "cert-ocsp-good",
		SerialNumber:  "OCSP-GOOD-001",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-ocsp-good"] = []*domain.CertificateVersion{version}

	// Request OCSP response for good cert
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "OCSP-GOOD-001")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for good cert")
	}

	t.Logf("OCSP response for good cert generated: %d bytes", len(resp))
}

func TestCAOperationsSvc_GetOCSPResponse_Revoked(t *testing.T) {
	caSvc, revocationRepo, certRepo := newCAOperationsSvcTest()

	now := time.Now()

	// Add a revoked certificate
	cert := &domain.ManagedCertificate{
		ID:               "cert-ocsp-revoked",
		CommonName:       "revoked.example.com",
		IssuerID:         "iss-local",
		Status:           domain.CertificateStatusRevoked,
		RevokedAt:        &now,
		RevocationReason: "keyCompromise",
		ExpiresAt:        time.Now().AddDate(1, 0, 0),
	}
	certRepo.AddCert(cert)

	version := &domain.CertificateVersion{
		ID:            "ver-ocsp-revoked",
		CertificateID: "cert-ocsp-revoked",
		SerialNumber:  "OCSP-REVOKED-001",
		NotBefore:     time.Now().Add(-24 * time.Hour),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-ocsp-revoked"] = []*domain.CertificateVersion{version}

	// Add revocation record
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{
			SerialNumber:  "OCSP-REVOKED-001",
			CertificateID: "cert-ocsp-revoked",
			IssuerID:      "iss-local",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-24 * time.Hour),
			RevokedBy:     "admin",
		},
	}

	// Request OCSP response for revoked cert
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "OCSP-REVOKED-001")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for revoked cert")
	}

	t.Logf("OCSP response for revoked cert generated: %d bytes", len(resp))
}
