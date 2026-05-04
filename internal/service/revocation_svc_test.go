// Tests for RevocationSvc, the focused sub-service that handles certificate
// revocation logic extracted from CertificateService (TICKET-007).
package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// helper to create a RevocationSvc for testing
func newRevocationSvcTest() (*RevocationSvc, *mockCertRepo, *mockRevocationRepo, *mockAuditRepo) {
	certRepo := newMockCertificateRepository()
	revocationRepo := newMockRevocationRepository()
	auditRepo := newMockAuditRepository()

	auditService := NewAuditService(auditRepo)
	revSvc := NewRevocationSvc(certRepo, revocationRepo, auditService)
	registry := NewIssuerRegistry(slog.Default())
	registry.Set("iss-local", &mockIssuerConnector{})
	revSvc.SetIssuerRegistry(registry)

	return revSvc, certRepo, revocationRepo, auditRepo
}

func TestRevocationSvc_RevokeCertificateWithActor_Success(t *testing.T) {
	revSvc, certRepo, revocationRepo, auditRepo := newRevocationSvcTest()

	// Set up test data
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)

	// Add a certificate version with a serial number
	version := &domain.CertificateVersion{
		ID:            "ver-1",
		CertificateID: "cert-1",
		SerialNumber:  "ABC123",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-1"] = []*domain.CertificateVersion{version}

	// Revoke
	err := revSvc.RevokeCertificateWithActor(context.Background(), "cert-1", "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify certificate status changed
	updated, _ := certRepo.Get(context.Background(), "cert-1")
	if updated.Status != domain.CertificateStatusRevoked {
		t.Errorf("expected status Revoked, got %s", updated.Status)
	}
	if updated.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if updated.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason keyCompromise, got %s", updated.RevocationReason)
	}

	// Verify revocation record created
	if len(revocationRepo.Revocations) != 1 {
		t.Fatalf("expected 1 revocation record, got %d", len(revocationRepo.Revocations))
	}
	rev := revocationRepo.Revocations[0]
	if rev.SerialNumber != "ABC123" {
		t.Errorf("expected serial ABC123, got %s", rev.SerialNumber)
	}
	if rev.Reason != "keyCompromise" {
		t.Errorf("expected reason keyCompromise, got %s", rev.Reason)
	}
	if rev.RevokedBy != "admin" {
		t.Errorf("expected revokedBy admin, got %s", rev.RevokedBy)
	}

	// Verify audit event recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected audit event to be recorded")
	}
}

func TestRevocationSvc_RevokeCertificateWithActor_AlreadyRevoked(t *testing.T) {
	revSvc, certRepo, _, _ := newRevocationSvcTest()

	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:               "cert-3",
		CommonName:       "already-revoked.com",
		IssuerID:         "iss-local",
		Status:           domain.CertificateStatusRevoked,
		RevokedAt:        &now,
		RevocationReason: "keyCompromise",
		ExpiresAt:        time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)

	err := revSvc.RevokeCertificateWithActor(context.Background(), "cert-3", "superseded", "admin")
	if err == nil {
		t.Fatal("expected error for already revoked certificate")
	}
	if err.Error() != "certificate is already revoked" {
		t.Errorf("expected 'already revoked' error, got: %v", err)
	}
}

func TestRevocationSvc_GetRevokedCertificates_Success(t *testing.T) {
	revSvc, _, revocationRepo, _ := newRevocationSvcTest()

	// Pre-populate revocation records
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{ID: "rev-1", CertificateID: "cert-1", SerialNumber: "SER-1", Reason: "keyCompromise", RevokedAt: time.Now()},
		{ID: "rev-2", CertificateID: "cert-2", SerialNumber: "SER-2", Reason: "superseded", RevokedAt: time.Now()},
	}

	revocations, err := revSvc.GetRevokedCertificates(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(revocations) != 2 {
		t.Errorf("expected 2 revocations, got %d", len(revocations))
	}
}
