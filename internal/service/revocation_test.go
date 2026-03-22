package service

import (
	"context"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to create a test CertificateService wired for revocation tests
func newRevocationTestService() (*CertificateService, *mockCertRepo, *mockRevocationRepo, *mockAuditRepo) {
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()
	revocationRepo := newMockRevocationRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)
	certService := NewCertificateService(certRepo, policyService, auditService)
	certService.SetRevocationRepo(revocationRepo)

	return certService, certRepo, revocationRepo, auditRepo
}

func TestRevokeCertificate_Success(t *testing.T) {
	svc, certRepo, revocationRepo, auditRepo := newRevocationTestService()

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
	err := svc.RevokeCertificateWithActor(context.Background(), "cert-1", "keyCompromise", "admin")
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
	foundRevocationAudit := false
	for _, e := range auditRepo.Events {
		if e.Action == "certificate_revoked" {
			foundRevocationAudit = true
		}
	}
	if !foundRevocationAudit {
		t.Error("expected certificate_revoked audit event")
	}
}

func TestRevokeCertificate_DefaultReason(t *testing.T) {
	svc, certRepo, revocationRepo, _ := newRevocationTestService()

	cert := &domain.ManagedCertificate{
		ID:         "cert-2",
		CommonName: "default-reason.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)
	certRepo.Versions["cert-2"] = []*domain.CertificateVersion{
		{ID: "ver-2", CertificateID: "cert-2", SerialNumber: "DEF456", CreatedAt: time.Now()},
	}

	// Revoke with empty reason — should default to "unspecified"
	err := svc.RevokeCertificateWithActor(context.Background(), "cert-2", "", "api")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	updated, _ := certRepo.Get(context.Background(), "cert-2")
	if updated.RevocationReason != "unspecified" {
		t.Errorf("expected default reason 'unspecified', got %s", updated.RevocationReason)
	}

	if len(revocationRepo.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(revocationRepo.Revocations))
	}
	if revocationRepo.Revocations[0].Reason != "unspecified" {
		t.Errorf("expected revocation reason 'unspecified', got %s", revocationRepo.Revocations[0].Reason)
	}
}

func TestRevokeCertificate_AlreadyRevoked(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

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

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-3", "superseded", "admin")
	if err == nil {
		t.Fatal("expected error for already revoked certificate")
	}
	if err.Error() != "certificate is already revoked" {
		t.Errorf("expected 'already revoked' error, got: %v", err)
	}
}

func TestRevokeCertificate_ArchivedCert(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

	cert := &domain.ManagedCertificate{
		ID:         "cert-4",
		CommonName: "archived.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusArchived,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-4", "keyCompromise", "admin")
	if err == nil {
		t.Fatal("expected error for archived certificate")
	}
	if err.Error() != "cannot revoke archived certificate" {
		t.Errorf("expected 'cannot revoke archived' error, got: %v", err)
	}
}

func TestRevokeCertificate_InvalidReason(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

	cert := &domain.ManagedCertificate{
		ID:         "cert-5",
		CommonName: "invalid-reason.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-5", "notAValidReason", "admin")
	if err == nil {
		t.Fatal("expected error for invalid reason")
	}
	if err.Error() != "invalid revocation reason: notAValidReason" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	svc, _, _, _ := newRevocationTestService()

	err := svc.RevokeCertificateWithActor(context.Background(), "nonexistent-cert", "keyCompromise", "admin")
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

func TestRevokeCertificate_NoVersion(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

	cert := &domain.ManagedCertificate{
		ID:         "cert-6",
		CommonName: "no-version.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)
	// No versions added — should fail

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-6", "keyCompromise", "admin")
	if err == nil {
		t.Fatal("expected error when no certificate version exists")
	}
}

func TestRevokeCertificate_WithIssuerNotification(t *testing.T) {
	svc, certRepo, revocationRepo, _ := newRevocationTestService()

	// Wire up issuer registry with mock
	mockIssuer := &mockIssuerConnector{}
	svc.SetIssuerRegistry(map[string]IssuerConnector{
		"iss-local": mockIssuer,
	})

	cert := &domain.ManagedCertificate{
		ID:         "cert-7",
		CommonName: "issuer-notify.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)
	certRepo.Versions["cert-7"] = []*domain.CertificateVersion{
		{ID: "ver-7", CertificateID: "cert-7", SerialNumber: "GHI789", CreatedAt: time.Now()},
	}

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-7", "cessationOfOperation", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify revocation was recorded and issuer was notified
	if len(revocationRepo.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(revocationRepo.Revocations))
	}
	if !revocationRepo.Revocations[0].IssuerNotified {
		t.Error("expected issuer to be marked as notified")
	}
}

func TestRevokeCertificate_WithNotificationService(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

	// Wire up notification service
	notifRepo := newMockNotificationRepository()
	notifService := NewNotificationService(notifRepo, make(map[string]Notifier))
	svc.SetNotificationService(notifService)

	cert := &domain.ManagedCertificate{
		ID:         "cert-8",
		CommonName: "with-notify.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		OwnerID:    "owner-alice",
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)
	certRepo.Versions["cert-8"] = []*domain.CertificateVersion{
		{ID: "ver-8", CertificateID: "cert-8", SerialNumber: "JKL012", CreatedAt: time.Now()},
	}

	err := svc.RevokeCertificateWithActor(context.Background(), "cert-8", "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should have created revocation notifications (webhook + email)
	if len(notifRepo.Notifications) < 1 {
		t.Error("expected at least one revocation notification to be created")
	}

	foundRevocationNotif := false
	for _, n := range notifRepo.Notifications {
		if n.Type == domain.NotificationTypeRevocation {
			foundRevocationNotif = true
		}
	}
	if !foundRevocationNotif {
		t.Error("expected Revocation type notification")
	}
}

func TestRevokeCertificate_AllValidReasons(t *testing.T) {
	reasons := []string{
		"unspecified", "keyCompromise", "caCompromise", "affiliationChanged",
		"superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn",
	}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			svc, certRepo, _, _ := newRevocationTestService()

			cert := &domain.ManagedCertificate{
				ID:         "cert-" + reason,
				CommonName: reason + ".com",
				IssuerID:   "iss-local",
				Status:     domain.CertificateStatusActive,
				ExpiresAt:  time.Now().AddDate(0, 6, 0),
			}
			certRepo.AddCert(cert)
			certRepo.Versions["cert-"+reason] = []*domain.CertificateVersion{
				{ID: "ver-" + reason, CertificateID: "cert-" + reason, SerialNumber: "SER-" + reason, CreatedAt: time.Now()},
			}

			err := svc.RevokeCertificateWithActor(context.Background(), "cert-"+reason, reason, "admin")
			if err != nil {
				t.Fatalf("expected no error for reason %s, got: %v", reason, err)
			}

			updated, _ := certRepo.Get(context.Background(), "cert-"+reason)
			if updated.Status != domain.CertificateStatusRevoked {
				t.Errorf("expected Revoked status, got %s", updated.Status)
			}
		})
	}
}

func TestGetRevokedCertificates_Success(t *testing.T) {
	svc, _, revocationRepo, _ := newRevocationTestService()

	// Pre-populate revocation records
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{ID: "rev-1", CertificateID: "cert-1", SerialNumber: "SER-1", Reason: "keyCompromise", RevokedAt: time.Now()},
		{ID: "rev-2", CertificateID: "cert-2", SerialNumber: "SER-2", Reason: "superseded", RevokedAt: time.Now()},
	}

	revocations, err := svc.GetRevokedCertificates()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(revocations) != 2 {
		t.Errorf("expected 2 revocations, got %d", len(revocations))
	}
}

func TestGetRevokedCertificates_Empty(t *testing.T) {
	svc, _, _, _ := newRevocationTestService()

	revocations, err := svc.GetRevokedCertificates()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if revocations == nil {
		// nil is acceptable for empty
	} else if len(revocations) != 0 {
		t.Errorf("expected 0 revocations, got %d", len(revocations))
	}
}

func TestGetRevokedCertificates_NoRepo(t *testing.T) {
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()
	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)
	svc := NewCertificateService(certRepo, policyService, auditService)
	// Do NOT set revocation repo

	_, err := svc.GetRevokedCertificates()
	if err == nil {
		t.Fatal("expected error when revocation repo not configured")
	}
}

func TestRevokeCertificate_HandlerInterfaceMethod(t *testing.T) {
	svc, certRepo, _, _ := newRevocationTestService()

	cert := &domain.ManagedCertificate{
		ID:         "cert-handler",
		CommonName: "handler-test.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)
	certRepo.Versions["cert-handler"] = []*domain.CertificateVersion{
		{ID: "ver-handler", CertificateID: "cert-handler", SerialNumber: "SER-HANDLER", CreatedAt: time.Now()},
	}

	// Test the handler interface method (no actor param)
	err := svc.RevokeCertificate("cert-handler", "superseded")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	updated, _ := certRepo.Get(context.Background(), "cert-handler")
	if updated.Status != domain.CertificateStatusRevoked {
		t.Errorf("expected Revoked status, got %s", updated.Status)
	}
}
