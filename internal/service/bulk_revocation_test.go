package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to create a test BulkRevocationService wired for bulk revocation tests
func newBulkRevocationTestService() (*BulkRevocationService, *mockCertRepo, *mockRevocationRepo, *mockAuditRepo) {
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	revocationRepo := newMockRevocationRepository()

	auditService := NewAuditService(auditRepo)

	// Create RevocationSvc (underlying single-cert revocation)
	revSvc := NewRevocationSvc(certRepo, revocationRepo, auditService)
	registry := NewIssuerRegistry(slog.Default())
	registry.Set("iss-local", &mockIssuerConnector{})
	revSvc.SetIssuerRegistry(registry)

	bulkSvc := NewBulkRevocationService(revSvc, certRepo, auditService, slog.Default())

	return bulkSvc, certRepo, revocationRepo, auditRepo
}

func addTestCert(repo *mockCertRepo, id, status, issuerID string) {
	cert := &domain.ManagedCertificate{
		ID:         id,
		CommonName: id + ".example.com",
		Status:     domain.CertificateStatus(status),
		IssuerID:   issuerID,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	repo.AddCert(cert)
	// Add a version with serial number (needed by RevokeCertificateWithActor)
	repo.Versions[id] = []*domain.CertificateVersion{
		{
			ID:            "ver-" + id,
			CertificateID: id,
			SerialNumber:  "serial-" + id,
			NotBefore:     time.Now(),
			NotAfter:      time.Now().AddDate(1, 0, 0),
			CreatedAt:     time.Now(),
		},
	}
}

func addTestCertWithProfile(repo *mockCertRepo, id, status, issuerID, profileID, ownerID string) {
	cert := &domain.ManagedCertificate{
		ID:                   id,
		CommonName:           id + ".example.com",
		Status:               domain.CertificateStatus(status),
		IssuerID:             issuerID,
		CertificateProfileID: profileID,
		OwnerID:              ownerID,
		ExpiresAt:            time.Now().AddDate(0, 6, 0),
	}
	repo.AddCert(cert)
	repo.Versions[id] = []*domain.CertificateVersion{
		{
			ID:            "ver-" + id,
			CertificateID: id,
			SerialNumber:  "serial-" + id,
			NotBefore:     time.Now(),
			NotAfter:      time.Now().AddDate(1, 0, 0),
			CreatedAt:     time.Now(),
		},
	}
}

func TestBulkRevoke_ByExplicitIDs(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	addTestCert(certRepo, "mc-1", "Active", "iss-local")
	addTestCert(certRepo, "mc-2", "Active", "iss-local")
	addTestCert(certRepo, "mc-3", "Active", "iss-local")

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-1", "mc-2", "mc-3"},
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.TotalMatched != 3 {
		t.Errorf("expected TotalMatched=3, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 3 {
		t.Errorf("expected TotalRevoked=3, got %d", result.TotalRevoked)
	}
	if result.TotalSkipped != 0 {
		t.Errorf("expected TotalSkipped=0, got %d", result.TotalSkipped)
	}
	if result.TotalFailed != 0 {
		t.Errorf("expected TotalFailed=0, got %d", result.TotalFailed)
	}

	// Verify certs are revoked
	for _, id := range []string{"mc-1", "mc-2", "mc-3"} {
		cert, _ := certRepo.Get(context.Background(), id)
		if cert.Status != domain.CertificateStatusRevoked {
			t.Errorf("expected cert %s to be Revoked, got %s", id, cert.Status)
		}
	}
}

func TestBulkRevoke_ByProfile(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	// The mock List returns all certs regardless of filter (mock limitation).
	// We test the code path — real repo would filter by profile.
	addTestCert(certRepo, "mc-1", "Active", "iss-local")
	addTestCert(certRepo, "mc-2", "Active", "iss-local")

	criteria := domain.BulkRevocationCriteria{
		ProfileID: "prof-tls",
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.TotalMatched != 2 {
		t.Errorf("expected TotalMatched=2, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 2 {
		t.Errorf("expected TotalRevoked=2, got %d", result.TotalRevoked)
	}
}

func TestBulkRevoke_ByOwner(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	addTestCertWithProfile(certRepo, "mc-1", "Active", "iss-local", "", "o-alice")
	addTestCertWithProfile(certRepo, "mc-2", "Active", "iss-local", "", "o-alice")

	criteria := domain.BulkRevocationCriteria{
		OwnerID: "o-alice",
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "cessationOfOperation", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.TotalRevoked != 2 {
		t.Errorf("expected TotalRevoked=2, got %d", result.TotalRevoked)
	}
}

func TestBulkRevoke_MultipleCriteria(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	addTestCertWithProfile(certRepo, "mc-1", "Active", "iss-local", "prof-tls", "o-alice")
	addTestCertWithProfile(certRepo, "mc-2", "Active", "iss-local", "prof-tls", "o-bob")

	criteria := domain.BulkRevocationCriteria{
		ProfileID:      "prof-tls",
		CertificateIDs: []string{"mc-1"}, // Intersect: only mc-1 from the filter results
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Both certs match the filter, but intersection with IDs gives 1
	if result.TotalMatched != 1 {
		t.Errorf("expected TotalMatched=1, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 1 {
		t.Errorf("expected TotalRevoked=1, got %d", result.TotalRevoked)
	}

	// mc-1 should be revoked, mc-2 should not
	cert1, _ := certRepo.Get(context.Background(), "mc-1")
	if cert1.Status != domain.CertificateStatusRevoked {
		t.Errorf("expected mc-1 to be Revoked, got %s", cert1.Status)
	}
	cert2, _ := certRepo.Get(context.Background(), "mc-2")
	if cert2.Status == domain.CertificateStatusRevoked {
		t.Error("expected mc-2 to NOT be revoked")
	}
}

func TestBulkRevoke_EmptyCriteria_Error(t *testing.T) {
	svc, _, _, _ := newBulkRevocationTestService()

	criteria := domain.BulkRevocationCriteria{}
	_, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err == nil {
		t.Fatal("expected error for empty criteria")
	}
	if !strings.Contains(err.Error(), "at least one filter criterion") {
		t.Errorf("expected 'at least one filter criterion' error, got: %v", err)
	}
}

func TestBulkRevoke_InvalidReason_Error(t *testing.T) {
	svc, _, _, _ := newBulkRevocationTestService()

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-1"},
	}

	_, err := svc.BulkRevoke(context.Background(), criteria, "totallyBogus", "admin")
	if err == nil {
		t.Fatal("expected error for invalid reason")
	}
	if !strings.Contains(err.Error(), "invalid revocation reason") {
		t.Errorf("expected 'invalid revocation reason' error, got: %v", err)
	}
}

func TestBulkRevoke_EmptyReason_Error(t *testing.T) {
	svc, _, _, _ := newBulkRevocationTestService()

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-1"},
	}

	_, err := svc.BulkRevoke(context.Background(), criteria, "", "admin")
	if err == nil {
		t.Fatal("expected error for empty reason")
	}
	if !strings.Contains(err.Error(), "revocation reason is required") {
		t.Errorf("expected 'revocation reason is required' error, got: %v", err)
	}
}

func TestBulkRevoke_SkipsRevokedAndArchived(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	addTestCert(certRepo, "mc-active", "Active", "iss-local")
	addTestCert(certRepo, "mc-revoked", "Revoked", "iss-local")
	addTestCert(certRepo, "mc-archived", "Archived", "iss-local")

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-active", "mc-revoked", "mc-archived"},
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.TotalMatched != 3 {
		t.Errorf("expected TotalMatched=3, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 1 {
		t.Errorf("expected TotalRevoked=1, got %d", result.TotalRevoked)
	}
	if result.TotalSkipped != 2 {
		t.Errorf("expected TotalSkipped=2, got %d", result.TotalSkipped)
	}
}

func TestBulkRevoke_PartialFailure(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()

	// mc-1 is active with version — will succeed
	addTestCert(certRepo, "mc-1", "Active", "iss-local")
	// mc-2 is active but has NO version — RevokeCertificateWithActor will fail on GetLatestVersion
	cert2 := &domain.ManagedCertificate{
		ID:         "mc-2",
		CommonName: "mc-2.example.com",
		Status:     domain.CertificateStatusActive,
		IssuerID:   "iss-local",
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert2)
	// Don't add versions for mc-2 so GetLatestVersion returns errNotFound

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-1", "mc-2"},
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error (partial failure is ok), got: %v", err)
	}

	if result.TotalMatched != 2 {
		t.Errorf("expected TotalMatched=2, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 1 {
		t.Errorf("expected TotalRevoked=1, got %d", result.TotalRevoked)
	}
	if result.TotalFailed != 1 {
		t.Errorf("expected TotalFailed=1, got %d", result.TotalFailed)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error entry, got %d", len(result.Errors))
	}
	if result.Errors[0].CertificateID != "mc-2" {
		t.Errorf("expected error for mc-2, got %s", result.Errors[0].CertificateID)
	}
}

func TestBulkRevoke_AuditEvent(t *testing.T) {
	svc, certRepo, _, auditRepo := newBulkRevocationTestService()

	addTestCert(certRepo, "mc-1", "Active", "iss-local")

	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-1"},
	}

	_, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Find the bulk_revocation_initiated audit event
	var found bool
	for _, event := range auditRepo.Events {
		if event.Action == "bulk_revocation_initiated" {
			found = true
			if event.Actor != "admin" {
				t.Errorf("expected actor 'admin', got '%s'", event.Actor)
			}
			if event.ResourceType != "certificate" {
				t.Errorf("expected resource type 'certificate', got '%s'", event.ResourceType)
			}
			break
		}
	}
	if !found {
		t.Error("expected bulk_revocation_initiated audit event")
	}
}

func TestBulkRevoke_NoMatches(t *testing.T) {
	svc, _, _, _ := newBulkRevocationTestService()

	// IDs that don't exist in the repo
	criteria := domain.BulkRevocationCriteria{
		CertificateIDs: []string{"mc-nonexistent-1", "mc-nonexistent-2"},
	}

	result, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.TotalMatched != 0 {
		t.Errorf("expected TotalMatched=0, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 0 {
		t.Errorf("expected TotalRevoked=0, got %d", result.TotalRevoked)
	}
}

func TestBulkRevoke_ListError(t *testing.T) {
	svc, certRepo, _, _ := newBulkRevocationTestService()
	certRepo.ListErr = errors.New("database connection failed")

	criteria := domain.BulkRevocationCriteria{
		ProfileID: "prof-tls",
	}

	_, err := svc.BulkRevoke(context.Background(), criteria, "keyCompromise", "admin")
	if err == nil {
		t.Fatal("expected error from list failure")
	}
	if !strings.Contains(err.Error(), "failed to resolve certificates") {
		t.Errorf("expected 'failed to resolve certificates' error, got: %v", err)
	}
}
