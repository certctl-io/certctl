package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

func newBulkReassignmentTestService() (*BulkReassignmentService, *mockCertRepo, *mockOwnerRepo, *mockAuditRepo) {
	certRepo := newMockCertificateRepository()
	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewBulkReassignmentService(certRepo, ownerRepo, auditService, slog.Default())
	return svc, certRepo, ownerRepo, auditRepo
}

// addOwnedCert seeds a cert with a specific owner+team for reassignment.
func addOwnedCert(repo *mockCertRepo, id, ownerID, teamID string) {
	cert := &domain.ManagedCertificate{
		ID: id, CommonName: id, Status: domain.CertificateStatusActive,
		OwnerID: ownerID, TeamID: teamID,
		ExpiresAt: time.Now().AddDate(0, 1, 0),
	}
	repo.AddCert(cert)
}

func addOwner(repo *mockOwnerRepo, id string) {
	repo.owners[id] = &domain.Owner{ID: id, Name: id}
}

// TestBulkReassign_HappyPath — N certs all reassigned successfully.
func TestBulkReassign_HappyPath(t *testing.T) {
	svc, certRepo, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-alice", "")
	addOwnedCert(certRepo, "mc-2", "o-alice", "")
	addOwnedCert(certRepo, "mc-3", "o-alice", "")

	res, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1", "mc-2", "mc-3"},
			OwnerID:        "o-bob",
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign failed: %v", err)
	}
	if res.TotalReassigned != 3 || res.TotalSkipped != 0 || res.TotalFailed != 0 {
		t.Errorf("counts = reassigned:%d skipped:%d failed:%d, want 3/0/0",
			res.TotalReassigned, res.TotalSkipped, res.TotalFailed)
	}
	for _, id := range []string{"mc-1", "mc-2", "mc-3"} {
		if certRepo.Certs[id].OwnerID != "o-bob" {
			t.Errorf("cert %s: owner_id = %s, want o-bob", id, certRepo.Certs[id].OwnerID)
		}
	}
}

// TestBulkReassign_SkipsAlreadyOwned — certs already owned by the
// target are no-op-skipped (not counted as reassigned, not surfaced as
// errors). Operator sees "5 of your 10 selections were no-ops because
// Bob already owned them" without triaging fake errors.
func TestBulkReassign_SkipsAlreadyOwned(t *testing.T) {
	svc, certRepo, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-bob", "")   // already owned by target
	addOwnedCert(certRepo, "mc-2", "o-alice", "") // needs reassign

	res, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1", "mc-2"},
			OwnerID:        "o-bob",
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign failed: %v", err)
	}
	if res.TotalReassigned != 1 || res.TotalSkipped != 1 {
		t.Errorf("counts = reassigned:%d skipped:%d, want 1/1", res.TotalReassigned, res.TotalSkipped)
	}
	if len(res.Errors) != 0 {
		t.Errorf("already-owned skip should NOT populate Errors; got %v", res.Errors)
	}
}

// TestBulkReassign_OwnerIDRequired_Error — empty owner_id rejected.
func TestBulkReassign_OwnerIDRequired_Error(t *testing.T) {
	svc, certRepo, _, _ := newBulkReassignmentTestService()
	addOwnedCert(certRepo, "mc-1", "o-alice", "")
	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{CertificateIDs: []string{"mc-1"}, OwnerID: ""}, "admin")
	if err == nil {
		t.Fatal("expected error for empty owner_id, got nil")
	}
}

// TestBulkReassign_EmptyIDs_Error — empty IDs rejected.
func TestBulkReassign_EmptyIDs_Error(t *testing.T) {
	svc, _, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{CertificateIDs: []string{}, OwnerID: "o-bob"}, "admin")
	if err == nil {
		t.Fatal("expected error for empty IDs, got nil")
	}
}

// TestBulkReassign_OwnerNotFound_TypedSentinel — non-existent OwnerID
// returns ErrBulkReassignOwnerNotFound. Handler maps this to 400 (the
// operator picked an owner that doesn't exist) rather than 500 (server
// error). Sentinel-error rather than substring-error matches the
// project's post-M-1 error-mapping convention.
func TestBulkReassign_OwnerNotFound_TypedSentinel(t *testing.T) {
	svc, certRepo, _, _ := newBulkReassignmentTestService()
	addOwnedCert(certRepo, "mc-1", "o-alice", "")
	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{CertificateIDs: []string{"mc-1"}, OwnerID: "o-ghost"}, "admin")
	if err == nil {
		t.Fatal("expected ErrBulkReassignOwnerNotFound, got nil")
	}
	if !errors.Is(err, ErrBulkReassignOwnerNotFound) {
		t.Errorf("err is not ErrBulkReassignOwnerNotFound; got: %v", err)
	}
}

// TestBulkReassign_TeamIDOptional — happy path WITHOUT team_id leaves
// team_id unchanged. Empty team_id in request must not zero out the
// existing team_id on the cert.
func TestBulkReassign_TeamIDOptional(t *testing.T) {
	svc, certRepo, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-alice", "t-platform")

	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1"},
			OwnerID:        "o-bob",
			// TeamID intentionally omitted
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign failed: %v", err)
	}
	if certRepo.Certs["mc-1"].TeamID != "t-platform" {
		t.Errorf("team_id was zeroed out; want unchanged 't-platform', got %q", certRepo.Certs["mc-1"].TeamID)
	}
}

// TestBulkReassign_TeamIDProvided_Updates — when TeamID is non-empty in
// the request, both owner_id and team_id update.
func TestBulkReassign_TeamIDProvided_Updates(t *testing.T) {
	svc, certRepo, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-alice", "t-platform")

	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1"},
			OwnerID:        "o-bob",
			TeamID:         "t-security",
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign failed: %v", err)
	}
	if certRepo.Certs["mc-1"].TeamID != "t-security" {
		t.Errorf("team_id = %q, want t-security", certRepo.Certs["mc-1"].TeamID)
	}
}

// TestBulkReassign_PartialFailure — N=3, one cert mid-batch hits an
// Update error. Rest of the batch continues; failure surfaced in
// Errors.
func TestBulkReassign_PartialFailure(t *testing.T) {
	svc, certRepo, ownerRepo, _ := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-alice", "")
	addOwnedCert(certRepo, "mc-2", "o-alice", "")
	addOwnedCert(certRepo, "mc-3", "o-alice", "")

	// Force the next Update to fail uniformly. Mirrors how
	// TestBulkRevoke_PartialFailure injects a downstream failure.
	certRepo.UpdateErr = errors.New("simulated DB outage")

	res, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1", "mc-2", "mc-3"},
			OwnerID:        "o-bob",
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign should not propagate per-cert errors; got: %v", err)
	}
	if res.TotalFailed != 3 || res.TotalReassigned != 0 {
		t.Errorf("counts = failed:%d reassigned:%d, want 3/0", res.TotalFailed, res.TotalReassigned)
	}
}

// TestBulkReassign_AuditEventEmitted — single bulk audit event.
func TestBulkReassign_AuditEventEmitted(t *testing.T) {
	svc, certRepo, ownerRepo, auditRepo := newBulkReassignmentTestService()
	addOwner(ownerRepo, "o-bob")
	addOwnedCert(certRepo, "mc-1", "o-alice", "")
	addOwnedCert(certRepo, "mc-2", "o-alice", "")

	_, err := svc.BulkReassign(context.Background(),
		domain.BulkReassignmentRequest{
			CertificateIDs: []string{"mc-1", "mc-2"},
			OwnerID:        "o-bob",
		}, "admin")
	if err != nil {
		t.Fatalf("BulkReassign failed: %v", err)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("audit events count = %d, want exactly 1 (one bulk event, NOT N per-cert events)", len(auditRepo.Events))
	}
	if len(auditRepo.Events) > 0 && auditRepo.Events[0].Action != "bulk_reassignment_initiated" {
		t.Errorf("audit action = %q, want 'bulk_reassignment_initiated'", auditRepo.Events[0].Action)
	}
}
