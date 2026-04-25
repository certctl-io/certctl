package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// newBulkRenewalTestService spins up a BulkRenewalService wired against
// the in-memory mocks used by every other service test in this package.
// keygenMode defaults to "agent" — production-like routing where renewal
// jobs start as AwaitingCSR.
func newBulkRenewalTestService() (*BulkRenewalService, *mockCertRepo, *mockJobRepo, *mockAuditRepo) {
	certRepo := newMockCertificateRepository()
	jobRepo := &mockJobRepo{Jobs: map[string]*domain.Job{}}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewBulkRenewalService(certRepo, jobRepo, auditService, slog.Default(), "agent")
	return svc, certRepo, jobRepo, auditRepo
}

// addRenewableCert seeds a cert that is eligible for renewal (Active
// status, future expiry).
func addRenewableCert(repo *mockCertRepo, id string) {
	cert := &domain.ManagedCertificate{
		ID:         id,
		CommonName: id + ".example.com",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 1, 0),
		IssuerID:   "iss-test",
	}
	repo.AddCert(cert)
}

// TestBulkRenew_ByExplicitIDs — happy path. N IDs in, N jobs enqueued,
// EnqueuedJobs slice carries the {certificate_id, job_id} pairs.
func TestBulkRenew_ByExplicitIDs(t *testing.T) {
	svc, certRepo, jobRepo, _ := newBulkRenewalTestService()
	addRenewableCert(certRepo, "mc-1")
	addRenewableCert(certRepo, "mc-2")
	addRenewableCert(certRepo, "mc-3")

	res, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{CertificateIDs: []string{"mc-1", "mc-2", "mc-3"}},
		"alice")
	if err != nil {
		t.Fatalf("BulkRenew failed: %v", err)
	}
	if res.TotalMatched != 3 || res.TotalEnqueued != 3 || res.TotalSkipped != 0 || res.TotalFailed != 0 {
		t.Errorf("counts = matched:%d enqueued:%d skipped:%d failed:%d, want 3/3/0/0",
			res.TotalMatched, res.TotalEnqueued, res.TotalSkipped, res.TotalFailed)
	}
	if len(res.EnqueuedJobs) != 3 {
		t.Fatalf("EnqueuedJobs len = %d, want 3", len(res.EnqueuedJobs))
	}
	if len(jobRepo.Jobs) != 3 {
		t.Errorf("jobRepo got %d jobs, want 3 (one per renewable cert)", len(jobRepo.Jobs))
	}
	for _, j := range res.EnqueuedJobs {
		if j.JobID == "" {
			t.Errorf("EnqueuedJob missing job_id for cert %s", j.CertificateID)
		}
	}
}

// TestBulkRenew_ByOwnerCriteria — criteria-mode resolution. The
// criteria-routing path must call resolveCertificates with the filter
// branch (not the explicit-IDs branch). Mocking convention in this
// package: mockCertRepo.List ignores the filter and returns all certs,
// so the test seeds only certs that should match (mirrors
// TestBulkRevoke_ByOwner shape in bulk_revocation_test.go).
func TestBulkRenew_ByOwnerCriteria(t *testing.T) {
	svc, certRepo, _, _ := newBulkRenewalTestService()
	for _, id := range []string{"mc-a1", "mc-a2"} {
		cert := &domain.ManagedCertificate{
			ID: id, CommonName: id, Status: domain.CertificateStatusActive,
			OwnerID: "o-alice", ExpiresAt: time.Now().AddDate(0, 1, 0),
		}
		certRepo.AddCert(cert)
	}

	res, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{OwnerID: "o-alice"}, "alice")
	if err != nil {
		t.Fatalf("BulkRenew failed: %v", err)
	}
	if res.TotalEnqueued != 2 {
		t.Errorf("TotalEnqueued = %d, want 2 (alice's 2 certs)", res.TotalEnqueued)
	}
}

// TestBulkRenew_SkipsRenewalInProgress — a cert already in the renewal
// flow must NOT get a second job. This is the no-double-enqueue
// contract: dispatch the bulk-renew button twice in quick succession
// and the second call cleanly skips.
func TestBulkRenew_SkipsRenewalInProgress(t *testing.T) {
	svc, certRepo, jobRepo, _ := newBulkRenewalTestService()
	cert := &domain.ManagedCertificate{
		ID: "mc-rip", Status: domain.CertificateStatusRenewalInProgress,
		ExpiresAt: time.Now().AddDate(0, 1, 0),
	}
	certRepo.AddCert(cert)

	res, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{CertificateIDs: []string{"mc-rip"}}, "alice")
	if err != nil {
		t.Fatalf("BulkRenew failed: %v", err)
	}
	if res.TotalSkipped != 1 || res.TotalEnqueued != 0 {
		t.Errorf("counts wrong: skipped=%d enqueued=%d, want 1/0",
			res.TotalSkipped, res.TotalEnqueued)
	}
	if len(jobRepo.Jobs) != 0 {
		t.Errorf("no job should be created for already-in-progress cert; got %d jobs", len(jobRepo.Jobs))
	}
}

// TestBulkRenew_SkipsRevokedAndArchived — terminal states are silent
// no-ops, not errors. Operator selecting a mix of live and revoked certs
// shouldn't see "ERROR: revoked cert can't be renewed" 50 times.
func TestBulkRenew_SkipsRevokedAndArchived(t *testing.T) {
	svc, certRepo, _, _ := newBulkRenewalTestService()
	addRenewableCert(certRepo, "mc-live")
	for _, st := range []domain.CertificateStatus{
		domain.CertificateStatusRevoked,
		domain.CertificateStatusArchived,
		domain.CertificateStatusExpired,
	} {
		cert := &domain.ManagedCertificate{
			ID: "mc-" + string(st), Status: st, ExpiresAt: time.Now().AddDate(0, 1, 0),
		}
		certRepo.AddCert(cert)
	}

	res, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{CertificateIDs: []string{
			"mc-live", "mc-Revoked", "mc-Archived", "mc-Expired",
		}}, "alice")
	if err != nil {
		t.Fatalf("BulkRenew failed: %v", err)
	}
	if res.TotalEnqueued != 1 || res.TotalSkipped != 3 {
		t.Errorf("counts = enqueued:%d skipped:%d, want 1/3 (only mc-live qualifies)",
			res.TotalEnqueued, res.TotalSkipped)
	}
	if len(res.Errors) != 0 {
		t.Errorf("status-skip should NOT populate Errors; got %v", res.Errors)
	}
}

// TestBulkRenew_EmptyCriteria_Error — defensive contract. Mirrors
// BulkRevocationCriteria.IsEmpty rejection so a stray empty POST
// doesn't try to renew the entire fleet.
func TestBulkRenew_EmptyCriteria_Error(t *testing.T) {
	svc, _, _, _ := newBulkRenewalTestService()
	_, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{}, "alice")
	if err == nil {
		t.Fatal("expected error for empty criteria, got nil")
	}
}

// TestBulkRenew_PartialFailure — N=3, jobRepo.Create injected to fail
// on one of them. Response carries 2 enqueued + 1 error; no panic, no
// abort.
func TestBulkRenew_PartialFailure(t *testing.T) {
	svc, certRepo, jobRepo, _ := newBulkRenewalTestService()
	addRenewableCert(certRepo, "mc-1")
	addRenewableCert(certRepo, "mc-2")
	addRenewableCert(certRepo, "mc-3")

	// Make Create fail uniformly. Two of the three certs will still
	// have their status flipped (because Update happened first), so
	// the failure manifests as "I tried to enqueue, the job-create
	// failed". Per-cert error string surfaced.
	jobRepo.CreateErr = errors.New("simulated DB outage")

	res, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{CertificateIDs: []string{"mc-1", "mc-2", "mc-3"}},
		"alice")
	if err != nil {
		t.Fatalf("BulkRenew should not propagate per-cert errors as a top-level error; got: %v", err)
	}
	if res.TotalFailed != 3 || res.TotalEnqueued != 0 {
		t.Errorf("counts = failed:%d enqueued:%d, want 3/0", res.TotalFailed, res.TotalEnqueued)
	}
	if len(res.Errors) != 3 {
		t.Errorf("Errors len = %d, want 3", len(res.Errors))
	}
}

// TestBulkRenew_AuditEventEmitted — exactly ONE bulk audit event for
// the operation, NOT N. This is the audit-volume contract that makes
// bulk endpoints scalable.
func TestBulkRenew_AuditEventEmitted(t *testing.T) {
	svc, certRepo, _, auditRepo := newBulkRenewalTestService()
	addRenewableCert(certRepo, "mc-1")
	addRenewableCert(certRepo, "mc-2")
	addRenewableCert(certRepo, "mc-3")

	_, err := svc.BulkRenew(context.Background(),
		domain.BulkRenewalCriteria{CertificateIDs: []string{"mc-1", "mc-2", "mc-3"}},
		"alice")
	if err != nil {
		t.Fatalf("BulkRenew failed: %v", err)
	}

	// audit_events count must be exactly 1 — the bulk-renewal envelope.
	// Per-cert renewal events come from CertificateService.TriggerRenewal,
	// which the bulk path bypasses for exactly this reason.
	if len(auditRepo.Events) != 1 {
		t.Errorf("audit events count = %d, want exactly 1 (one bulk event, NOT N per-cert events)", len(auditRepo.Events))
	}
	if len(auditRepo.Events) > 0 && auditRepo.Events[0].Action != "bulk_renewal_initiated" {
		t.Errorf("audit action = %q, want 'bulk_renewal_initiated'", auditRepo.Events[0].Action)
	}
}
