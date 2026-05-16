package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// fakeApprovalRepo is a minimal in-memory ApprovalRepository for unit
// testing the service-layer logic in isolation. Stores rows in a map
// keyed by ID; List returns rows matching a single state filter.
type fakeApprovalRepo struct {
	mu   sync.Mutex
	rows map[string]*domain.ApprovalRequest
}

func newFakeApprovalRepo() *fakeApprovalRepo {
	return &fakeApprovalRepo{rows: make(map[string]*domain.ApprovalRequest)}
}

func (f *fakeApprovalRepo) Create(ctx context.Context, req *domain.ApprovalRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.ID == "" {
		req.ID = "ar-fake-" + time.Now().Format("150405.000000000")
	}
	// Enforce the partial-unique pending-per-job at the mock layer too.
	// Bundle 1 Phase 9: Postgres treats NULLs as distinct in UNIQUE
	// indexes, so profile_edit rows (JobID="") never collide with
	// each other or with cert_issuance rows. Mirror that here.
	if req.JobID != "" {
		for _, existing := range f.rows {
			if existing.JobID == req.JobID && existing.State == domain.ApprovalStatePending {
				return repository.ErrAlreadyExists
			}
		}
	}
	cp := *req
	f.rows[req.ID] = &cp
	return nil
}

func (f *fakeApprovalRepo) Get(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[id]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeApprovalRepo) GetByJobID(ctx context.Context, jobID string) (*domain.ApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.JobID == jobID {
			cp := *r
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeApprovalRepo) List(ctx context.Context, filter *repository.ApprovalFilter) ([]*domain.ApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.ApprovalRequest
	for _, r := range f.rows {
		if filter != nil && filter.State != "" && string(r.State) != filter.State {
			continue
		}
		if filter != nil && filter.CertificateID != "" && r.CertificateID != filter.CertificateID {
			continue
		}
		if filter != nil && filter.RequestedBy != "" && r.RequestedBy != filter.RequestedBy {
			continue
		}
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeApprovalRepo) UpdateState(ctx context.Context, id string, state domain.ApprovalState,
	decidedBy string, decidedAt time.Time, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok {
		return repository.ErrNotFound
	}
	if r.State != domain.ApprovalStatePending {
		return repository.ErrAlreadyExists // signals "already terminal"
	}
	r.State = state
	r.DecidedBy = &decidedBy
	r.DecidedAt = &decidedAt
	if note != "" {
		n := note
		r.DecisionNote = &n
	}
	r.UpdatedAt = decidedAt
	return nil
}

func (f *fakeApprovalRepo) ExpireStale(ctx context.Context, before time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for _, r := range f.rows {
		if r.State == domain.ApprovalStatePending && (r.CreatedAt.Before(before) || r.CreatedAt.Equal(before)) {
			r.State = domain.ApprovalStateExpired
			s := "system-reaper"
			r.DecidedBy = &s
			r.DecidedAt = &now
			r.UpdatedAt = now
			count++
		}
	}
	return count, nil
}

// fakeJobStateRepo implements service.JobStatusUpdater and tracks per-job
// status mutations so the tests can introspect them. It does NOT implement
// the full repository.JobRepository — ApprovalService only needs UpdateStatus.
type fakeJobStateRepo struct {
	mu       sync.Mutex
	statuses map[string]domain.JobStatus
}

func newFakeJobStateRepo() *fakeJobStateRepo {
	return &fakeJobStateRepo{statuses: make(map[string]domain.JobStatus)}
}

func (f *fakeJobStateRepo) seed(id string, status domain.JobStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses[id] = status
}

func (f *fakeJobStateRepo) status(id string) domain.JobStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses[id]
}

func (f *fakeJobStateRepo) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses[id] = status
	return nil
}

// helper builders --------------------------------------------------------

func newApprovalSvcForTest(bypass bool) (*ApprovalService, *fakeApprovalRepo, *fakeJobStateRepo) {
	ar := newFakeApprovalRepo()
	jr := newFakeJobStateRepo()
	metrics := NewApprovalMetrics()
	svc := NewApprovalService(ar, jr, nil, metrics, bypass)
	return svc, ar, jr
}

func sampleCert() *domain.ManagedCertificate {
	return &domain.ManagedCertificate{ID: "mc-test-cert"}
}

// tests ------------------------------------------------------------------

func TestApproval_RequestCreatesPendingRow_BypassDisabled(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)
	jr.seed("job-1", domain.JobStatusAwaitingApproval)

	id, err := svc.RequestApproval(context.Background(), sampleCert(),
		"job-1", "profile-prod-cdn", "user-alice", map[string]string{"common_name": "api.example.com"})
	if err != nil {
		t.Fatalf("RequestApproval err: %v", err)
	}
	got, err := ar.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get err: %v", err)
	}
	if got.State != domain.ApprovalStatePending {
		t.Fatalf("expected state=pending, got %s", got.State)
	}
	if got.RequestedBy != "user-alice" {
		t.Fatalf("requested_by mismatch: %s", got.RequestedBy)
	}
	if jr.status("job-1") != domain.JobStatusAwaitingApproval {
		t.Fatalf("job should remain AwaitingApproval; got %s", jr.status("job-1"))
	}
}

func TestApproval_BypassMode_AutoApprovesWithSystemBypassActor(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(true)
	jr.seed("job-2", domain.JobStatusAwaitingApproval)

	id, err := svc.RequestApproval(context.Background(), sampleCert(),
		"job-2", "profile-iot", "user-bob", nil)
	if err != nil {
		t.Fatalf("bypass RequestApproval err: %v", err)
	}
	got, err := ar.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get err: %v", err)
	}
	if got.State != domain.ApprovalStateApproved {
		t.Fatalf("bypass should auto-approve; got state=%s", got.State)
	}
	if got.DecidedBy == nil || *got.DecidedBy != domain.ApprovalActorSystemBypass {
		t.Fatalf("bypass should stamp decided_by=%s; got %v",
			domain.ApprovalActorSystemBypass, got.DecidedBy)
	}
	if jr.status("job-2") != domain.JobStatusPending {
		t.Fatalf("bypass should transition job to Pending; got %s", jr.status("job-2"))
	}
}

func TestApproval_Approve_TransitionsJobFromAwaitingApprovalToPending(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)
	jr.seed("job-3", domain.JobStatusAwaitingApproval)
	id, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-3", "p1", "user-alice", nil)

	if err := svc.Approve(context.Background(), id, "user-bob", "approved per ticket SECOPS-123"); err != nil {
		t.Fatalf("Approve err: %v", err)
	}
	got, _ := ar.Get(context.Background(), id)
	if got.State != domain.ApprovalStateApproved {
		t.Fatalf("expected state=approved; got %s", got.State)
	}
	if jr.status("job-3") != domain.JobStatusPending {
		t.Fatalf("expected job=Pending; got %s", jr.status("job-3"))
	}
}

func TestApproval_Reject_TransitionsJobFromAwaitingApprovalToCancelled(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)
	jr.seed("job-4", domain.JobStatusAwaitingApproval)
	id, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-4", "p1", "user-alice", nil)

	if err := svc.Reject(context.Background(), id, "user-bob", "not on the approved-domains list"); err != nil {
		t.Fatalf("Reject err: %v", err)
	}
	got, _ := ar.Get(context.Background(), id)
	if got.State != domain.ApprovalStateRejected {
		t.Fatalf("expected state=rejected; got %s", got.State)
	}
	if jr.status("job-4") != domain.JobStatusCancelled {
		t.Fatalf("expected job=Cancelled; got %s", jr.status("job-4"))
	}
}

func TestApproval_Approve_RejectsSameActor(t *testing.T) {
	// LOAD-BEARING TWO-PERSON INTEGRITY TEST. PCI-DSS 6.4.5 / NIST 800-53
	// SA-15 / SOC 2 CC6.1 compliance auditors pattern-match against this.
	svc, _, jr := newApprovalSvcForTest(false)
	jr.seed("job-5", domain.JobStatusAwaitingApproval)
	id, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-5", "p1", "user-alice", nil)

	err := svc.Approve(context.Background(), id, "user-alice", "trying to self-approve")
	if !errors.Is(err, ErrApproveBySameActor) {
		t.Fatalf("expected ErrApproveBySameActor; got %v", err)
	}
	if jr.status("job-5") != domain.JobStatusAwaitingApproval {
		t.Fatalf("job should remain AwaitingApproval; got %s", jr.status("job-5"))
	}

	// Approval as a different actor succeeds.
	if err := svc.Approve(context.Background(), id, "user-bob", "approved by separate actor"); err != nil {
		t.Fatalf("Approve as different actor err: %v", err)
	}
	if jr.status("job-5") != domain.JobStatusPending {
		t.Fatalf("expected job=Pending after bob approve; got %s", jr.status("job-5"))
	}

	// Same-actor rejection also fails.
	jr.seed("job-5b", domain.JobStatusAwaitingApproval)
	id2, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-5b", "p1", "user-charlie", nil)
	err2 := svc.Reject(context.Background(), id2, "user-charlie", "self-reject")
	if !errors.Is(err2, ErrApproveBySameActor) {
		t.Fatalf("expected ErrApproveBySameActor on Reject; got %v", err2)
	}
}

func TestApproval_Approve_RejectsAlreadyDecided(t *testing.T) {
	svc, _, jr := newApprovalSvcForTest(false)
	jr.seed("job-6", domain.JobStatusAwaitingApproval)
	id, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-6", "p1", "user-alice", nil)
	if err := svc.Approve(context.Background(), id, "user-bob", ""); err != nil {
		t.Fatalf("first Approve err: %v", err)
	}

	err := svc.Approve(context.Background(), id, "user-charlie", "second approve")
	if !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("expected ErrApprovalAlreadyDecided; got %v", err)
	}
	err2 := svc.Reject(context.Background(), id, "user-charlie", "late reject")
	if !errors.Is(err2, ErrApprovalAlreadyDecided) {
		t.Fatalf("expected ErrApprovalAlreadyDecided on Reject; got %v", err2)
	}
}

func TestApproval_ExpireStale_TransitionsPendingToExpired_AndCancelsJob(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)
	jr.seed("job-7", domain.JobStatusAwaitingApproval)
	jr.seed("job-8", domain.JobStatusAwaitingApproval)
	id7, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-7", "p1", "user-alice", nil)
	id8, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-8", "p1", "user-alice", nil)

	// Backdate one of the requests to before the cutoff.
	old := time.Now().Add(-200 * time.Hour).UTC()
	ar.mu.Lock()
	ar.rows[id7].CreatedAt = old
	ar.mu.Unlock()

	cutoff := time.Now().Add(-168 * time.Hour).UTC()
	count, err := svc.ExpireStale(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("ExpireStale err: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row expired; got %d", count)
	}
	got7, _ := ar.Get(context.Background(), id7)
	if got7.State != domain.ApprovalStateExpired {
		t.Fatalf("expected job-7 expired; got %s", got7.State)
	}
	got8, _ := ar.Get(context.Background(), id8)
	if got8.State != domain.ApprovalStatePending {
		t.Fatalf("job-8 should still be pending; got %s", got8.State)
	}
	if jr.status("job-7") != domain.JobStatusCancelled {
		t.Fatalf("expected job-7 cancelled; got %s", jr.status("job-7"))
	}
	if jr.status("job-8") != domain.JobStatusAwaitingApproval {
		t.Fatalf("job-8 should remain AwaitingApproval; got %s", jr.status("job-8"))
	}
}

func TestApproval_MetricCounterIncrements(t *testing.T) {
	svc, _, jr := newApprovalSvcForTest(false)
	metrics := svc.metrics

	jr.seed("job-9", domain.JobStatusAwaitingApproval)
	id9, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-9", "p-cdn", "user-alice", nil)
	_ = svc.Approve(context.Background(), id9, "user-bob", "approved")

	jr.seed("job-10", domain.JobStatusAwaitingApproval)
	id10, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-10", "p-cdn", "user-alice", nil)
	_ = svc.Reject(context.Background(), id10, "user-bob", "rejected")

	jr.seed("job-11", domain.JobStatusAwaitingApproval)
	id11, _ := svc.RequestApproval(context.Background(), sampleCert(), "job-11", "p-cdn", "user-alice", nil)
	// Backdate + expire.
	old := time.Now().Add(-200 * time.Hour).UTC()
	repo := svc.approvalRepo.(*fakeApprovalRepo)
	repo.mu.Lock()
	repo.rows[id11].CreatedAt = old
	repo.mu.Unlock()
	if _, err := svc.ExpireStale(context.Background(), time.Now().Add(-168*time.Hour)); err != nil {
		t.Fatalf("ExpireStale err: %v", err)
	}

	snap := metrics.SnapshotApprovalDecisions()
	got := map[string]uint64{}
	for _, e := range snap {
		got[e.Outcome] = e.Count
	}
	if got[domain.ApprovalOutcomeApproved] != 1 {
		t.Fatalf("expected 1 approved counter; got %d", got[domain.ApprovalOutcomeApproved])
	}
	if got[domain.ApprovalOutcomeRejected] != 1 {
		t.Fatalf("expected 1 rejected counter; got %d", got[domain.ApprovalOutcomeRejected])
	}
	if got[domain.ApprovalOutcomeExpired] != 1 {
		t.Fatalf("expected 1 expired counter; got %d", got[domain.ApprovalOutcomeExpired])
	}

	// Histogram observed at least 3 samples.
	hist := metrics.SnapshotApprovalPendingAgeHistogram()
	if hist.Count < 3 {
		t.Fatalf("expected at least 3 histogram samples; got %d", hist.Count)
	}
}

// =============================================================================
// Bundle 1 Phase 9 — profile_edit kind tests.
// =============================================================================

// TestApproval_RequestProfileEditCreatesPendingRow pins the new
// RequestProfileEditApproval entry point: creates a pending row with
// Kind=profile_edit, no cert_id / job_id, and the serialized profile
// diff in Payload.
func TestApproval_RequestProfileEditCreatesPendingRow(t *testing.T) {
	svc, ar, _ := newApprovalSvcForTest(false)
	payload := []byte(`{"id":"prof-prod","name":"renamed","requires_approval":true}`)
	id, err := svc.RequestProfileEditApproval(context.Background(), "prof-prod", "user-alice", payload)
	if err != nil {
		t.Fatalf("RequestProfileEditApproval err: %v", err)
	}
	got, err := ar.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get err: %v", err)
	}
	if got.Kind != domain.ApprovalKindProfileEdit {
		t.Errorf("Kind = %q, want profile_edit", got.Kind)
	}
	if got.CertificateID != "" || got.JobID != "" {
		t.Errorf("profile_edit row carries cert_id=%q job_id=%q; both must be empty", got.CertificateID, got.JobID)
	}
	if string(got.Payload) != string(payload) {
		t.Errorf("payload roundtrip wrong; got %s", string(got.Payload))
	}
}

// TestApproval_ProfileEdit_SameActorSelfApproveRejected pins the
// load-bearing two-person integrity invariant for profile_edit
// approvals: the requester cannot approve their own row.
func TestApproval_ProfileEdit_SameActorSelfApproveRejected(t *testing.T) {
	svc, _, _ := newApprovalSvcForTest(false)
	id, err := svc.RequestProfileEditApproval(context.Background(),
		"prof-prod", "user-alice",
		[]byte(`{"id":"prof-prod"}`))
	if err != nil {
		t.Fatalf("RequestProfileEditApproval err: %v", err)
	}
	got := svc.Approve(context.Background(), id, "user-alice", "self-approve attempt")
	if !errors.Is(got, ErrApproveBySameActor) {
		t.Errorf("self-approve err = %v, want ErrApproveBySameActor", got)
	}
}

// TestApproval_ProfileEdit_RejectsWhenApplyCallbackMissing pins
// that the approve path fails closed when a profile_edit row is
// approved without a registered profileEditApply callback. Better
// to surface a 500 than silently mark the row approved while the
// underlying profile is untouched.
func TestApproval_ProfileEdit_RejectsWhenApplyCallbackMissing(t *testing.T) {
	svc, _, _ := newApprovalSvcForTest(false)
	id, _ := svc.RequestProfileEditApproval(context.Background(),
		"prof-prod", "user-alice",
		[]byte(`{"id":"prof-prod"}`))
	// Approver = different actor.
	err := svc.Approve(context.Background(), id, "user-bob", "approving")
	if err == nil {
		t.Fatalf("Approve must fail when profile-edit-apply is unwired; got nil")
	}
	// Sentinel propagates from approveInternal — message contains the cue.
	if !strings.Contains(err.Error(), "apply callback not registered") {
		t.Errorf("err = %v, want 'apply callback not registered'", err)
	}
}

// TestApproval_ProfileEdit_ApplyCallbackInvokedOnApprove pins the
// happy-path: when a profile-edit-apply callback is registered AND
// a non-requester approves, the callback fires with the right row.
func TestApproval_ProfileEdit_ApplyCallbackInvokedOnApprove(t *testing.T) {
	svc, _, _ := newApprovalSvcForTest(false)
	var captured *domain.ApprovalRequest
	svc.SetProfileEditApply(func(_ context.Context, req *domain.ApprovalRequest) error {
		captured = req
		return nil
	})
	id, _ := svc.RequestProfileEditApproval(context.Background(),
		"prof-prod", "user-alice",
		[]byte(`{"id":"prof-prod","name":"renamed"}`))
	if err := svc.Approve(context.Background(), id, "user-bob", "looks good"); err != nil {
		t.Fatalf("Approve err: %v", err)
	}
	if captured == nil {
		t.Fatalf("apply callback never invoked")
	}
	if captured.Kind != domain.ApprovalKindProfileEdit {
		t.Errorf("captured.Kind = %q, want profile_edit", captured.Kind)
	}
	if captured.ProfileID != "prof-prod" {
		t.Errorf("captured.ProfileID = %q, want prof-prod", captured.ProfileID)
	}
}

// =============================================================================
// Acquisition-audit COMP-006 closure (Sprint 7 ACQ, 2026-05-16).
// =============================================================================
//
// The audit flagged COMP-006 as UNKNOWN because it couldn't independently
// verify that the approval workflow was bullet-tight: i.e., that a denied
// approval definitely results in NO certificate being signed, and an
// approved approval definitely lets the issuance proceed. The two tests
// below pin the load-bearing state-transition invariants AND document the
// enforcement chain end-to-end so a future auditor can re-derive the
// proof without rebuilding the trail.
//
// Enforcement chain (operator-visible invariant: no cert if denied)
// -----------------------------------------------------------------
// Layer 1 — Issuance gate
//   internal/service/certificate.go::CertificateService.Create (around
//   L341-373) reads CertificateProfile.RequiresApproval. When true, the
//   created Job is stamped JobStatusAwaitingApproval (not Pending), AND
//   a parallel ApprovalRequest row is created. The job processor never
//   touches AwaitingApproval rows.
//
// Layer 2 — Approval state machine
//   internal/service/approval.go::ApprovalService.Reject and Approve
//   flip the approval row + the job row atomically:
//     Reject  → approval=Rejected, job=Cancelled   (pinned by
//               TestApproval_Reject_TransitionsJobFromAwaitingApprovalToCancelled
//               above)
//     Approve → approval=Approved, job=Pending     (pinned by
//               TestApproval_Approve_TransitionsJobFromAwaitingApprovalToPending
//               above)
//   The "already terminal" guard
//   (TestApproval_Approve_RejectsAlreadyDecided + the Reject-side
//   analogue) prevents a rejected approval from later being flipped
//   to approved.
//
// Layer 3 — Job claim filter (the LOAD-BEARING SQL invariant)
//   internal/repository/postgres/job.go::JobRepository.ClaimPendingJobs
//   (around L296-310) issues
//     SELECT ... FROM jobs WHERE status = $1
//   with $1 = domain.JobStatusPending. Cancelled jobs are therefore
//   NEVER returned to ProcessPendingJobs, so the certificate-issuance
//   call path (the only path that signs certs) is unreachable for a
//   denied approval. This SQL filter is the load-bearing "no cert if
//   denied" enforcement — Layer 2 transitions the job to Cancelled,
//   Layer 3 ensures Cancelled jobs are inert.
//
// What this test DOES
//   This is a service-layer unit test on the same fake repos as the
//   rest of approval_test.go. It pins the Layer-2 transition that
//   feeds Layer-3's filter (Reject → Cancelled, Approve → Pending),
//   plus the already-terminal guard, in a single named test so a
//   future contributor reading the test name immediately sees the
//   COMP-006 attestation.
//
// What this test does NOT do
//   It does NOT spin up Postgres + the job processor + the
//   certificate signer to drive the full happy-path. That would
//   duplicate the per-layer unit-test coverage already in place
//   AND introduce a testcontainers dependency for a closure that's
//   already provable by composition. The integration suite
//   (deploy/test/integration_test.go) already exercises the live
//   issuance path; this test pins the approval-side invariant in
//   isolation so a future refactor of approval.go can't silently
//   widen the guard without tripping a named test.

// TestApproval_COMP006_DenyChainPinsNoCertIfRejected attests that an
// approval-required issuance, once rejected, lands its job in
// Cancelled and stays terminal (no subsequent approve can re-enable
// it). Combined with the Layer-3 SQL filter documented above, this is
// the operator-visible guarantee that a denied approval produces zero
// certificates.
func TestApproval_COMP006_DenyChainPinsNoCertIfRejected(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)

	// Layer 1 simulation: the upstream certificate.Create path
	// stamps the job at AwaitingApproval when the profile has
	// RequiresApproval=true. We seed that state directly because
	// the upstream is exercised separately by the certificate
	// service tests.
	jr.seed("job-comp006-deny", domain.JobStatusAwaitingApproval)

	// Layer 2 — issuance creates the parallel approval row.
	approvalID, err := svc.RequestApproval(
		context.Background(),
		sampleCert(),
		"job-comp006-deny",
		"prof-prod",
		"user-alice",
		nil,
	)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	// Pre-decision state: job MUST be in AwaitingApproval (Layer-1
	// + Layer-2 invariant). If this flipped silently to Pending,
	// Layer 3's SQL filter would pick it up — that would be the
	// COMP-006 worst case.
	if got := jr.status("job-comp006-deny"); got != domain.JobStatusAwaitingApproval {
		t.Fatalf("pre-Reject job status = %q; want AwaitingApproval (cert would issue without approval)", got)
	}

	// Layer 2 transition: Reject by a different actor (two-person
	// integrity already enforced by
	// TestApproval_Approve_RejectsSameActor).
	if err := svc.Reject(context.Background(), approvalID, "user-bob", "denied — domain not on policy allowlist"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	// Post-decision: approval=Rejected, job=Cancelled.
	got, _ := ar.Get(context.Background(), approvalID)
	if got.State != domain.ApprovalStateRejected {
		t.Fatalf("approval state after Reject = %q; want Rejected", got.State)
	}
	if jstat := jr.status("job-comp006-deny"); jstat != domain.JobStatusCancelled {
		t.Fatalf("job status after Reject = %q; want Cancelled (Layer-3 SQL filter requires this)", jstat)
	}

	// Already-terminal guard: a subsequent Approve MUST fail. The
	// "rejected → approved" loophole would be the only way to
	// re-enable issuance on a denied approval; the existing
	// repository ErrAlreadyExists return from UpdateState (mocked
	// in fakeApprovalRepo.UpdateState) wraps this into the
	// "already decided" path that approval.go::Approve maps to a
	// 409 at the handler layer.
	if err := svc.Approve(context.Background(), approvalID, "user-bob", "re-approve attempt"); err == nil {
		t.Fatal("Approve on already-rejected approval succeeded; want already-decided rejection (LOOPHOLE — would let a denied cert issue)")
	}
	if jstat := jr.status("job-comp006-deny"); jstat != domain.JobStatusCancelled {
		t.Errorf("job status drifted after failed re-Approve = %q; want still Cancelled", jstat)
	}
}

// TestApproval_COMP006_ApproveChainPinsJobReachesPending attests the
// sibling happy-path: an approved approval transitions the job to
// Pending, which is the ONLY status ClaimPendingJobs accepts (Layer 3
// SQL filter). From Pending, the existing certificate-service +
// renewal-service tests (and the integration suite) prove the cert
// gets signed. This test pins the Layer-2-to-Layer-3 handoff in
// isolation so a future refactor that, e.g., transitioned the job
// to AwaitingCSR instead of Pending would trip here BEFORE shipping.
func TestApproval_COMP006_ApproveChainPinsJobReachesPending(t *testing.T) {
	svc, ar, jr := newApprovalSvcForTest(false)

	jr.seed("job-comp006-approve", domain.JobStatusAwaitingApproval)

	approvalID, err := svc.RequestApproval(
		context.Background(),
		sampleCert(),
		"job-comp006-approve",
		"prof-prod",
		"user-alice",
		nil,
	)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	// Layer 2 transition: Approve by a different actor.
	if err := svc.Approve(context.Background(), approvalID, "user-bob", "approved per change ticket SECOPS-456"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, _ := ar.Get(context.Background(), approvalID)
	if got.State != domain.ApprovalStateApproved {
		t.Fatalf("approval state after Approve = %q; want Approved", got.State)
	}

	// THE LOAD-BEARING ASSERTION for COMP-006's positive path: the
	// job MUST be in Pending after Approve. ClaimPendingJobs in the
	// postgres repo filters on exactly this status. A future change
	// that transitioned to a different status would silently break
	// every approval-required issuance.
	if jstat := jr.status("job-comp006-approve"); jstat != domain.JobStatusPending {
		t.Fatalf("job status after Approve = %q; want Pending (ClaimPendingJobs filters on exactly this status)", jstat)
	}
}
