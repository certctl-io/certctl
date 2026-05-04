package service

import (
	"context"
	"errors"
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
	for _, existing := range f.rows {
		if existing.JobID == req.JobID && existing.State == domain.ApprovalStatePending {
			return repository.ErrAlreadyExists
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
