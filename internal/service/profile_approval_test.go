package service

import (
	"context"
	"errors"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Bundle 1 Phase 9 — approval-bypass closure regression tests.
//
// Ship a tiny in-memory profile-repo + approval-repo so the gate can
// be exercised without testcontainers. The gate's invariant: any edit
// to a profile that has RequiresApproval=true (or that would set
// RequiresApproval=true) routes through ApprovalService and never
// reaches profileRepo.Update directly.
// =============================================================================

type fakeProfileRepo struct {
	rows map[string]*domain.CertificateProfile
}

func newFakeProfileRepo() *fakeProfileRepo {
	return &fakeProfileRepo{rows: make(map[string]*domain.CertificateProfile)}
}

func (f *fakeProfileRepo) List(_ context.Context) ([]*domain.CertificateProfile, error) {
	out := make([]*domain.CertificateProfile, 0, len(f.rows))
	for _, p := range f.rows {
		out = append(out, p)
	}
	return out, nil
}
func (f *fakeProfileRepo) Get(_ context.Context, id string) (*domain.CertificateProfile, error) {
	p, ok := f.rows[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *p
	return &cp, nil
}
func (f *fakeProfileRepo) Create(_ context.Context, p *domain.CertificateProfile) error {
	cp := *p
	f.rows[p.ID] = &cp
	return nil
}
func (f *fakeProfileRepo) Update(_ context.Context, p *domain.CertificateProfile) error {
	if _, ok := f.rows[p.ID]; !ok {
		return repository.ErrNotFound
	}
	cp := *p
	f.rows[p.ID] = &cp
	return nil
}
func (f *fakeProfileRepo) Delete(_ context.Context, id string) error {
	delete(f.rows, id)
	return nil
}

// fakeApprovalGate counts requests + lets the test inspect the
// payload that was queued. Mirrors ProfileEditApprovalRequester.
type fakeApprovalGate struct {
	requests []struct {
		ProfileID, RequestedBy string
		Payload                []byte
	}
	err error
}

func (f *fakeApprovalGate) RequestProfileEditApproval(_ context.Context, profileID, requestedBy string, payload []byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.requests = append(f.requests, struct {
		ProfileID, RequestedBy string
		Payload                []byte
	}{profileID, requestedBy, payload})
	return "ar-pending-" + profileID, nil
}

// TestProfileEdit_RequiresApprovalLoopholeClosed pins the load-bearing
// invariant: a profile with RequiresApproval=true cannot be mutated
// in-place. The flip-flop loophole (set false → mutate → set true) is
// closed because every call against an approval-tier profile routes
// through ApprovalService BEFORE reaching profileRepo.Update.
func TestProfileEdit_RequiresApprovalLoopholeClosed(t *testing.T) {
	repo := newFakeProfileRepo()
	repo.rows["prof-prod"] = &domain.CertificateProfile{
		ID:               "prof-prod",
		Name:             "production",
		RequiresApproval: true,
	}
	gate := &fakeApprovalGate{}
	svc := NewProfileService(repo, nil)
	svc.SetApprovalService(gate)

	// Attempt 1 — admin tries to flip RequiresApproval off.
	flippedOff := domain.CertificateProfile{
		ID:               "prof-prod",
		Name:             "production",
		RequiresApproval: false, // bypass attempt
	}
	_, err := svc.UpdateProfile(context.Background(), "prof-prod", flippedOff)
	if !errors.Is(err, ErrProfileEditPendingApproval) {
		t.Fatalf("flip-off attempt err = %v, want ErrProfileEditPendingApproval", err)
	}
	live, _ := repo.Get(context.Background(), "prof-prod")
	if !live.RequiresApproval {
		t.Errorf("flip-off attempt mutated live profile (RequiresApproval = false) — loophole NOT closed")
	}
	if len(gate.requests) != 1 {
		t.Fatalf("gate not called for flip-off attempt: %d requests", len(gate.requests))
	}

	// Attempt 2 — admin tries to mutate other fields (RequiresApproval still true).
	keptOn := domain.CertificateProfile{
		ID:               "prof-prod",
		Name:             "renamed",
		RequiresApproval: true,
	}
	_, err = svc.UpdateProfile(context.Background(), "prof-prod", keptOn)
	if !errors.Is(err, ErrProfileEditPendingApproval) {
		t.Errorf("kept-on attempt err = %v, want ErrProfileEditPendingApproval", err)
	}
	live2, _ := repo.Get(context.Background(), "prof-prod")
	if live2.Name == "renamed" {
		t.Errorf("kept-on attempt mutated profile name without approval — loophole NOT closed")
	}

	// Attempt 3 — admin tries to flip a NON-approval profile to approval-tier.
	repo.rows["prof-staging"] = &domain.CertificateProfile{
		ID:               "prof-staging",
		Name:             "staging",
		RequiresApproval: false,
	}
	flippedOn := domain.CertificateProfile{
		ID:               "prof-staging",
		Name:             "staging",
		RequiresApproval: true, // operator wants to enable approvals
	}
	_, err = svc.UpdateProfile(context.Background(), "prof-staging", flippedOn)
	if !errors.Is(err, ErrProfileEditPendingApproval) {
		t.Errorf("flip-on attempt err = %v, want ErrProfileEditPendingApproval (gate fires when target state is approval-tier)", err)
	}
	live3, _ := repo.Get(context.Background(), "prof-staging")
	if live3.RequiresApproval {
		t.Errorf("flip-on attempt enabled approval without an approval — gate must fire BEFORE the persistence")
	}
	if len(gate.requests) != 3 {
		t.Errorf("gate request count = %d, want 3 (one per attempt)", len(gate.requests))
	}
}

// TestProfileEdit_NonApprovalProfileApplyDirectly confirms the gate
// is dormant for profiles that have RequiresApproval=false AND the
// edit doesn't flip it on. Pre-Phase-9 behaviour preserved.
func TestProfileEdit_NonApprovalProfileApplyDirectly(t *testing.T) {
	repo := newFakeProfileRepo()
	repo.rows["prof-dev"] = &domain.CertificateProfile{
		ID:               "prof-dev",
		Name:             "development",
		RequiresApproval: false,
	}
	gate := &fakeApprovalGate{}
	svc := NewProfileService(repo, nil)
	svc.SetApprovalService(gate)

	updated := domain.CertificateProfile{
		ID:               "prof-dev",
		Name:             "development-renamed",
		RequiresApproval: false,
	}
	got, err := svc.UpdateProfile(context.Background(), "prof-dev", updated)
	if err != nil {
		t.Fatalf("non-approval update err = %v", err)
	}
	if got.Name != "development-renamed" {
		t.Errorf("name not updated; got %q", got.Name)
	}
	if len(gate.requests) != 0 {
		t.Errorf("gate fired for non-approval profile: %d requests", len(gate.requests))
	}
}

// TestProfileEdit_NilApprovalService_PreservesLegacyBehaviour confirms
// that a nil-ApprovalService wiring (test fixtures, alternate boot
// paths) preserves the pre-Phase-9 direct-apply path even on
// approval-tier profiles. The gate is opt-in.
func TestProfileEdit_NilApprovalService_PreservesLegacyBehaviour(t *testing.T) {
	repo := newFakeProfileRepo()
	repo.rows["prof-prod"] = &domain.CertificateProfile{
		ID:               "prof-prod",
		Name:             "production",
		RequiresApproval: true,
	}
	svc := NewProfileService(repo, nil) // approvalService not wired
	updated := domain.CertificateProfile{
		ID:               "prof-prod",
		Name:             "renamed",
		RequiresApproval: true,
	}
	if _, err := svc.UpdateProfile(context.Background(), "prof-prod", updated); err != nil {
		t.Fatalf("nil-gate err = %v", err)
	}
	live, _ := repo.Get(context.Background(), "prof-prod")
	if live.Name != "renamed" {
		t.Errorf("nil-gate did not fall through to direct apply; got %q", live.Name)
	}
}
