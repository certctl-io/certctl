package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockVerificationJobRepo is a test double for JobRepository used by verification tests.
type mockVerificationJobRepo struct {
	jobs map[string]*domain.Job
	err  error
}

func (m *mockVerificationJobRepo) Get(ctx context.Context, id string) (*domain.Job, error) {
	if m.err != nil {
		return nil, m.err
	}
	job, ok := m.jobs[id]
	if !ok {
		return nil, errors.New("job not found")
	}
	return job, nil
}

func (m *mockVerificationJobRepo) Create(ctx context.Context, job *domain.Job) error {
	m.jobs[job.ID] = job
	return nil
}

func (m *mockVerificationJobRepo) Update(ctx context.Context, job *domain.Job) error {
	if m.err != nil {
		return m.err
	}
	m.jobs[job.ID] = job
	return nil
}

func (m *mockVerificationJobRepo) List(ctx context.Context) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) Delete(ctx context.Context, id string) error {
	delete(m.jobs, id)
	return nil
}

func (m *mockVerificationJobRepo) ListByStatus(ctx context.Context, status domain.JobStatus) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) ListByCertificate(ctx context.Context, certID string) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error {
	return nil
}

func (m *mockVerificationJobRepo) GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) ListPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) ClaimPendingJobs(ctx context.Context, jobType domain.JobType, limit int) ([]*domain.Job, error) {
	return nil, nil
}

func (m *mockVerificationJobRepo) ClaimPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	return nil, nil
}

// newVerificationTestService creates a VerificationService wired with test doubles.
func newVerificationTestService(jobs map[string]*domain.Job, jobRepoErr error) (*VerificationService, *mockVerificationJobRepo, *mockAuditRepo) {
	jobRepo := &mockVerificationJobRepo{jobs: jobs, err: jobRepoErr}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewVerificationService(jobRepo, auditService, slog.Default())
	return svc, jobRepo, auditRepo
}

func TestVerificationService_RecordVerificationResult_Success(t *testing.T) {
	ctx := context.Background()
	jobs := map[string]*domain.Job{
		"j-test1": {
			ID:     "j-test1",
			Status: domain.JobStatusCompleted,
		},
	}
	svc, jobRepo, auditRepo := newVerificationTestService(jobs, nil)

	result := &domain.VerificationResult{
		JobID:               "j-test1",
		TargetID:            "t-nginx1",
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
		VerifiedAt:          time.Now().UTC(),
	}

	err := svc.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check job was updated
	job, _ := jobRepo.Get(ctx, "j-test1")
	if job.VerificationStatus != domain.VerificationSuccess {
		t.Errorf("expected VerificationSuccess, got %s", job.VerificationStatus)
	}
	if job.VerifiedAt == nil {
		t.Error("expected verified_at to be set")
	}

	// Check audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected at least 1 audit event")
	}
}

func TestVerificationService_RecordVerificationResult_Failed(t *testing.T) {
	ctx := context.Background()
	jobs := map[string]*domain.Job{
		"j-test2": {
			ID:     "j-test2",
			Status: domain.JobStatusCompleted,
		},
	}
	svc, jobRepo, _ := newVerificationTestService(jobs, nil)

	result := &domain.VerificationResult{
		JobID:               "j-test2",
		TargetID:            "t-apache1",
		ExpectedFingerprint: "aaa111",
		ActualFingerprint:   "bbb222",
		Verified:            false,
		VerifiedAt:          time.Now().UTC(),
	}

	err := svc.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	job, _ := jobRepo.Get(ctx, "j-test2")
	if job.VerificationStatus != domain.VerificationFailed {
		t.Errorf("expected VerificationFailed, got %s", job.VerificationStatus)
	}
}

func TestVerificationService_RecordVerificationResult_WithError(t *testing.T) {
	ctx := context.Background()
	jobs := map[string]*domain.Job{
		"j-test3": {
			ID:     "j-test3",
			Status: domain.JobStatusCompleted,
		},
	}
	svc, jobRepo, _ := newVerificationTestService(jobs, nil)

	result := &domain.VerificationResult{
		JobID:      "j-test3",
		TargetID:   "t-haproxy1",
		VerifiedAt: time.Now().UTC(),
		Error:      "connection refused",
	}

	err := svc.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	job, _ := jobRepo.Get(ctx, "j-test3")
	if job.VerificationStatus != domain.VerificationFailed {
		t.Errorf("expected VerificationFailed, got %s", job.VerificationStatus)
	}
	if job.VerificationError == nil || *job.VerificationError != "connection refused" {
		t.Error("expected verification error to be set")
	}
}

func TestVerificationService_RecordVerificationResult_JobNotFound(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newVerificationTestService(map[string]*domain.Job{}, nil)

	result := &domain.VerificationResult{
		JobID:      "j-nonexistent",
		TargetID:   "t-nginx1",
		VerifiedAt: time.Now().UTC(),
	}

	err := svc.RecordVerificationResult(ctx, result)
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestVerificationService_RecordVerificationResult_MissingJobID(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newVerificationTestService(map[string]*domain.Job{}, nil)

	result := &domain.VerificationResult{
		TargetID:   "t-nginx1",
		VerifiedAt: time.Now().UTC(),
	}

	err := svc.RecordVerificationResult(ctx, result)
	if err == nil {
		t.Error("expected error for missing job ID")
	}
}

func TestVerificationService_RecordVerificationResult_NilResult(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newVerificationTestService(map[string]*domain.Job{}, nil)

	err := svc.RecordVerificationResult(ctx, nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestVerificationService_GetVerificationResult_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	targetID := "t-nginx1"
	fp := "abc123"
	jobs := map[string]*domain.Job{
		"j-test1": {
			ID:                 "j-test1",
			TargetID:           &targetID,
			VerificationStatus: domain.VerificationSuccess,
			VerifiedAt:         &now,
			VerificationFp:     &fp,
		},
	}
	svc, _, _ := newVerificationTestService(jobs, nil)

	result, err := svc.GetVerificationResult(ctx, "j-test1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result.JobID != "j-test1" {
		t.Errorf("expected job ID j-test1, got %s", result.JobID)
	}
	if !result.Verified {
		t.Error("expected Verified to be true")
	}
	if result.ActualFingerprint != "abc123" {
		t.Errorf("expected fingerprint abc123, got %s", result.ActualFingerprint)
	}
}

func TestVerificationService_GetVerificationResult_NotFound(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newVerificationTestService(map[string]*domain.Job{}, nil)

	_, err := svc.GetVerificationResult(ctx, "j-nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestVerificationService_GetVerificationResult_EmptyJobID(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newVerificationTestService(map[string]*domain.Job{}, nil)

	_, err := svc.GetVerificationResult(ctx, "")
	if err == nil {
		t.Error("expected error for empty job ID")
	}
}
