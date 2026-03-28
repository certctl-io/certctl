package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// mockJobRepository is a test double for JobRepository.
type mockJobRepository struct {
	jobs map[string]*domain.Job
	err  error
}

func (m *mockJobRepository) Get(ctx context.Context, id string) (*domain.Job, error) {
	if m.err != nil {
		return nil, m.err
	}
	job, ok := m.jobs[id]
	if !ok {
		return nil, errors.New("job not found")
	}
	return job, nil
}

func (m *mockJobRepository) Create(ctx context.Context, job *domain.Job) error {
	m.jobs[job.ID] = job
	return nil
}

func (m *mockJobRepository) Update(ctx context.Context, job *domain.Job) error {
	if m.err != nil {
		return m.err
	}
	m.jobs[job.ID] = job
	return nil
}

func (m *mockJobRepository) List(ctx context.Context, filter *repository.JobFilter) ([]*domain.Job, error) {
	return nil, nil
}

// mockAuditService is a test double for AuditService.
type mockAuditService struct {
	events []interface{}
}

func (m *mockAuditService) RecordEvent(ctx context.Context, actor string, actorType domain.ActorType, event string, resourceType string, resourceID string, details map[string]interface{}) {
	m.events = append(m.events, map[string]interface{}{
		"actor":        actor,
		"actor_type":   actorType,
		"event":        event,
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"details":      details,
	})
}

func TestVerificationService_RecordVerificationResult_Success(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{
			"j-test1": {
				ID:     "j-test1",
				Status: domain.JobStatusCompleted,
			},
		},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result := &domain.VerificationResult{
		JobID:               "j-test1",
		TargetID:            "t-nginx1",
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
		VerifiedAt:          time.Now().UTC(),
	}

	err := service.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check job was updated
	job, _ := mockJobRepo.Get(ctx, "j-test1")
	if job.VerificationStatus != domain.VerificationSuccess {
		t.Errorf("expected VerificationSuccess, got %s", job.VerificationStatus)
	}
	if !*job.VerifiedAt == result.VerifiedAt {
		t.Errorf("verified_at mismatch")
	}

	// Check audit event was recorded
	if len(mockAudit.events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(mockAudit.events))
	}
}

func TestVerificationService_RecordVerificationResult_Failed(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{
			"j-test2": {
				ID:     "j-test2",
				Status: domain.JobStatusCompleted,
			},
		},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result := &domain.VerificationResult{
		JobID:               "j-test2",
		TargetID:            "t-apache1",
		ExpectedFingerprint: "aaa111",
		ActualFingerprint:   "bbb222",
		Verified:            false,
		VerifiedAt:          time.Now().UTC(),
	}

	err := service.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	job, _ := mockJobRepo.Get(ctx, "j-test2")
	if job.VerificationStatus != domain.VerificationFailed {
		t.Errorf("expected VerificationFailed, got %s", job.VerificationStatus)
	}
}

func TestVerificationService_RecordVerificationResult_WithError(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{
			"j-test3": {
				ID:     "j-test3",
				Status: domain.JobStatusCompleted,
			},
		},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result := &domain.VerificationResult{
		JobID:      "j-test3",
		TargetID:   "t-haproxy1",
		VerifiedAt: time.Now().UTC(),
		Error:      "connection refused",
	}

	err := service.RecordVerificationResult(ctx, result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	job, _ := mockJobRepo.Get(ctx, "j-test3")
	if job.VerificationStatus != domain.VerificationFailed {
		t.Errorf("expected VerificationFailed, got %s", job.VerificationStatus)
	}
	if job.VerificationError == nil || *job.VerificationError != "connection refused" {
		t.Error("expected verification error to be set")
	}
}

func TestVerificationService_RecordVerificationResult_JobNotFound(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result := &domain.VerificationResult{
		JobID:      "j-nonexistent",
		TargetID:   "t-nginx1",
		VerifiedAt: time.Now().UTC(),
	}

	err := service.RecordVerificationResult(ctx, result)
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestVerificationService_RecordVerificationResult_MissingJobID(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{jobs: map[string]*domain.Job{}}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result := &domain.VerificationResult{
		TargetID:   "t-nginx1",
		VerifiedAt: time.Now().UTC(),
	}

	err := service.RecordVerificationResult(ctx, result)
	if err == nil {
		t.Error("expected error for missing job ID")
	}
}

func TestVerificationService_RecordVerificationResult_NilResult(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{jobs: map[string]*domain.Job{}}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	err := service.RecordVerificationResult(ctx, nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestVerificationService_GetVerificationResult_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	targetID := "t-nginx1"
	fp := "abc123"
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{
			"j-test1": {
				ID:                 "j-test1",
				TargetID:           &targetID,
				VerificationStatus: domain.VerificationSuccess,
				VerifiedAt:         &now,
				VerificationFp:     &fp,
			},
		},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	result, err := service.GetVerificationResult(ctx, "j-test1")
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
	mockJobRepo := &mockJobRepository{
		jobs: map[string]*domain.Job{},
	}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	_, err := service.GetVerificationResult(ctx, "j-nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestVerificationService_GetVerificationResult_EmptyJobID(t *testing.T) {
	ctx := context.Background()
	mockJobRepo := &mockJobRepository{jobs: map[string]*domain.Job{}}
	mockAudit := &mockAuditService{events: []interface{}{}}
	service := NewVerificationService(mockJobRepo, mockAudit, slog.Default())

	_, err := service.GetVerificationResult(ctx, "")
	if err == nil {
		t.Error("expected error for empty job ID")
	}
}
