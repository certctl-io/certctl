package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// MockJobService is a mock implementation of JobService interface.
type MockJobService struct {
	ListJobsFn   func(status, jobType string, page, perPage int) ([]domain.Job, int64, error)
	GetJobFn     func(id string) (*domain.Job, error)
	CancelJobFn  func(id string) error
	ApproveJobFn func(id string) error
	RejectJobFn  func(id string, reason string) error
}

func (m *MockJobService) ListJobs(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
	if m.ListJobsFn != nil {
		return m.ListJobsFn(status, jobType, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockJobService) GetJob(id string) (*domain.Job, error) {
	if m.GetJobFn != nil {
		return m.GetJobFn(id)
	}
	return nil, nil
}

func (m *MockJobService) CancelJob(id string) error {
	if m.CancelJobFn != nil {
		return m.CancelJobFn(id)
	}
	return nil
}

func (m *MockJobService) ApproveJob(id string) error {
	if m.ApproveJobFn != nil {
		return m.ApproveJobFn(id)
	}
	return nil
}

func (m *MockJobService) RejectJob(id string, reason string) error {
	if m.RejectJobFn != nil {
		return m.RejectJobFn(id, reason)
	}
	return nil
}

func TestListJobs_Success(t *testing.T) {
	now := time.Now()
	job1 := domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeRenewal,
		CertificateID: "mc-prod-001",
		Status:        domain.JobStatusPending,
		Attempts:      0,
		MaxAttempts:   3,
		ScheduledAt:   now,
		CreatedAt:     now,
	}
	job2 := domain.Job{
		ID:            "job-002",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-prod-002",
		Status:        domain.JobStatusCompleted,
		Attempts:      1,
		MaxAttempts:   3,
		ScheduledAt:   now,
		CreatedAt:     now,
	}

	mock := &MockJobService{
		ListJobsFn: func(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
			return []domain.Job{job1, job2}, 2, nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("expected total 2, got %d", resp.Total)
	}
}

func TestListJobs_FilterByStatus(t *testing.T) {
	var capturedStatus string
	mock := &MockJobService{
		ListJobsFn: func(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
			capturedStatus = status
			return []domain.Job{}, 0, nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs?status=Pending", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if capturedStatus != "Pending" {
		t.Errorf("expected status filter 'Pending', got '%s'", capturedStatus)
	}
}

func TestListJobs_FilterByType(t *testing.T) {
	var capturedType string
	mock := &MockJobService{
		ListJobsFn: func(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
			capturedType = jobType
			return []domain.Job{}, 0, nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs?type=Renewal", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if capturedType != "Renewal" {
		t.Errorf("expected type filter 'Renewal', got '%s'", capturedType)
	}
}

func TestListJobs_ServiceError(t *testing.T) {
	mock := &MockJobService{
		ListJobsFn: func(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListJobs_MethodNotAllowed(t *testing.T) {
	handler := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", nil)
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestListJobs_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockJobService{
		ListJobsFn: func(status, jobType string, page, perPage int) ([]domain.Job, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.Job{}, 0, nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs?page=3&per_page=25", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListJobs(w, req)

	if capturedPage != 3 {
		t.Errorf("expected page 3, got %d", capturedPage)
	}
	if capturedPerPage != 25 {
		t.Errorf("expected per_page 25, got %d", capturedPerPage)
	}
}

func TestGetJob_Success(t *testing.T) {
	now := time.Now()
	mock := &MockJobService{
		GetJobFn: func(id string) (*domain.Job, error) {
			return &domain.Job{
				ID:            id,
				Type:          domain.JobTypeRenewal,
				CertificateID: "mc-prod-001",
				Status:        domain.JobStatusPending,
				ScheduledAt:   now,
				CreatedAt:     now,
			}, nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetJob(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetJob_NotFound(t *testing.T) {
	mock := &MockJobService{
		GetJobFn: func(id string) (*domain.Job, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetJob(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestGetJob_EmptyID(t *testing.T) {
	handler := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetJob(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCancelJob_Success(t *testing.T) {
	var cancelledID string
	mock := &MockJobService{
		CancelJobFn: func(id string) error {
			cancelledID = id
			return nil
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-001/cancel", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CancelJob(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if cancelledID != "job-001" {
		t.Errorf("expected cancelled ID 'job-001', got '%s'", cancelledID)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "job_cancelled" {
		t.Errorf("expected status 'job_cancelled', got '%s'", resp["status"])
	}
}

func TestCancelJob_ServiceError(t *testing.T) {
	mock := &MockJobService{
		CancelJobFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-001/cancel", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CancelJob(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestCancelJob_MethodNotAllowed(t *testing.T) {
	handler := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-001/cancel", nil)
	w := httptest.NewRecorder()

	handler.CancelJob(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestCancelJob_EmptyID(t *testing.T) {
	handler := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs//cancel", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CancelJob(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestApproveJob_Success(t *testing.T) {
	var approvedID string
	mock := &MockJobService{
		ApproveJobFn: func(id string) error {
			approvedID = id
			return nil
		},
	}

	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-001/approve", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ApproveJob(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if approvedID != "job-001" {
		t.Errorf("expected approved ID 'job-001', got '%s'", approvedID)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "job_approved" {
		t.Errorf("expected status 'job_approved', got '%s'", resp["status"])
	}
}

func TestApproveJob_NotFound(t *testing.T) {
	mock := &MockJobService{
		ApproveJobFn: func(id string) error {
			return fmt.Errorf("job not found: no rows")
		},
	}

	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-ghost/approve", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ApproveJob(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestApproveJob_BadStatus(t *testing.T) {
	mock := &MockJobService{
		ApproveJobFn: func(id string) error {
			return fmt.Errorf("cannot approve job with status Running")
		},
	}

	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-001/approve", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ApproveJob(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestApproveJob_MethodNotAllowed(t *testing.T) {
	h := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-001/approve", nil)
	w := httptest.NewRecorder()

	h.ApproveJob(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestRejectJob_Success(t *testing.T) {
	var rejectedID, capturedReason string
	mock := &MockJobService{
		RejectJobFn: func(id string, reason string) error {
			rejectedID = id
			capturedReason = reason
			return nil
		},
	}

	body := `{"reason":"Certificate no longer needed"}`
	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-002/reject", strings.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.RejectJob(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if rejectedID != "job-002" {
		t.Errorf("expected rejected ID 'job-002', got '%s'", rejectedID)
	}
	if capturedReason != "Certificate no longer needed" {
		t.Errorf("expected reason 'Certificate no longer needed', got '%s'", capturedReason)
	}
}

func TestRejectJob_NoReason(t *testing.T) {
	mock := &MockJobService{
		RejectJobFn: func(id string, reason string) error {
			return nil
		},
	}

	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-002/reject", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.RejectJob(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestRejectJob_NotFound(t *testing.T) {
	mock := &MockJobService{
		RejectJobFn: func(id string, reason string) error {
			return fmt.Errorf("job not found: no rows")
		},
	}

	h := NewJobHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-ghost/reject", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.RejectJob(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestRejectJob_MethodNotAllowed(t *testing.T) {
	h := NewJobHandler(&MockJobService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-001/reject", nil)
	w := httptest.NewRecorder()

	h.RejectJob(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}
