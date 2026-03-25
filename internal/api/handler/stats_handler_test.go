package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MockStatsService implements both StatsService and MetricsService.
type MockStatsService struct {
	GetDashboardSummaryFn     func(ctx context.Context) (interface{}, error)
	GetCertificatesByStatusFn func(ctx context.Context) (interface{}, error)
	GetExpirationTimelineFn   func(ctx context.Context, days int) (interface{}, error)
	GetJobStatsFn             func(ctx context.Context, days int) (interface{}, error)
	GetIssuanceRateFn         func(ctx context.Context, days int) (interface{}, error)
}

func (m *MockStatsService) GetDashboardSummary(ctx context.Context) (interface{}, error) {
	if m.GetDashboardSummaryFn != nil {
		return m.GetDashboardSummaryFn(ctx)
	}
	return map[string]int64{"total_certificates": 0}, nil
}

func (m *MockStatsService) GetCertificatesByStatus(ctx context.Context) (interface{}, error) {
	if m.GetCertificatesByStatusFn != nil {
		return m.GetCertificatesByStatusFn(ctx)
	}
	return []interface{}{}, nil
}

func (m *MockStatsService) GetExpirationTimeline(ctx context.Context, days int) (interface{}, error) {
	if m.GetExpirationTimelineFn != nil {
		return m.GetExpirationTimelineFn(ctx, days)
	}
	return []interface{}{}, nil
}

func (m *MockStatsService) GetJobStats(ctx context.Context, days int) (interface{}, error) {
	if m.GetJobStatsFn != nil {
		return m.GetJobStatsFn(ctx, days)
	}
	return []interface{}{}, nil
}

func (m *MockStatsService) GetIssuanceRate(ctx context.Context, days int) (interface{}, error) {
	if m.GetIssuanceRateFn != nil {
		return m.GetIssuanceRateFn(ctx, days)
	}
	return []interface{}{}, nil
}

func TestGetDashboardSummary_Success(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil)
	w := httptest.NewRecorder()
	h.GetDashboardSummary(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetDashboardSummary_MethodNotAllowed(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stats/summary", nil)
	w := httptest.NewRecorder()
	h.GetDashboardSummary(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGetDashboardSummary_ServiceError(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil)
	w := httptest.NewRecorder()
	h.GetDashboardSummary(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestGetCertificatesByStatus_Success(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/certificates-by-status", nil)
	w := httptest.NewRecorder()
	h.GetCertificatesByStatus(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetExpirationTimeline_Success(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/expiration-timeline?days=60", nil)
	w := httptest.NewRecorder()
	h.GetExpirationTimeline(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetExpirationTimeline_DefaultDays(t *testing.T) {
	mock := &MockStatsService{
		GetExpirationTimelineFn: func(ctx context.Context, days int) (interface{}, error) {
			if days != 30 {
				t.Errorf("expected default 30 days, got %d", days)
			}
			return []interface{}{}, nil
		},
	}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/expiration-timeline", nil)
	w := httptest.NewRecorder()
	h.GetExpirationTimeline(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetJobTrends_Success(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/job-trends?days=14", nil)
	w := httptest.NewRecorder()
	h.GetJobTrends(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetIssuanceRate_Success(t *testing.T) {
	mock := &MockStatsService{}
	h := NewStatsHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/issuance-rate?days=7", nil)
	w := httptest.NewRecorder()
	h.GetIssuanceRate(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetMetrics_Success(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return &DashboardSummary{
				TotalCertificates:    10,
				ExpiringCertificates: 2,
				ExpiredCertificates:  1,
				RevokedCertificates:  0,
				ActiveAgents:         3,
				TotalAgents:          5,
				PendingJobs:          1,
				FailedJobs:           0,
				CompleteJobs:         8,
			}, nil
		},
	}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	w := httptest.NewRecorder()
	h.GetMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetMetrics_MethodNotAllowed(t *testing.T) {
	mock := &MockStatsService{}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics", nil)
	w := httptest.NewRecorder()
	h.GetMetrics(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGetMetrics_ServiceError(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	w := httptest.NewRecorder()
	h.GetMetrics(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- Prometheus metrics endpoint tests ---

func TestGetPrometheusMetrics_Success(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return &DashboardSummary{
				TotalCertificates:    25,
				ExpiringCertificates: 3,
				ExpiredCertificates:  2,
				RevokedCertificates:  1,
				ActiveAgents:         4,
				TotalAgents:          6,
				PendingJobs:          2,
				FailedJobs:           1,
				CompleteJobs:         15,
			}, nil
		},
	}
	h := NewMetricsHandler(mock, time.Now().Add(-1*time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/prometheus", nil)
	w := httptest.NewRecorder()
	h.GetPrometheusMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("expected Prometheus content type, got %q", contentType)
	}

	body := w.Body.String()

	// Check metric lines are present
	expected := []string{
		"certctl_certificate_total 25",
		"certctl_certificate_active 19",
		"certctl_certificate_expiring_soon 3",
		"certctl_certificate_expired 2",
		"certctl_certificate_revoked 1",
		"certctl_agent_total 6",
		"certctl_agent_online 4",
		"certctl_job_pending 2",
		"certctl_job_completed_total 15",
		"certctl_job_failed_total 1",
		"# TYPE certctl_certificate_total gauge",
		"# TYPE certctl_job_completed_total counter",
		"# HELP certctl_uptime_seconds",
		"# TYPE certctl_uptime_seconds gauge",
	}
	for _, exp := range expected {
		if !containsLine(body, exp) {
			t.Errorf("expected body to contain %q", exp)
		}
	}
}

func TestGetPrometheusMetrics_MethodNotAllowed(t *testing.T) {
	mock := &MockStatsService{}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics/prometheus", nil)
	w := httptest.NewRecorder()
	h.GetPrometheusMetrics(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGetPrometheusMetrics_ServiceError(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/prometheus", nil)
	w := httptest.NewRecorder()
	h.GetPrometheusMetrics(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestGetPrometheusMetrics_ZeroValues(t *testing.T) {
	mock := &MockStatsService{
		GetDashboardSummaryFn: func(ctx context.Context) (interface{}, error) {
			return &DashboardSummary{}, nil
		},
	}
	h := NewMetricsHandler(mock, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/prometheus", nil)
	w := httptest.NewRecorder()
	h.GetPrometheusMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !containsLine(body, "certctl_certificate_total 0") {
		t.Error("expected zero value for certificate_total")
	}
	if !containsLine(body, "certctl_job_pending 0") {
		t.Error("expected zero value for job_pending")
	}
}

// containsLine checks if the text contains the given substring.
func containsLine(text, substr string) bool {
	return strings.Contains(text, substr)
}
