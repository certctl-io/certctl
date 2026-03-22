package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
