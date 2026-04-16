package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// mockHealthCheckSvc implements HealthCheckServicer for testing.
type mockHealthCheckSvc struct {
	createErr      error
	getErr         error
	updateErr      error
	deleteErr      error
	listErr        error
	getHistoryErr  error
	acknowledgeErr error
	getSummaryErr  error
	checks         map[string]*domain.EndpointHealthCheck
	summary        *domain.HealthCheckSummary
}

func newMockHealthCheckSvc() *mockHealthCheckSvc {
	return &mockHealthCheckSvc{
		checks: make(map[string]*domain.EndpointHealthCheck),
		summary: &domain.HealthCheckSummary{
			Healthy:      1,
			Degraded:     0,
			Down:         0,
			CertMismatch: 0,
			Unknown:      0,
		},
	}
}

func (m *mockHealthCheckSvc) Create(ctx context.Context, check *domain.EndpointHealthCheck) error {
	if m.createErr != nil {
		return m.createErr
	}
	check.ID = "hc-created-1"
	m.checks[check.ID] = check
	return nil
}

func (m *mockHealthCheckSvc) Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if check, ok := m.checks[id]; ok {
		return check, nil
	}
	return nil, errors.New("not found")
}

func (m *mockHealthCheckSvc) Update(ctx context.Context, check *domain.EndpointHealthCheck) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.checks[check.ID] = check
	return nil
}

func (m *mockHealthCheckSvc) Delete(ctx context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.checks, id)
	return nil
}

func (m *mockHealthCheckSvc) List(ctx context.Context, filter *repository.HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	checks := make([]*domain.EndpointHealthCheck, 0, len(m.checks))
	for _, check := range m.checks {
		checks = append(checks, check)
	}
	return checks, len(checks), nil
}

func (m *mockHealthCheckSvc) GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error) {
	if m.getHistoryErr != nil {
		return nil, m.getHistoryErr
	}
	return make([]*domain.HealthHistoryEntry, 0), nil
}

func (m *mockHealthCheckSvc) AcknowledgeIncident(ctx context.Context, id string, actor string) error {
	if m.acknowledgeErr != nil {
		return m.acknowledgeErr
	}
	if check, ok := m.checks[id]; ok {
		check.Acknowledged = true
		check.AcknowledgedBy = actor
	}
	return nil
}

func (m *mockHealthCheckSvc) GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error) {
	if m.getSummaryErr != nil {
		return nil, m.getSummaryErr
	}
	return m.summary, nil
}

// Tests

func TestListHealthChecks_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	svc.checks["hc-1"] = &domain.EndpointHealthCheck{
		ID:       "hc-1",
		Endpoint: "api.example.com:443",
		Status:   domain.HealthStatusHealthy,
	}
	handler := NewHealthCheckHandler(svc)

	req := httptest.NewRequest("GET", "/api/v1/health-checks", nil)
	w := httptest.NewRecorder()

	handler.ListHealthChecks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Total != 1 {
		t.Errorf("Expected 1 health check, got %d", resp.Total)
	}
}

func TestListHealthChecks_MethodNotAllowed(t *testing.T) {
	handler := NewHealthCheckHandler(newMockHealthCheckSvc())

	req := httptest.NewRequest("POST", "/api/v1/health-checks", nil)
	w := httptest.NewRecorder()

	handler.ListHealthChecks(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestGetHealthCheck_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	check := &domain.EndpointHealthCheck{
		ID:       "hc-1",
		Endpoint: "api.example.com:443",
		Status:   domain.HealthStatusHealthy,
	}
	svc.checks["hc-1"] = check
	handler := NewHealthCheckHandler(svc)

	req := httptest.NewRequest("GET", "/api/v1/health-checks/hc-1", nil)
	req.SetPathValue("id", "hc-1")
	w := httptest.NewRecorder()

	handler.GetHealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp domain.EndpointHealthCheck
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.ID != "hc-1" {
		t.Errorf("Expected ID hc-1, got %s", resp.ID)
	}
}

func TestGetHealthCheck_NotFound(t *testing.T) {
	handler := NewHealthCheckHandler(newMockHealthCheckSvc())

	req := httptest.NewRequest("GET", "/api/v1/health-checks/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	handler.GetHealthCheck(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestCreateHealthCheck_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	handler := NewHealthCheckHandler(svc)

	check := domain.EndpointHealthCheck{
		Endpoint: "web.example.com:443",
		Enabled:  true,
	}
	body, _ := json.Marshal(check)

	req := httptest.NewRequest("POST", "/api/v1/health-checks", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.CreateHealthCheck(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var resp domain.EndpointHealthCheck
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Endpoint != "web.example.com:443" {
		t.Errorf("Expected endpoint web.example.com:443, got %s", resp.Endpoint)
	}
}

func TestDeleteHealthCheck_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	svc.checks["hc-1"] = &domain.EndpointHealthCheck{
		ID:       "hc-1",
		Endpoint: "api.example.com:443",
	}
	handler := NewHealthCheckHandler(svc)

	req := httptest.NewRequest("DELETE", "/api/v1/health-checks/hc-1", nil)
	req.SetPathValue("id", "hc-1")
	w := httptest.NewRecorder()

	handler.DeleteHealthCheck(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	if _, ok := svc.checks["hc-1"]; ok {
		t.Fatal("Expected check to be deleted")
	}
}

func TestAcknowledgeHealthCheck_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	svc.checks["hc-1"] = &domain.EndpointHealthCheck{
		ID:       "hc-1",
		Endpoint: "api.example.com:443",
		Status:   domain.HealthStatusDown,
	}
	handler := NewHealthCheckHandler(svc)

	req := httptest.NewRequest("POST", "/api/v1/health-checks/hc-1/acknowledge", bytes.NewReader([]byte(`{"actor":"user@example.com"}`)))
	req.SetPathValue("id", "hc-1")
	w := httptest.NewRecorder()

	handler.AcknowledgeHealthCheck(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	if !svc.checks["hc-1"].Acknowledged {
		t.Fatal("Expected check to be acknowledged")
	}
}

func TestGetHealthCheckSummary_Success(t *testing.T) {
	svc := newMockHealthCheckSvc()
	svc.summary = &domain.HealthCheckSummary{
		Healthy:      3,
		Degraded:     1,
		Down:         0,
		CertMismatch: 0,
		Unknown:      1,
	}
	handler := NewHealthCheckHandler(svc)

	req := httptest.NewRequest("GET", "/api/v1/health-checks/summary", nil)
	w := httptest.NewRecorder()

	handler.GetHealthCheckSummary(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp domain.HealthCheckSummary
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Healthy != 3 {
		t.Errorf("Expected 3 healthy checks, got %d", resp.Healthy)
	}
}
