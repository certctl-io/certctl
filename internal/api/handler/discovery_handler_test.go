package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// MockDiscoveryService is a mock implementation of DiscoveryService interface.
type MockDiscoveryService struct {
	ProcessDiscoveryReportFn func(ctx context.Context, report *domain.DiscoveryReport) (*domain.DiscoveryScan, error)
	ListDiscoveredFn         func(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error)
	GetDiscoveredFn          func(ctx context.Context, id string) (*domain.DiscoveredCertificate, error)
	ClaimDiscoveredFn        func(ctx context.Context, id string, managedCertID string, actor string) error
	DismissDiscoveredFn      func(ctx context.Context, id string, actor string) error
	ListScansFn              func(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error)
	GetScanFn                func(ctx context.Context, id string) (*domain.DiscoveryScan, error)
	GetDiscoverySummaryFn    func(ctx context.Context) (map[string]int, error)
}

func (m *MockDiscoveryService) ProcessDiscoveryReport(ctx context.Context, report *domain.DiscoveryReport) (*domain.DiscoveryScan, error) {
	if m.ProcessDiscoveryReportFn != nil {
		return m.ProcessDiscoveryReportFn(ctx, report)
	}
	return nil, nil
}

func (m *MockDiscoveryService) ListDiscovered(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error) {
	if m.ListDiscoveredFn != nil {
		return m.ListDiscoveredFn(ctx, agentID, status, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockDiscoveryService) GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
	if m.GetDiscoveredFn != nil {
		return m.GetDiscoveredFn(ctx, id)
	}
	return nil, nil
}

func (m *MockDiscoveryService) ClaimDiscovered(ctx context.Context, id string, managedCertID string, actor string) error {
	if m.ClaimDiscoveredFn != nil {
		return m.ClaimDiscoveredFn(ctx, id, managedCertID, actor)
	}
	return nil
}

func (m *MockDiscoveryService) DismissDiscovered(ctx context.Context, id string, actor string) error {
	if m.DismissDiscoveredFn != nil {
		return m.DismissDiscoveredFn(ctx, id, actor)
	}
	return nil
}

func (m *MockDiscoveryService) ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
	if m.ListScansFn != nil {
		return m.ListScansFn(ctx, agentID, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockDiscoveryService) GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error) {
	if m.GetScanFn != nil {
		return m.GetScanFn(ctx, id)
	}
	return nil, nil
}

func (m *MockDiscoveryService) GetDiscoverySummary(ctx context.Context) (map[string]int, error) {
	if m.GetDiscoverySummaryFn != nil {
		return m.GetDiscoverySummaryFn(ctx)
	}
	return nil, nil
}

// Helper function to create context with request ID.
func discoveryContextWithRequestID() context.Context {
	return context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id-123")
}

// Test SubmitDiscoveryReport - success case
func TestSubmitDiscoveryReport_Success(t *testing.T) {
	now := time.Now()
	scan := &domain.DiscoveryScan{
		ID:                "dscan-1",
		AgentID:           "agent-1",
		CertificatesFound: 2,
		CertificatesNew:   1,
		ErrorsCount:       0,
		ScanDurationMs:    150,
		StartedAt:         now,
		CompletedAt:       &now,
	}

	mock := &MockDiscoveryService{
		ProcessDiscoveryReportFn: func(ctx context.Context, report *domain.DiscoveryReport) (*domain.DiscoveryScan, error) {
			if report.AgentID == "agent-1" && len(report.Certificates) == 2 {
				return scan, nil
			}
			return nil, fmt.Errorf("unexpected report")
		},
	}

	handler := NewDiscoveryHandler(mock)

	reportBody := domain.DiscoveryReport{
		AgentID: "agent-1",
		Certificates: []domain.DiscoveredCertEntry{
			{
				FingerprintSHA256: "abc123",
				CommonName:        "example.com",
				SerialNumber:      "001",
				SourcePath:        "/etc/certs/example.com.crt",
			},
			{
				FingerprintSHA256: "def456",
				CommonName:        "api.example.com",
				SerialNumber:      "002",
				SourcePath:        "/etc/certs/api.example.com.crt",
			},
		},
		ScanDurationMs: 150,
	}

	body, _ := json.Marshal(reportBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/discoveries", bytes.NewReader(body))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "agent-1")
	w := httptest.NewRecorder()

	handler.SubmitDiscoveryReport(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var response *domain.DiscoveryScan
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "dscan-1" {
		t.Errorf("expected scan ID dscan-1, got %s", response.ID)
	}
	if response.CertificatesFound != 2 {
		t.Errorf("expected 2 certificates found, got %d", response.CertificatesFound)
	}
}

// Test SubmitDiscoveryReport - invalid body
func TestSubmitDiscoveryReport_InvalidBody(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/discoveries", bytes.NewReader([]byte("invalid json")))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "agent-1")
	w := httptest.NewRecorder()

	handler.SubmitDiscoveryReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test SubmitDiscoveryReport - method not allowed
func TestSubmitDiscoveryReport_MethodNotAllowed(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-1/discoveries", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "agent-1")
	w := httptest.NewRecorder()

	handler.SubmitDiscoveryReport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test ListDiscovered - success case
func TestListDiscovered_Success(t *testing.T) {
	now := time.Now()
	certs := []*domain.DiscoveredCertificate{
		{
			ID:           "dcert-1",
			CommonName:   "example.com",
			SerialNumber: "001",
			Status:       domain.DiscoveryStatusUnmanaged,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		{
			ID:           "dcert-2",
			CommonName:   "api.example.com",
			SerialNumber: "002",
			Status:       domain.DiscoveryStatusManaged,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}

	mock := &MockDiscoveryService{
		ListDiscoveredFn: func(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error) {
			if page == 1 && perPage == 50 {
				return certs, 2, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates?page=1&per_page=50", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListDiscovered(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Total != 2 {
		t.Errorf("expected total 2, got %d", response.Total)
	}
}

// Test ListDiscovered - with filters
func TestListDiscovered_WithFilters(t *testing.T) {
	mock := &MockDiscoveryService{
		ListDiscoveredFn: func(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error) {
			if agentID == "agent-1" && status == "Unmanaged" {
				return []*domain.DiscoveredCertificate{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates?agent_id=agent-1&status=Unmanaged&page=1&per_page=25", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListDiscovered(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test ListDiscovered - method not allowed
func TestListDiscovered_MethodNotAllowed(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListDiscovered(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test GetDiscovered - success case
func TestGetDiscovered_Success(t *testing.T) {
	now := time.Now()
	cert := &domain.DiscoveredCertificate{
		ID:           "dcert-1",
		CommonName:   "example.com",
		SerialNumber: "001",
		Status:       domain.DiscoveryStatusUnmanaged,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	mock := &MockDiscoveryService{
		GetDiscoveredFn: func(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
			if id == "dcert-1" {
				return cert, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates/dcert-1", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.GetDiscovered(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response *domain.DiscoveredCertificate
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "dcert-1" {
		t.Errorf("expected ID dcert-1, got %s", response.ID)
	}
}

// Test GetDiscovered - not found
func TestGetDiscovered_NotFound(t *testing.T) {
	mock := &MockDiscoveryService{
		GetDiscoveredFn: func(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
			return nil, fmt.Errorf("not found")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates/nonexistent", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	handler.GetDiscovered(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// Test ClaimDiscovered - success case
func TestClaimDiscovered_Success(t *testing.T) {
	mock := &MockDiscoveryService{
		ClaimDiscoveredFn: func(ctx context.Context, id string, managedCertID string, actor string) error {
			if id == "dcert-1" && managedCertID == "mc-prod-1" {
				return nil
			}
			return fmt.Errorf("unexpected parameters")
		},
	}

	handler := NewDiscoveryHandler(mock)

	claimBody := map[string]string{
		"managed_certificate_id": "mc-prod-1",
	}
	body, _ := json.Marshal(claimBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/dcert-1/claim", bytes.NewReader(body))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.ClaimDiscovered(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "claimed" {
		t.Errorf("expected status 'claimed', got %s", response["status"])
	}
}

// Test ClaimDiscovered - missing managed_certificate_id
func TestClaimDiscovered_MissingManagedCertID(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	claimBody := map[string]string{}
	body, _ := json.Marshal(claimBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/dcert-1/claim", bytes.NewReader(body))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.ClaimDiscovered(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test ClaimDiscovered - discovered cert not found
func TestClaimDiscovered_NotFound(t *testing.T) {
	mock := &MockDiscoveryService{
		ClaimDiscoveredFn: func(ctx context.Context, id string, managedCertID string, actor string) error {
			return fmt.Errorf("discovered certificate not found")
		},
	}

	handler := NewDiscoveryHandler(mock)

	claimBody := map[string]string{
		"managed_certificate_id": "mc-prod-1",
	}
	body, _ := json.Marshal(claimBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/nonexistent/claim", bytes.NewReader(body))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	handler.ClaimDiscovered(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test DismissDiscovered - success case
func TestDismissDiscovered_Success(t *testing.T) {
	mock := &MockDiscoveryService{
		DismissDiscoveredFn: func(ctx context.Context, id string, actor string) error {
			if id == "dcert-1" {
				return nil
			}
			return fmt.Errorf("not found")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/dcert-1/dismiss", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.DismissDiscovered(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "dismissed" {
		t.Errorf("expected status 'dismissed', got %s", response["status"])
	}
}

// Test DismissDiscovered - method not allowed
func TestDismissDiscovered_MethodNotAllowed(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates/dcert-1/dismiss", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.DismissDiscovered(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test ListScans - success case
func TestListScans_Success(t *testing.T) {
	now := time.Now()
	scans := []*domain.DiscoveryScan{
		{
			ID:                "dscan-1",
			AgentID:           "agent-1",
			CertificatesFound: 5,
			CertificatesNew:   2,
			ScanDurationMs:    200,
			StartedAt:         now,
			CompletedAt:       &now,
		},
	}

	mock := &MockDiscoveryService{
		ListScansFn: func(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
			if page == 1 && perPage == 50 {
				return scans, 1, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery-scans?page=1&per_page=50", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListScans(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Total != 1 {
		t.Errorf("expected total 1, got %d", response.Total)
	}
}

// Test ListScans - with agent filter
func TestListScans_WithAgentFilter(t *testing.T) {
	mock := &MockDiscoveryService{
		ListScansFn: func(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
			if agentID == "agent-1" {
				return []*domain.DiscoveryScan{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery-scans?agent_id=agent-1", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListScans(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test GetDiscoverySummary - success case
func TestGetDiscoverySummary_Success(t *testing.T) {
	summary := map[string]int{
		"Unmanaged": 5,
		"Managed":   3,
		"Dismissed": 1,
	}

	mock := &MockDiscoveryService{
		GetDiscoverySummaryFn: func(ctx context.Context) (map[string]int, error) {
			return summary, nil
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery-summary", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDiscoverySummary(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]int
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["Unmanaged"] != 5 {
		t.Errorf("expected Unmanaged count 5, got %d", response["Unmanaged"])
	}
	if response["Managed"] != 3 {
		t.Errorf("expected Managed count 3, got %d", response["Managed"])
	}
}

// Test GetDiscoverySummary - method not allowed
func TestGetDiscoverySummary_MethodNotAllowed(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery-summary", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDiscoverySummary(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test DismissDiscovered - service error
func TestDismissDiscovered_ServiceError(t *testing.T) {
	mock := &MockDiscoveryService{
		DismissDiscoveredFn: func(ctx context.Context, id string, actor string) error {
			return fmt.Errorf("database error")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/dcert-1/dismiss", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.DismissDiscovered(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test ClaimDiscovered - invalid body (malformed JSON)
func TestClaimDiscovered_InvalidJSON(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovered-certificates/dcert-1/claim", bytes.NewReader([]byte("invalid json")))
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.ClaimDiscovered(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test ClaimDiscovered - method not allowed
func TestClaimDiscovered_MethodNotAllowed(t *testing.T) {
	mock := &MockDiscoveryService{}
	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates/dcert-1/claim", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	req.SetPathValue("id", "dcert-1")
	w := httptest.NewRecorder()

	handler.ClaimDiscovered(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test ListDiscovered - service error
func TestListDiscovered_ServiceError(t *testing.T) {
	mock := &MockDiscoveryService{
		ListDiscoveredFn: func(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error) {
			return nil, 0, fmt.Errorf("database error")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovered-certificates", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListDiscovered(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test ListScans - service error
func TestListScans_ServiceError(t *testing.T) {
	mock := &MockDiscoveryService{
		ListScansFn: func(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
			return nil, 0, fmt.Errorf("database error")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery-scans", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListScans(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test GetDiscoverySummary - service error
func TestGetDiscoverySummary_ServiceError(t *testing.T) {
	mock := &MockDiscoveryService{
		GetDiscoverySummaryFn: func(ctx context.Context) (map[string]int, error) {
			return nil, fmt.Errorf("database error")
		},
	}

	handler := NewDiscoveryHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery-summary", nil)
	req = req.WithContext(discoveryContextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDiscoverySummary(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}
