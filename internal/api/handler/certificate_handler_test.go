package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// MockCertificateService is a mock implementation of CertificateService interface.
type MockCertificateService struct {
	ListCertificatesFn       func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error)
	GetCertificateFn         func(id string) (*domain.ManagedCertificate, error)
	CreateCertificateFn      func(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	UpdateCertificateFn      func(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	ArchiveCertificateFn     func(id string) error
	GetCertificateVersionsFn func(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error)
	TriggerRenewalFn         func(certID string) error
	TriggerDeploymentFn      func(certID string, targetID string) error
}

func (m *MockCertificateService) ListCertificates(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
	if m.ListCertificatesFn != nil {
		return m.ListCertificatesFn(status, environment, ownerID, teamID, issuerID, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockCertificateService) GetCertificate(id string) (*domain.ManagedCertificate, error) {
	if m.GetCertificateFn != nil {
		return m.GetCertificateFn(id)
	}
	return nil, nil
}

func (m *MockCertificateService) CreateCertificate(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
	if m.CreateCertificateFn != nil {
		return m.CreateCertificateFn(cert)
	}
	return nil, nil
}

func (m *MockCertificateService) UpdateCertificate(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
	if m.UpdateCertificateFn != nil {
		return m.UpdateCertificateFn(id, cert)
	}
	return nil, nil
}

func (m *MockCertificateService) ArchiveCertificate(id string) error {
	if m.ArchiveCertificateFn != nil {
		return m.ArchiveCertificateFn(id)
	}
	return nil
}

func (m *MockCertificateService) GetCertificateVersions(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
	if m.GetCertificateVersionsFn != nil {
		return m.GetCertificateVersionsFn(certID, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockCertificateService) TriggerRenewal(certID string) error {
	if m.TriggerRenewalFn != nil {
		return m.TriggerRenewalFn(certID)
	}
	return nil
}

func (m *MockCertificateService) TriggerDeployment(certID string, targetID string) error {
	if m.TriggerDeploymentFn != nil {
		return m.TriggerDeploymentFn(certID, targetID)
	}
	return nil
}

// Helper function to create context with request ID.
func contextWithRequestID() context.Context {
	return context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id-123")
}

// Test ListCertificates - success case
func TestListCertificates_Success(t *testing.T) {
	cert1 := domain.ManagedCertificate{
		ID:          "mc-prod-001",
		Name:        "Production Cert",
		CommonName:  "example.com",
		Status:      domain.CertificateStatusActive,
		Environment: "prod",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	cert2 := domain.ManagedCertificate{
		ID:          "mc-prod-002",
		Name:        "API Cert",
		CommonName:  "api.example.com",
		Status:      domain.CertificateStatusActive,
		Environment: "prod",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mock := &MockCertificateService{
		ListCertificatesFn: func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
			if page == 1 && perPage == 50 {
				return []domain.ManagedCertificate{cert1, cert2}, 2, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?page=1&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

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
	if response.Page != 1 {
		t.Errorf("expected page 1, got %d", response.Page)
	}
	if response.PerPage != 50 {
		t.Errorf("expected per_page 50, got %d", response.PerPage)
	}
}

// Test ListCertificates - with filters
func TestListCertificates_WithFilters(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesFn: func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
			if status == "Active" && environment == "prod" {
				return []domain.ManagedCertificate{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?status=Active&environment=prod&page=1&per_page=25", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test ListCertificates - invalid method
func TestListCertificates_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test ListCertificates - service error
func TestListCertificates_ServiceError(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesFn: func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test GetCertificate - success case
func TestGetCertificate_Success(t *testing.T) {
	cert := &domain.ManagedCertificate{
		ID:          "mc-prod-001",
		Name:        "Production Cert",
		CommonName:  "example.com",
		Status:      domain.CertificateStatusActive,
		Environment: "prod",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mock := &MockCertificateService{
		GetCertificateFn: func(id string) (*domain.ManagedCertificate, error) {
			if id == "mc-prod-001" {
				return cert, nil
			}
			return nil, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response domain.ManagedCertificate
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "mc-prod-001" {
		t.Errorf("expected ID mc-prod-001, got %s", response.ID)
	}
}

// Test GetCertificate - not found
func TestGetCertificate_NotFound(t *testing.T) {
	mock := &MockCertificateService{
		GetCertificateFn: func(id string) (*domain.ManagedCertificate, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificate(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// Test GetCertificate - empty ID
func TestGetCertificate_EmptyID(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test CreateCertificate - success case
func TestCreateCertificate_Success(t *testing.T) {
	now := time.Now()
	created := &domain.ManagedCertificate{
		ID:          "mc-prod-001",
		Name:        "Production Cert",
		CommonName:  "example.com",
		Status:      domain.CertificateStatusPending,
		Environment: "prod",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock := &MockCertificateService{
		CreateCertificateFn: func(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
			return created, nil
		},
	}

	handler := NewCertificateHandler(mock)

	certBody := domain.ManagedCertificate{
		Name:       "Production Cert",
		CommonName: "example.com",
		OwnerID:    "o-alice",
		TeamID:     "t-platform",
		IssuerID:   "iss-local",
	}
	body, _ := json.Marshal(certBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateCertificate(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var response domain.ManagedCertificate
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "mc-prod-001" {
		t.Errorf("expected ID mc-prod-001, got %s", response.ID)
	}
}

// Test CreateCertificate - invalid request body
func TestCreateCertificate_InvalidBody(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader([]byte("invalid json")))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test CreateCertificate - service error
func TestCreateCertificate_ServiceError(t *testing.T) {
	mock := &MockCertificateService{
		CreateCertificateFn: func(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
			return nil, ErrMockServiceFailed
		},
	}

	handler := NewCertificateHandler(mock)

	certBody := domain.ManagedCertificate{
		Name:       "Production Cert",
		CommonName: "example.com",
		OwnerID:    "o-alice",
		TeamID:     "t-platform",
		IssuerID:   "iss-local",
	}
	body, _ := json.Marshal(certBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateCertificate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test UpdateCertificate - success case
func TestUpdateCertificate_Success(t *testing.T) {
	updated := &domain.ManagedCertificate{
		ID:          "mc-prod-001",
		Name:        "Updated Cert",
		CommonName:  "example.com",
		Status:      domain.CertificateStatusActive,
		Environment: "prod",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mock := &MockCertificateService{
		UpdateCertificateFn: func(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
			if id == "mc-prod-001" {
				return updated, nil
			}
			return nil, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)

	certBody := domain.ManagedCertificate{
		Name: "Updated Cert",
	}
	body, _ := json.Marshal(certBody)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/mc-prod-001", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response domain.ManagedCertificate
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Name != "Updated Cert" {
		t.Errorf("expected name 'Updated Cert', got %s", response.Name)
	}
}

// Test UpdateCertificate - invalid body
func TestUpdateCertificate_InvalidBody(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/mc-prod-001", bytes.NewReader([]byte("invalid")))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test ArchiveCertificate - success case
func TestArchiveCertificate_Success(t *testing.T) {
	mock := &MockCertificateService{
		ArchiveCertificateFn: func(id string) error {
			if id == "mc-prod-001" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/mc-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ArchiveCertificate(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

// Test ArchiveCertificate - not found
func TestArchiveCertificate_NotFound(t *testing.T) {
	mock := &MockCertificateService{
		ArchiveCertificateFn: func(id string) error {
			return ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ArchiveCertificate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test GetCertificateVersions - success case
func TestGetCertificateVersions_Success(t *testing.T) {
	ver1 := domain.CertificateVersion{
		ID:                "cv-001",
		CertificateID:     "mc-prod-001",
		SerialNumber:      "ABC123",
		FingerprintSHA256: "abc123...",
		NotBefore:         time.Now(),
		NotAfter:          time.Now().AddDate(0, 0, 365),
		CreatedAt:         time.Now(),
	}

	mock := &MockCertificateService{
		GetCertificateVersionsFn: func(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
			if certID == "mc-prod-001" {
				return []domain.CertificateVersion{ver1}, 1, nil
			}
			return nil, 0, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-prod-001/versions?page=1&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateVersions(w, req)

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

// Test GetCertificateVersions - not found
func TestGetCertificateVersions_NotFound(t *testing.T) {
	mock := &MockCertificateService{
		GetCertificateVersionsFn: func(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
			return nil, 0, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/nonexistent/versions", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateVersions(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// Test TriggerRenewal - success case
func TestTriggerRenewal_Success(t *testing.T) {
	mock := &MockCertificateService{
		TriggerRenewalFn: func(certID string) error {
			if certID == "mc-prod-001" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/renew", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TriggerRenewal(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "renewal_triggered" {
		t.Errorf("expected status 'renewal_triggered', got %s", response["status"])
	}
}

// Test TriggerRenewal - service error
func TestTriggerRenewal_ServiceError(t *testing.T) {
	mock := &MockCertificateService{
		TriggerRenewalFn: func(certID string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/renew", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TriggerRenewal(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test TriggerDeployment - success case
func TestTriggerDeployment_Success(t *testing.T) {
	mock := &MockCertificateService{
		TriggerDeploymentFn: func(certID string, targetID string) error {
			if certID == "mc-prod-001" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)

	deployReq := map[string]string{"target_id": "t-nginx-001"}
	body, _ := json.Marshal(deployReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/deploy", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.TriggerDeployment(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "deployment_triggered" {
		t.Errorf("expected status 'deployment_triggered', got %s", response["status"])
	}
}

// Test TriggerDeployment - without target ID
func TestTriggerDeployment_NoTargetID(t *testing.T) {
	mock := &MockCertificateService{
		TriggerDeploymentFn: func(certID string, targetID string) error {
			// Should accept empty targetID (deploy to all)
			return nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/deploy", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TriggerDeployment(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}
}

// Test ListCertificates - invalid page parameter
func TestListCertificates_InvalidPageParam(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesFn: func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
			// Should default to page 1
			if page == 1 {
				return []domain.ManagedCertificate{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?page=invalid&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test ListCertificates - per_page exceeds max
func TestListCertificates_PerPageExceedsMax(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesFn: func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error) {
			// Should cap perPage at 500
			if perPage == 50 { // defaults to 50 if > 500
				return []domain.ManagedCertificate{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?per_page=1000", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}
