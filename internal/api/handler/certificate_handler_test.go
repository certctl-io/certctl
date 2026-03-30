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
	"github.com/shankar0123/certctl/internal/repository"
)

// MockCertificateService is a mock implementation of CertificateService interface.
type MockCertificateService struct {
	ListCertificatesFn           func(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error)
	ListCertificatesWithFilterFn func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error)
	GetCertificateFn             func(id string) (*domain.ManagedCertificate, error)
	CreateCertificateFn          func(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	UpdateCertificateFn          func(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	ArchiveCertificateFn         func(id string) error
	GetCertificateVersionsFn     func(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error)
	TriggerRenewalFn             func(certID string) error
	TriggerDeploymentFn          func(certID string, targetID string) error
	RevokeCertificateFn          func(certID string, reason string) error
	GetRevokedCertificatesFn     func() ([]*domain.CertificateRevocation, error)
	GenerateDERCRLFn             func(issuerID string) ([]byte, error)
	GetOCSPResponseFn            func(issuerID string, serialHex string) ([]byte, error)
	GetCertificateDeploymentsFn  func(certID string) ([]domain.DeploymentTarget, error)
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

func (m *MockCertificateService) RevokeCertificate(certID string, reason string) error {
	if m.RevokeCertificateFn != nil {
		return m.RevokeCertificateFn(certID, reason)
	}
	return nil
}

func (m *MockCertificateService) GetRevokedCertificates() ([]*domain.CertificateRevocation, error) {
	if m.GetRevokedCertificatesFn != nil {
		return m.GetRevokedCertificatesFn()
	}
	return nil, nil
}

func (m *MockCertificateService) GenerateDERCRL(issuerID string) ([]byte, error) {
	if m.GenerateDERCRLFn != nil {
		return m.GenerateDERCRLFn(issuerID)
	}
	return nil, nil
}

func (m *MockCertificateService) GetOCSPResponse(issuerID string, serialHex string) ([]byte, error) {
	if m.GetOCSPResponseFn != nil {
		return m.GetOCSPResponseFn(issuerID, serialHex)
	}
	return nil, nil
}

func (m *MockCertificateService) ListCertificatesWithFilter(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
	if m.ListCertificatesWithFilterFn != nil {
		return m.ListCertificatesWithFilterFn(filter)
	}
	return nil, 0, nil
}

func (m *MockCertificateService) GetCertificateDeployments(certID string) ([]domain.DeploymentTarget, error) {
	if m.GetCertificateDeploymentsFn != nil {
		return m.GetCertificateDeploymentsFn(certID)
	}
	return nil, nil
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
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.Page == 1 && filter.PerPage == 50 {
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
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.Status == "Active" && filter.Environment == "prod" {
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
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
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
		Name:            "Production Cert",
		CommonName:      "example.com",
		OwnerID:         "o-alice",
		TeamID:          "t-platform",
		IssuerID:        "iss-local",
		RenewalPolicyID: "rp-standard",
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
		Name:            "Production Cert",
		CommonName:      "example.com",
		OwnerID:         "o-alice",
		TeamID:          "t-platform",
		IssuerID:        "iss-local",
		RenewalPolicyID: "rp-standard",
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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
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
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			// Should default to page 1
			if filter.Page == 1 {
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
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			// Should cap perPage at 500
			if filter.PerPage == 50 { // defaults to 50 if > 500
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

// === Revocation Handler Tests ===

func TestRevokeCertificate_Handler_Success(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			if certID != "mc-prod-001" {
				t.Errorf("expected certID mc-prod-001, got %s", certID)
			}
			if reason != "keyCompromise" {
				t.Errorf("expected reason keyCompromise, got %s", reason)
			}
			return nil
		},
	}

	handler := NewCertificateHandler(mock)
	body := `{"reason":"keyCompromise"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "revoked" {
		t.Errorf("expected status 'revoked', got %s", resp["status"])
	}
}

func TestRevokeCertificate_Handler_NoBody(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			// Empty reason is OK — service defaults to "unspecified"
			return nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestRevokeCertificate_Handler_AlreadyRevoked(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			return fmt.Errorf("certificate is already revoked")
		},
	}

	handler := NewCertificateHandler(mock)
	body := `{"reason":"keyCompromise"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeCertificate_Handler_NotFound(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			return fmt.Errorf("failed to fetch certificate: not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/nonexistent/revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestRevokeCertificate_Handler_InvalidReason(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			return fmt.Errorf("invalid revocation reason: badReason")
		},
	}

	handler := NewCertificateHandler(mock)
	body := `{"reason":"badReason"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeCertificate_Handler_InvalidBody(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeCertificate_Handler_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-prod-001/revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestRevokeCertificate_Handler_EmptyID(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates//revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeCertificate_Handler_CannotRevokeArchived(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			return fmt.Errorf("cannot revoke archived certificate")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-archived/revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeCertificate_Handler_ServerError(t *testing.T) {
	mock := &MockCertificateService{
		RevokeCertificateFn: func(certID string, reason string) error {
			return fmt.Errorf("database connection lost")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/revoke", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// === CRL Handler Tests ===

func TestGetCRL_Success(t *testing.T) {
	mock := &MockCertificateService{
		GetRevokedCertificatesFn: func() ([]*domain.CertificateRevocation, error) {
			return []*domain.CertificateRevocation{
				{
					ID:            "rev-1",
					CertificateID: "cert-1",
					SerialNumber:  "ABC123",
					Reason:        "keyCompromise",
					RevokedAt:     time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
				},
				{
					ID:            "rev-2",
					CertificateID: "cert-2",
					SerialNumber:  "DEF456",
					Reason:        "superseded",
					RevokedAt:     time.Date(2026, 3, 21, 14, 30, 0, 0, time.UTC),
				},
			}, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCRL(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["version"] != float64(1) {
		t.Errorf("expected version 1, got %v", resp["version"])
	}
	if resp["total"] != float64(2) {
		t.Errorf("expected total 2, got %v", resp["total"])
	}

	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatal("expected entries to be an array")
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	entry1 := entries[0].(map[string]interface{})
	if entry1["serial_number"] != "ABC123" {
		t.Errorf("expected serial ABC123, got %v", entry1["serial_number"])
	}
	if entry1["revocation_reason"] != "keyCompromise" {
		t.Errorf("expected reason keyCompromise, got %v", entry1["revocation_reason"])
	}
}

func TestGetCRL_Empty(t *testing.T) {
	mock := &MockCertificateService{
		GetRevokedCertificatesFn: func() ([]*domain.CertificateRevocation, error) {
			return nil, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCRL(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["total"] != float64(0) {
		t.Errorf("expected total 0, got %v", resp["total"])
	}
}

func TestGetCRL_ServiceError(t *testing.T) {
	mock := &MockCertificateService{
		GetRevokedCertificatesFn: func() ([]*domain.CertificateRevocation, error) {
			return nil, fmt.Errorf("revocation repository not configured")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCRL(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestGetCRL_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/crl", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCRL(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// M15b: DER CRL and OCSP Handler Tests

func TestGetDERCRL_Success(t *testing.T) {
	derCRLData := []byte{0x30, 0x82, 0x01, 0x00} // Mock DER CRL bytes
	mock := &MockCertificateService{
		GenerateDERCRLFn: func(issuerID string) ([]byte, error) {
			if issuerID == "iss-local" {
				return derCRLData, nil
			}
			return nil, fmt.Errorf("issuer not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl/iss-local", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDERCRL(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify response is DER data
	responseBody := w.Body.Bytes()
	if len(responseBody) == 0 {
		t.Error("expected non-empty response body")
	}
}

func TestGetDERCRL_IssuerNotFound(t *testing.T) {
	mock := &MockCertificateService{
		GenerateDERCRLFn: func(issuerID string) ([]byte, error) {
			return nil, fmt.Errorf("issuer not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDERCRL(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetDERCRL_NotSupported(t *testing.T) {
	mock := &MockCertificateService{
		GenerateDERCRLFn: func(issuerID string) ([]byte, error) {
			return nil, fmt.Errorf("issuer does not support CRL generation")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/crl/iss-acme", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDERCRL(w, req)

	// Service should return an error; handler routes to appropriate status
	if w.Code == http.StatusOK {
		t.Errorf("expected error status, got %d", w.Code)
	}
}

func TestGetDERCRL_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/crl/iss-local", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetDERCRL(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleOCSP_Success(t *testing.T) {
	ocspResponseBytes := []byte{0x30, 0x82, 0x02, 0x00} // Mock OCSP response
	mock := &MockCertificateService{
		GetOCSPResponseFn: func(issuerID string, serialHex string) ([]byte, error) {
			if issuerID == "iss-local" && serialHex == "12345" {
				return ocspResponseBytes, nil
			}
			return nil, fmt.Errorf("certificate not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/iss-local/12345", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.HandleOCSP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	responseBody := w.Body.Bytes()
	if len(responseBody) == 0 {
		t.Error("expected non-empty OCSP response body")
	}
}

func TestHandleOCSP_MissingSerial(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/iss-local/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.HandleOCSP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleOCSP_IssuerNotFound(t *testing.T) {
	mock := &MockCertificateService{
		GetOCSPResponseFn: func(issuerID string, serialHex string) ([]byte, error) {
			return nil, fmt.Errorf("issuer not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/nonexistent/ABC123", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.HandleOCSP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHandleOCSP_CertNotFound(t *testing.T) {
	mock := &MockCertificateService{
		GetOCSPResponseFn: func(issuerID string, serialHex string) ([]byte, error) {
			return nil, fmt.Errorf("certificate not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/iss-local/UNKNOWN", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.HandleOCSP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHandleOCSP_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ocsp/iss-local/12345", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.HandleOCSP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// === M20 Enhanced Query API Tests ===

// TestListCertificates_SortParam tests sort parameter parsing and passing to service.
func TestListCertificates_SortParam(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			// Handler strips the '-' prefix and sets SortDesc = true
			if filter.Sort != "notAfter" || !filter.SortDesc {
				t.Errorf("expected sort=notAfter desc=true, got sort=%s desc=%v", filter.Sort, filter.SortDesc)
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?sort=-notAfter", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_SortParam_Ascending tests sort parameter without '-' prefix (ascending).
func TestListCertificates_SortParam_Ascending(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.Sort != "createdAt" || filter.SortDesc {
				t.Errorf("expected sort=createdAt desc=false, got sort=%s desc=%v", filter.Sort, filter.SortDesc)
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}
	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?sort=createdAt", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_TimeRangeFilters tests time-range filter parsing.
func TestListCertificates_TimeRangeFilters(t *testing.T) {
	before := time.Now().AddDate(0, 0, 90)
	after := time.Now().AddDate(0, 0, -90)

	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.ExpiresBefore == nil {
				t.Error("expected ExpiresBefore to be set")
			}
			if filter.ExpiresAfter == nil {
				t.Error("expected ExpiresAfter to be set")
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	url := fmt.Sprintf("/api/v1/certificates?expires_before=%s&expires_after=%s",
		before.Format(time.RFC3339), after.Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_CreatedAfterFilter tests created_after filter parsing.
func TestListCertificates_CreatedAfterFilter(t *testing.T) {
	past := time.Now().AddDate(-1, 0, 0)

	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.CreatedAfter == nil {
				t.Error("expected CreatedAfter to be set")
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	url := fmt.Sprintf("/api/v1/certificates?created_after=%s", past.Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_CursorPagination tests cursor-based pagination response.
func TestListCertificates_CursorPagination(t *testing.T) {
	cert := domain.ManagedCertificate{
		ID:        "mc-cursor-test-1",
		CommonName: "cursor.example.com",
		CreatedAt: time.Now(),
	}

	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			return []domain.ManagedCertificate{cert}, 1, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?cursor=abc123&page_size=10", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp CursorPagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.NextCursor == "" {
		t.Error("expected NextCursor to be populated with cursor pagination")
	}
	if resp.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", resp.PageSize)
	}
}

// TestListCertificates_SparseFields tests field filtering in response.
func TestListCertificates_SparseFields(t *testing.T) {
	cert := domain.ManagedCertificate{
		ID:          "mc-sparse-test-1",
		Name:        "Sparse Test Cert",
		CommonName:  "sparse.example.com",
		Environment: "staging",
		Status:      domain.CertificateStatusActive,
	}

	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if len(filter.Fields) != 2 {
				t.Errorf("expected 2 fields, got %d", len(filter.Fields))
			}
			return []domain.ManagedCertificate{cert}, 1, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?fields=id,common_name", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Response data should have sparse fields applied
	data, ok := resp.Data.([]interface{})
	if !ok || len(data) == 0 {
		t.Fatal("expected data array in response")
	}

	certMap, ok := data[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected cert object in response")
	}

	// Check that requested fields are present
	if _, ok := certMap["id"]; !ok {
		t.Error("expected 'id' field in filtered response")
	}
	if _, ok := certMap["common_name"]; !ok {
		t.Error("expected 'common_name' field in filtered response")
	}
}

// TestListCertificates_ProfileFilter tests profile_id filter.
func TestListCertificates_ProfileFilter(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.ProfileID != "prof-standard" {
				t.Errorf("expected ProfileID=prof-standard, got %s", filter.ProfileID)
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?profile_id=prof-standard", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_AgentIDFilter tests agent_id filter.
func TestListCertificates_AgentIDFilter(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.AgentID != "agent-prod-001" {
				t.Errorf("expected AgentID=agent-prod-001, got %s", filter.AgentID)
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?agent_id=agent-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestListCertificates_CombinedFilters tests multiple filters together.
func TestListCertificates_CombinedFilters(t *testing.T) {
	mock := &MockCertificateService{
		ListCertificatesWithFilterFn: func(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
			if filter.Status != "Active" || filter.Environment != "production" || filter.ProfileID != "prof-standard" {
				t.Error("expected all filters to be set")
			}
			return []domain.ManagedCertificate{}, 0, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?status=Active&environment=production&profile_id=prof-standard", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListCertificates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestGetCertificateDeployments_Success tests retrieving deployments for a certificate.
func TestGetCertificateDeployments_Success(t *testing.T) {
	deployments := []domain.DeploymentTarget{
		{
			ID:     "t-nginx-prod-1",
			Name:   "NGINX Production",
			Type:   "NGINX",
			Config: json.RawMessage(`{"cert_path": "/etc/nginx/ssl/cert.pem"}`),
		},
		{
			ID:     "t-haproxy-prod-1",
			Name:   "HAProxy Production",
			Type:   "HAProxy",
			Config: json.RawMessage(`{"pem_path": "/etc/haproxy/ssl/cert.pem"}`),
		},
	}

	mock := &MockCertificateService{
		GetCertificateDeploymentsFn: func(certID string) ([]domain.DeploymentTarget, error) {
			if certID != "mc-prod-001" {
				return nil, ErrMockNotFound
			}
			return deployments, nil
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-prod-001/deployments", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateDeployments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if data, ok := resp["data"].([]interface{}); !ok || len(data) != 2 {
		t.Errorf("expected 2 deployments in response")
	}

	if total, ok := resp["total"].(float64); !ok || int(total) != 2 {
		t.Errorf("expected total=2, got %v", resp["total"])
	}
}

// TestGetCertificateDeployments_NotFound tests 404 for nonexistent certificate.
func TestGetCertificateDeployments_NotFound(t *testing.T) {
	mock := &MockCertificateService{
		GetCertificateDeploymentsFn: func(certID string) ([]domain.DeploymentTarget, error) {
			return nil, fmt.Errorf("certificate not found")
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-nonexistent/deployments", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateDeployments(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestGetCertificateDeployments_Empty tests successful response with no deployments.
func TestGetCertificateDeployments_Empty(t *testing.T) {
	mock := &MockCertificateService{
		GetCertificateDeploymentsFn: func(certID string) ([]domain.DeploymentTarget, error) {
			if certID == "mc-no-deployments" {
				return []domain.DeploymentTarget{}, nil
			}
			return nil, ErrMockNotFound
		},
	}

	handler := NewCertificateHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-no-deployments/deployments", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateDeployments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if total, ok := resp["total"].(float64); !ok || int(total) != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
}

// TestGetCertificateDeployments_MethodNotAllowed tests 405 for non-GET requests.
func TestGetCertificateDeployments_MethodNotAllowed(t *testing.T) {
	mock := &MockCertificateService{}
	handler := NewCertificateHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-prod-001/deployments", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetCertificateDeployments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
