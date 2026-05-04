package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// MockIssuerService is a mock implementation of IssuerService interface.
type MockIssuerService struct {
	ListIssuersFn    func(ctx context.Context, page, perPage int) ([]domain.Issuer, int64, error)
	GetIssuerFn      func(ctx context.Context, id string) (*domain.Issuer, error)
	CreateIssuerFn   func(ctx context.Context, issuer domain.Issuer) (*domain.Issuer, error)
	UpdateIssuerFn   func(ctx context.Context, id string, issuer domain.Issuer) (*domain.Issuer, error)
	DeleteIssuerFn   func(ctx context.Context, id string) error
	TestConnectionFn func(ctx context.Context, id string) error
}

func (m *MockIssuerService) ListIssuers(ctx context.Context, page, perPage int) ([]domain.Issuer, int64, error) {
	if m.ListIssuersFn != nil {
		return m.ListIssuersFn(ctx, page, perPage)
	}
	return nil, 0, nil
}

func (m *MockIssuerService) GetIssuer(ctx context.Context, id string) (*domain.Issuer, error) {
	if m.GetIssuerFn != nil {
		return m.GetIssuerFn(ctx, id)
	}
	return nil, nil
}

func (m *MockIssuerService) CreateIssuer(ctx context.Context, issuer domain.Issuer) (*domain.Issuer, error) {
	if m.CreateIssuerFn != nil {
		return m.CreateIssuerFn(ctx, issuer)
	}
	return nil, nil
}

func (m *MockIssuerService) UpdateIssuer(ctx context.Context, id string, issuer domain.Issuer) (*domain.Issuer, error) {
	if m.UpdateIssuerFn != nil {
		return m.UpdateIssuerFn(ctx, id, issuer)
	}
	return nil, nil
}

func (m *MockIssuerService) DeleteIssuer(ctx context.Context, id string) error {
	if m.DeleteIssuerFn != nil {
		return m.DeleteIssuerFn(ctx, id)
	}
	return nil
}

func (m *MockIssuerService) TestConnection(ctx context.Context, id string) error {
	if m.TestConnectionFn != nil {
		return m.TestConnectionFn(ctx, id)
	}
	return nil
}

func TestListIssuers_Success(t *testing.T) {
	now := time.Now()
	iss1 := domain.Issuer{
		ID:        "iss-local",
		Name:      "Local CA",
		Type:      "LocalCA",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	iss2 := domain.Issuer{
		ID:        "iss-acme",
		Name:      "ACME Staging",
		Type:      "ACME",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock := &MockIssuerService{
		ListIssuersFn: func(_ context.Context, page, perPage int) ([]domain.Issuer, int64, error) {
			return []domain.Issuer{iss1, iss2}, 2, nil
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListIssuers(w, req)

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

func TestListIssuers_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockIssuerService{
		ListIssuersFn: func(_ context.Context, page, perPage int) ([]domain.Issuer, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.Issuer{}, 0, nil
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers?page=2&per_page=10", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListIssuers(w, req)

	if capturedPage != 2 {
		t.Errorf("expected page 2, got %d", capturedPage)
	}
	if capturedPerPage != 10 {
		t.Errorf("expected per_page 10, got %d", capturedPerPage)
	}
}

func TestListIssuers_ServiceError(t *testing.T) {
	mock := &MockIssuerService{
		ListIssuersFn: func(_ context.Context, page, perPage int) ([]domain.Issuer, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListIssuers(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListIssuers_MethodNotAllowed(t *testing.T) {
	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/issuers", nil)
	w := httptest.NewRecorder()

	handler.ListIssuers(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetIssuer_Success(t *testing.T) {
	now := time.Now()
	mock := &MockIssuerService{
		GetIssuerFn: func(_ context.Context, id string) (*domain.Issuer, error) {
			return &domain.Issuer{
				ID:        id,
				Name:      "Local CA",
				Type:      "LocalCA",
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers/iss-local", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetIssuer(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetIssuer_NotFound(t *testing.T) {
	mock := &MockIssuerService{
		GetIssuerFn: func(_ context.Context, id string) (*domain.Issuer, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetIssuer(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestGetIssuer_EmptyID(t *testing.T) {
	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/issuers/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateIssuer_Success(t *testing.T) {
	now := time.Now()
	mock := &MockIssuerService{
		CreateIssuerFn: func(_ context.Context, issuer domain.Issuer) (*domain.Issuer, error) {
			issuer.ID = "iss-new"
			issuer.CreatedAt = now
			issuer.UpdatedAt = now
			return &issuer, nil
		},
	}

	body := map[string]interface{}{
		"name": "New Issuer",
		"type": "LocalCA",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}
}

func TestCreateIssuer_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"type": "LocalCA",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateIssuer_MissingType(t *testing.T) {
	body := map[string]interface{}{
		"name": "New Issuer",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateIssuer_InvalidJSON(t *testing.T) {
	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader([]byte("{invalid")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateIssuer_NameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 256; i++ {
		longName += "x"
	}
	body := map[string]interface{}{
		"name": longName,
		"type": "LocalCA",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateIssuer_DuplicateName(t *testing.T) {
	mock := &MockIssuerService{
		CreateIssuerFn: func(_ context.Context, issuer domain.Issuer) (*domain.Issuer, error) {
			return nil, fmt.Errorf("failed to create issuer: duplicate key value violates unique constraint \"issuers_name_key\"")
		},
	}

	body := map[string]interface{}{
		"name": "ACME Issuer",
		"type": "ACME",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !strings.Contains(resp.Message, "already exists") {
		t.Errorf("expected message to contain 'already exists', got %q", resp.Message)
	}
}

func TestCreateIssuer_UnsupportedType(t *testing.T) {
	mock := &MockIssuerService{
		CreateIssuerFn: func(_ context.Context, issuer domain.Issuer) (*domain.Issuer, error) {
			return nil, fmt.Errorf("unsupported issuer type: FakeCA")
		},
	}

	body := map[string]interface{}{
		"name": "Fake Issuer",
		"type": "FakeCA",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !strings.Contains(resp.Message, "unsupported issuer type") {
		t.Errorf("expected message to contain 'unsupported issuer type', got %q", resp.Message)
	}
}

func TestCreateIssuer_GenericServiceError(t *testing.T) {
	mock := &MockIssuerService{
		CreateIssuerFn: func(_ context.Context, issuer domain.Issuer) (*domain.Issuer, error) {
			return nil, fmt.Errorf("failed to encrypt config: cipher error")
		},
	}

	body := map[string]interface{}{
		"name": "Some Issuer",
		"type": "ACME",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateIssuer(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestUpdateIssuer_DuplicateName(t *testing.T) {
	mock := &MockIssuerService{
		UpdateIssuerFn: func(_ context.Context, id string, issuer domain.Issuer) (*domain.Issuer, error) {
			return nil, fmt.Errorf("failed to update issuer: duplicate key value violates unique constraint")
		},
	}

	body := map[string]interface{}{
		"name": "Existing Name",
		"type": "ACME",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/issuers/iss-test", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateIssuer(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}
}

func TestDeleteIssuer_Success(t *testing.T) {
	var deletedID string
	mock := &MockIssuerService{
		DeleteIssuerFn: func(_ context.Context, id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/issuers/iss-local", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteIssuer(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "iss-local" {
		t.Errorf("expected deleted ID 'iss-local', got '%s'", deletedID)
	}
}

func TestDeleteIssuer_ServiceError(t *testing.T) {
	mock := &MockIssuerService{
		DeleteIssuerFn: func(_ context.Context, id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/issuers/iss-local", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteIssuer(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestTestConnection_Success(t *testing.T) {
	mock := &MockIssuerService{
		TestConnectionFn: func(_ context.Context, id string) error {
			return nil
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-local/test", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TestConnection(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "connection_successful" {
		t.Errorf("expected status 'connection_successful', got '%s'", resp["status"])
	}
}

func TestTestConnection_Failure(t *testing.T) {
	mock := &MockIssuerService{
		TestConnectionFn: func(_ context.Context, id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewIssuerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-local/test", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TestConnection(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestTestConnection_EmptyID(t *testing.T) {
	handler := NewIssuerHandler(&MockIssuerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers//test", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TestConnection(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
