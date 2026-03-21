package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// MockProfileService is a mock implementation of ProfileService interface.
type MockProfileService struct {
	ListProfilesFn  func(page, perPage int) ([]domain.CertificateProfile, int64, error)
	GetProfileFn    func(id string) (*domain.CertificateProfile, error)
	CreateProfileFn func(profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	UpdateProfileFn func(id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	DeleteProfileFn func(id string) error
}

func (m *MockProfileService) ListProfiles(page, perPage int) ([]domain.CertificateProfile, int64, error) {
	if m.ListProfilesFn != nil {
		return m.ListProfilesFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockProfileService) GetProfile(id string) (*domain.CertificateProfile, error) {
	if m.GetProfileFn != nil {
		return m.GetProfileFn(id)
	}
	return nil, nil
}

func (m *MockProfileService) CreateProfile(profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	if m.CreateProfileFn != nil {
		return m.CreateProfileFn(profile)
	}
	return nil, nil
}

func (m *MockProfileService) UpdateProfile(id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	if m.UpdateProfileFn != nil {
		return m.UpdateProfileFn(id, profile)
	}
	return nil, nil
}

func (m *MockProfileService) DeleteProfile(id string) error {
	if m.DeleteProfileFn != nil {
		return m.DeleteProfileFn(id)
	}
	return nil
}

func TestListProfiles_Success(t *testing.T) {
	now := time.Now()
	prof1 := domain.CertificateProfile{
		ID:   "prof-standard-tls",
		Name: "Standard TLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
			{Algorithm: "RSA", MinSize: 2048},
		},
		MaxTTLSeconds: 7776000,
		AllowedEKUs:   []string{"serverAuth"},
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	prof2 := domain.CertificateProfile{
		ID:   "prof-internal-mtls",
		Name: "Internal mTLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
		},
		MaxTTLSeconds: 2592000,
		AllowedEKUs:   []string{"serverAuth", "clientAuth"},
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	mock := &MockProfileService{
		ListProfilesFn: func(page, perPage int) ([]domain.CertificateProfile, int64, error) {
			return []domain.CertificateProfile{prof1, prof2}, 2, nil
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

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

func TestListProfiles_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockProfileService{
		ListProfilesFn: func(page, perPage int) ([]domain.CertificateProfile, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.CertificateProfile{}, 0, nil
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles?page=3&per_page=25", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	if capturedPage != 3 {
		t.Errorf("expected page 3, got %d", capturedPage)
	}
	if capturedPerPage != 25 {
		t.Errorf("expected per_page 25, got %d", capturedPerPage)
	}
}

func TestListProfiles_ServiceError(t *testing.T) {
	mock := &MockProfileService{
		ListProfilesFn: func(page, perPage int) ([]domain.CertificateProfile, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListProfiles_MethodNotAllowed(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/profiles", nil)
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetProfile_Success(t *testing.T) {
	now := time.Now()
	mock := &MockProfileService{
		GetProfileFn: func(id string) (*domain.CertificateProfile, error) {
			return &domain.CertificateProfile{
				ID:            id,
				Name:          "Standard TLS",
				MaxTTLSeconds: 7776000,
				Enabled:       true,
				CreatedAt:     now,
				UpdatedAt:     now,
			}, nil
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles/prof-standard-tls", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	mock := &MockProfileService{
		GetProfileFn: func(id string) (*domain.CertificateProfile, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestGetProfile_EmptyID(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateProfile_Success(t *testing.T) {
	now := time.Now()
	mock := &MockProfileService{
		CreateProfileFn: func(profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
			profile.ID = "prof-new"
			profile.CreatedAt = now
			profile.UpdatedAt = now
			return &profile, nil
		},
	}

	body := map[string]interface{}{
		"name":          "New Profile",
		"max_ttl_seconds": 86400,
		"allowed_ekus":  []string{"serverAuth"},
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestCreateProfile_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"max_ttl_seconds": 86400,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateProfile_NameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 256; i++ {
		longName += "x"
	}
	body := map[string]interface{}{
		"name": longName,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateProfile_InvalidJSON(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", bytes.NewReader([]byte("{invalid")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateProfile_MethodNotAllowed(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	now := time.Now()
	mock := &MockProfileService{
		UpdateProfileFn: func(id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
			profile.ID = id
			profile.UpdatedAt = now
			return &profile, nil
		},
	}

	body := map[string]interface{}{
		"name":          "Updated Profile",
		"max_ttl_seconds": 172800,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/profiles/prof-standard-tls", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateProfile_InvalidJSON(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/profiles/prof-x", bytes.NewReader([]byte("{bad")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestDeleteProfile_Success(t *testing.T) {
	var deletedID string
	mock := &MockProfileService{
		DeleteProfileFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/profiles/prof-standard-tls", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "prof-standard-tls" {
		t.Errorf("expected deleted ID 'prof-standard-tls', got '%s'", deletedID)
	}
}

func TestDeleteProfile_ServiceError(t *testing.T) {
	mock := &MockProfileService{
		DeleteProfileFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewProfileHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/profiles/prof-x", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestDeleteProfile_EmptyID(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/profiles/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestDeleteProfile_MethodNotAllowed(t *testing.T) {
	handler := NewProfileHandler(&MockProfileService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles/prof-x", nil)
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}
