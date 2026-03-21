package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// ProfileService defines the service interface for certificate profile operations.
type ProfileService interface {
	ListProfiles(page, perPage int) ([]domain.CertificateProfile, int64, error)
	GetProfile(id string) (*domain.CertificateProfile, error)
	CreateProfile(profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	UpdateProfile(id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	DeleteProfile(id string) error
}

// ProfileHandler handles HTTP requests for certificate profile operations.
type ProfileHandler struct {
	svc ProfileService
}

// NewProfileHandler creates a new ProfileHandler with a service dependency.
func NewProfileHandler(svc ProfileService) ProfileHandler {
	return ProfileHandler{svc: svc}
}

// ListProfiles lists all certificate profiles.
// GET /api/v1/profiles?page=1&per_page=50
func (h ProfileHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	page := 1
	perPage := 50
	query := r.URL.Query()
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 && parsed <= 500 {
			perPage = parsed
		}
	}

	profiles, total, err := h.svc.ListProfiles(page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list profiles", requestID)
		return
	}

	response := PagedResponse{
		Data:    profiles,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetProfile retrieves a single certificate profile by ID.
// GET /api/v1/profiles/{id}
func (h ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/profiles/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Profile ID is required", requestID)
		return
	}

	profile, err := h.svc.GetProfile(id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Profile not found", requestID)
		return
	}

	JSON(w, http.StatusOK, profile)
}

// CreateProfile creates a new certificate profile.
// POST /api/v1/profiles
func (h ProfileHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var profile domain.CertificateProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", profile.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", profile.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateProfile(profile)
	if err != nil {
		// Check if it's a validation error from the service
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "cannot") {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create profile", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateProfile updates an existing certificate profile.
// PUT /api/v1/profiles/{id}
func (h ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/profiles/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Profile ID is required", requestID)
		return
	}
	id = parts[0]

	var profile domain.CertificateProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateProfile(id, profile)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Profile not found", requestID)
			return
		}
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "cannot") {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update profile", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteProfile deletes a certificate profile.
// DELETE /api/v1/profiles/{id}
func (h ProfileHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/profiles/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Profile ID is required", requestID)
		return
	}

	if err := h.svc.DeleteProfile(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Profile not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete profile", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
