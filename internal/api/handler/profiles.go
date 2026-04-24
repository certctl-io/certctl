package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// ProfileService defines the service interface for certificate profile operations.
type ProfileService interface {
	ListProfiles(ctx context.Context, page, perPage int) ([]domain.CertificateProfile, int64, error)
	GetProfile(ctx context.Context, id string) (*domain.CertificateProfile, error)
	CreateProfile(ctx context.Context, profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	UpdateProfile(ctx context.Context, id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error)
	DeleteProfile(ctx context.Context, id string) error
}

// ProfileHandler handles HTTP requests for certificate profile operations.
//
// Error dispatch (post-M-1): every service error routes through the [errToStatus]
// choke point via `errors.Is` walking the wrap chain, with one explicit
// [service.ErrValidation] arm on the write paths (Create, Update) so the
// composed "validation: <field-specific reason>" message the service layer
// attaches via `fmt.Errorf("%w: ...", ErrValidation)` can be passed through to
// the 400 response body. Before M-1, the Create and Update handlers branched on
// `strings.Contains(err.Error(), "invalid"|"required"|"must be"|"cannot")` — a
// fragile pattern where a single reword in [service.validateProfile] would
// demote the 400 to 500 with no compile-time signal. The substring-based 404
// branches on Update and Delete likewise depended on the repository's
// human-readable "profile not found" message surviving forever; both now ride
// the same [repository.ErrNotFound] wrap that G-1's renewal-policy and M-1's
// other repositories use.
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

	profiles, total, err := h.svc.ListProfiles(r.Context(), page, perPage)
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

	profile, err := h.svc.GetProfile(r.Context(), id)
	if err != nil {
		// M-1: route through errToStatus so a repo-level `sql.ErrNoRows`
		// (wrapped as repository.ErrNotFound) becomes 404, but a transient DB
		// failure no longer masquerades as 404 — it correctly surfaces 500. The
		// pre-M-1 "any error → 404" shortcut was plausible when Get's only
		// expected failure was "not found", but the choke point now gives us
		// correct dispatch for free. Mirrors GetRenewalPolicy.
		status := errToStatus(err)
		msg := "Failed to get profile"
		if status == http.StatusNotFound {
			msg = "Profile not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
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

	created, err := h.svc.CreateProfile(r.Context(), profile)
	if err != nil {
		// M-1: replace the 4-term substring net
		// (`"invalid"|"required"|"must be"|"cannot"`) with a single
		// `errors.Is(err, service.ErrValidation)` arm. validateProfile wraps
		// every field-specific failure via `fmt.Errorf("%w: <reason>",
		// ErrValidation)`, so `err.Error()` still contains the human-readable
		// reason (e.g., "RSA minimum key size must be at least 2048") and can be
		// safely passed to the 400 body — but the status decision no longer
		// depends on the exact wording. Other errors redact to a generic 500.
		if errors.Is(err, service.ErrValidation) {
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

	updated, err := h.svc.UpdateProfile(r.Context(), id, profile)
	if err != nil {
		// M-1: explicit ErrValidation arm preserves the user-facing reason in
		// the 400 body (validateProfile wraps every failure via
		// `fmt.Errorf("%w: ...", ErrValidation)`); every other error — including
		// repo-layer ErrNotFound on a missing row — routes through errToStatus
		// so the 404/500 decision no longer depends on substring matching.
		if errors.Is(err, service.ErrValidation) {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		status := errToStatus(err)
		msg := "Failed to update profile"
		if status == http.StatusNotFound {
			msg = "Profile not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
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

	if err := h.svc.DeleteProfile(r.Context(), id); err != nil {
		// M-1: sentinel dispatch replaces the substring 404 check — see the
		// parallel comment block in UpdateProfile for the rationale.
		status := errToStatus(err)
		msg := "Failed to delete profile"
		if status == http.StatusNotFound {
			msg = "Profile not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
