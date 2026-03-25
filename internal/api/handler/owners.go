package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// OwnerService defines the service interface for owner operations.
type OwnerService interface {
	ListOwners(page, perPage int) ([]domain.Owner, int64, error)
	GetOwner(id string) (*domain.Owner, error)
	CreateOwner(owner domain.Owner) (*domain.Owner, error)
	UpdateOwner(id string, owner domain.Owner) (*domain.Owner, error)
	DeleteOwner(id string) error
}

// OwnerHandler handles HTTP requests for owner operations.
type OwnerHandler struct {
	svc OwnerService
}

// NewOwnerHandler creates a new OwnerHandler with a service dependency.
func NewOwnerHandler(svc OwnerService) OwnerHandler {
	return OwnerHandler{svc: svc}
}

// ListOwners lists all owners.
// GET /api/v1/owners?page=1&per_page=50
func (h OwnerHandler) ListOwners(w http.ResponseWriter, r *http.Request) {
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

	owners, total, err := h.svc.ListOwners(page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list owners", requestID)
		return
	}

	response := PagedResponse{
		Data:    owners,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetOwner retrieves a single owner by ID.
// GET /api/v1/owners/{id}
func (h OwnerHandler) GetOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/owners/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Owner ID is required", requestID)
		return
	}
	id = parts[0]

	owner, err := h.svc.GetOwner(id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Owner not found", requestID)
		return
	}

	JSON(w, http.StatusOK, owner)
}

// CreateOwner creates a new owner.
// POST /api/v1/owners
func (h OwnerHandler) CreateOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var owner domain.Owner
	if err := json.NewDecoder(r.Body).Decode(&owner); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", owner.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", owner.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateOwner(owner)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create owner", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateOwner updates an existing owner.
// PUT /api/v1/owners/{id}
func (h OwnerHandler) UpdateOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/owners/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Owner ID is required", requestID)
		return
	}
	id = parts[0]

	var owner domain.Owner
	if err := json.NewDecoder(r.Body).Decode(&owner); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateOwner(id, owner)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update owner", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteOwner deletes an owner.
// DELETE /api/v1/owners/{id}
func (h OwnerHandler) DeleteOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/owners/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Owner ID is required", requestID)
		return
	}
	id = parts[0]

	if err := h.svc.DeleteOwner(id); err != nil {
		if strings.Contains(err.Error(), "violates foreign key") || strings.Contains(err.Error(), "RESTRICT") {
			ErrorWithRequestID(w, http.StatusConflict, "Cannot delete owner: certificates are still assigned to this owner", requestID)
		} else if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Owner not found", requestID)
		} else {
			ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete owner", requestID)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
