package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// TargetService defines the service interface for deployment target operations.
type TargetService interface {
	ListTargets(ctx context.Context, page, perPage int) ([]domain.DeploymentTarget, int64, error)
	GetTarget(ctx context.Context, id string) (*domain.DeploymentTarget, error)
	CreateTarget(ctx context.Context, target domain.DeploymentTarget) (*domain.DeploymentTarget, error)
	UpdateTarget(ctx context.Context, id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error)
	DeleteTarget(ctx context.Context, id string) error
	TestConnection(ctx context.Context, id string) error
}

// TargetHandler handles HTTP requests for deployment target operations.
type TargetHandler struct {
	svc TargetService
}

// NewTargetHandler creates a new TargetHandler with a service dependency.
func NewTargetHandler(svc TargetService) TargetHandler {
	return TargetHandler{svc: svc}
}

// ListTargets lists all deployment targets.
// GET /api/v1/targets?page=1&per_page=50
func (h TargetHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
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

	targets, total, err := h.svc.ListTargets(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list targets", requestID)
		return
	}

	response := PagedResponse{
		Data:    targets,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetTarget retrieves a single deployment target by ID.
// GET /api/v1/targets/{id}
func (h TargetHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Target ID is required", requestID)
		return
	}

	target, err := h.svc.GetTarget(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Target not found", requestID)
		return
	}

	JSON(w, http.StatusOK, target)
}

// CreateTarget creates a new deployment target.
// POST /api/v1/targets
func (h TargetHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var target domain.DeploymentTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", target.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", target.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if target.Type == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "type is required", requestID)
		return
	}

	created, err := h.svc.CreateTarget(r.Context(), target)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create target", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateTarget updates an existing deployment target.
// PUT /api/v1/targets/{id}
func (h TargetHandler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Target ID is required", requestID)
		return
	}
	id = parts[0]

	var target domain.DeploymentTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateTarget(r.Context(), id, target)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update target", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteTarget deletes a deployment target.
// DELETE /api/v1/targets/{id}
func (h TargetHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Target ID is required", requestID)
		return
	}

	if err := h.svc.DeleteTarget(r.Context(), id); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete target", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TestTargetConnection tests target connectivity by checking the assigned agent's heartbeat.
// POST /api/v1/targets/{id}/test
func (h TargetHandler) TestTargetConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract target ID from path: /api/v1/targets/{id}/test
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Target ID is required", requestID)
		return
	}
	id := parts[0]

	if err := h.svc.TestConnection(r.Context(), id); err != nil {
		JSON(w, http.StatusOK, map[string]interface{}{
			"status":  "failed",
			"message": err.Error(),
		})
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Agent is online and reachable",
	})
}
