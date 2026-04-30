package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shankar0123/certctl/internal/repository"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// AgentGroupService defines the service interface for agent group operations.
type AgentGroupService interface {
	ListAgentGroups(ctx context.Context, page, perPage int) ([]domain.AgentGroup, int64, error)
	GetAgentGroup(ctx context.Context, id string) (*domain.AgentGroup, error)
	CreateAgentGroup(ctx context.Context, group domain.AgentGroup) (*domain.AgentGroup, error)
	UpdateAgentGroup(ctx context.Context, id string, group domain.AgentGroup) (*domain.AgentGroup, error)
	DeleteAgentGroup(ctx context.Context, id string) error
	ListMembers(ctx context.Context, id string) ([]domain.Agent, int64, error)
}

// AgentGroupHandler handles HTTP requests for agent group operations.
type AgentGroupHandler struct {
	svc AgentGroupService
}

// NewAgentGroupHandler creates a new AgentGroupHandler with a service dependency.
func NewAgentGroupHandler(svc AgentGroupService) AgentGroupHandler {
	return AgentGroupHandler{svc: svc}
}

// ListAgentGroups lists all agent groups.
// GET /api/v1/agent-groups?page=1&per_page=50
func (h AgentGroupHandler) ListAgentGroups(w http.ResponseWriter, r *http.Request) {
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

	groups, total, err := h.svc.ListAgentGroups(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list agent groups", requestID)
		return
	}

	response := PagedResponse{
		Data:    groups,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetAgentGroup retrieves a single agent group by ID.
// GET /api/v1/agent-groups/{id}
func (h AgentGroupHandler) GetAgentGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-groups/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent group ID is required", requestID)
		return
	}

	group, err := h.svc.GetAgentGroup(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Agent group not found", requestID)
		return
	}

	JSON(w, http.StatusOK, group)
}

// CreateAgentGroup creates a new agent group.
// POST /api/v1/agent-groups
func (h AgentGroupHandler) CreateAgentGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var group domain.AgentGroup
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	if err := ValidateRequired("name", group.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", group.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateAgentGroup(r.Context(), group)
	if err != nil {
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create agent group", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateAgentGroup updates an existing agent group.
// PUT /api/v1/agent-groups/{id}
func (h AgentGroupHandler) UpdateAgentGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-groups/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent group ID is required", requestID)
		return
	}
	id = parts[0]

	var group domain.AgentGroup
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateAgentGroup(r.Context(), id, group)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Agent group not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update agent group", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteAgentGroup deletes an agent group.
// DELETE /api/v1/agent-groups/{id}
func (h AgentGroupHandler) DeleteAgentGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-groups/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent group ID is required", requestID)
		return
	}

	if err := h.svc.DeleteAgentGroup(r.Context(), id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Agent group not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete agent group", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListAgentGroupMembers lists agents in a group.
// GET /api/v1/agent-groups/{id}/members
func (h AgentGroupHandler) ListAgentGroupMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse ID from: /api/v1/agent-groups/{id}/members
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-groups/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent group ID is required", requestID)
		return
	}
	id := parts[0]

	members, total, err := h.svc.ListMembers(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list group members", requestID)
		return
	}

	response := PagedResponse{
		Data:    members,
		Total:   total,
		Page:    1,
		PerPage: int(total),
	}

	JSON(w, http.StatusOK, response)
}
