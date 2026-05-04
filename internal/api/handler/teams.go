package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
)

// TeamService defines the service interface for team operations.
type TeamService interface {
	ListTeams(ctx context.Context, page, perPage int) ([]domain.Team, int64, error)
	GetTeam(ctx context.Context, id string) (*domain.Team, error)
	CreateTeam(ctx context.Context, team domain.Team) (*domain.Team, error)
	UpdateTeam(ctx context.Context, id string, team domain.Team) (*domain.Team, error)
	DeleteTeam(ctx context.Context, id string) error
}

// TeamHandler handles HTTP requests for team operations.
type TeamHandler struct {
	svc TeamService
}

// NewTeamHandler creates a new TeamHandler with a service dependency.
func NewTeamHandler(svc TeamService) TeamHandler {
	return TeamHandler{svc: svc}
}

// ListTeams lists all teams.
// GET /api/v1/teams?page=1&per_page=50
func (h TeamHandler) ListTeams(w http.ResponseWriter, r *http.Request) {
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

	teams, total, err := h.svc.ListTeams(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list teams", requestID)
		return
	}

	response := PagedResponse{
		Data:    teams,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetTeam retrieves a single team by ID.
// GET /api/v1/teams/{id}
func (h TeamHandler) GetTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/teams/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Team ID is required", requestID)
		return
	}
	id = parts[0]

	team, err := h.svc.GetTeam(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Team not found", requestID)
		return
	}

	JSON(w, http.StatusOK, team)
}

// CreateTeam creates a new team.
// POST /api/v1/teams
func (h TeamHandler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var team domain.Team
	if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", team.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", team.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateTeam(r.Context(), team)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create team", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateTeam updates an existing team.
// PUT /api/v1/teams/{id}
func (h TeamHandler) UpdateTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/teams/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Team ID is required", requestID)
		return
	}
	id = parts[0]

	var team domain.Team
	if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateTeam(r.Context(), id, team)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update team", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteTeam deletes a team.
// DELETE /api/v1/teams/{id}
func (h TeamHandler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/teams/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Team ID is required", requestID)
		return
	}
	id = parts[0]

	if err := h.svc.DeleteTeam(r.Context(), id); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete team", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
