package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/certctl-io/certctl/internal/repository"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

// JobService defines the service interface for job operations.
type JobService interface {
	ListJobs(ctx context.Context, status, jobType string, page, perPage int) ([]domain.Job, int64, error)
	GetJob(ctx context.Context, id string) (*domain.Job, error)
	CancelJob(ctx context.Context, id string) error
	// ApproveJob approves a renewal job. actor is the named-key identity
	// resolved from the auth middleware; the service returns ErrSelfApproval
	// (mapped to 403) when actor matches the certificate owner.
	ApproveJob(ctx context.Context, id, actor string) error
	// RejectJob rejects a renewal job. actor is the named-key identity
	// recorded for audit attribution; no not-self restriction.
	RejectJob(ctx context.Context, id, reason, actor string) error
}

// JobHandler handles HTTP requests for job operations.
type JobHandler struct {
	svc JobService
}

// NewJobHandler creates a new JobHandler with a service dependency.
func NewJobHandler(svc JobService) JobHandler {
	return JobHandler{svc: svc}
}

// ListJobs lists jobs with optional filtering by status and type.
// GET /api/v1/jobs?status=Pending&type=Renewal&page=1&per_page=50
func (h JobHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	query := r.URL.Query()
	status := query.Get("status")
	jobType := query.Get("type")

	page := 1
	perPage := 50
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

	jobs, total, err := h.svc.ListJobs(r.Context(), status, jobType, page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list jobs", requestID)
		return
	}

	response := PagedResponse{
		Data:    jobs,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetJob retrieves a single job by ID.
// GET /api/v1/jobs/{id}
func (h JobHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Job ID is required", requestID)
		return
	}
	id = parts[0]

	job, err := h.svc.GetJob(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Job not found", requestID)
		return
	}

	JSON(w, http.StatusOK, job)
}

// CancelJob cancels a job.
// POST /api/v1/jobs/{id}/cancel
func (h JobHandler) CancelJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract job ID from path /api/v1/jobs/{id}/cancel
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Job ID is required", requestID)
		return
	}
	jobID := parts[0]

	if err := h.svc.CancelJob(r.Context(), jobID); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to cancel job", requestID)
		return
	}

	response := map[string]string{
		"status": "job_cancelled",
	}

	JSON(w, http.StatusOK, response)
}

// ApproveJob approves a renewal job awaiting approval.
// POST /api/v1/jobs/{id}/approve
func (h JobHandler) ApproveJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Job ID is required", requestID)
		return
	}
	jobID := parts[0]

	actor := resolveActor(r.Context())

	if err := h.svc.ApproveJob(r.Context(), jobID, actor); err != nil {
		// M-003: self-approval by the certificate owner is forbidden.
		if errors.Is(err, service.ErrSelfApproval) {
			ErrorWithRequestID(w, http.StatusForbidden,
				"Self-approval is forbidden: the certificate owner cannot approve their own renewal",
				requestID)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Job not found", requestID)
			return
		}
		if strings.Contains(err.Error(), "cannot approve") {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to approve job", requestID)
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "job_approved"})
}

// RejectJob rejects a renewal job awaiting approval.
// POST /api/v1/jobs/{id}/reject
func (h JobHandler) RejectJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Job ID is required", requestID)
		return
	}
	jobID := parts[0]

	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
			return
		}
	}

	actor := resolveActor(r.Context())

	if err := h.svc.RejectJob(r.Context(), jobID, body.Reason, actor); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Job not found", requestID)
			return
		}
		if strings.Contains(err.Error(), "cannot reject") {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to reject job", requestID)
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "job_rejected"})
}
