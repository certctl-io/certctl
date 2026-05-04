package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/certctl-io/certctl/internal/api/middleware"
)

// StatsService defines the service interface for statistics operations.
type StatsService interface {
	GetDashboardSummary(ctx context.Context) (interface{}, error)
	GetCertificatesByStatus(ctx context.Context) (interface{}, error)
	GetExpirationTimeline(ctx context.Context, days int) (interface{}, error)
	GetJobStats(ctx context.Context, days int) (interface{}, error)
	GetIssuanceRate(ctx context.Context, days int) (interface{}, error)
}

// StatsHandler handles HTTP requests for statistics and observability endpoints.
type StatsHandler struct {
	svc StatsService
}

// NewStatsHandler creates a new StatsHandler with a service dependency.
func NewStatsHandler(svc StatsService) StatsHandler {
	return StatsHandler{svc: svc}
}

// GetDashboardSummary returns a high-level summary of system state.
// GET /api/v1/stats/summary
func (h StatsHandler) GetDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	summary, err := h.svc.GetDashboardSummary(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get dashboard summary", requestID)
		return
	}

	JSON(w, http.StatusOK, summary)
}

// GetCertificatesByStatus returns certificate counts grouped by status.
// GET /api/v1/stats/certificates-by-status
func (h StatsHandler) GetCertificatesByStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	counts, err := h.svc.GetCertificatesByStatus(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get certificate status counts", requestID)
		return
	}

	JSON(w, http.StatusOK, counts)
}

// GetExpirationTimeline returns certificates expiring over the next N days.
// GET /api/v1/stats/expiration-timeline?days=30
func (h StatsHandler) GetExpirationTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse query parameter
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	timeline, err := h.svc.GetExpirationTimeline(r.Context(), days)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get expiration timeline", requestID)
		return
	}

	JSON(w, http.StatusOK, timeline)
}

// GetJobTrends returns job success/failure trends over the past N days.
// GET /api/v1/stats/job-trends?days=30
func (h StatsHandler) GetJobTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse query parameter
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	trends, err := h.svc.GetJobStats(r.Context(), days)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get job trends", requestID)
		return
	}

	JSON(w, http.StatusOK, trends)
}

// GetIssuanceRate returns the rate of new certificate issuance over the past N days.
// GET /api/v1/stats/issuance-rate?days=30
func (h StatsHandler) GetIssuanceRate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse query parameter
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	issuanceRate, err := h.svc.GetIssuanceRate(r.Context(), days)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get issuance rate", requestID)
		return
	}

	JSON(w, http.StatusOK, issuanceRate)
}
