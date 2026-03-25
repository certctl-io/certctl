package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/shankar0123/certctl/internal/domain"
)

// DiscoveryService defines the interface used by the discovery handler.
type DiscoveryService interface {
	ProcessDiscoveryReport(ctx context.Context, report *domain.DiscoveryReport) (*domain.DiscoveryScan, error)
	ListDiscovered(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error)
	GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error)
	ClaimDiscovered(ctx context.Context, id string, managedCertID string) error
	DismissDiscovered(ctx context.Context, id string) error
	ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error)
	GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error)
	GetDiscoverySummary(ctx context.Context) (map[string]int, error)
}

// DiscoveryHandler handles HTTP requests for certificate discovery.
type DiscoveryHandler struct {
	svc DiscoveryService
}

// NewDiscoveryHandler creates a new discovery handler.
func NewDiscoveryHandler(svc DiscoveryService) DiscoveryHandler {
	return DiscoveryHandler{svc: svc}
}

// SubmitDiscoveryReport handles POST /api/v1/agents/{id}/discoveries
// Agents submit their filesystem scan results here.
func (h DiscoveryHandler) SubmitDiscoveryReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	agentID := r.PathValue("id")
	if agentID == "" {
		Error(w, http.StatusBadRequest, "agent ID is required")
		return
	}

	var report domain.DiscoveryReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Override agent ID from path (security: agents can only report for themselves)
	report.AgentID = agentID

	scan, err := h.svc.ProcessDiscoveryReport(r.Context(), &report)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to process discovery report: %v", err))
		return
	}

	JSON(w, http.StatusAccepted, scan)
}

// ListDiscovered handles GET /api/v1/discovered-certificates
func (h DiscoveryHandler) ListDiscovered(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	query := r.URL.Query()
	agentID := query.Get("agent_id")
	status := query.Get("status")
	page := parseIntDefault(query.Get("page"), 1)
	perPage := parseIntDefault(query.Get("per_page"), 50)
	if perPage > 500 {
		perPage = 50
	}

	certs, total, err := h.svc.ListDiscovered(r.Context(), agentID, status, page, perPage)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to list discovered certificates: %v", err))
		return
	}

	JSON(w, http.StatusOK, PagedResponse{
		Data:    certs,
		Total:   int64(total),
		Page:    page,
		PerPage: perPage,
	})
}

// GetDiscovered handles GET /api/v1/discovered-certificates/{id}
func (h DiscoveryHandler) GetDiscovered(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "discovered certificate ID is required")
		return
	}

	cert, err := h.svc.GetDiscovered(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("discovered certificate not found: %v", err))
		return
	}

	JSON(w, http.StatusOK, cert)
}

// ClaimDiscovered handles POST /api/v1/discovered-certificates/{id}/claim
func (h DiscoveryHandler) ClaimDiscovered(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "discovered certificate ID is required")
		return
	}

	var body struct {
		ManagedCertificateID string `json:"managed_certificate_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if body.ManagedCertificateID == "" {
		Error(w, http.StatusBadRequest, "managed_certificate_id is required")
		return
	}

	if err := h.svc.ClaimDiscovered(r.Context(), id, body.ManagedCertificateID); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to claim certificate: %v", err))
		return
	}

	JSON(w, http.StatusOK, map[string]string{
		"status":  "claimed",
		"message": "Discovered certificate linked to managed certificate",
	})
}

// DismissDiscovered handles POST /api/v1/discovered-certificates/{id}/dismiss
func (h DiscoveryHandler) DismissDiscovered(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "discovered certificate ID is required")
		return
	}

	if err := h.svc.DismissDiscovered(r.Context(), id); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to dismiss certificate: %v", err))
		return
	}

	JSON(w, http.StatusOK, map[string]string{
		"status":  "dismissed",
		"message": "Discovered certificate dismissed",
	})
}

// ListScans handles GET /api/v1/discovery-scans
func (h DiscoveryHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	query := r.URL.Query()
	agentID := query.Get("agent_id")
	page := parseIntDefault(query.Get("page"), 1)
	perPage := parseIntDefault(query.Get("per_page"), 50)

	scans, total, err := h.svc.ListScans(r.Context(), agentID, page, perPage)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to list discovery scans: %v", err))
		return
	}

	JSON(w, http.StatusOK, PagedResponse{
		Data:    scans,
		Total:   int64(total),
		Page:    page,
		PerPage: perPage,
	})
}

// GetDiscoverySummary handles GET /api/v1/discovery-summary
func (h DiscoveryHandler) GetDiscoverySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	summary, err := h.svc.GetDiscoverySummary(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to get discovery summary: %v", err))
		return
	}

	JSON(w, http.StatusOK, summary)
}

// parseIntDefault parses an integer from a string with a default fallback.
func parseIntDefault(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil || val < 1 {
		return defaultVal
	}
	return val
}
