package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/certctl-io/certctl/internal/domain"
)

// NetworkScanService defines the interface used by the network scan handler.
type NetworkScanService interface {
	ListTargets(ctx context.Context) ([]*domain.NetworkScanTarget, error)
	GetTarget(ctx context.Context, id string) (*domain.NetworkScanTarget, error)
	CreateTarget(ctx context.Context, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error)
	UpdateTarget(ctx context.Context, id string, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error)
	DeleteTarget(ctx context.Context, id string) error
	TriggerScan(ctx context.Context, targetID string) (*domain.DiscoveryScan, error)

	// SCEP RFC 8894 + Intune master bundle Phase 11.5 — SCEP probe.
	// ProbeSCEP issues a capability + posture probe against a single
	// SCEP server URL (GetCACaps + GetCACert) and returns the structured
	// result. ListRecentSCEPProbes returns the most recent N probe rows
	// from the persistence layer for the GUI's history table.
	ProbeSCEP(ctx context.Context, url string) (*domain.SCEPProbeResult, error)
	ListRecentSCEPProbes(ctx context.Context, limit int) ([]*domain.SCEPProbeResult, error)
}

// NetworkScanHandler handles HTTP requests for network scan targets.
type NetworkScanHandler struct {
	svc NetworkScanService
}

// NewNetworkScanHandler creates a new network scan handler.
func NewNetworkScanHandler(svc NetworkScanService) NetworkScanHandler {
	return NetworkScanHandler{svc: svc}
}

// ListNetworkScanTargets handles GET /api/v1/network-scan-targets
func (h NetworkScanHandler) ListNetworkScanTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	targets, err := h.svc.ListTargets(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to list network scan targets: %v", err))
		return
	}

	if targets == nil {
		targets = []*domain.NetworkScanTarget{}
	}

	JSON(w, http.StatusOK, PagedResponse{
		Data:    targets,
		Total:   int64(len(targets)),
		Page:    1,
		PerPage: len(targets),
	})
}

// GetNetworkScanTarget handles GET /api/v1/network-scan-targets/{id}
func (h NetworkScanHandler) GetNetworkScanTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "network scan target ID is required")
		return
	}

	target, err := h.svc.GetTarget(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("network scan target not found: %v", err))
		return
	}

	JSON(w, http.StatusOK, target)
}

// CreateNetworkScanTarget handles POST /api/v1/network-scan-targets
func (h NetworkScanHandler) CreateNetworkScanTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var target domain.NetworkScanTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	created, err := h.svc.CreateTarget(r.Context(), &target)
	if err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("failed to create network scan target: %v", err))
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateNetworkScanTarget handles PUT /api/v1/network-scan-targets/{id}
func (h NetworkScanHandler) UpdateNetworkScanTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "network scan target ID is required")
		return
	}

	var target domain.NetworkScanTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	updated, err := h.svc.UpdateTarget(r.Context(), id, &target)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to update network scan target: %v", err))
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteNetworkScanTarget handles DELETE /api/v1/network-scan-targets/{id}
func (h NetworkScanHandler) DeleteNetworkScanTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "network scan target ID is required")
		return
	}

	if err := h.svc.DeleteTarget(r.Context(), id); err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("failed to delete network scan target: %v", err))
		return
	}

	JSON(w, http.StatusNoContent, nil)
}

// TriggerNetworkScan handles POST /api/v1/network-scan-targets/{id}/scan
func (h NetworkScanHandler) TriggerNetworkScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "network scan target ID is required")
		return
	}

	scan, err := h.svc.TriggerScan(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to trigger scan: %v", err))
		return
	}

	// scan may be nil if no certs found
	if scan == nil {
		JSON(w, http.StatusOK, map[string]string{
			"status":  "completed",
			"message": "Scan completed, no certificates found",
		})
		return
	}

	JSON(w, http.StatusAccepted, scan)
}

// scepProbeRequest is the POST body for /api/v1/network-scan/scep-probe.
// Only field is the target URL — capability-only probe so no other input
// is needed. Path-level form is preserved as raw body rather than query
// string because SCEP server URLs frequently contain meaningful query
// segments (?operation=PKIOperation, etc.) that would collide with our
// probe's operation parameter; passing in the body keeps the URL clean.
type scepProbeRequest struct {
	URL string `json:"url"`
}

// ProbeSCEP handles POST /api/v1/network-scan/scep-probe.
//
// SCEP RFC 8894 + Intune master bundle Phase 11.5. Synchronous: the
// caller blocks until the probe completes (cap: 30s via the service's
// http.Client.Timeout). Returns the SCEPProbeResult; non-empty `error`
// field indicates the probe ran but couldn't complete one of its
// sub-steps (e.g. unreachable server, malformed response). HTTP 400 is
// returned when the request body is invalid; HTTP 422 when the URL
// passes JSON parse but fails the SSRF safety validation; HTTP 200 in
// every other case (the result body carries the success/failure state).
func (h NetworkScanHandler) ProbeSCEP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var body scepProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}
	if body.URL == "" {
		Error(w, http.StatusBadRequest, "url is required")
		return
	}

	result, err := h.svc.ProbeSCEP(r.Context(), body.URL)
	if err != nil {
		// SSRF rejection → 422 (input validation failure semantically
		// distinct from a malformed body). Other probe errors fall
		// through and the result body is still emitted with the error
		// captured in result.Error.
		if result == nil {
			Error(w, http.StatusInternalServerError, "SCEP probe failed: "+err.Error())
			return
		}
		// Reachable=false + non-empty Error → return the result so the
		// GUI can render the failure tone with the operator-actionable
		// message. The HTTP 200 response carries the diagnostic body.
	}
	JSON(w, http.StatusOK, result)
}

// ListSCEPProbes handles GET /api/v1/network-scan/scep-probes.
//
// Returns the most recent N probe rows for the GUI's history table.
// Default limit is 50; max via ?limit=N is clamped at 200 by the
// underlying repository. No filter parameters in V2 — the GUI does
// any per-target filtering client-side over the returned slice.
func (h NetworkScanHandler) ListSCEPProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	rows, err := h.svc.ListRecentSCEPProbes(r.Context(), 50)
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to list SCEP probe history: "+err.Error())
		return
	}
	if rows == nil {
		rows = []*domain.SCEPProbeResult{}
	}
	JSON(w, http.StatusOK, map[string]any{
		"probes":      rows,
		"probe_count": len(rows),
	})
}
