package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/shankar0123/certctl/internal/domain"
)

// NetworkScanService defines the interface used by the network scan handler.
type NetworkScanService interface {
	ListTargets(ctx context.Context) ([]*domain.NetworkScanTarget, error)
	GetTarget(ctx context.Context, id string) (*domain.NetworkScanTarget, error)
	CreateTarget(ctx context.Context, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error)
	UpdateTarget(ctx context.Context, id string, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error)
	DeleteTarget(ctx context.Context, id string) error
	TriggerScan(ctx context.Context, targetID string) (*domain.DiscoveryScan, error)
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
