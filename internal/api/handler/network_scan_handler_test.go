package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockNetworkScanService implements NetworkScanService for testing.
type mockNetworkScanService struct {
	targets []*domain.NetworkScanTarget
}

func (m *mockNetworkScanService) ListTargets(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	return m.targets, nil
}

func (m *mockNetworkScanService) GetTarget(ctx context.Context, id string) (*domain.NetworkScanTarget, error) {
	for _, t := range m.targets {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockNetworkScanService) CreateTarget(ctx context.Context, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error) {
	if target.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	target.ID = "nst-test-123"
	m.targets = append(m.targets, target)
	return target, nil
}

func (m *mockNetworkScanService) UpdateTarget(ctx context.Context, id string, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error) {
	for _, t := range m.targets {
		if t.ID == id {
			if target.Name != "" {
				t.Name = target.Name
			}
			return t, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockNetworkScanService) DeleteTarget(ctx context.Context, id string) error {
	for i, t := range m.targets {
		if t.ID == id {
			m.targets = append(m.targets[:i], m.targets[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockNetworkScanService) TriggerScan(ctx context.Context, targetID string) (*domain.DiscoveryScan, error) {
	for _, t := range m.targets {
		if t.ID == targetID {
			return &domain.DiscoveryScan{
				ID:                "dscan-test",
				AgentID:           "server-scanner",
				CertificatesFound: 3,
			}, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", targetID)
}

func TestListNetworkScanTargets(t *testing.T) {
	svc := &mockNetworkScanService{
		targets: []*domain.NetworkScanTarget{
			{ID: "nst-1", Name: "target1", CIDRs: []string{"10.0.0.0/24"}, Ports: []int{443}},
			{ID: "nst-2", Name: "target2", CIDRs: []string{"192.168.0.0/16"}, Ports: []int{443, 8443}},
		},
	}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/network-scan-targets", nil)
	w := httptest.NewRecorder()
	h.ListNetworkScanTargets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp PagedResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("expected total 2, got %d", resp.Total)
	}
}

func TestListNetworkScanTargets_Empty(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/network-scan-targets", nil)
	w := httptest.NewRecorder()
	h.ListNetworkScanTargets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateNetworkScanTarget(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "Production",
		"cidrs": []string{"10.0.0.0/24"},
		"ports": []int{443},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateNetworkScanTarget(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateNetworkScanTarget_InvalidJSON(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	h.CreateNetworkScanTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateNetworkScanTarget_MissingName(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	body, _ := json.Marshal(map[string]interface{}{
		"cidrs": []string{"10.0.0.0/24"},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateNetworkScanTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteNetworkScanTarget_NotFound(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/network-scan-targets/nst-nonexistent", nil)
	req.SetPathValue("id", "nst-nonexistent")
	w := httptest.NewRecorder()
	h.DeleteNetworkScanTarget(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestTriggerNetworkScan(t *testing.T) {
	svc := &mockNetworkScanService{
		targets: []*domain.NetworkScanTarget{
			{ID: "nst-1", Name: "target1"},
		},
	}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets/nst-1/scan", nil)
	req.SetPathValue("id", "nst-1")
	w := httptest.NewRecorder()
	h.TriggerNetworkScan(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTriggerNetworkScan_NotFound(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets/nst-nonexistent/scan", nil)
	req.SetPathValue("id", "nst-nonexistent")
	w := httptest.NewRecorder()
	h.TriggerNetworkScan(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestListNetworkScanTargets_MethodNotAllowed(t *testing.T) {
	svc := &mockNetworkScanService{}
	h := NewNetworkScanHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/network-scan-targets", nil)
	w := httptest.NewRecorder()
	h.ListNetworkScanTargets(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
