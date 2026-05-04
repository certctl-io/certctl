package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

type mockBulkReassignmentService struct {
	BulkReassignFn func(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error)
}

func (m *mockBulkReassignmentService) BulkReassign(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
	if m.BulkReassignFn != nil {
		return m.BulkReassignFn(ctx, request, actor)
	}
	return &domain.BulkReassignmentResult{}, nil
}

func TestBulkReassign_Handler_HappyPath(t *testing.T) {
	svc := &mockBulkReassignmentService{
		BulkReassignFn: func(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
			if request.OwnerID != "o-bob" {
				t.Errorf("owner_id = %q, want 'o-bob'", request.OwnerID)
			}
			return &domain.BulkReassignmentResult{
				TotalMatched: 2, TotalReassigned: 2,
			}, nil
		},
	}
	h := NewBulkReassignmentHandler(svc)

	body := `{"certificate_ids":["mc-1","mc-2"],"owner_id":"o-bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkReassign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var result domain.BulkReassignmentResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if result.TotalReassigned != 2 {
		t.Errorf("envelope drift: TotalReassigned=%d, want 2", result.TotalReassigned)
	}
}

func TestBulkReassign_Handler_EmptyIDs_400(t *testing.T) {
	svc := &mockBulkReassignmentService{}
	h := NewBulkReassignmentHandler(svc)

	body := `{"certificate_ids":[],"owner_id":"o-bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkReassign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestBulkReassign_Handler_MissingOwnerID_400(t *testing.T) {
	svc := &mockBulkReassignmentService{}
	h := NewBulkReassignmentHandler(svc)

	body := `{"certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkReassign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "owner_id") {
		t.Errorf("body should name owner_id; got: %s", w.Body.String())
	}
}

// TestBulkReassign_Handler_OwnerNotFound_400 — sentinel-error → 400
// mapping. Operator picked an owner that doesn't exist; that's bad
// input, not a server error.
func TestBulkReassign_Handler_OwnerNotFound_400(t *testing.T) {
	svc := &mockBulkReassignmentService{
		BulkReassignFn: func(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
			return nil, fmt.Errorf("%w: %s", service.ErrBulkReassignOwnerNotFound, request.OwnerID)
		},
	}
	h := NewBulkReassignmentHandler(svc)

	body := `{"certificate_ids":["mc-1"],"owner_id":"o-ghost"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkReassign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (ErrBulkReassignOwnerNotFound → 400)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "owner not found") {
		t.Errorf("body should mention 'owner not found'; got: %s", w.Body.String())
	}
}

func TestBulkReassign_Handler_WrongMethod_405(t *testing.T) {
	svc := &mockBulkReassignmentService{}
	h := NewBulkReassignmentHandler(svc)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/certificates/bulk-reassign", nil)
		req = req.WithContext(authedContext())
		w := httptest.NewRecorder()
		h.BulkReassign(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s → %d, want 405", method, w.Code)
		}
	}
}

func TestBulkReassign_Handler_GenericError_500(t *testing.T) {
	svc := &mockBulkReassignmentService{
		BulkReassignFn: func(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
			return nil, errors.New("simulated outage")
		},
	}
	h := NewBulkReassignmentHandler(svc)
	body := `{"certificate_ids":["mc-1"],"owner_id":"o-bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkReassign(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
