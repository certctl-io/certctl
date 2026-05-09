package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// =============================================================================
// Bundle 1 Phase 8 — audit category-filter HTTP behaviour.
// =============================================================================

// TestListAuditEvents_Phase8_CategoryFilterDispatchesToService pins the
// happy-path: ?category=auth routes through ListAuditEventsByCategory
// with the right argument.
func TestListAuditEvents_Phase8_CategoryFilterDispatchesToService(t *testing.T) {
	var capturedCategory string
	mockSvc := &mockAuditService{
		listByCatFunc: func(category string, _, _ int) ([]domain.AuditEvent, int64, error) {
			capturedCategory = category
			return []domain.AuditEvent{
				{ID: "audit-1", Action: "auth.role.assign", EventCategory: domain.EventCategoryAuth},
			}, 1, nil
		},
	}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?category=auth", nil)
	rec := httptest.NewRecorder()
	h.ListAuditEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if capturedCategory != "auth" {
		t.Errorf("captured category = %q, want auth", capturedCategory)
	}
}

// TestListAuditEvents_Phase8_NoCategoryFallsBackToListAuditEvents pins
// that the legacy unfiltered path still routes through ListAuditEvents
// (preserves back-compat).
func TestListAuditEvents_Phase8_NoCategoryFallsBackToListAuditEvents(t *testing.T) {
	listCalled := false
	listByCatCalled := false
	mockSvc := &mockAuditService{
		listFunc: func(_, _ int) ([]domain.AuditEvent, int64, error) {
			listCalled = true
			return nil, 0, nil
		},
		listByCatFunc: func(_ string, _, _ int) ([]domain.AuditEvent, int64, error) {
			listByCatCalled = true
			return nil, 0, nil
		},
	}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	h.ListAuditEvents(rec, req)
	if !listCalled {
		t.Errorf("ListAuditEvents not called for unfiltered request")
	}
	if listByCatCalled {
		t.Errorf("ListAuditEventsByCategory called unexpectedly for unfiltered request")
	}
}

// TestListAuditEvents_Phase8_RejectsUnknownCategory pins the 400 surface
// for misuse. Allowed values are exactly cert_lifecycle/auth/config;
// anything else surfaces a clear error rather than silently returning
// every row.
func TestListAuditEvents_Phase8_RejectsUnknownCategory(t *testing.T) {
	mockSvc := &mockAuditService{}
	h := NewAuditHandler(mockSvc)
	for _, bad := range []string{"agent", "AUTH", "auth%20", "system"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?category="+bad, nil)
		rec := httptest.NewRecorder()
		h.ListAuditEvents(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("category=%q got status %d, want 400", bad, rec.Code)
		}
	}
}

// TestListAuditEvents_Phase8_AcceptsAllThreeCategories pins that each of
// the three documented enum values dispatches without a 400.
func TestListAuditEvents_Phase8_AcceptsAllThreeCategories(t *testing.T) {
	mockSvc := &mockAuditService{
		listByCatFunc: func(_ string, _, _ int) ([]domain.AuditEvent, int64, error) {
			return nil, 0, nil
		},
	}
	h := NewAuditHandler(mockSvc)
	for _, cat := range []string{
		domain.EventCategoryCertLifecycle,
		domain.EventCategoryAuth,
		domain.EventCategoryConfig,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?category="+cat, nil)
		rec := httptest.NewRecorder()
		h.ListAuditEvents(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("category=%s got status %d, want 200", cat, rec.Code)
		}
	}
}

// TestListAuditEvents_Phase8_CategoryAndPageCombine confirms the query
// parser respects both the page and category params concurrently.
func TestListAuditEvents_Phase8_CategoryAndPageCombine(t *testing.T) {
	var capturedCategory string
	var capturedPage int
	mockSvc := &mockAuditService{
		listByCatFunc: func(category string, page, _ int) ([]domain.AuditEvent, int64, error) {
			capturedCategory = category
			capturedPage = page
			return nil, 0, nil
		},
	}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?category=auth&page=3", nil)
	rec := httptest.NewRecorder()
	h.ListAuditEvents(rec, req)
	if capturedCategory != "auth" || capturedPage != 3 {
		t.Errorf("captured (cat=%q page=%d), want (auth, 3)", capturedCategory, capturedPage)
	}
}

// TestListAuditEvents_Phase8_ResponseSurfacesEventCategory confirms the
// JSON output carries the event_category field for downstream auditors.
func TestListAuditEvents_Phase8_ResponseSurfacesEventCategory(t *testing.T) {
	mockSvc := &mockAuditService{
		listByCatFunc: func(_ string, _, _ int) ([]domain.AuditEvent, int64, error) {
			return []domain.AuditEvent{
				{ID: "a1", Action: "auth.role.assign", EventCategory: "auth"},
				{ID: "a2", Action: "issuer.edit", EventCategory: "config"},
			}, 2, nil
		},
	}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?category=auth", nil)
	rec := httptest.NewRecorder()
	h.ListAuditEvents(rec, req)
	var resp struct {
		Data []domain.AuditEvent `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data) != 2 || resp.Data[0].EventCategory != "auth" || resp.Data[1].EventCategory != "config" {
		t.Errorf("event_category not surfaced in JSON: %+v", resp.Data)
	}
}

var _ = context.Background // keep import even if other tests strip it
