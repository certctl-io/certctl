package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
)

// mockAuditService implements AuditService for testing.
type mockAuditService struct {
	listFunc       func(page, perPage int) ([]domain.AuditEvent, int64, error)
	listByCatFunc  func(category string, page, perPage int) ([]domain.AuditEvent, int64, error)
	listByFiltFunc func(since, until time.Time, category string, page, perPage int) ([]domain.AuditEvent, int64, error)
	getFunc        func(id string) (*domain.AuditEvent, error)
	// HIGH-11 self-audit trace — last RecordEventWithCategory call.
	lastAuditActor    string
	lastAuditAction   string
	lastAuditCategory string
	// P-H2 trace — last ListAuditEventsByFilter args.
	lastFilterSince    time.Time
	lastFilterUntil    time.Time
	lastFilterCategory string
}

func (m *mockAuditService) ListAuditEvents(_ context.Context, page, perPage int) ([]domain.AuditEvent, int64, error) {
	if m.listFunc != nil {
		return m.listFunc(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockAuditService) ListAuditEventsByCategory(_ context.Context, category string, page, perPage int) ([]domain.AuditEvent, int64, error) {
	if m.listByCatFunc != nil {
		return m.listByCatFunc(category, page, perPage)
	}
	if m.listFunc != nil {
		return m.listFunc(page, perPage)
	}
	return nil, 0, nil
}

// ListAuditEventsByFilter satisfies the P-H2 interface extension. The
// test fixture remembers the (since, until, category) tuple so
// per-subtest assertions can pin that the handler threaded the
// query-string params through correctly. Falls back to listFunc /
// listByCatFunc so existing tests don't need to set listByFiltFunc.
func (m *mockAuditService) ListAuditEventsByFilter(_ context.Context, since, until time.Time, category string, page, perPage int) ([]domain.AuditEvent, int64, error) {
	m.lastFilterSince = since
	m.lastFilterUntil = until
	m.lastFilterCategory = category
	if m.listByFiltFunc != nil {
		return m.listByFiltFunc(since, until, category, page, perPage)
	}
	if category != "" && m.listByCatFunc != nil {
		return m.listByCatFunc(category, page, perPage)
	}
	if m.listFunc != nil {
		return m.listFunc(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockAuditService) GetAuditEvent(_ context.Context, id string) (*domain.AuditEvent, error) {
	if m.getFunc != nil {
		return m.getFunc(id)
	}
	return nil, nil
}

// ExportEventsByFilter satisfies the Audit 2026-05-10 HIGH-11 interface
// extension. The test mock just defers to the existing list helpers
// (no separate export-specific test fixture needed for the bundles that
// don't exercise export).
func (m *mockAuditService) ExportEventsByFilter(_ context.Context, _, _ time.Time, eventCategory string, _ int) ([]domain.AuditEvent, error) {
	if m.listFunc != nil {
		events, _, err := m.listFunc(1, 50000)
		if err != nil {
			return nil, err
		}
		return events, nil
	}
	return nil, nil
}

// RecordEventWithCategory satisfies the Audit 2026-05-10 HIGH-11
// interface extension (the export handler self-audits each call).
// Tests that don't care about the audit row trace can leave the field
// nil; tests that do can read m.lastAuditAction etc. after the call.
func (m *mockAuditService) RecordEventWithCategory(_ context.Context, actor string, _ domain.ActorType, action, eventCategory, _, _ string, _ map[string]interface{}) error {
	m.lastAuditActor = actor
	m.lastAuditAction = action
	m.lastAuditCategory = eventCategory
	return nil
}

func TestListAuditEvents_Success(t *testing.T) {
	events := []domain.AuditEvent{
		{
			ID:           "ev-1",
			Action:       "certificate_issued",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
		{
			ID:           "ev-2",
			Action:       "certificate_renewed",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
	}

	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			if page != 1 || perPage != 50 {
				t.Errorf("ListAuditEvents called with page=%d, perPage=%d, expected 1, 50", page, perPage)
			}
			return events, 2, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	// Add request ID to context
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Total = %d, want 2", result.Total)
	}

	if result.Page != 1 {
		t.Errorf("Page = %d, want 1", result.Page)
	}

	if result.PerPage != 50 {
		t.Errorf("PerPage = %d, want 50", result.PerPage)
	}

	// Check data is present
	if result.Data == nil {
		t.Error("Data is nil, want events slice")
	}
}

func TestListAuditEvents_WithPagination(t *testing.T) {
	events := []domain.AuditEvent{
		{
			ID:           "ev-5",
			Action:       "certificate_issued",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
	}

	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			if page != 2 || perPage != 25 {
				t.Errorf("ListAuditEvents called with page=%d, perPage=%d, expected 2, 25", page, perPage)
			}
			return events, 100, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit?page=2&per_page=25", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Page != 2 {
		t.Errorf("Page = %d, want 2", result.Page)
	}

	if result.PerPage != 25 {
		t.Errorf("PerPage = %d, want 25", result.PerPage)
	}
}

func TestListAuditEvents_PerPageMaxLimit(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			// Should be capped at 500
			if perPage > 500 {
				t.Errorf("perPage = %d, expected <= 500", perPage)
			}
			return []domain.AuditEvent{}, 0, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit?per_page=1000", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.PerPage > 500 {
		t.Errorf("PerPage = %d, want <= 500", result.PerPage)
	}
}

func TestListAuditEvents_EmptyResult(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			return []domain.AuditEvent{}, 0, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
}

func TestListAuditEvents_ServiceError(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			return nil, 0, errors.New("database error")
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusInternalServerError {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusInternalServerError)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Failed to list audit events" {
		t.Errorf("Message = %q, want 'Failed to list audit events'", errResp.Message)
	}
}

func TestListAuditEvents_MethodNotAllowed(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

// ── P-H2 closure (since / until time-range query params) ───────────

// TestListAuditEvents_WithSinceUntil pins the happy path — both bounds
// supplied in RFC3339, mock observes them threaded into the service
// call, response is 200.
func TestListAuditEvents_WithSinceUntil(t *testing.T) {
	since := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	mockSvc := &mockAuditService{
		listByFiltFunc: func(s, u time.Time, _ string, _, _ int) ([]domain.AuditEvent, int64, error) {
			if !s.Equal(since) {
				t.Errorf("service since = %v, want %v", s, since)
			}
			if !u.Equal(until) {
				t.Errorf("service until = %v, want %v", u, until)
			}
			return []domain.AuditEvent{}, 0, nil
		},
	}
	handler := NewAuditHandler(mockSvc)

	url := "/api/v1/audit?since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !mockSvc.lastFilterSince.Equal(since) {
		t.Errorf("mock recorded since = %v, want %v", mockSvc.lastFilterSince, since)
	}
	if !mockSvc.lastFilterUntil.Equal(until) {
		t.Errorf("mock recorded until = %v, want %v", mockSvc.lastFilterUntil, until)
	}
}

// TestListAuditEvents_SinceOnly pins one-sided bound — only `since`
// supplied, `until` stays zero. Closure of "operator filters to events
// from the last hour" via since=<now-1h>.
func TestListAuditEvents_SinceOnly(t *testing.T) {
	since := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/audit?since="+since.Format(time.RFC3339), nil)
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !mockSvc.lastFilterSince.Equal(since) {
		t.Errorf("since = %v, want %v", mockSvc.lastFilterSince, since)
	}
	if !mockSvc.lastFilterUntil.IsZero() {
		t.Errorf("until = %v, want zero (open-ended)", mockSvc.lastFilterUntil)
	}
}

// TestListAuditEvents_InvalidSince pins the parse-error 400 path.
// Silently dropping a malformed since would return ALL rows when the
// operator thought they were filtering — worse than rejecting.
func TestListAuditEvents_InvalidSince(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/audit?since=not-a-date", nil)
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !mockSvc.lastFilterSince.IsZero() {
		t.Error("service should NOT have been called on bad since")
	}
}

// TestListAuditEvents_UntilBeforeSince pins the order assertion — a
// reversed range surfaces 400, doesn't quietly return empty.
func TestListAuditEvents_UntilBeforeSince(t *testing.T) {
	since := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	url := "/api/v1/audit?since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestListAuditEvents_TimeRangePlusCategory pins that since/until
// compose with category (the auditor-role narrow-to-auth use case
// extended to "auth events from yesterday" without a separate
// endpoint).
func TestListAuditEvents_TimeRangePlusCategory(t *testing.T) {
	since := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	url := "/api/v1/audit?category=auth&since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if mockSvc.lastFilterCategory != "auth" {
		t.Errorf("category = %q, want auth", mockSvc.lastFilterCategory)
	}
	if !mockSvc.lastFilterSince.Equal(since) {
		t.Errorf("since = %v, want %v", mockSvc.lastFilterSince, since)
	}
	if !mockSvc.lastFilterUntil.Equal(until) {
		t.Errorf("until = %v, want %v", mockSvc.lastFilterUntil, until)
	}
}

func TestGetAuditEvent_Success(t *testing.T) {
	event := &domain.AuditEvent{
		ID:           "ev-123",
		Action:       "certificate_issued",
		Actor:        "user@example.com",
		ActorType:    domain.ActorTypeUser,
		ResourceID:   "mc-api-prod",
		ResourceType: "Certificate",
		Timestamp:    time.Now(),
	}

	mockSvc := &mockAuditService{
		getFunc: func(id string) (*domain.AuditEvent, error) {
			if id != "ev-123" {
				t.Errorf("GetAuditEvent called with id=%q, expected ev-123", id)
			}
			return event, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/ev-123", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusOK)
	}

	var result domain.AuditEvent
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ID != "ev-123" {
		t.Errorf("ID = %q, want ev-123", result.ID)
	}

	if result.Action != "certificate_issued" {
		t.Errorf("Action = %q, want certificate_issued", result.Action)
	}
}

func TestGetAuditEvent_NotFound(t *testing.T) {
	mockSvc := &mockAuditService{
		getFunc: func(id string) (*domain.AuditEvent, error) {
			return nil, errors.New("not found")
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/nonexistent", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusNotFound {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusNotFound)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Audit event not found" {
		t.Errorf("Message = %q, want 'Audit event not found'", errResp.Message)
	}
}

func TestGetAuditEvent_MethodNotAllowed(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodDelete, "/api/v1/audit/ev-123", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestGetAuditEvent_EmptyID(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusBadRequest {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Audit event ID is required" {
		t.Errorf("Message = %q, want 'Audit event ID is required'", errResp.Message)
	}
}
