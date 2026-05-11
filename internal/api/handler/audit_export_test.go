package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// Audit 2026-05-10 HIGH-11 closure — pin the streaming NDJSON audit
// export endpoint. Pre-fix, the `audit.export` permission was seeded
// into r-admin + r-auditor (migration 000031) but no endpoint enforced
// it; the auditor role's claim was misleading capability advertisement.
// Post-fix, GET /api/v1/audit/export gates on `audit.export`, streams
// audit rows as line-delimited JSON, bounded to a 90-day window, and
// recursively self-audits each export call.

// exportMockSvc extends mockAuditService with explicit hooks for the
// HIGH-11 export path.
type exportMockSvc struct {
	mockAuditService
	exportFn func(from, to time.Time, eventCategory string, maxRows int) ([]domain.AuditEvent, error)
}

func (m *exportMockSvc) ExportEventsByFilter(_ context.Context, from, to time.Time, eventCategory string, maxRows int) ([]domain.AuditEvent, error) {
	if m.exportFn != nil {
		return m.exportFn(from, to, eventCategory, maxRows)
	}
	return nil, nil
}

func TestExportAudit_StreamsNDJSONLines(t *testing.T) {
	events := []domain.AuditEvent{
		{ID: "ev-1", Action: "cert.issue", Actor: "alice", Timestamp: time.Now()},
		{ID: "ev-2", Action: "cert.revoke", Actor: "bob", Timestamp: time.Now()},
		{ID: "ev-3", Action: "auth.role.grant", Actor: "alice", Timestamp: time.Now()},
	}
	mockSvc := &exportMockSvc{
		exportFn: func(from, to time.Time, _ string, _ int) ([]domain.AuditEvent, error) {
			return events, nil
		},
	}
	h := NewAuditHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/export?from=2026-04-01T00:00:00Z&to=2026-05-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q; want application/x-ndjson", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q; want attachment;...", cd)
	}

	scanner := bufio.NewScanner(strings.NewReader(w.Body.String()))
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var got domain.AuditEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not valid JSON: %v; line=%s", count, err, line)
		}
		count++
	}
	if count != len(events) {
		t.Errorf("scanned %d NDJSON lines; want %d", count, len(events))
	}

	// Self-audit leg: the export must emit an audit.export row for the
	// recursive trail.
	if mockSvc.lastAuditAction != "audit.export" {
		t.Errorf("lastAuditAction = %q; want audit.export (recursive self-audit)", mockSvc.lastAuditAction)
	}
	if mockSvc.lastAuditCategory != domain.EventCategoryAuth {
		t.Errorf("lastAuditCategory = %q; want %q", mockSvc.lastAuditCategory, domain.EventCategoryAuth)
	}
}

func TestExportAudit_RejectsRangeBeyond90Days(t *testing.T) {
	mockSvc := &exportMockSvc{}
	h := NewAuditHandler(mockSvc)

	// 100-day window — must reject.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/export?from=2026-01-01T00:00:00Z&to=2026-04-15T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 for >90d range", w.Code)
	}
	if !strings.Contains(w.Body.String(), "90-day") {
		t.Errorf("body = %q; want it to mention the 90-day cap", w.Body.String())
	}
}

func TestExportAudit_RejectsMissingFromOrTo(t *testing.T) {
	mockSvc := &exportMockSvc{}
	h := NewAuditHandler(mockSvc)

	cases := []string{
		"/api/v1/audit/export",
		"/api/v1/audit/export?from=2026-04-01T00:00:00Z",
		"/api/v1/audit/export?to=2026-04-30T00:00:00Z",
	}
	for _, url := range cases {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		h.ExportAudit(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("URL %q: status = %d; want 400 (missing from/to)", url, w.Code)
		}
	}
}

func TestExportAudit_RejectsInvalidCategory(t *testing.T) {
	mockSvc := &exportMockSvc{}
	h := NewAuditHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/export?from=2026-04-01T00:00:00Z&to=2026-04-30T00:00:00Z&category=zzz_unknown", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 for invalid category", w.Code)
	}
}

func TestExportAudit_AcceptsValidCategoryFilter(t *testing.T) {
	captured := struct {
		category string
	}{}
	mockSvc := &exportMockSvc{
		exportFn: func(_, _ time.Time, eventCategory string, _ int) ([]domain.AuditEvent, error) {
			captured.category = eventCategory
			return []domain.AuditEvent{}, nil
		},
	}
	h := NewAuditHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/export?from=2026-04-01T00:00:00Z&to=2026-04-30T00:00:00Z&category=auth", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
	if captured.category != domain.EventCategoryAuth {
		t.Errorf("captured.category = %q; want %q", captured.category, domain.EventCategoryAuth)
	}
}

func TestExportAudit_RejectsNonGET(t *testing.T) {
	mockSvc := &exportMockSvc{}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/audit/export?from=2026-04-01T00:00:00Z&to=2026-04-30T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405 for POST", w.Code)
	}
}

func TestExportAudit_RejectsToBeforeFrom(t *testing.T) {
	mockSvc := &exportMockSvc{}
	h := NewAuditHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/export?from=2026-05-01T00:00:00Z&to=2026-04-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ExportAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (to before from)", w.Code)
	}
}
