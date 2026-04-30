package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// EST RFC 7030 hardening master bundle Phase 11.4 — BulkRevokeEST handler tests.
// Mirror the BulkRevoke pattern in bulk_revocation_handler_test.go but pin
// the EST-source-scoping contract (criteria.Source MUST be set to EST + the
// safety-guard that rejects narrower-criterion-empty requests fires
// regardless of Source).

func TestBulkRevokeEST_AdminTrue_PinsSourceToEST(t *testing.T) {
	var capturedSource domain.CertificateSource
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(_ context.Context, criteria domain.BulkRevocationCriteria, _ string, _ string) (*domain.BulkRevocationResult, error) {
			capturedSource = criteria.Source
			return &domain.BulkRevocationResult{TotalMatched: 1, TotalRevoked: 1}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)
	body := `{"reason":"keyCompromise","profile_id":"prof-iot"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/est/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()
	h.BulkRevokeEST(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if capturedSource != domain.CertificateSourceEST {
		t.Errorf("Source = %q, want %q (handler must pin)", capturedSource, domain.CertificateSourceEST)
	}
}

func TestBulkRevokeEST_NonAdmin_Returns403(t *testing.T) {
	called := false
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(_ context.Context, _ domain.BulkRevocationCriteria, _ string, _ string) (*domain.BulkRevocationResult, error) {
			called = true
			return nil, nil
		},
	}
	h := NewBulkRevocationHandler(svc)
	body := `{"reason":"keyCompromise","profile_id":"prof-iot"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/est/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// non-admin context (no AdminKey).
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.BulkRevokeEST(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", w.Code)
	}
	if called {
		t.Error("service was called despite non-admin caller")
	}
}

func TestBulkRevokeEST_EmptyCriteria_400(t *testing.T) {
	svc := &mockBulkRevocationService{}
	h := NewBulkRevocationHandler(svc)
	body := `{"reason":"keyCompromise"}` // no narrower criterion
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/est/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()
	h.BulkRevokeEST(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty-criterion status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "criterion") {
		t.Errorf("error body should mention criterion; got %q", w.Body.String())
	}
}

func TestBulkRevokeEST_InvalidReason_400(t *testing.T) {
	svc := &mockBulkRevocationService{}
	h := NewBulkRevocationHandler(svc)
	body := `{"reason":"not-a-valid-reason","profile_id":"prof-iot"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/est/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()
	h.BulkRevokeEST(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid-reason status = %d, want 400", w.Code)
	}
}

func TestBulkRevokeEST_MethodNotAllowed(t *testing.T) {
	svc := &mockBulkRevocationService{}
	h := NewBulkRevocationHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/est/certificates/bulk-revoke", nil)
	w := httptest.NewRecorder()
	h.BulkRevokeEST(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET against POST-only endpoint status = %d, want 405", w.Code)
	}
}
