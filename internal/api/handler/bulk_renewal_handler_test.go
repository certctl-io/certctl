package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// mockBulkRenewalService is a test implementation of BulkRenewalService.
type mockBulkRenewalService struct {
	BulkRenewFn func(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error)
}

func (m *mockBulkRenewalService) BulkRenew(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
	if m.BulkRenewFn != nil {
		return m.BulkRenewFn(ctx, criteria, actor)
	}
	return &domain.BulkRenewalResult{}, nil
}

// authedContext mirrors adminContext but without the admin flag —
// bulk-renew is NOT admin-gated, any authenticated caller can use it.
func authedContext() context.Context {
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id-renew")
	ctx = context.WithValue(ctx, middleware.UserKey{}, "alice")
	return ctx
}

func TestBulkRenew_Handler_HappyPath(t *testing.T) {
	svc := &mockBulkRenewalService{
		BulkRenewFn: func(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
			if len(criteria.CertificateIDs) != 3 {
				t.Errorf("expected 3 IDs, got %d", len(criteria.CertificateIDs))
			}
			if actor != "alice" {
				t.Errorf("actor = %q, want 'alice' (resolved from middleware UserKey)", actor)
			}
			return &domain.BulkRenewalResult{
				TotalMatched:  3,
				TotalEnqueued: 3,
				EnqueuedJobs: []domain.BulkEnqueuedJob{
					{CertificateID: "mc-1", JobID: "job-a"},
					{CertificateID: "mc-2", JobID: "job-b"},
					{CertificateID: "mc-3", JobID: "job-c"},
				},
			}, nil
		},
	}
	h := NewBulkRenewalHandler(svc)

	body := `{"certificate_ids":["mc-1","mc-2","mc-3"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-renew", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkRenew(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var result domain.BulkRenewalResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if result.TotalEnqueued != 3 || len(result.EnqueuedJobs) != 3 {
		t.Errorf("envelope drift: enqueued=%d jobs=%d, want 3/3",
			result.TotalEnqueued, len(result.EnqueuedJobs))
	}
}

func TestBulkRenew_Handler_EmptyBody_400(t *testing.T) {
	svc := &mockBulkRenewalService{}
	h := NewBulkRenewalHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-renew", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkRenew(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty criteria must reject)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "filter criterion") {
		t.Errorf("body should name the criteria-required contract; got: %s", w.Body.String())
	}
}

func TestBulkRenew_Handler_WrongMethod_405(t *testing.T) {
	svc := &mockBulkRenewalService{}
	h := NewBulkRenewalHandler(svc)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/certificates/bulk-renew", nil)
		req = req.WithContext(authedContext())
		w := httptest.NewRecorder()
		h.BulkRenew(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s → status %d, want 405", method, w.Code)
		}
	}
}

func TestBulkRenew_Handler_ActorAttribution(t *testing.T) {
	var capturedActor string
	svc := &mockBulkRenewalService{
		BulkRenewFn: func(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
			capturedActor = actor
			return &domain.BulkRenewalResult{}, nil
		},
	}
	h := NewBulkRenewalHandler(svc)

	body := `{"certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-renew", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkRenew(w, req)

	if capturedActor != "alice" {
		t.Errorf("actor not threaded from middleware.UserKey: got %q, want 'alice'", capturedActor)
	}
}

func TestBulkRenew_Handler_ServiceError_500(t *testing.T) {
	svc := &mockBulkRenewalService{
		BulkRenewFn: func(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
			return nil, errors.New("simulated DB failure")
		},
	}
	h := NewBulkRenewalHandler(svc)
	body := `{"certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-renew", bytes.NewBufferString(body))
	req = req.WithContext(authedContext())
	w := httptest.NewRecorder()
	h.BulkRenew(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
