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

// mockBulkRevocationService is a test implementation of BulkRevocationService
type mockBulkRevocationService struct {
	BulkRevokeFn func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error)
}

func (m *mockBulkRevocationService) BulkRevoke(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
	if m.BulkRevokeFn != nil {
		return m.BulkRevokeFn(ctx, criteria, reason, actor)
	}
	return &domain.BulkRevocationResult{}, nil
}

func TestBulkRevoke_Success_WithIDs(t *testing.T) {
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			if len(criteria.CertificateIDs) != 2 {
				t.Errorf("expected 2 IDs, got %d", len(criteria.CertificateIDs))
			}
			if reason != "keyCompromise" {
				t.Errorf("expected reason keyCompromise, got %s", reason)
			}
			return &domain.BulkRevocationResult{
				TotalMatched: 2,
				TotalRevoked: 2,
			}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)

	body := `{"reason":"keyCompromise","certificate_ids":["mc-1","mc-2"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result domain.BulkRevocationResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.TotalMatched != 2 {
		t.Errorf("expected TotalMatched=2, got %d", result.TotalMatched)
	}
	if result.TotalRevoked != 2 {
		t.Errorf("expected TotalRevoked=2, got %d", result.TotalRevoked)
	}
}

func TestBulkRevoke_Success_WithProfile(t *testing.T) {
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			if criteria.ProfileID != "prof-tls" {
				t.Errorf("expected profile prof-tls, got %s", criteria.ProfileID)
			}
			return &domain.BulkRevocationResult{
				TotalMatched: 5,
				TotalRevoked: 4,
				TotalSkipped: 1,
			}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)

	body := `{"reason":"keyCompromise","profile_id":"prof-tls"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestBulkRevoke_MissingReason_400(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	body := `{"certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkRevoke_EmptyCriteria_400(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	body := `{"reason":"keyCompromise"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkRevoke_InvalidReason_400(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	body := `{"reason":"totallyBogus","certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkRevoke_MethodNotAllowed_405(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/bulk-revoke", nil)
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestBulkRevoke_ServiceError_500(t *testing.T) {
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			return nil, fmt.Errorf("database connection failed")
		},
	}
	h := NewBulkRevocationHandler(svc)

	body := `{"reason":"keyCompromise","certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
