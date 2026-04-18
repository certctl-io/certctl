package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/middleware"
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

// adminContext returns a context carrying the admin flag, mimicking what the
// auth middleware sets for named-key callers whose entry is admin-tagged.
// M-003: bulk revocation handler requires admin context to reach the service.
func adminContext() context.Context {
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id-bulk")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	return ctx
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
	req = req.WithContext(adminContext())
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
	req = req.WithContext(adminContext())
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
	req = req.WithContext(adminContext())
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
	req = req.WithContext(adminContext())
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
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkRevoke_MethodNotAllowed_405(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	// Method check fires before the admin gate, so 405 must hold even for a
	// non-admin caller — asserting this keeps the ordering explicit.
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
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- M-003: admin-only gate on bulk revocation ---

// TestBulkRevoke_NonAdmin_Returns403 is the central authorization regression
// for M-003. A caller without an admin-tagged context must be rejected with
// HTTP 403, regardless of how well-formed its body is, and the service layer
// must never see the request.
func TestBulkRevoke_NonAdmin_Returns403(t *testing.T) {
	var serviceCalled bool
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			serviceCalled = true
			return &domain.BulkRevocationResult{}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)

	// Well-formed body + well-formed reason + filter — the only thing
	// missing is an admin-tagged context. The gate must still fire.
	body := `{"reason":"keyCompromise","certificate_ids":["mc-1","mc-2"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID()) // request id only, no admin flag
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d (body=%q)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	msg, _ := resp["message"].(string)
	if !strings.Contains(strings.ToLower(msg), "admin") {
		t.Errorf("expected message to mention admin requirement, got %q", msg)
	}
	if serviceCalled {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

// TestBulkRevoke_AdminExplicitFalse_Returns403 pins the specific case where the
// AdminKey exists but is set to false — e.g., a non-admin named-key caller.
// Without this we could regress to "key missing == deny, key present == allow"
// which would silently grant a false flag.
func TestBulkRevoke_AdminExplicitFalse_Returns403(t *testing.T) {
	h := NewBulkRevocationHandler(&mockBulkRevocationService{})

	body := `{"reason":"keyCompromise","certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for admin=false, got %d", w.Code)
	}
}

// TestBulkRevoke_AdminPermitted_ForwardsActor confirms the happy path:
// an admin-tagged context reaches the service and the actor (from the auth
// UserKey) is propagated through to BulkRevoke. This keeps the admin gate and
// the M-002 actor-propagation wired together in a single regression.
func TestBulkRevoke_AdminPermitted_ForwardsActor(t *testing.T) {
	var capturedActor string
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			capturedActor = actor
			return &domain.BulkRevocationResult{TotalMatched: 1, TotalRevoked: 1}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)

	body := `{"reason":"keyCompromise","certificate_ids":["mc-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for admin caller, got %d (body=%q)", w.Code, w.Body.String())
	}
	if capturedActor != "ops-admin" {
		t.Errorf("expected actor ops-admin, got %q", capturedActor)
	}
}
