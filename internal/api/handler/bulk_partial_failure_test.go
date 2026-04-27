package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// Bundle C / Audit M-007 (CWE-754): partial-failure tests for the three
// bulk endpoints. Pre-bundle all three handlers had only happy-path
// (TotalRevoked = TotalMatched, no Errors) and full-failure (service
// returns err) tests. The mixed-result branch — where some certs
// succeed and others fail — is the most operationally common shape
// and was completely uncovered.
//
// Each test asserts:
//   1. HTTP 200 (mixed result is a successful HTTP response carrying
//      both succeeded and failed counters).
//   2. The response body's TotalMatched / Total<verb> / TotalFailed
//      counters all round-trip from the service mock.
//   3. The Errors[] array is preserved and operators can correlate
//      each failure to its certificate ID.

// --- bulk-revoke ----------------------------------------------------------

func TestBulkRevoke_PartialFailure_ReportsBoth(t *testing.T) {
	svc := &mockBulkRevocationService{
		BulkRevokeFn: func(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error) {
			return &domain.BulkRevocationResult{
				TotalMatched: 3,
				TotalRevoked: 2,
				TotalSkipped: 0,
				TotalFailed:  1,
				Errors: []domain.BulkRevocationError{
					{CertificateID: "mc-failed", Error: "issuer connector unreachable"},
				},
			}, nil
		},
	}
	h := NewBulkRevocationHandler(svc)

	body := `{"reason":"keyCompromise","certificate_ids":["mc-1","mc-2","mc-failed"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminContext())
	w := httptest.NewRecorder()

	h.BulkRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("partial failure must still return HTTP 200, got %d", w.Code)
	}

	var result domain.BulkRevocationResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.TotalMatched != 3 {
		t.Errorf("TotalMatched = %d, want 3", result.TotalMatched)
	}
	if result.TotalRevoked != 2 {
		t.Errorf("TotalRevoked = %d, want 2", result.TotalRevoked)
	}
	if result.TotalFailed != 1 {
		t.Errorf("TotalFailed = %d, want 1", result.TotalFailed)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("Errors len = %d, want 1", len(result.Errors))
	}
	if result.Errors[0].CertificateID != "mc-failed" {
		t.Errorf("error CertificateID = %q, want mc-failed", result.Errors[0].CertificateID)
	}
	if result.Errors[0].Error == "" {
		t.Error("error message must be non-empty so operators can triage")
	}
}

// --- bulk-renew -----------------------------------------------------------

func TestBulkRenew_PartialFailure_ReportsBoth(t *testing.T) {
	svc := &mockBulkRenewalService{
		BulkRenewFn: func(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error) {
			return &domain.BulkRenewalResult{
				TotalMatched: 3,
				TotalEnqueued: 2,
				TotalSkipped: 0,
				TotalFailed:  1,
				Errors: []domain.BulkOperationError{
					{CertificateID: "mc-failed", Error: "renewal job enqueue failed: db timeout"},
				},
			}, nil
		},
	}
	h := NewBulkRenewalHandler(svc)

	body := `{"certificate_ids":["mc-1","mc-2","mc-failed"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-renew", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authenticatedContext("test-actor"))
	w := httptest.NewRecorder()

	h.BulkRenew(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("partial failure must still return HTTP 200, got %d", w.Code)
	}

	var result domain.BulkRenewalResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.TotalMatched != 3 || result.TotalEnqueued != 2 || result.TotalFailed != 1 {
		t.Errorf("counters mismatch: matched=%d enqueued=%d failed=%d, want 3/2/1",
			result.TotalMatched, result.TotalEnqueued, result.TotalFailed)
	}
	if len(result.Errors) != 1 || result.Errors[0].CertificateID != "mc-failed" {
		t.Errorf("Errors not preserved: %+v", result.Errors)
	}
}

// --- bulk-reassign --------------------------------------------------------

func TestBulkReassign_PartialFailure_ReportsBoth(t *testing.T) {
	svc := &mockBulkReassignmentService{
		BulkReassignFn: func(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error) {
			return &domain.BulkReassignmentResult{
				TotalMatched:    3,
				TotalReassigned: 2,
				TotalSkipped:    0,
				TotalFailed:     1,
				Errors: []domain.BulkOperationError{
					{CertificateID: "mc-failed", Error: "FK violation: cert no longer exists"},
				},
			}, nil
		},
	}
	h := NewBulkReassignmentHandler(svc)

	body := `{"certificate_ids":["mc-1","mc-2","mc-failed"],"owner_id":"o-bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-reassign", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authenticatedContext("test-actor"))
	w := httptest.NewRecorder()

	h.BulkReassign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("partial failure must still return HTTP 200, got %d", w.Code)
	}

	var result domain.BulkReassignmentResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.TotalMatched != 3 || result.TotalReassigned != 2 || result.TotalFailed != 1 {
		t.Errorf("counters mismatch: matched=%d reassigned=%d failed=%d, want 3/2/1",
			result.TotalMatched, result.TotalReassigned, result.TotalFailed)
	}
	if len(result.Errors) != 1 || result.Errors[0].CertificateID != "mc-failed" {
		t.Errorf("Errors not preserved: %+v", result.Errors)
	}
}

// --- helper context for unauth-allowed handlers (renew + reassign aren't admin-gated) ---

func authenticatedContext(actor string) context.Context {
	type userKey struct{}
	// The middleware UserKey is a private type in the middleware package, so
	// in this handler test we can't construct one directly. Bulk-renew and
	// bulk-reassign read the actor through the same middleware.GetUser path
	// that bulk-revoke does — adminContext() in the existing test suite is
	// the canonical helper. Reuse it (delivers both UserKey and AdminKey).
	_ = userKey{}
	return adminContext()
}
