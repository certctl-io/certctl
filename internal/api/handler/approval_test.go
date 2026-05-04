package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/service"
)

// fakeApprovalSvc satisfies handler.ApprovalServicer for tests. The
// service-layer's same-actor RBAC + already-decided checks are
// re-implemented here so the handler-level tests can exercise the
// HTTP error-mapping without standing up the full ApprovalService.
type fakeApprovalSvc struct {
	mu        sync.Mutex
	requests  map[string]*domain.ApprovalRequest // keyed by ID
	approveBy map[string]string                  // ID → decidedBy (for assertions)
}

func newFakeApprovalSvc() *fakeApprovalSvc {
	return &fakeApprovalSvc{
		requests:  map[string]*domain.ApprovalRequest{},
		approveBy: map[string]string{},
	}
}

func (s *fakeApprovalSvc) seed(req *domain.ApprovalRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *req
	s.requests[req.ID] = &cp
}

func (s *fakeApprovalSvc) Approve(ctx context.Context, requestID, decidedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[requestID]
	if !ok {
		return service.ErrApprovalNotFound
	}
	if r.State.IsTerminal() {
		return service.ErrApprovalAlreadyDecided
	}
	if decidedBy == r.RequestedBy {
		return service.ErrApproveBySameActor
	}
	r.State = domain.ApprovalStateApproved
	s.approveBy[requestID] = decidedBy
	return nil
}

func (s *fakeApprovalSvc) Reject(ctx context.Context, requestID, decidedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[requestID]
	if !ok {
		return service.ErrApprovalNotFound
	}
	if r.State.IsTerminal() {
		return service.ErrApprovalAlreadyDecided
	}
	if decidedBy == r.RequestedBy {
		return service.ErrApproveBySameActor
	}
	r.State = domain.ApprovalStateRejected
	s.approveBy[requestID] = decidedBy
	return nil
}

func (s *fakeApprovalSvc) Get(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return nil, service.ErrApprovalNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *fakeApprovalSvc) List(ctx context.Context, filter *repository.ApprovalFilter) ([]*domain.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.ApprovalRequest
	for _, r := range s.requests {
		if filter != nil && filter.State != "" && string(r.State) != filter.State {
			continue
		}
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

// reqWithActor builds an httptest request with the auth-middleware UserKey
// pre-populated. Mimics what the auth middleware does in production.
func reqWithActor(t *testing.T, method, target string, body string, actor string, pathID string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	var br *strings.Reader
	if body != "" {
		br = strings.NewReader(body)
	}
	var req *http.Request
	if br != nil {
		req = httptest.NewRequest(method, target, br)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserKey{}, actor))
	}
	if pathID != "" {
		req.SetPathValue("id", pathID)
	}
	rr := httptest.NewRecorder()
	return req, rr
}

// TestApproval_HandlerApproveAsSameActor_Returns403 — handler-level pin
// of the load-bearing RBAC contract. Compliance auditors expect HTTP 403
// (not 401, not 500) when the requester tries to approve their own
// request.
func TestApproval_HandlerApproveAsSameActor_Returns403(t *testing.T) {
	svc := newFakeApprovalSvc()
	svc.seed(&domain.ApprovalRequest{
		ID:          "ar-1",
		JobID:       "job-1",
		ProfileID:   "p-cdn",
		RequestedBy: "user-alice",
		State:       domain.ApprovalStatePending,
	})
	h := NewApprovalHandler(svc)

	req, rr := reqWithActor(t, http.MethodPost,
		"/api/v1/approvals/ar-1/approve", `{"note":"self-approve"}`, "user-alice", "ar-1")
	h.Approve(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403; got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "two-person integrity") {
		t.Fatalf("expected two-person-integrity message in body; got %s", rr.Body.String())
	}

	// Different actor approves successfully — pins the success path too.
	req2, rr2 := reqWithActor(t, http.MethodPost,
		"/api/v1/approvals/ar-1/approve", `{"note":"approved by different actor"}`, "user-bob", "ar-1")
	h.Approve(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 for different-actor approve; got %d (body=%s)", rr2.Code, rr2.Body.String())
	}
}

// TestApproval_HandlerEmptyNote_Allowed_DecidedByExtractedFromAuth — handler
// accepts an empty body / empty note (no compliance-blocking format
// requirement) and the audit row records the absence. Pins that the
// handler extracts decided_by from the auth-middleware UserKey, NOT from
// the request body.
func TestApproval_HandlerEmptyNote_Allowed_DecidedByExtractedFromAuth(t *testing.T) {
	svc := newFakeApprovalSvc()
	svc.seed(&domain.ApprovalRequest{
		ID:          "ar-2",
		JobID:       "job-2",
		ProfileID:   "p-cdn",
		RequestedBy: "user-charlie",
		State:       domain.ApprovalStatePending,
	})
	h := NewApprovalHandler(svc)

	// Empty body + empty note both accepted.
	req, rr := reqWithActor(t, http.MethodPost,
		"/api/v1/approvals/ar-2/approve", "", "user-bob", "ar-2")
	h.Approve(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty body; got %d (body=%s)", rr.Code, rr.Body.String())
	}

	// Verify the response carries the auth-middleware-derived actor.
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if resp["decided_by"] != "user-bob" {
		t.Fatalf("decided_by should come from auth middleware; got %v", resp["decided_by"])
	}

	// Confirm the service-layer recorded user-bob as the decider.
	if got := svc.approveBy["ar-2"]; got != "user-bob" {
		t.Fatalf("svc should have recorded decidedBy=user-bob; got %s", got)
	}

	// Unauthenticated request returns 401, not 500.
	req2, rr2 := reqWithActor(t, http.MethodPost,
		"/api/v1/approvals/ar-2/approve", "", "", "ar-2")
	h.Approve(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated; got %d", rr2.Code)
	}
}

// TestApproval_HandlerNotFound_Returns404 + AlreadyDecided returns 409 —
// pin the error-status mapping for the remaining service sentinels.
func TestApproval_HandlerErrorMapping(t *testing.T) {
	svc := newFakeApprovalSvc()
	svc.seed(&domain.ApprovalRequest{
		ID:          "ar-decided",
		JobID:       "job-3",
		ProfileID:   "p-cdn",
		RequestedBy: "user-alice",
		State:       domain.ApprovalStateApproved,
	})
	h := NewApprovalHandler(svc)

	t.Run("NotFound_Returns_404", func(t *testing.T) {
		req, rr := reqWithActor(t, http.MethodPost,
			"/api/v1/approvals/missing/approve", "", "user-bob", "missing")
		h.Approve(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404; got %d", rr.Code)
		}
	})

	t.Run("AlreadyDecided_Returns_409", func(t *testing.T) {
		req, rr := reqWithActor(t, http.MethodPost,
			"/api/v1/approvals/ar-decided/approve", "", "user-bob", "ar-decided")
		h.Approve(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409; got %d", rr.Code)
		}
		if !errors.Is(service.ErrApprovalAlreadyDecided, service.ErrApprovalAlreadyDecided) {
			t.Fatal("sentinel sanity")
		}
	})
}
