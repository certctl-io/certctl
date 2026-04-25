package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// agentRetireTestSetup builds an AgentHandler with a mock AgentService whose
// RetireAgent / ListRetiredAgents / Heartbeat behavior is driven by the
// returned mock. Keeps every I-004 handler test self-contained so a single
// failing assertion can't cascade through a shared fixture.
func agentRetireTestSetup() (*MockAgentService, AgentHandler) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock)
	return mock, handler
}

// TestRetireAgentHandler_Success_200 pins the happy-path contract for the
// soft-retirement HTTP surface: DELETE /api/v1/agents/{id} with no dependency
// fallout returns 200 OK and a JSON body echoing retirement metadata
// (retired_at timestamp, already_retired=false, cascade=false, zero counts).
// Operators building dashboards parse these fields; keep the shape stable.
func TestRetireAgentHandler_Success_200(t *testing.T) {
	retiredAt := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	mock, handler := agentRetireTestSetup()
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		if agentID != "a-prod-001" {
			t.Fatalf("retire handler received agentID=%q want a-prod-001", agentID)
		}
		if force {
			t.Fatalf("retire handler set force=true unexpectedly; default path must be force=false")
		}
		return &service.AgentRetirementResult{
			AlreadyRetired: false,
			Cascade:        false,
			RetiredAt:      retiredAt,
			Counts:         domain.AgentDependencyCounts{},
		}, nil
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/a-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", w.Code, w.Body.String())
	}

	var body struct {
		RetiredAt      time.Time                     `json:"retired_at"`
		AlreadyRetired bool                          `json:"already_retired"`
		Cascade        bool                          `json:"cascade"`
		Counts         domain.AgentDependencyCounts  `json:"counts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode 200 body: %v", err)
	}
	if !body.RetiredAt.Equal(retiredAt) {
		t.Errorf("retired_at=%v want %v", body.RetiredAt, retiredAt)
	}
	if body.AlreadyRetired {
		t.Errorf("already_retired=true want false on clean retire")
	}
	if body.Cascade {
		t.Errorf("cascade=true want false on clean retire")
	}
}

// TestRetireAgentHandler_AlreadyRetired_204 covers the idempotent contract: a
// retire call against an already-retired agent completes with 204 No Content
// (no body). This lets operators safely re-issue the DELETE after a network
// blip without fearing duplicate audit events or state mutations.
func TestRetireAgentHandler_AlreadyRetired_204(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	past := time.Now().Add(-24 * time.Hour)
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		return &service.AgentRetirementResult{
			AlreadyRetired: true,
			Cascade:        false,
			RetiredAt:      past,
			Counts:         domain.AgentDependencyCounts{},
		}, nil
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/a-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s want 204", w.Code, w.Body.String())
	}
	// 204 No Content must have zero body. If anything leaks through, downstream
	// clients (curl scripts, dashboards) break.
	if w.Body.Len() != 0 {
		t.Errorf("204 body=%q want empty", w.Body.String())
	}
}

// TestRetireAgentHandler_Sentinel_403 covers the hard guard against retiring
// any of the four sentinel agents that back discovery sources and the
// network scanner. These IDs are reserved; the handler must surface the
// service-layer ErrAgentIsSentinel as 403 Forbidden regardless of force/reason
// because no operator intent can legitimately retire them.
func TestRetireAgentHandler_Sentinel_403(t *testing.T) {
	sentinels := []string{"server-scanner", "cloud-aws-sm", "cloud-azure-kv", "cloud-gcp-sm"}
	for _, id := range sentinels {
		t.Run(id, func(t *testing.T) {
			mock, handler := agentRetireTestSetup()
			mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
				return nil, service.ErrAgentIsSentinel
			}

			req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/"+id, nil)
			req = req.WithContext(contextWithRequestID())
			w := httptest.NewRecorder()

			handler.RetireAgent(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("sentinel %q status=%d body=%s want 403", id, w.Code, w.Body.String())
			}
		})
	}
}

// TestRetireAgentHandler_NotFound_404 covers the lookup-miss path. Service
// returns a not-found error; handler maps to 404. Keeping the error
// discrimination at the service layer (sentinel errors.Is) rather than string
// matching is the whole point of wrapping.
func TestRetireAgentHandler_NotFound_404(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		// S-2 closure (cat-s6-efc7f6f6bd50): wrap repository.ErrNotFound
		// so the handler's errors.Is dispatch resolves to 404.
		return nil, ErrMockNotFound
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/unknown-id", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s want 404", w.Code, w.Body.String())
	}
}

// TestRetireAgentHandler_Blocked_409_WithCounts covers the preflight-blocked
// path. Service returns *BlockedByDependenciesError wrapping
// ErrBlockedByDependencies; handler unwraps via errors.As, maps to 409, and
// MUST include the counts in the response body so operators know what's
// blocking them. Without counts the 409 is useless — the operator has to
// guess which downstream dependency is holding up the retirement.
func TestRetireAgentHandler_Blocked_409_WithCounts(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	blockCounts := domain.AgentDependencyCounts{
		ActiveTargets:      3,
		ActiveCertificates: 7,
		PendingJobs:        2,
	}
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		return nil, &service.BlockedByDependenciesError{Counts: blockCounts}
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/a-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s want 409", w.Code, w.Body.String())
	}

	var body struct {
		Error   string                       `json:"error"`
		Message string                       `json:"message"`
		Counts  domain.AgentDependencyCounts `json:"counts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body.Counts.ActiveTargets != 3 {
		t.Errorf("counts.active_targets=%d want 3", body.Counts.ActiveTargets)
	}
	if body.Counts.ActiveCertificates != 7 {
		t.Errorf("counts.active_certificates=%d want 7", body.Counts.ActiveCertificates)
	}
	if body.Counts.PendingJobs != 2 {
		t.Errorf("counts.pending_jobs=%d want 2", body.Counts.PendingJobs)
	}
	if body.Message == "" {
		t.Errorf("409 body missing human-readable message; operators need guidance")
	}
}

// TestRetireAgentHandler_Force_NoReason_400 covers the force-escape-hatch
// guardrail: force=true without a non-empty reason must be rejected at the
// handler seam BEFORE the service performs any DB work, because a
// reason-less cascade is unauditable. Service returns ErrForceReasonRequired;
// handler maps to 400.
func TestRetireAgentHandler_Force_NoReason_400(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		if !force {
			t.Fatalf("handler did not forward force=true; force query param was dropped")
		}
		if reason != "" {
			t.Fatalf("handler passed reason=%q; empty reason must reach service for error path", reason)
		}
		return nil, service.ErrForceReasonRequired
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/a-prod-001?force=true", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s want 400", w.Code, w.Body.String())
	}
}

// TestRetireAgentHandler_ForceCascade_200 covers the successful force-cascade
// path: DELETE ?force=true&reason=... → service executes transactional
// cascade → 200 with cascade=true and the pre-cascade counts echoed back so
// the operator's confirmation dialog can show "I just retired N targets,
// M certificates, K pending jobs."
func TestRetireAgentHandler_ForceCascade_200(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	retiredAt := time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC)
	mock.RetireAgentFn = func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
		if !force {
			t.Fatalf("handler did not forward force=true; query-param parsing broken")
		}
		if reason != "decommissioning rack 7" {
			t.Fatalf("handler forwarded reason=%q want %q", reason, "decommissioning rack 7")
		}
		return &service.AgentRetirementResult{
			AlreadyRetired: false,
			Cascade:        true,
			RetiredAt:      retiredAt,
			Counts: domain.AgentDependencyCounts{
				ActiveTargets:      2,
				ActiveCertificates: 5,
				PendingJobs:        1,
			},
		}, nil
	}

	url := "/api/v1/agents/a-prod-001?force=true&reason=decommissioning+rack+7"
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.RetireAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", w.Code, w.Body.String())
	}

	var body struct {
		RetiredAt      time.Time                     `json:"retired_at"`
		AlreadyRetired bool                          `json:"already_retired"`
		Cascade        bool                          `json:"cascade"`
		Counts         domain.AgentDependencyCounts  `json:"counts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode force-cascade 200 body: %v", err)
	}
	if !body.Cascade {
		t.Errorf("cascade=false want true on ?force=true successful retire")
	}
	if body.Counts.ActiveTargets != 2 || body.Counts.ActiveCertificates != 5 || body.Counts.PendingJobs != 1 {
		t.Errorf("counts=%+v want {ActiveTargets:2 ActiveCertificates:5 PendingJobs:1}", body.Counts)
	}
}

// TestHeartbeatHandler_RetiredAgent_410 covers the agent-shutdown signal. A
// retired agent that is still polling must be told its identity is gone
// (410 Gone) rather than offered the normal 200 "recorded" response.
// cmd/agent treats 410 as a terminal signal and exits rather than looping
// forever against a decommissioned identity. Service returns ErrAgentRetired;
// handler maps to 410.
func TestHeartbeatHandler_RetiredAgent_410(t *testing.T) {
	mock, handler := agentRetireTestSetup()
	mock.HeartbeatFn = func(agentID string, metadata *domain.AgentMetadata) error {
		return service.ErrAgentRetired
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/heartbeat", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("heartbeat(retired) status=%d body=%s want 410", w.Code, w.Body.String())
	}
}

// TestListRetiredAgentsHandler_Success covers the audit/forensics-facing
// endpoint GET /api/v1/agents/retired. Returns a paged list of retired rows
// alongside total count so the GUI can render a "Retired Agents" tab with
// pagination. Default listing (GET /agents) hides retired rows; this is the
// opt-in surface for them.
func TestListRetiredAgentsHandler_Success(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	reason := "old hardware"
	retired := []domain.Agent{
		{
			ID:            "agent-retired-01",
			Name:          "decom-01",
			Hostname:      "server-old",
			Status:        domain.AgentStatusOffline,
			RegisteredAt:  past,
			RetiredAt:     &past,
			RetiredReason: &reason,
		},
	}

	mock, handler := agentRetireTestSetup()
	mock.ListRetiredAgentsFn = func(page, perPage int) ([]domain.Agent, int64, error) {
		if page != 1 || perPage != 50 {
			t.Fatalf("ListRetired handler received page=%d perPage=%d want 1/50 defaults", page, perPage)
		}
		return retired, 1, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/retired", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListRetiredAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", w.Code, w.Body.String())
	}

	var response PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode list-retired body: %v", err)
	}
	if response.Total != 1 {
		t.Errorf("total=%d want 1", response.Total)
	}
}

// TestRetireAgentHandler_MethodNotAllowed covers defense-in-depth: only
// DELETE is valid on /api/v1/agents/{id} for retirement. Using POST/PUT/PATCH
// must be rejected with 405 so misconfigured callers don't accidentally
// trigger retirement via a wrong-method request.
func TestRetireAgentHandler_MethodNotAllowed(t *testing.T) {
	_, handler := agentRetireTestSetup()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/agents/a-prod-001", nil)
			req = req.WithContext(contextWithRequestID())
			w := httptest.NewRecorder()

			handler.RetireAgent(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("method=%s status=%d want 405", method, w.Code)
			}
		})
	}
}

// Compile-time asserts: the mock must satisfy the handler's AgentService
// interface. Red state: this fails until the interface grows RetireAgent +
// ListRetiredAgents. Once Phase 2b adds those methods to AgentService, this
// assertion goes green along with every test above.
var _ AgentService = (*MockAgentService)(nil)

// Unused-import suppressor for context — the package-level tests already
// pull context from agent_handler_test.go, but leaving this here documents
// that the mock methods receive context.Context values even though this
// file's tests don't construct them directly (they ride on httptest.NewRequest).
var _ = context.Background
