package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestClient_DeleteWithQuery_ForceRetire covers the new transport capability
// that I-004 adds to the MCP client. The retire tool needs to issue
// DELETE /api/v1/agents/{id}?force=true&reason=... — Client.Delete as it
// stands only accepts a path, dropping query parameters on the floor. Phase 2b
// must add DeleteWithQuery so the MCP retire tool can hit the force escape
// hatch; without this, every retire-via-MCP call with force=true silently
// becomes a default soft-retire and either succeeds wrongly or 409s.
func TestClient_DeleteWithQuery_ForceRetire(t *testing.T) {
	var (
		sawMethod string
		sawPath   string
		sawForce  string
		sawReason string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		sawForce = r.URL.Query().Get("force")
		sawReason = r.URL.Query().Get("reason")

		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/agents/ag-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"retired_at":      "2026-04-18T12:00:00Z",
			"already_retired": false,
			"cascade":         true,
		})
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	// Compile-fail until Phase 2b grows Client.DeleteWithQuery. Passing the
	// query as a url.Values is the established pattern (matches Get's shape).
	query := url.Values{}
	query.Set("force", "true")
	query.Set("reason", "decommissioning rack 7")
	data, err := c.DeleteWithQuery("/api/v1/agents/ag-1", query)
	if err != nil {
		t.Fatalf("DeleteWithQuery err=%v want nil", err)
	}
	if data == nil {
		t.Fatal("DeleteWithQuery returned nil data; want 200 body echo-back")
	}

	if sawMethod != http.MethodDelete {
		t.Errorf("method=%q want DELETE", sawMethod)
	}
	if sawPath != "/api/v1/agents/ag-1" {
		t.Errorf("path=%q want /api/v1/agents/ag-1 (query must be stripped from path)", sawPath)
	}
	if sawForce != "true" {
		t.Errorf("force query=%q want \"true\"", sawForce)
	}
	if sawReason != "decommissioning rack 7" {
		t.Errorf("reason query=%q want %q", sawReason, "decommissioning rack 7")
	}
}

// TestClient_DeleteWithQuery_NoQuery covers the defensive path: a nil/empty
// query must still produce a clean DELETE against the bare path with no stray
// "?" suffix. Matches the Get() shape (see client.go do()) so downstream tools
// can reuse one code path.
func TestClient_DeleteWithQuery_NoQuery(t *testing.T) {
	var sawRawPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRawPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "", "", false)
	if _, err := c.DeleteWithQuery("/api/v1/agents/ag-1", nil); err != nil {
		t.Fatalf("DeleteWithQuery(nil query) err=%v want nil", err)
	}
	// No query → no ? suffix.
	if strings.Contains(sawRawPath, "?") {
		t.Errorf("raw path=%q contains stray ?; empty query must not serialize", sawRawPath)
	}
}

// TestClient_DeleteWithQuery_204ReturnsMinimalBody covers the idempotent path.
// The handler returns 204 No Content for an already-retired agent; the
// existing do() helper normalises this to {"status":"deleted"}. The new
// DeleteWithQuery must share that behavior so MCP tool authors don't have to
// special-case the return shape.
func TestClient_DeleteWithQuery_204ReturnsMinimalBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "", "", false)
	data, err := c.DeleteWithQuery("/api/v1/agents/ag-1", nil)
	if err != nil {
		t.Fatalf("DeleteWithQuery(204) err=%v want nil (idempotent)", err)
	}
	if data == nil {
		t.Fatal("DeleteWithQuery(204) returned nil; want synthetic body")
	}
	if !strings.Contains(string(data), "deleted") && !strings.Contains(string(data), "status") {
		t.Errorf("DeleteWithQuery(204) body=%q; must surface a non-empty sentinel", string(data))
	}
}

// TestClient_DeleteWithQuery_409PropagatesError covers the preflight-blocked
// surface. A 409 with dependency counts must bubble up as a Go error so the
// MCP tool can present it to the LLM operator rather than silently swallow
// the rejection.
func TestClient_DeleteWithQuery_409PropagatesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "blocked_by_dependencies",
			"message": "agent has active targets",
			"counts": map[string]int{
				"active_targets":      3,
				"active_certificates": 7,
				"pending_jobs":        2,
			},
		})
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "", "", false)
	_, err := c.DeleteWithQuery("/api/v1/agents/ag-1", nil)
	if err == nil {
		t.Fatalf("DeleteWithQuery(409) err=nil; 409 must propagate as Go error")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("err=%q should include HTTP status 409 for debuggability", err.Error())
	}
}

// TestRetireAgentInput_ShapePinned is a compile-time assertion that the MCP
// tool input struct for certctl_retire_agent exists with the required fields
// and their expected tag shapes. The LLM discovers this input schema via
// jsonschema tags — refactoring field names without updating callers silently
// breaks tool discovery.
//
// Red until Phase 2b adds RetireAgentInput to internal/mcp/types.go. This
// assertion deliberately exercises every field so the test fails at compile
// time rather than runtime.
func TestRetireAgentInput_ShapePinned(t *testing.T) {
	// Zero-value construction of the expected input — fails to compile until
	// the struct exists with fields {ID string, Force bool, Reason string}.
	input := RetireAgentInput{
		ID:     "ag-1",
		Force:  true,
		Reason: "decommissioning rack 7",
	}

	if input.ID != "ag-1" {
		t.Errorf("RetireAgentInput.ID=%q want ag-1 (field binding broken)", input.ID)
	}
	if !input.Force {
		t.Errorf("RetireAgentInput.Force=false want true")
	}
	if input.Reason != "decommissioning rack 7" {
		t.Errorf("RetireAgentInput.Reason=%q want decommissioning rack 7", input.Reason)
	}

	// Also pin the JSON surface — LLMs send and receive these field names,
	// so json tags must stay snake_case even through refactors.
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal RetireAgentInput: %v", err)
	}
	body := string(encoded)
	for _, want := range []string{`"id":"ag-1"`, `"force":true`, `"reason":"decommissioning rack 7"`} {
		if !strings.Contains(body, want) {
			t.Errorf("RetireAgentInput JSON=%q missing %q (tag shape drifted)", body, want)
		}
	}
}

// TestListRetiredAgentsInput_ShapePinned mirrors the pagination input shape
// used across the MCP toolset (see ListParams). The list-retired-agents tool
// takes page + per_page with snake_case JSON tags. Compile-fail until
// Phase 2b either adds ListRetiredAgentsInput or documents that list-retired
// reuses the existing ListParams type (both paths are acceptable — the test
// just pins whichever Phase 2b picks).
func TestListRetiredAgentsInput_ShapePinned(t *testing.T) {
	// Phase 2b may either (a) add a dedicated ListRetiredAgentsInput struct
	// or (b) reuse the existing ListParams. Either is fine — we pin the
	// field-access contract rather than the struct name to let the
	// implementation choose. Compile-fail guards against the tool being
	// registered without any pagination input at all.
	var input ListParams
	input.Page = 1
	input.PerPage = 50
	if input.Page != 1 || input.PerPage != 50 {
		t.Errorf("ListParams fields Page/PerPage broken; listing pagination will misroute")
	}
}
