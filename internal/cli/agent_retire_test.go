package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClient_RetireAgent_Success pins the I-004 CLI happy path: the operator
// runs `certctl-cli agents retire <id>` and the client issues a DELETE to
// /api/v1/agents/{id}, parses the 200 JSON body (retired_at, already_retired,
// cascade, counts), and reports success. The handler test already covers the
// server-side contract; this test covers the client-side wire formatting so a
// refactor of the server's 200 body shape can't silently break the CLI.
func TestClient_RetireAgent_Success(t *testing.T) {
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

		if r.Method != "DELETE" || r.URL.Path != "/api/v1/agents/ag-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"retired_at":      "2026-04-18T12:00:00Z",
			"already_retired": false,
			"cascade":         false,
			"counts": map[string]interface{}{
				"active_targets":      0,
				"active_certificates": 0,
				"pending_jobs":        0,
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	// Positional arg: the agent ID. No --force, no --reason — the default
	// soft-retire path. Compile-fail until client.RetireAgent exists.
	if err := client.RetireAgent([]string{"ag-1"}); err != nil {
		t.Fatalf("RetireAgent(ag-1) err=%v want nil", err)
	}

	if sawMethod != "DELETE" {
		t.Errorf("method=%q want DELETE", sawMethod)
	}
	if sawPath != "/api/v1/agents/ag-1" {
		t.Errorf("path=%q want /api/v1/agents/ag-1", sawPath)
	}
	if sawForce != "" {
		t.Errorf("force query=%q want empty (default path sends no force)", sawForce)
	}
	if sawReason != "" {
		t.Errorf("reason query=%q want empty (default path sends no reason)", sawReason)
	}
}

// TestClient_RetireAgent_Force_WithReason_Success pins the ?force=true&reason=...
// escape hatch wiring. Operators who supply --force + --reason get their values
// propagated as URL query parameters exactly once, so the server sees the same
// contract the handler test expects. Also verifies the cascade=true response
// body parses cleanly.
func TestClient_RetireAgent_Force_WithReason_Success(t *testing.T) {
	var (
		sawForce  string
		sawReason string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawForce = r.URL.Query().Get("force")
		sawReason = r.URL.Query().Get("reason")

		if r.Method != "DELETE" || r.URL.Path != "/api/v1/agents/ag-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"retired_at":      "2026-04-18T12:00:00Z",
			"already_retired": false,
			"cascade":         true,
			"counts": map[string]interface{}{
				"active_targets":      2,
				"active_certificates": 5,
				"pending_jobs":        1,
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	if err := client.RetireAgent([]string{"ag-1", "--force", "--reason", "decommissioning rack 7"}); err != nil {
		t.Fatalf("RetireAgent(force+reason) err=%v want nil", err)
	}
	if sawForce != "true" {
		t.Errorf("force query=%q want \"true\"", sawForce)
	}
	if sawReason != "decommissioning rack 7" {
		t.Errorf("reason query=%q want %q", sawReason, "decommissioning rack 7")
	}
}

// TestClient_RetireAgent_Force_RequiresReason pins the client-side guard: using
// --force without --reason must fail BEFORE any HTTP request is made. Without
// this, the client would bounce off the server's 400 ErrForceReasonRequired
// only after a round trip — slow feedback, wasted audit-trail noise, and a
// worse operator experience. requestCount=0 enforces that no HTTP call happens.
func TestClient_RetireAgent_Force_RequiresReason(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.RetireAgent([]string{"ag-1", "--force"})
	if err == nil {
		t.Fatalf("RetireAgent(force, no reason) err=nil want client-side error")
	}
	if !containsStr(err.Error(), "reason") {
		t.Errorf("err=%q should mention --reason to guide operator", err.Error())
	}
	if requestCount != 0 {
		t.Fatalf("requestCount=%d want 0; client must short-circuit before HTTP call", requestCount)
	}
}

// TestClient_RetireAgent_MissingID covers the other common operator mistake:
// invoking `certctl-cli agents retire` with no agent ID. Must be caught by the
// client with a clear error, not a malformed DELETE to /api/v1/agents/.
func TestClient_RetireAgent_MissingID(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.RetireAgent([]string{})
	if err == nil {
		t.Fatalf("RetireAgent([]) err=nil want missing-id error")
	}
	if requestCount != 0 {
		t.Fatalf("requestCount=%d want 0; client must reject missing-id before HTTP", requestCount)
	}
}

// TestClient_ListRetiredAgents_Success pins the audit/forensics CLI surface:
// `certctl-cli agents list-retired` must GET /api/v1/agents/retired and render
// the paged response. The server returns a PagedResponse; the client is
// responsible for printing it in table or JSON format, same as ListAgents.
func TestClient_ListRetiredAgents_Success(t *testing.T) {
	var (
		sawMethod string
		sawPath   string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path

		if r.Method != "GET" || r.URL.Path != "/api/v1/agents/retired" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":             "ag-old-01",
					"name":           "decom-01",
					"hostname":       "server-old",
					"status":         "Offline",
					"registered_at":  "2024-01-01T00:00:00Z",
					"retired_at":     "2026-01-01T00:00:00Z",
					"retired_reason": "old hardware",
				},
			},
			"total":    1,
			"page":     1,
			"per_page": 50,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	if err := client.ListRetiredAgents([]string{}); err != nil {
		t.Fatalf("ListRetiredAgents err=%v want nil", err)
	}
	if sawMethod != "GET" {
		t.Errorf("method=%q want GET", sawMethod)
	}
	if sawPath != "/api/v1/agents/retired" {
		t.Errorf("path=%q want /api/v1/agents/retired", sawPath)
	}
}

// TestClient_ListRetiredAgents_ServerError covers the non-happy path: server
// returns 5xx → client surfaces the error rather than silently printing an
// empty list. Without this, operators running the command as part of a
// compliance audit could miss a backend outage.
func TestClient_ListRetiredAgents_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "db unreachable", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ListRetiredAgents([]string{})
	if err == nil {
		t.Fatalf("ListRetiredAgents(500) err=nil want propagated error")
	}
}
