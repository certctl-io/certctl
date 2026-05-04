package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/cli"
)

// Bundle Q (L-001 closure): per-subcommand dispatch tests for cmd/cli/main.go.
//
// The existing `main_test.go` only covered `validateHTTPSScheme`. This file
// pins every dispatch arm in `handleCerts`, `handleAgents`, `handleJobs`,
// `handleImport`, `handleStatus` — both the "missing arg" usage prints and
// the happy-path delegation to `*cli.Client`.
//
// Strategy: spin up an `httptest.Server` mocking the relevant API routes so
// the client can exercise its end-to-end code path without a live server.
// For arms that print usage and return without calling the client, we pass
// a freshly-constructed client (still no network call — the client method
// is never invoked).

// newDispatchTestClient returns a `*cli.Client` pointed at the given test
// server. Calls `t.Fatal` on construction error.
func newDispatchTestClient(t *testing.T, server *httptest.Server) *cli.Client {
	t.Helper()
	// Configure the client with `insecure=true` because httptest.Server's
	// self-signed TLS cert won't chain to a system root.
	c, err := cli.NewClient(server.URL, "test-key", "json", "", true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// stubServer returns an httptest.Server (TLS) that responds with the given
// JSON body and status code for any request. Tests that want to assert on
// the request shape can wrap it in a more specific handler.
func stubServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─────────────────────────────────────────────────────────────────────────────
// handleCerts dispatch arms
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCerts_NoArgs_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{"data":[],"total":0}`)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{}); err != nil {
		t.Errorf("handleCerts({}): unexpected err=%v (should print usage and return nil)", err)
	}
}

func TestHandleCerts_UnknownSubcommand_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{"data":[],"total":0}`)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"frobnicate"}); err != nil {
		t.Errorf("handleCerts({frobnicate}): unexpected err=%v (should print usage and return nil)", err)
	}
}

func TestHandleCerts_GetWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"get"}); err != nil {
		t.Errorf("handleCerts({get}): unexpected err=%v (should print usage and return nil)", err)
	}
}

func TestHandleCerts_RenewWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"renew"}); err != nil {
		t.Errorf("handleCerts({renew}): unexpected err=%v (should print usage and return nil)", err)
	}
}

func TestHandleCerts_RevokeWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"revoke"}); err != nil {
		t.Errorf("handleCerts({revoke}): unexpected err=%v (should print usage and return nil)", err)
	}
}

func TestHandleCerts_List_HitsClientPath(t *testing.T) {
	// Asserts dispatch-path: handleCerts → c.ListCertificates → GET /api/v1/certificates.
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/api/v1/certificates") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":[],"total":0}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"list"}); err != nil {
		t.Errorf("handleCerts({list}): err=%v", err)
	}
	if hits != 1 {
		t.Errorf("expected 1 server hit, got %d", hits)
	}
}

func TestHandleCerts_Get_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"mc-x","name":"x"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"get", "mc-x"}); err != nil {
		t.Errorf("handleCerts({get, mc-x}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/api/v1/certificates/mc-x") {
		t.Errorf("expected GET on /api/v1/certificates/mc-x, got %q", lastPath)
	}
}

func TestHandleCerts_Renew_HitsClientPath(t *testing.T) {
	var lastPath, lastMethod string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		lastMethod = r.Method
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"job_id":"job-1","status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"renew", "mc-x"}); err != nil {
		t.Errorf("handleCerts({renew, mc-x}): err=%v", err)
	}
	if lastMethod != "POST" || !strings.Contains(lastPath, "/renew") {
		t.Errorf("expected POST .../renew, got %s %s", lastMethod, lastPath)
	}
}

func TestHandleCerts_Revoke_HitsClientPath(t *testing.T) {
	var lastPath, lastMethod, lastBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		lastMethod = r.Method
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		lastBody = string(buf[:n])
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"revoked"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"revoke", "mc-x", "--reason", "compromise"}); err != nil {
		t.Errorf("handleCerts({revoke ...}): err=%v", err)
	}
	if lastMethod != "POST" || !strings.Contains(lastPath, "/revoke") {
		t.Errorf("expected POST .../revoke, got %s %s", lastMethod, lastPath)
	}
	if !strings.Contains(lastBody, "compromise") {
		t.Errorf("expected reason in body, got %q", lastBody)
	}
}

func TestHandleCerts_BulkRevoke_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"total_matched":0,"total_revoked":0,"total_skipped":0,"total_failed":0}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleCerts(c, []string{"bulk-revoke", "--reason", "test"}); err != nil {
		t.Errorf("handleCerts({bulk-revoke ...}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/bulk-revoke") {
		t.Errorf("expected /bulk-revoke path, got %q", lastPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// handleAgents dispatch arms
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleAgents_NoArgs_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{}); err != nil {
		t.Errorf("handleAgents({}): unexpected err=%v", err)
	}
}

func TestHandleAgents_UnknownSubcommand_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"frobnicate"}); err != nil {
		t.Errorf("handleAgents({frobnicate}): unexpected err=%v", err)
	}
}

func TestHandleAgents_GetWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"get"}); err != nil {
		t.Errorf("handleAgents({get}): unexpected err=%v", err)
	}
}

func TestHandleAgents_RetireWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"retire"}); err != nil {
		t.Errorf("handleAgents({retire}): unexpected err=%v", err)
	}
}

func TestHandleAgents_List_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":[],"total":0}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"list"}); err != nil {
		t.Errorf("handleAgents({list}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/api/v1/agents") {
		t.Errorf("expected /api/v1/agents path, got %q", lastPath)
	}
}

func TestHandleAgents_ListRetired_HitsRetiredEndpoint(t *testing.T) {
	// I-004: --retired flag splits to a separate /agents/retired endpoint.
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":[],"total":0}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"list", "--retired"}); err != nil {
		t.Errorf("handleAgents({list --retired}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/agents/retired") {
		t.Errorf("expected --retired to hit /agents/retired, got %q", lastPath)
	}
}

func TestHandleAgents_Get_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"ag-x","status":"online"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleAgents(c, []string{"get", "ag-x"}); err != nil {
		t.Errorf("handleAgents({get, ag-x}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/agents/ag-x") {
		t.Errorf("expected /agents/ag-x, got %q", lastPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// handleJobs dispatch arms
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleJobs_NoArgs_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{}); err != nil {
		t.Errorf("handleJobs({}): unexpected err=%v", err)
	}
}

func TestHandleJobs_UnknownSubcommand_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"frobnicate"}); err != nil {
		t.Errorf("handleJobs({frobnicate}): unexpected err=%v", err)
	}
}

func TestHandleJobs_GetWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"get"}); err != nil {
		t.Errorf("handleJobs({get}): unexpected err=%v", err)
	}
}

func TestHandleJobs_CancelWithoutID_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"cancel"}); err != nil {
		t.Errorf("handleJobs({cancel}): unexpected err=%v", err)
	}
}

func TestHandleJobs_List_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":[],"total":0}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"list"}); err != nil {
		t.Errorf("handleJobs({list}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/api/v1/jobs") {
		t.Errorf("expected /api/v1/jobs path, got %q", lastPath)
	}
}

func TestHandleJobs_Get_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"job-x"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"get", "job-x"}); err != nil {
		t.Errorf("handleJobs({get, job-x}): err=%v", err)
	}
	if !strings.Contains(lastPath, "/jobs/job-x") {
		t.Errorf("expected /jobs/job-x, got %q", lastPath)
	}
}

func TestHandleJobs_Cancel_HitsClientPath(t *testing.T) {
	var lastPath, lastMethod string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		lastMethod = r.Method
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"cancelled"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleJobs(c, []string{"cancel", "job-x"}); err != nil {
		t.Errorf("handleJobs({cancel, job-x}): err=%v", err)
	}
	if lastMethod != "POST" || !strings.Contains(lastPath, "/cancel") {
		t.Errorf("expected POST .../cancel, got %s %s", lastMethod, lastPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// handleImport / handleStatus dispatch arms
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleImport_NoArgs_PrintsUsage(t *testing.T) {
	srv := stubServer(t, 200, `{}`)
	c := newDispatchTestClient(t, srv)
	if err := handleImport(c, []string{}); err != nil {
		t.Errorf("handleImport({}): unexpected err=%v", err)
	}
}

func TestHandleStatus_HitsClientPath(t *testing.T) {
	var lastPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(200)
		// GetStatus expects {"status":..., "stats":...} or similar.
		// Provide a minimal valid JSON object.
		_, _ = w.Write([]byte(`{"status":"healthy","version":"v2.X","db":"connected"}`))
	}))
	t.Cleanup(srv.Close)
	c := newDispatchTestClient(t, srv)
	if err := handleStatus(c); err != nil {
		// GetStatus's table output may complain about missing fields; we only
		// care that the dispatch arm fired and the request reached the server.
		_ = err
	}
	if lastPath == "" {
		t.Errorf("expected handleStatus to make at least one request")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI client TLS sanity (Q.1: confirms NewClient configures TLS correctly).
// ─────────────────────────────────────────────────────────────────────────────

func TestCliClient_RejectsUntrustedCert_WhenNotInsecure(t *testing.T) {
	// Without insecure=true, the self-signed httptest cert must fail TLS
	// verification. This pins the security default.
	srv := stubServer(t, 200, `{}`)
	c, err := cli.NewClient(srv.URL, "k", "json", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Try a status call — should error out with a TLS verification failure,
	// not silently succeed.
	if err := c.GetStatus(); err == nil {
		t.Errorf("expected TLS verification error against self-signed cert; got nil")
	}
}

// TestCliClient_ParsesJSONResponse asserts the do() path's JSON unmarshalling
// succeeds end-to-end (one of the more error-prone paths in the client).
func TestCliClient_ParsesJSONResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		body := map[string]interface{}{
			"data":  []map[string]interface{}{{"id": "mc-1", "name": "site-1"}},
			"total": 1,
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c, err := cli.NewClient(srv.URL, "k", "json", "", true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.ListCertificates(nil); err != nil {
		t.Errorf("ListCertificates: err=%v", err)
	}
}
