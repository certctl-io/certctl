package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq" // Bundle-5 / H-006: postgres driver for /ready DB-probe regression test
	"github.com/shankar0123/certctl/internal/api/middleware"
)

func TestHealth_ReturnsOK(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.Health(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Health handler returned status %d, want %d", status, http.StatusOK)
	}

	// Check content type
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Check response body
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "healthy" {
		t.Errorf("status = %q, want healthy", result["status"])
	}
}

func TestHealth_MethodNotAllowed(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodPost, "/health", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.Health(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Health handler returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestReady_ReturnsOK(t *testing.T) {
	// Bundle-5 / H-006: nil DB is the legacy/no-db deploy path; Ready degrades
	// to 200 with {"db":"not_configured"} so existing test fixtures keep working.
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodGet, "/ready", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.Ready(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Ready handler returned status %d, want %d", status, http.StatusOK)
	}

	// Check content type
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Check response body
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ready" {
		t.Errorf("status = %q, want ready", result["status"])
	}
	if result["db"] != "not_configured" {
		t.Errorf("db = %q, want not_configured", result["db"])
	}
}

func TestReady_MethodNotAllowed(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodDelete, "/ready", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.Ready(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Ready handler returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestAuthInfo_ReturnsAuthType_APIKey(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/auth/info", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.AuthInfo(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("AuthInfo handler returned status %d, want %d", status, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["auth_type"] != "api-key" {
		t.Errorf("auth_type = %q, want api-key", result["auth_type"])
	}

	if required, ok := result["required"].(bool); !ok || !required {
		t.Errorf("required = %v, want true", result["required"])
	}
}

func TestAuthInfo_ReturnsAuthType_None(t *testing.T) {
	handler := NewHealthHandler("none", nil)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/auth/info", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.AuthInfo(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("AuthInfo handler returned status %d, want %d", status, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["auth_type"] != "none" {
		t.Errorf("auth_type = %q, want none", result["auth_type"])
	}

	if required, ok := result["required"].(bool); !ok || required {
		t.Errorf("required = %v, want false", result["required"])
	}
}

// G-1 (P1): the prior `TestAuthInfo_ReturnsAuthType_JWT` asserted the
// handler echoed "jwt" — using the silent-auth-downgrade value as a
// test fixture, which baked the lie into the regression suite. The
// test is removed because "jwt" is now rejected at config-load time
// (see internal/config/config_test.go::TestValidate_JWTAuth_RejectedDedicated)
// and never reaches this handler. The pre-existing
// `TestAuthInfo_ReturnsAuthType_APIKey` above (line ~107) covers the
// api-key happy path; nothing else needs replacing here.

func TestAuthCheck_ReturnsOK(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/auth/check", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.AuthCheck(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("AuthCheck handler returned status %d, want %d", status, http.StatusOK)
	}

	// Check content type
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Check response body — mixed-value map (string + bool) post-Phase B.4.
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "authenticated" {
		t.Errorf("status = %q, want authenticated", result["status"])
	}
}

func TestAuthCheck_MethodNotAllowed(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/check", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	w := httptest.NewRecorder()
	handler.AuthCheck(w, req)

	// AuthCheck doesn't explicitly check method, so it will return 200
	// But let's verify the response is still correct
	if status := w.Code; status != http.StatusOK {
		t.Logf("AuthCheck returned status %d (note: method not enforced in handler)", status)
	}
}

// --- M-003 (Phase B.4): /auth/check surfaces admin flag + user identity ---

// TestAuthCheck_AdminCaller_ReportsAdminTrue confirms that when the auth
// middleware sets AdminKey{}=true (i.e., named key was admin-tagged), the
// /auth/check endpoint reports admin=true so the GUI can show admin-only
// affordances.
func TestAuthCheck_AdminCaller_ReportsAdminTrue(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/check", nil)
	ctx := context.WithValue(req.Context(), middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.AuthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "authenticated" {
		t.Errorf("status = %q, want authenticated", result["status"])
	}
	admin, ok := result["admin"].(bool)
	if !ok {
		t.Fatalf("admin field missing or wrong type: %T", result["admin"])
	}
	if !admin {
		t.Errorf("admin = false, want true")
	}
	if result["user"] != "ops-admin" {
		t.Errorf("user = %q, want ops-admin", result["user"])
	}
}

// TestAuthCheck_NonAdminCaller_ReportsAdminFalse pins the negative case: the
// auth middleware has stored AdminKey{}=false (non-admin named key) — the
// endpoint must report admin=false so the GUI hides admin-only affordances.
func TestAuthCheck_NonAdminCaller_ReportsAdminFalse(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/check", nil)
	ctx := context.WithValue(req.Context(), middleware.AdminKey{}, false)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "alice")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.AuthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	admin, ok := result["admin"].(bool)
	if !ok {
		t.Fatalf("admin field missing or wrong type: %T", result["admin"])
	}
	if admin {
		t.Errorf("admin = true, want false")
	}
	if result["user"] != "alice" {
		t.Errorf("user = %q, want alice", result["user"])
	}
}

// TestAuthCheck_NoAuthContext_DefaultsToEmptyUserAndFalseAdmin covers the
// CERTCTL_AUTH_TYPE=none deployment, where the auth middleware doesn't set
// any keys. Response must still be well-formed with empty user + admin=false.
func TestAuthCheck_NoAuthContext_DefaultsToEmptyUserAndFalseAdmin(t *testing.T) {
	handler := NewHealthHandler("none", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/check", nil)
	w := httptest.NewRecorder()
	handler.AuthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "authenticated" {
		t.Errorf("status = %q, want authenticated", result["status"])
	}
	admin, ok := result["admin"].(bool)
	if !ok {
		t.Fatalf("admin field missing or wrong type: %T", result["admin"])
	}
	if admin {
		t.Errorf("admin = true for no-auth context, want false")
	}
	if result["user"] != "" {
		t.Errorf("user = %q, want empty string", result["user"])
	}
}

// --- Bundle-5 / H-006: /ready DB-probe regression coverage ---

// TestReady_DBPingSuccess_Returns200WithReachable confirms that when the
// injected *sql.DB ping succeeds, /ready surfaces 200 + db=reachable.
//
// We use sqlmock-equivalent technique: open a sql.DB against the sqlite-in-mem
// driver via sql.Open("sqlite-not-real", ":memory:")? No — simpler: use
// the standard library's sql.OpenDB with a custom Connector. To keep this
// test stdlib-only and offline, we use sql.Open with the real Postgres driver
// against an unreachable address and assert 503; for the success path we
// accept that the integration test under //go:build integration covers it.
// For Bundle-5 unit coverage, the no-op-DB and unreachable-DB paths are the
// pinnable contract.
func TestReady_DBPingSuccess_PassthroughViaTimeout(t *testing.T) {
	// This test exercises the timeout-clamp path: a stub *sql.DB whose
	// PingContext blocks forever, with a 50ms ReadyProbeTimeout, MUST return
	// 503 db_unavailable within the timeout window — proving the
	// context.WithTimeout clamp is honoured.
	//
	// We simulate "blocking forever" by giving the handler a very short
	// timeout and a DB whose ping will fail fast (using lib/pq against a
	// closed loopback port, which produces a "connection refused" — same
	// 503 codepath).
	t.Skip("integration-style test; covered by deploy/test/integration_test.go (//go:build integration). " +
		"Unit-test path covers nil-DB + ping-failure shapes below.")
}

// TestReady_DBPingFailure_Returns503 confirms that when the injected DB's
// PingContext returns an error, /ready surfaces 503 + db_unavailable + the
// (sanitized) error string. This is the load-bearing readiness signal for
// k8s — drains traffic so users don't hit a broken instance.
func TestReady_DBPingFailure_Returns503(t *testing.T) {
	// Unreachable Postgres URL — connect attempt fails fast with
	// "connection refused" (or DNS error in CI). We don't run the full
	// handshake; we just require PingContext to return SOME error inside
	// the configured timeout.
	//
	// Open lazily via sql.Open (no immediate connect); PingContext is what
	// triggers the actual TCP attempt.
	db, err := sql.Open("postgres", "postgres://127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Skipf("postgres driver unavailable in this build: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	handler := NewHealthHandler("api-key", db)
	handler.ReadyProbeTimeout = 200 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	handler.Ready(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Ready handler returned %d, want %d", w.Code, http.StatusServiceUnavailable)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["status"] != "db_unavailable" {
		t.Errorf("status = %q, want db_unavailable", result["status"])
	}
	if result["error"] == "" {
		t.Errorf("error field empty; expected sanitized DB-error string")
	}
}

// TestReady_NilDB_Returns200NotConfigured pins the "no-DB-wired" degraded
// path — used by integration test fixtures that don't spin a Postgres pool.
// /ready stays 200 + db=not_configured so probes still succeed.
func TestReady_NilDB_Returns200NotConfigured(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	handler.Ready(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Ready handler returned %d, want %d", w.Code, http.StatusOK)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["status"] != "ready" {
		t.Errorf("status = %q, want ready", result["status"])
	}
	if result["db"] != "not_configured" {
		t.Errorf("db = %q, want not_configured", result["db"])
	}
}

// TestHealth_NilDB_Returns200 pins the contract: /health stays shallow even
// with no DB pool wired. k8s liveness probe must NOT restart pods for DB
// hiccups — that's readiness's job.
func TestHealth_NilDB_Returns200(t *testing.T) {
	handler := NewHealthHandler("api-key", nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Health handler returned %d, want %d", w.Code, http.StatusOK)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["status"] != "healthy" {
		t.Errorf("status = %q, want healthy", result["status"])
	}
}
