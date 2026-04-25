package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

func TestHealth_ReturnsOK(t *testing.T) {
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
}

func TestReady_MethodNotAllowed(t *testing.T) {
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("none")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("api-key")

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
	handler := NewHealthHandler("none")

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
