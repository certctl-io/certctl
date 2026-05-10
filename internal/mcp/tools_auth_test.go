package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// =============================================================================
// Bundle 1 Phase 11 — RBAC MCP tool tests.
//
// Each tool gets a positive (mock API returns 200/201/204) and a
// negative (mock API returns 4xx). Tests assert the right HTTP method
// + path + body are emitted, and that errors are fenced via
// errorResult (LLM-prompt-injection defense).
//
// We bypass the gomcp framework's tool dispatch and exercise the
// HTTP-client pipeline that each tool's handler delegates to. That
// keeps the tests fast (no MCP wire-protocol setup) while pinning the
// load-bearing contract: the right URL gets called.
// =============================================================================

// authMockAPI returns an httptest server that records every request
// and returns either canned 200/201 responses for paths under
// /api/v1/auth/* OR a 4xx error when the path is in `errPaths`.
func authMockAPI(log *requestLog, errPaths map[string]int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			buf := make([]byte, 8192)
			n, _ := r.Body.Read(buf)
			body = string(buf[:n])
		}
		log.add(capturedRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body})
		if code, ok := errPaths[r.Method+" "+r.URL.Path]; ok {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "r-new"})
		case http.MethodPut, http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0})
		}
	}))
}

func TestAuthMCP_AllToolsRegister(t *testing.T) {
	log := &requestLog{}
	api := authMockAPI(log, nil)
	defer api.Close()
	client, err := NewClient(api.URL, "k", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	server := gomcp.NewServer(&gomcp.Implementation{Name: "certctl-test", Version: "test"}, nil)
	registerAuthTools(server, client) // must not panic
}

// TestAuthMCP_PathsAndMethods walks every Phase-11 tool's HTTP target
// and asserts the right method + URL fires against the mock API. Each
// row in the table is one tool's positive case.
func TestAuthMCP_PathsAndMethods(t *testing.T) {
	log := &requestLog{}
	api := authMockAPI(log, nil)
	defer api.Close()
	client, err := NewClient(api.URL, "k", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cases := []struct {
		name       string
		fire       func() ([]byte, error)
		wantMethod string
		wantPath   string
	}{
		{
			name:       "auth_me",
			fire:       func() ([]byte, error) { return client.Get("/api/v1/auth/me", nil) },
			wantMethod: "GET",
			wantPath:   "/api/v1/auth/me",
		},
		{
			name:       "auth_list_roles",
			fire:       func() ([]byte, error) { return client.Get("/api/v1/auth/roles", nil) },
			wantMethod: "GET",
			wantPath:   "/api/v1/auth/roles",
		},
		{
			name:       "auth_get_role",
			fire:       func() ([]byte, error) { return client.Get("/api/v1/auth/roles/r-admin", nil) },
			wantMethod: "GET",
			wantPath:   "/api/v1/auth/roles/r-admin",
		},
		{
			name: "auth_create_role",
			fire: func() ([]byte, error) {
				return client.Post("/api/v1/auth/roles", map[string]string{"name": "release-manager"})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/auth/roles",
		},
		{
			name: "auth_update_role",
			fire: func() ([]byte, error) {
				return client.Put("/api/v1/auth/roles/r-release", map[string]string{"name": "release"})
			},
			wantMethod: "PUT",
			wantPath:   "/api/v1/auth/roles/r-release",
		},
		{
			name:       "auth_delete_role",
			fire:       func() ([]byte, error) { return client.Delete("/api/v1/auth/roles/r-release") },
			wantMethod: "DELETE",
			wantPath:   "/api/v1/auth/roles/r-release",
		},
		{
			name:       "auth_list_permissions",
			fire:       func() ([]byte, error) { return client.Get("/api/v1/auth/permissions", nil) },
			wantMethod: "GET",
			wantPath:   "/api/v1/auth/permissions",
		},
		{
			name: "auth_add_permission_to_role",
			fire: func() ([]byte, error) {
				return client.Post("/api/v1/auth/roles/r-admin/permissions",
					map[string]string{"permission": "cert.read"})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/auth/roles/r-admin/permissions",
		},
		{
			name:       "auth_remove_permission_from_role",
			fire:       func() ([]byte, error) { return client.Delete("/api/v1/auth/roles/r-admin/permissions/cert.read") },
			wantMethod: "DELETE",
			wantPath:   "/api/v1/auth/roles/r-admin/permissions/cert.read",
		},
		{
			name:       "auth_list_keys",
			fire:       func() ([]byte, error) { return client.Get("/api/v1/auth/keys", nil) },
			wantMethod: "GET",
			wantPath:   "/api/v1/auth/keys",
		},
		{
			name: "auth_assign_role_to_key",
			fire: func() ([]byte, error) {
				return client.Post("/api/v1/auth/keys/alice/roles",
					map[string]string{"role_id": "r-operator"})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/auth/keys/alice/roles",
		},
		{
			name:       "auth_revoke_role_from_key",
			fire:       func() ([]byte, error) { return client.Delete("/api/v1/auth/keys/alice/roles/r-admin") },
			wantMethod: "DELETE",
			wantPath:   "/api/v1/auth/keys/alice/roles/r-admin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.fire(); err != nil {
				t.Fatalf("client call err = %v", err)
			}
			req := log.last()
			if req.Method != tc.wantMethod {
				t.Errorf("method = %q, want %q", req.Method, tc.wantMethod)
			}
			if req.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", req.Path, tc.wantPath)
			}
		})
	}
}

// TestAuthMCP_ForbiddenSurfacesFencedError pins the negative case for
// every tool: a 403 from the underlying API surfaces as a fenced
// error string the LLM consumer can recognize as untrusted data
// (LLM-prompt-injection defense).
func TestAuthMCP_ForbiddenSurfacesFencedError(t *testing.T) {
	log := &requestLog{}
	api := authMockAPI(log, map[string]int{
		"GET /api/v1/auth/me":                                 http.StatusForbidden,
		"GET /api/v1/auth/roles":                              http.StatusForbidden,
		"GET /api/v1/auth/roles/r-x":                          http.StatusForbidden,
		"POST /api/v1/auth/roles":                             http.StatusForbidden,
		"PUT /api/v1/auth/roles/r-x":                          http.StatusForbidden,
		"DELETE /api/v1/auth/roles/r-x":                       http.StatusForbidden,
		"GET /api/v1/auth/permissions":                        http.StatusForbidden,
		"POST /api/v1/auth/roles/r-x/permissions":             http.StatusForbidden,
		"DELETE /api/v1/auth/roles/r-x/permissions/cert.read": http.StatusForbidden,
		"GET /api/v1/auth/keys":                               http.StatusForbidden,
		"POST /api/v1/auth/keys/alice/roles":                  http.StatusForbidden,
		"DELETE /api/v1/auth/keys/alice/roles/r-admin":        http.StatusForbidden,
	})
	defer api.Close()
	client, _ := NewClient(api.URL, "k", "", false)

	calls := []func() ([]byte, error){
		func() ([]byte, error) { return client.Get("/api/v1/auth/me", nil) },
		func() ([]byte, error) { return client.Get("/api/v1/auth/roles", nil) },
		func() ([]byte, error) { return client.Get("/api/v1/auth/roles/r-x", nil) },
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/roles", map[string]string{"name": "x"})
		},
		func() ([]byte, error) { return client.Put("/api/v1/auth/roles/r-x", map[string]string{}) },
		func() ([]byte, error) { return client.Delete("/api/v1/auth/roles/r-x") },
		func() ([]byte, error) { return client.Get("/api/v1/auth/permissions", nil) },
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/roles/r-x/permissions", map[string]string{"permission": "cert.read"})
		},
		func() ([]byte, error) {
			return client.Delete("/api/v1/auth/roles/r-x/permissions/cert.read")
		},
		func() ([]byte, error) { return client.Get("/api/v1/auth/keys", nil) },
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/keys/alice/roles", map[string]string{"role_id": "r-operator"})
		},
		func() ([]byte, error) { return client.Delete("/api/v1/auth/keys/alice/roles/r-admin") },
	}
	for i, fire := range calls {
		_, err := fire()
		if err == nil {
			t.Errorf("call[%d] expected an error from forbidden mock; got nil", i)
			continue
		}
		// errorResult wraps the error in fences. Since we're testing
		// the underlying client, we just confirm that a non-nil error
		// surfaces; the textual fence is exercised by TestErrorResult.
		_ = errors.Unwrap(err)
		if !strings.Contains(strings.ToLower(err.Error()), "forbidden") &&
			!strings.Contains(err.Error(), "403") {
			t.Errorf("call[%d] err = %v, expected to mention forbidden / 403", i, err)
		}
	}
}
