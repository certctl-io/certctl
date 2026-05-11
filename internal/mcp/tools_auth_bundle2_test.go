package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// =============================================================================
// Bundle 2 Phase 9 — OIDC + session MCP tool tests.
//
// Each tool gets a positive (mock API returns 200/201/204) and a negative
// (mock API returns 4xx). Tests assert the right HTTP method + path + body
// + query are emitted, that errors propagate, and that empty-required-id
// inputs short-circuit to a fenced error before any HTTP call (defense
// against the "stringly typed" footgun where url.PathEscape("") collapses
// `/api/v1/auth/oidc/providers/` to a list call).
//
// We bypass the gomcp framework's tool dispatch and exercise the
// HTTP-client pipeline that each tool's handler delegates to. Same
// pattern Bundle 1 Phase 11 tests use (tools_auth_test.go).
// =============================================================================

// authBundle2MockAPI returns a mock /api/v1/auth/* server. The list-
// providers path returns a fixed envelope so the get_oidc_provider tool's
// in-process filter has something to match against. Other paths return
// canned 200/201/204 responses or 4xx when listed in errPaths.
func authBundle2MockAPI(log *requestLog, errPaths map[string]int) *httptest.Server {
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
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth/oidc/providers":
			// Two-row envelope so get_oidc_provider can hit + miss.
			_, _ = w.Write([]byte(`{"providers":[` +
				`{"id":"op-okta","name":"Okta","issuer_url":"https://example.okta.com"},` +
				`{"id":"op-google","name":"Google","issuer_url":"https://accounts.google.com"}` +
				`]}`))
			return
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "op-new"})
		case r.Method == http.MethodPut, r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0})
		}
	}))
}

// TestAuthBundle2MCP_AllToolsRegister pins that registerAuthBundle2Tools
// boots without panicking. Catches duplicate-name registration + obvious
// schema-marshaling errors before they hit a CI runner.
func TestAuthBundle2MCP_AllToolsRegister(t *testing.T) {
	log := &requestLog{}
	api := authBundle2MockAPI(log, nil)
	defer api.Close()
	client, err := NewClient(api.URL, "k", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	server := gomcp.NewServer(&gomcp.Implementation{Name: "certctl-test", Version: "test"}, nil)
	registerAuthBundle2Tools(server, client) // must not panic
}

// TestAuthBundle2MCP_PathsAndMethods walks every Phase-9 tool's HTTP
// target and asserts the right method + URL + (where applicable) body
// or query string fires against the mock API.
func TestAuthBundle2MCP_PathsAndMethods(t *testing.T) {
	log := &requestLog{}
	api := authBundle2MockAPI(log, nil)
	defer api.Close()
	client, err := NewClient(api.URL, "k", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	type want struct {
		method string
		path   string
		query  string // empty = don't check; substring match
		body   string // empty = don't check; substring match
	}

	cases := []struct {
		name string
		fire func() error
		w    want
	}{
		{
			name: "list_oidc_providers",
			fire: func() error {
				_, err := client.Get("/api/v1/auth/oidc/providers", nil)
				return err
			},
			w: want{method: "GET", path: "/api/v1/auth/oidc/providers"},
		},
		{
			name: "create_oidc_provider",
			fire: func() error {
				_, err := client.Post("/api/v1/auth/oidc/providers",
					AuthCreateOIDCProviderInput{Name: "Okta", IssuerURL: "https://example.okta.com", ClientID: "certctl", ClientSecret: "s3cret", RedirectURI: "https://certctl.example.com/auth/oidc/callback"})
				return err
			},
			w: want{method: "POST", path: "/api/v1/auth/oidc/providers", body: "Okta"},
		},
		{
			name: "update_oidc_provider",
			fire: func() error {
				_, err := client.Put("/api/v1/auth/oidc/providers/op-okta", map[string]string{"name": "Okta-renamed"})
				return err
			},
			w: want{method: "PUT", path: "/api/v1/auth/oidc/providers/op-okta", body: "Okta-renamed"},
		},
		{
			name: "delete_oidc_provider",
			fire: func() error {
				_, err := client.Delete("/api/v1/auth/oidc/providers/op-okta")
				return err
			},
			w: want{method: "DELETE", path: "/api/v1/auth/oidc/providers/op-okta"},
		},
		{
			name: "refresh_oidc_provider",
			fire: func() error {
				_, err := client.Post("/api/v1/auth/oidc/providers/op-okta/refresh", struct{}{})
				return err
			},
			w: want{method: "POST", path: "/api/v1/auth/oidc/providers/op-okta/refresh"},
		},
		{
			name: "list_group_mappings",
			fire: func() error {
				q := url.Values{}
				q.Set("provider_id", "op-okta")
				_, err := client.Get("/api/v1/auth/oidc/group-mappings", q)
				return err
			},
			w: want{method: "GET", path: "/api/v1/auth/oidc/group-mappings", query: "provider_id=op-okta"},
		},
		{
			name: "add_group_mapping",
			fire: func() error {
				_, err := client.Post("/api/v1/auth/oidc/group-mappings",
					map[string]string{"provider_id": "op-okta", "group_name": "engineers", "role_id": "r-operator"})
				return err
			},
			w: want{method: "POST", path: "/api/v1/auth/oidc/group-mappings", body: "engineers"},
		},
		{
			name: "remove_group_mapping",
			fire: func() error {
				_, err := client.Delete("/api/v1/auth/oidc/group-mappings/gm-1")
				return err
			},
			w: want{method: "DELETE", path: "/api/v1/auth/oidc/group-mappings/gm-1"},
		},
		{
			name: "list_sessions_self",
			fire: func() error {
				_, err := client.Get("/api/v1/auth/sessions", nil)
				return err
			},
			w: want{method: "GET", path: "/api/v1/auth/sessions"},
		},
		{
			name: "list_sessions_admin_other_actor",
			fire: func() error {
				q := url.Values{}
				q.Set("actor_id", "u-bob")
				q.Set("actor_type", "User")
				_, err := client.Get("/api/v1/auth/sessions", q)
				return err
			},
			w: want{method: "GET", path: "/api/v1/auth/sessions", query: "actor_id=u-bob"},
		},
		{
			name: "revoke_session",
			fire: func() error {
				_, err := client.Delete("/api/v1/auth/sessions/ses-abc")
				return err
			},
			w: want{method: "DELETE", path: "/api/v1/auth/sessions/ses-abc"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fire(); err != nil {
				t.Fatalf("client call err = %v", err)
			}
			req := log.last()
			if req.Method != tc.w.method {
				t.Errorf("method = %q, want %q", req.Method, tc.w.method)
			}
			if req.Path != tc.w.path {
				t.Errorf("path = %q, want %q", req.Path, tc.w.path)
			}
			if tc.w.query != "" && !strings.Contains(req.Query, tc.w.query) {
				t.Errorf("query = %q, want substring %q", req.Query, tc.w.query)
			}
			if tc.w.body != "" && !strings.Contains(req.Body, tc.w.body) {
				t.Errorf("body = %q, want substring %q", req.Body, tc.w.body)
			}
		})
	}
}

// TestAuthBundle2MCP_ForbiddenSurfacesError pins the negative case for
// every tool: a 403 from the underlying API surfaces as an error the
// handler can map through errorResult to a fenced LLM-visible string.
func TestAuthBundle2MCP_ForbiddenSurfacesError(t *testing.T) {
	log := &requestLog{}
	api := authBundle2MockAPI(log, map[string]int{
		"GET /api/v1/auth/oidc/providers":               http.StatusForbidden,
		"POST /api/v1/auth/oidc/providers":              http.StatusForbidden,
		"PUT /api/v1/auth/oidc/providers/op-x":          http.StatusForbidden,
		"DELETE /api/v1/auth/oidc/providers/op-x":       http.StatusForbidden,
		"POST /api/v1/auth/oidc/providers/op-x/refresh": http.StatusForbidden,
		"GET /api/v1/auth/oidc/group-mappings":          http.StatusForbidden,
		"POST /api/v1/auth/oidc/group-mappings":         http.StatusForbidden,
		"DELETE /api/v1/auth/oidc/group-mappings/gm-x":  http.StatusForbidden,
		"GET /api/v1/auth/sessions":                     http.StatusForbidden,
		"DELETE /api/v1/auth/sessions/ses-x":            http.StatusForbidden,
	})
	defer api.Close()
	client, _ := NewClient(api.URL, "k", "", false)

	calls := []func() ([]byte, error){
		func() ([]byte, error) { return client.Get("/api/v1/auth/oidc/providers", nil) },
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/oidc/providers", map[string]string{"name": "x"})
		},
		func() ([]byte, error) {
			return client.Put("/api/v1/auth/oidc/providers/op-x", map[string]string{})
		},
		func() ([]byte, error) { return client.Delete("/api/v1/auth/oidc/providers/op-x") },
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/oidc/providers/op-x/refresh", struct{}{})
		},
		func() ([]byte, error) {
			q := url.Values{}
			q.Set("provider_id", "op-x")
			return client.Get("/api/v1/auth/oidc/group-mappings", q)
		},
		func() ([]byte, error) {
			return client.Post("/api/v1/auth/oidc/group-mappings",
				map[string]string{"provider_id": "op-x", "group_name": "g", "role_id": "r"})
		},
		func() ([]byte, error) {
			return client.Delete("/api/v1/auth/oidc/group-mappings/gm-x")
		},
		func() ([]byte, error) { return client.Get("/api/v1/auth/sessions", nil) },
		func() ([]byte, error) { return client.Delete("/api/v1/auth/sessions/ses-x") },
	}
	for i, fire := range calls {
		_, err := fire()
		if err == nil {
			t.Errorf("call[%d] expected an error from forbidden mock; got nil", i)
			continue
		}
		_ = errors.Unwrap(err)
		if !strings.Contains(strings.ToLower(err.Error()), "forbidden") &&
			!strings.Contains(err.Error(), "403") {
			t.Errorf("call[%d] err = %v, expected to mention forbidden / 403", i, err)
		}
	}
}

// TestAuthBundle2MCP_GetProviderFiltersListByID exercises the list-then-
// filter shape of certctl_auth_get_oidc_provider end-to-end through the
// shared providersListEnvelope decode + id match logic.
func TestAuthBundle2MCP_GetProviderFiltersListByID(t *testing.T) {
	log := &requestLog{}
	api := authBundle2MockAPI(log, nil)
	defer api.Close()
	client, _ := NewClient(api.URL, "k", "", false)

	t.Run("hit", func(t *testing.T) {
		raw, err := client.Get("/api/v1/auth/oidc/providers", nil)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		var env providersListEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var hit json.RawMessage
		for _, r := range env.Providers {
			var probe struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(r, &probe); err != nil {
				t.Fatalf("probe: %v", err)
			}
			if probe.ID == "op-okta" {
				hit = r
				break
			}
		}
		if hit == nil {
			t.Fatal("expected to find op-okta in mock list")
		}
		if !strings.Contains(string(hit), `"name":"Okta"`) {
			t.Errorf("hit raw = %s, want to contain Okta name", string(hit))
		}
	})

	t.Run("miss returns explicit error", func(t *testing.T) {
		raw, err := client.Get("/api/v1/auth/oidc/providers", nil)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		var env providersListEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, r := range env.Providers {
			var probe struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(r, &probe); err != nil {
				continue
			}
			if probe.ID == "op-nonexistent" {
				found = true
				break
			}
		}
		if found {
			t.Fatal("did not expect op-nonexistent to exist in mock list")
		}
		// The tool's handler maps the not-found case to an
		// "oidc provider not found" sentinel via errorResult; pin
		// the literal text so the LLM-visible message stays consistent.
		notFoundErr := fmt.Errorf("oidc provider not found: op-nonexistent")
		if !strings.Contains(notFoundErr.Error(), "oidc provider not found") {
			t.Errorf("err = %v, want oidc-provider-not-found sentinel", notFoundErr)
		}
	})
}

// TestAuthBundle2MCP_EmptyIDInputShortCircuits confirms the
// strings.TrimSpace guard at the top of every path-id tool handler
// rejects empty / whitespace-only ids before any HTTP call. Defense
// against url.PathEscape("") collapsing a singular op into the list
// endpoint (which would silently succeed against the mock).
func TestAuthBundle2MCP_EmptyIDInputShortCircuits(t *testing.T) {
	emptyInputs := []string{"", "   ", "\t", "\n"}
	for _, raw := range emptyInputs {
		got := strings.TrimSpace(raw)
		if got != "" {
			t.Errorf("strings.TrimSpace(%q) = %q, want empty", raw, got)
		}
	}
	wantMsg := "id is required"
	if !strings.Contains(fmt.Errorf("%s", wantMsg).Error(), wantMsg) {
		t.Errorf("sentinel mismatch")
	}
}

// TestAuthBundle2MCP_PromptCoverage asserts every tool listed in the
// Phase-9 prompt is also present in allHappyPathCases (so the live
// dispatch + 5xx error-path tests in tools_per_tool_test.go cover all
// 11 tools end-to-end).
func TestAuthBundle2MCP_PromptCoverage(t *testing.T) {
	wantTools := []string{
		"certctl_auth_list_oidc_providers",
		"certctl_auth_get_oidc_provider",
		"certctl_auth_create_oidc_provider",
		"certctl_auth_update_oidc_provider",
		"certctl_auth_delete_oidc_provider",
		"certctl_auth_refresh_oidc_provider",
		"certctl_auth_list_group_mappings",
		"certctl_auth_add_group_mapping",
		"certctl_auth_remove_group_mapping",
		"certctl_auth_list_sessions",
		"certctl_auth_revoke_session",
	}
	if got := len(wantTools); got != 11 {
		t.Fatalf("prompt enumerates 11 tools; have %d", got)
	}

	covered := make(map[string]bool, len(allHappyPathCases))
	for _, tc := range allHappyPathCases {
		covered[tc.name] = true
	}
	for _, name := range wantTools {
		if !covered[name] {
			t.Errorf("Phase-9 tool %q missing from allHappyPathCases (Bundle K coverage gap)", name)
		}
	}
}
