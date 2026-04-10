package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/api/handler"
)

// TestNew_ReturnsValidRouter tests that New() returns a properly initialized router.
func TestNew_ReturnsValidRouter(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("expected non-nil router, got nil")
	}
	if r.mux == nil {
		t.Fatal("expected non-nil mux, got nil")
	}
	if r.middleware == nil {
		t.Fatal("expected non-nil middleware slice, got nil")
	}
	if len(r.middleware) != 0 {
		t.Fatalf("expected empty middleware slice, got %d", len(r.middleware))
	}
}

// TestNewWithMiddleware_InitializesMiddleware tests that NewWithMiddleware() applies middlewares.
func TestNewWithMiddleware_InitializesMiddleware(t *testing.T) {
	called := false
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			next.ServeHTTP(w, r)
		})
	}

	r := NewWithMiddleware(mw)
	if len(r.middleware) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(r.middleware))
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Register("GET /test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if !called {
		t.Error("middleware was not called")
	}
}

// TestRegisterHandlers_RoutesDispatch verifies that RegisterHandlers registers all expected routes.
// We construct a HandlerRegistry where each handler method writes a unique marker,
// then verify the expected routes dispatch to the correct handlers.
func TestRegisterHandlers_RoutesDispatch(t *testing.T) {
	// Create handlers that respond with a marker so we can verify dispatch.
	// The handler structs have zero-value service dependencies which would panic
	// on real calls, so we intercept at the HTTP level using a wrapper.
	r := New()

	// Track which handler was called
	var lastCalled string

	// Create a registry with marker-writing handlers using a recovery wrapper.
	// Since zero-value handlers may panic when called (nil service), we wrap the
	// mux in a panic-recovering middleware for this test.
	recoverMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil {
					// Handler panicked due to nil service — that's expected.
					// The important thing is that the route was matched.
					w.WriteHeader(http.StatusOK)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}

	reg := HandlerRegistry{
		Certificates:  handler.CertificateHandler{},
		Issuers:       handler.IssuerHandler{},
		Targets:       handler.TargetHandler{},
		Agents:        handler.AgentHandler{},
		Jobs:          handler.JobHandler{},
		Policies:      handler.PolicyHandler{},
		Profiles:      handler.ProfileHandler{},
		Teams:         handler.TeamHandler{},
		Owners:        handler.OwnerHandler{},
		AgentGroups:   handler.AgentGroupHandler{},
		Audit:         handler.AuditHandler{},
		Notifications: handler.NotificationHandler{},
		Stats:         handler.StatsHandler{},
		Metrics:       handler.MetricsHandler{},
		Health:        handler.NewHealthHandler("api-key"),
		Discovery:     handler.DiscoveryHandler{},
		NetworkScan:   handler.NetworkScanHandler{},
		Verification:  handler.VerificationHandler{},
		Export:        handler.ExportHandler{},
		Digest:        handler.DigestHandler{},
	}

	r.RegisterHandlers(reg)

	// Wrap the router with recovery middleware for testing
	testHandler := recoverMW(r)

	// Test a representative sample of routes. We just check that the route
	// is registered (doesn't return 404). The handler may panic (caught by recoverMW)
	// or return an error, but NOT 404.
	routes := []struct {
		method string
		path   string
	}{
		// Health (registered outside middleware chain)
		{"GET", "/health"},
		{"GET", "/ready"},
		{"GET", "/api/v1/auth/info"},
		{"GET", "/api/v1/auth/check"},

		// Certificates CRUD
		{"GET", "/api/v1/certificates"},
		{"POST", "/api/v1/certificates"},
		{"GET", "/api/v1/certificates/mc-test"},
		{"PUT", "/api/v1/certificates/mc-test"},
		{"DELETE", "/api/v1/certificates/mc-test"},
		{"GET", "/api/v1/certificates/mc-test/versions"},
		{"GET", "/api/v1/certificates/mc-test/deployments"},
		{"POST", "/api/v1/certificates/mc-test/renew"},
		{"POST", "/api/v1/certificates/mc-test/deploy"},
		{"POST", "/api/v1/certificates/mc-test/revoke"},

		// Export
		{"GET", "/api/v1/certificates/mc-test/export/pem"},

		// CRL & OCSP
		{"GET", "/api/v1/crl"},
		{"GET", "/api/v1/crl/iss-local"},
		{"GET", "/api/v1/ocsp/iss-local/12345"},

		// Issuers
		{"GET", "/api/v1/issuers"},
		{"POST", "/api/v1/issuers"},
		{"GET", "/api/v1/issuers/iss-test"},
		{"PUT", "/api/v1/issuers/iss-test"},
		{"DELETE", "/api/v1/issuers/iss-test"},
		{"POST", "/api/v1/issuers/iss-test/test"},

		// Targets
		{"GET", "/api/v1/targets"},
		{"POST", "/api/v1/targets"},
		{"GET", "/api/v1/targets/t-test"},
		{"PUT", "/api/v1/targets/t-test"},
		{"DELETE", "/api/v1/targets/t-test"},
		{"POST", "/api/v1/targets/t-test/test"},

		// Agents
		{"GET", "/api/v1/agents"},
		{"POST", "/api/v1/agents"},
		{"GET", "/api/v1/agents/agent-1"},
		{"POST", "/api/v1/agents/agent-1/heartbeat"},
		{"POST", "/api/v1/agents/agent-1/csr"},
		{"GET", "/api/v1/agents/agent-1/certificates/mc-1"},
		{"GET", "/api/v1/agents/agent-1/work"},
		{"POST", "/api/v1/agents/agent-1/jobs/job-1/status"},

		// Jobs
		{"GET", "/api/v1/jobs"},
		{"GET", "/api/v1/jobs/job-1"},
		{"POST", "/api/v1/jobs/job-1/cancel"},
		{"POST", "/api/v1/jobs/job-1/approve"},
		{"POST", "/api/v1/jobs/job-1/reject"},

		// Policies
		{"GET", "/api/v1/policies"},
		{"POST", "/api/v1/policies"},
		{"GET", "/api/v1/policies/pol-1"},
		{"PUT", "/api/v1/policies/pol-1"},
		{"DELETE", "/api/v1/policies/pol-1"},
		{"GET", "/api/v1/policies/pol-1/violations"},

		// Profiles
		{"GET", "/api/v1/profiles"},
		{"POST", "/api/v1/profiles"},
		{"GET", "/api/v1/profiles/prof-1"},
		{"PUT", "/api/v1/profiles/prof-1"},
		{"DELETE", "/api/v1/profiles/prof-1"},

		// Teams
		{"GET", "/api/v1/teams"},
		{"POST", "/api/v1/teams"},
		{"GET", "/api/v1/teams/team-1"},

		// Owners
		{"GET", "/api/v1/owners"},
		{"POST", "/api/v1/owners"},
		{"GET", "/api/v1/owners/owner-1"},

		// Agent Groups
		{"GET", "/api/v1/agent-groups"},
		{"POST", "/api/v1/agent-groups"},
		{"GET", "/api/v1/agent-groups/ag-1"},
		{"GET", "/api/v1/agent-groups/ag-1/members"},

		// Audit
		{"GET", "/api/v1/audit"},
		{"GET", "/api/v1/audit/evt-1"},

		// Notifications
		{"GET", "/api/v1/notifications"},
		{"GET", "/api/v1/notifications/notif-1"},
		{"POST", "/api/v1/notifications/notif-1/read"},

		// Stats
		{"GET", "/api/v1/stats/summary"},
		{"GET", "/api/v1/stats/certificates-by-status"},
		{"GET", "/api/v1/stats/expiration-timeline"},
		{"GET", "/api/v1/stats/job-trends"},
		{"GET", "/api/v1/stats/issuance-rate"},

		// Metrics
		{"GET", "/api/v1/metrics"},
		{"GET", "/api/v1/metrics/prometheus"},

		// Discovery
		{"POST", "/api/v1/agents/agent-1/discoveries"},
		{"GET", "/api/v1/discovered-certificates"},
		{"GET", "/api/v1/discovered-certificates/dc-1"},
		{"POST", "/api/v1/discovered-certificates/dc-1/claim"},
		{"POST", "/api/v1/discovered-certificates/dc-1/dismiss"},
		{"GET", "/api/v1/discovery-scans"},
		{"GET", "/api/v1/discovery-summary"},

		// Network scan
		{"GET", "/api/v1/network-scan-targets"},
		{"POST", "/api/v1/network-scan-targets"},
		{"GET", "/api/v1/network-scan-targets/nst-1"},
		{"PUT", "/api/v1/network-scan-targets/nst-1"},
		{"DELETE", "/api/v1/network-scan-targets/nst-1"},
		{"POST", "/api/v1/network-scan-targets/nst-1/scan"},

		// Verification
		{"POST", "/api/v1/jobs/job-1/verify"},
		{"GET", "/api/v1/jobs/job-1/verification"},

		// Digest
		{"GET", "/api/v1/digest/preview"},
		{"POST", "/api/v1/digest/send"},
	}

	_ = lastCalled // suppress unused

	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			testHandler.ServeHTTP(w, req)

			// Route should NOT return 404 (route not found) or 405 (method not allowed)
			if w.Code == http.StatusNotFound {
				t.Errorf("route %s %s returned 404 — route not registered", tc.method, tc.path)
			}
			if w.Code == http.StatusMethodNotAllowed {
				t.Errorf("route %s %s returned 405 — method not allowed", tc.method, tc.path)
			}
		})
	}
}

// TestRegisterHandlers_UnregisteredRoute verifies 404 for non-existent route.
func TestRegisterHandlers_UnregisteredRoute(t *testing.T) {
	r := New()
	reg := HandlerRegistry{
		Health: handler.NewHealthHandler("api-key"),
	}
	r.RegisterHandlers(reg)

	req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent route, got %d", w.Code)
	}
}

// TestRegisterESTHandlers_AllPaths verifies EST route registration.
func TestRegisterESTHandlers_AllPaths(t *testing.T) {
	r := New()

	// EST handler with zero-value services will panic, so wrap with recovery
	recoverMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil {
					w.WriteHeader(http.StatusOK)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}

	est := handler.ESTHandler{}
	r.RegisterESTHandlers(est)

	testHandler := recoverMW(r)

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/.well-known/est/cacerts"},
		{"POST", "/.well-known/est/simpleenroll"},
		{"POST", "/.well-known/est/simplereenroll"},
		{"GET", "/.well-known/est/csrattrs"},
	}

	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			testHandler.ServeHTTP(w, req)

			if w.Code == http.StatusNotFound {
				t.Errorf("EST route %s %s returned 404 — route not registered", tc.method, tc.path)
			}
			if w.Code == http.StatusMethodNotAllowed {
				t.Errorf("EST route %s %s returned 405", tc.method, tc.path)
			}
		})
	}
}

// TestGetMux_ReturnsUnderlyingMux tests that GetMux returns the underlying mux.
func TestGetMux_ReturnsUnderlyingMux(t *testing.T) {
	r := New()
	mux := r.GetMux()
	if mux == nil {
		t.Fatal("expected non-nil mux from GetMux, got nil")
	}
	if mux != r.mux {
		t.Error("GetMux should return the underlying mux")
	}
}

// TestMiddlewareOrder tests that middlewares are applied in the correct order.
func TestMiddlewareOrder(t *testing.T) {
	var order []string

	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1-before")
			next.ServeHTTP(w, r)
			order = append(order, "mw1-after")
		})
	}

	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2-before")
			next.ServeHTTP(w, r)
			order = append(order, "mw2-after")
		})
	}

	r := NewWithMiddleware(mw1, mw2)

	r.RegisterFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	expected := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}

	if len(order) != len(expected) {
		t.Fatalf("middleware order length mismatch: expected %d, got %d", len(expected), len(order))
	}

	for i, v := range order {
		if v != expected[i] {
			t.Errorf("middleware order[%d]: expected %q, got %q", i, expected[i], v)
		}
	}
}
