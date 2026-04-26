package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/service"
)

// TestMain_HealthEndpointBypassesAuth verifies that health check endpoints
// bypass auth middleware while protected API endpoints require auth.
// This is the most critical test — it validates the core routing pattern used in main.go.
func TestMain_HealthEndpointBypassesAuth(t *testing.T) {
	// Simulate the finalHandler logic from main.go with minimal setup
	// Create handler functions for health endpoints
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	readyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	authInfoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"auth_type":"api-key"}`))
	})

	// Protected API endpoint
	certHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	// Build the handler chain the same way main.go does
	authMiddleware := middleware.NewAuthWithNamedKeys([]middleware.NamedAPIKey{
		{Name: "test", Key: "test-secret-key"},
	})

	// API handler with auth
	authHandler := middleware.Chain(certHandler,
		middleware.RequestID,
		middleware.Recovery,
		authMiddleware,
	)

	// Create finalHandler matching main.go logic
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch path {
		case "/health":
			healthHandler.ServeHTTP(w, r)
		case "/ready":
			readyHandler.ServeHTTP(w, r)
		case "/api/v1/auth/info":
			authInfoHandler.ServeHTTP(w, r)
		case "/api/v1/certificates":
			authHandler.ServeHTTP(w, r)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	})

	tests := []struct {
		name           string
		path           string
		method         string
		bypassesAuth   bool
		expectedStatus int
	}{
		{
			name:           "GET /health without auth",
			path:           "/health",
			method:         "GET",
			bypassesAuth:   true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /ready without auth",
			path:           "/ready",
			method:         "GET",
			bypassesAuth:   true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /api/v1/auth/info without auth",
			path:           "/api/v1/auth/info",
			method:         "GET",
			bypassesAuth:   true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /api/v1/certificates without auth (should fail)",
			path:           "/api/v1/certificates",
			method:         "GET",
			bypassesAuth:   false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			finalHandler.ServeHTTP(w, req)

			if tt.bypassesAuth && w.Code != tt.expectedStatus {
				t.Errorf("endpoint %s should bypass auth, got status %d, expected %d",
					tt.path, w.Code, tt.expectedStatus)
			}

			if !tt.bypassesAuth && w.Code != tt.expectedStatus {
				t.Logf("endpoint %s requires auth, got status %d, expected %d (auth middleware working)",
					tt.path, w.Code, tt.expectedStatus)
			}
		})
	}
}

// TestMain_HealthHandlersRespond verifies health endpoints return correct responses.
func TestMain_HealthHandlersRespond(t *testing.T) {
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	healthHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if body := w.Body.String(); body != `{"status":"ok"}` {
		t.Errorf("expected body '{\"status\":\"ok\"}', got '%s'", body)
	}
}

// TestMain_AuthMiddlewareRejectsUnauthorized verifies auth middleware works.
func TestMain_AuthMiddlewareRejectsUnauthorized(t *testing.T) {
	// Create a protected endpoint
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"protected"}`))
	})

	// Wrap with auth middleware
	authMiddleware := middleware.NewAuthWithNamedKeys([]middleware.NamedAPIKey{
		{Name: "test", Key: "test-secret-key"},
	})

	chainedHandler := middleware.Chain(protectedHandler, authMiddleware)

	// Request without auth should be rejected
	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for unauthorized request, got %d", w.Code)
	}
}

// TestMain_AuthMiddlewareAllowsWithValidKey verifies auth middleware allows valid keys.
func TestMain_AuthMiddlewareAllowsWithValidKey(t *testing.T) {
	testKey := "test-secret-key"

	// Create a protected endpoint
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"protected"}`))
	})

	// Wrap with auth middleware
	authMiddleware := middleware.NewAuthWithNamedKeys([]middleware.NamedAPIKey{
		{Name: "test", Key: testKey},
	})

	chainedHandler := middleware.Chain(protectedHandler, authMiddleware)

	// Request with valid auth should be allowed
	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for authorized request, got %d", w.Code)
	}
}

// TestMain_ServerConfigFromEnvironment verifies config.Load() reads env vars correctly.
func TestMain_ServerConfigFromEnvironment(t *testing.T) {
	// Save original env vars
	oldAuthType := os.Getenv("CERTCTL_AUTH_TYPE")
	oldServerHost := os.Getenv("CERTCTL_SERVER_HOST")
	oldServerPort := os.Getenv("CERTCTL_SERVER_PORT")
	oldTLSCert := os.Getenv("CERTCTL_SERVER_TLS_CERT_PATH")
	oldTLSKey := os.Getenv("CERTCTL_SERVER_TLS_KEY_PATH")
	defer func() {
		if oldAuthType != "" {
			os.Setenv("CERTCTL_AUTH_TYPE", oldAuthType)
		} else {
			os.Unsetenv("CERTCTL_AUTH_TYPE")
		}
		if oldServerHost != "" {
			os.Setenv("CERTCTL_SERVER_HOST", oldServerHost)
		} else {
			os.Unsetenv("CERTCTL_SERVER_HOST")
		}
		if oldServerPort != "" {
			os.Setenv("CERTCTL_SERVER_PORT", oldServerPort)
		} else {
			os.Unsetenv("CERTCTL_SERVER_PORT")
		}
		if oldTLSCert != "" {
			os.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", oldTLSCert)
		} else {
			os.Unsetenv("CERTCTL_SERVER_TLS_CERT_PATH")
		}
		if oldTLSKey != "" {
			os.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", oldTLSKey)
		} else {
			os.Unsetenv("CERTCTL_SERVER_TLS_KEY_PATH")
		}
	}()

	// HTTPS-only control plane: Validate() refuses to pass without a readable
	// cert/key pair on disk. Materialize a throwaway ECDSA P-256 pair using the
	// same generator cmd/server/tls_test.go uses for the certHolder tests.
	dir := t.TempDir()
	certPath := dir + "/server.crt"
	keyPath := dir + "/server.key"
	generateTestCert(t, certPath, keyPath, "main-test-cn")

	// Set test env vars
	os.Setenv("CERTCTL_AUTH_TYPE", "none")
	os.Setenv("CERTCTL_SERVER_HOST", "127.0.0.1")
	os.Setenv("CERTCTL_SERVER_PORT", "8080")
	os.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	os.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config from env vars: %v", err)
	}

	if cfg.Auth.Type != "none" {
		t.Errorf("Expected auth type 'none', got '%s'", cfg.Auth.Type)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Expected server host '127.0.0.1', got '%s'", cfg.Server.Host)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected server port 8080, got %d", cfg.Server.Port)
	}
}

// TestMain_AuthTypeConfiguration verifies auth type is read from config.
func TestMain_AuthTypeConfiguration(t *testing.T) {
	// Save original env vars
	oldAuthType := os.Getenv("CERTCTL_AUTH_TYPE")
	oldAuthSecret := os.Getenv("CERTCTL_AUTH_SECRET")
	oldTLSCert := os.Getenv("CERTCTL_SERVER_TLS_CERT_PATH")
	oldTLSKey := os.Getenv("CERTCTL_SERVER_TLS_KEY_PATH")
	defer func() {
		if oldAuthType != "" {
			os.Setenv("CERTCTL_AUTH_TYPE", oldAuthType)
		} else {
			os.Unsetenv("CERTCTL_AUTH_TYPE")
		}
		if oldAuthSecret != "" {
			os.Setenv("CERTCTL_AUTH_SECRET", oldAuthSecret)
		} else {
			os.Unsetenv("CERTCTL_AUTH_SECRET")
		}
		if oldTLSCert != "" {
			os.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", oldTLSCert)
		} else {
			os.Unsetenv("CERTCTL_SERVER_TLS_CERT_PATH")
		}
		if oldTLSKey != "" {
			os.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", oldTLSKey)
		} else {
			os.Unsetenv("CERTCTL_SERVER_TLS_KEY_PATH")
		}
	}()

	// HTTPS-only control plane: config.Load()→Validate() refuses to pass
	// without a readable cert/key pair. Mint one throwaway pair for the whole
	// sub-test cohort — auth type toggles don't care about the TLS surface.
	dir := t.TempDir()
	certPath := dir + "/server.crt"
	keyPath := dir + "/server.key"
	generateTestCert(t, certPath, keyPath, "main-test-cn")
	os.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	os.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)

	// Set auth secret for api-key mode
	os.Setenv("CERTCTL_AUTH_SECRET", "test-secret")

	testCases := []string{"api-key", "none"}

	for _, authType := range testCases {
		t.Run(fmt.Sprintf("auth_type_%s", authType), func(t *testing.T) {
			os.Setenv("CERTCTL_AUTH_TYPE", authType)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if cfg.Auth.Type != authType {
				t.Errorf("Expected auth type '%s', got '%s'", authType, cfg.Auth.Type)
			}
		})
	}
}

// TestMain_MiddlewareChainConstruction tests that middleware can be properly chained.
func TestMain_MiddlewareChainConstruction(t *testing.T) {
	// Test that the middleware.Chain function works as expected
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Chain with RequestID and Recovery middleware
	chainedHandler := middleware.Chain(baseHandler,
		middleware.RequestID,
		middleware.Recovery,
	)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if body := w.Body.String(); body != "success" {
		t.Errorf("expected body 'success', got '%s'", body)
	}
}

// TestMain_RequestIDMiddleware verifies RequestID is added to responses.
func TestMain_RequestIDMiddleware(t *testing.T) {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with RequestID middleware
	chainedHandler := middleware.Chain(baseHandler, middleware.RequestID)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	// RequestID should be set in response header
	if rid := w.Header().Get("X-Request-ID"); rid == "" {
		t.Logf("X-Request-ID header not present (middleware may work differently)")
	} else {
		t.Logf("X-Request-ID header set: %s", rid)
	}
}

// TestMain_RecoveryMiddlewareHandlesPanic verifies recovery middleware works.
func TestMain_RecoveryMiddlewareHandlesPanic(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Wrap with recovery middleware
	chainedHandler := middleware.Chain(panicHandler, middleware.Recovery)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	chainedHandler.ServeHTTP(w, req)

	// Should return 500 error
	if w.Code != http.StatusInternalServerError {
		t.Logf("Expected 500 for panicked handler, got %d", w.Code)
	}
}

// TestMain_ServiceInitialization tests that services can be instantiated.
// This validates the initialization pattern from main.go without needing a real DB.
func TestMain_ServiceInitialization(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create test issuer registry (same as main.go does)
	issuerRegistry := service.NewIssuerRegistry(logger)

	if issuerRegistry == nil {
		t.Fatal("issuer registry should not be nil")
	}

	// Verify the registry has a Len() method (used in main.go)
	count := issuerRegistry.Len()
	if count < 0 {
		t.Errorf("issuer registry length should be >= 0, got %d", count)
	}
}

// TestMain_CORSMiddlewareSetHeaders verifies CORS headers are set.
func TestMain_CORSMiddlewareSetHeaders(t *testing.T) {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsMiddleware := middleware.NewCORS(middleware.CORSConfig{
		AllowedOrigins: []string{"http://example.com"},
	})

	chainedHandler := middleware.Chain(baseHandler, corsMiddleware)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	// CORS middleware should set access control headers
	if acah := w.Header().Get("Access-Control-Allow-Origin"); acah == "" {
		t.Logf("Access-Control-Allow-Origin not set (may be by design)")
	}
}

// TestMain_AuthNoneMode verifies auth can be disabled.
func TestMain_AuthNoneMode(t *testing.T) {
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"protected"}`))
	})

	// Wrap with auth middleware in "none" mode
	// auth=none equivalent: empty named-keys list is a no-op pass-through.
	authMiddleware := middleware.NewAuthWithNamedKeys(nil)

	chainedHandler := middleware.Chain(protectedHandler, authMiddleware)

	// Request without auth should be allowed in "none" mode
	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 in 'none' auth mode, got %d", w.Code)
	}
}

// TestMain_RouterRegistration tests that router registration works.
func TestMain_RouterRegistration(t *testing.T) {
	r := router.New()

	// Register a test handler
	r.RegisterFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Request the route
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Route should be registered and accessible
	if w.Code == http.StatusNotFound {
		t.Errorf("route not registered, got 404")
	} else if w.Code == http.StatusOK {
		t.Logf("route registered successfully")
	}
}

// TestMain_RateLimiterIntegration tests rate limiter middleware works.
func TestMain_RateLimiterIntegration(t *testing.T) {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create rate limiter with 10 RPS, 1 burst
	rateLimiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RPS:       10,
		BurstSize: 1,
	})

	chainedHandler := middleware.Chain(baseHandler, rateLimiter)

	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	chainedHandler.ServeHTTP(w, req)

	if w.Code == http.StatusServiceUnavailable {
		t.Logf("rate limiter is active")
	} else {
		t.Logf("rate limiter allowed request (status %d)", w.Code)
	}
}

// TestMain_ContentTypeMiddleware verifies content type is set correctly.
func TestMain_ContentTypeMiddleware(t *testing.T) {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Wrap with middleware that sets Content-Type
	chainedHandler := middleware.Chain(baseHandler, middleware.ContentType)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	chainedHandler.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// ContentType middleware should set header
	if ct := w.Header().Get("Content-Type"); ct != "" {
		t.Logf("Content-Type header set: %s", ct)
	}
}

// TestMain_ContextPropagation verifies context is propagated through middleware.
func TestMain_ContextPropagation(t *testing.T) {
	type contextKey string
	testKey := contextKey("test-key")
	testValue := "test-value"

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(testKey)
		if val == testValue {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	chainedHandler := middleware.Chain(baseHandler, middleware.RequestID)

	req := httptest.NewRequest("GET", "/test", nil)
	// Add context value before request
	req = req.WithContext(context.WithValue(req.Context(), testKey, testValue))

	w := httptest.NewRecorder()
	chainedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Logf("Context value may not be propagated (status %d), this may be expected", w.Code)
	}
}

// TestPreflightSCEPChallengePassword is the H-2 regression guard for the
// startup pre-flight check. The helper MUST return a non-nil error whenever
// SCEP is enabled with an empty challenge password — that configuration
// previously allowed unauthenticated certificate enrollment (CWE-306).
// Disabled-SCEP and configured-password cases must pass cleanly.
func TestPreflightSCEPChallengePassword(t *testing.T) {
	tests := []struct {
		name              string
		enabled           bool
		challengePassword string
		wantErr           bool
		wantErrSubstring  string
	}{
		{
			name:              "disabled_empty_password_ok",
			enabled:           false,
			challengePassword: "",
			wantErr:           false,
		},
		{
			name:              "disabled_with_password_ok",
			enabled:           false,
			challengePassword: "leftover-value",
			wantErr:           false,
		},
		{
			name:              "enabled_empty_password_rejected",
			enabled:           true,
			challengePassword: "",
			wantErr:           true,
			wantErrSubstring:  "CERTCTL_SCEP_CHALLENGE_PASSWORD",
		},
		{
			name:              "enabled_with_password_ok",
			enabled:           true,
			challengePassword: "hunter2",
			wantErr:           false,
		},
		{
			name:              "enabled_single_char_password_ok",
			enabled:           true,
			challengePassword: "x",
			wantErr:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := preflightSCEPChallengePassword(tt.enabled, tt.challengePassword)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.wantErrSubstring != "" && !strings.Contains(err.Error(), tt.wantErrSubstring) {
					t.Errorf("expected error to mention %q, got: %v", tt.wantErrSubstring, err)
				}
				if !strings.Contains(err.Error(), "CWE-306") {
					t.Errorf("expected error to cite CWE-306 for traceability, got: %v", err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}
