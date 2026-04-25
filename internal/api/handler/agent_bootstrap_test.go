package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Bundle-5 / Audit H-007 / CWE-306 + CWE-288:
// regression coverage for verifyBootstrapToken — the bootstrap-token gate
// applied to POST /api/v1/agents.

func TestVerifyBootstrapToken_EmptyExpected_PassThrough(t *testing.T) {
	// Warn-mode contract: when the configured token is empty, the helper
	// MUST return nil regardless of what the caller presents — preserves
	// backwards compat with v2.0.x demo deployments.
	cases := []struct {
		name   string
		header string
	}{
		{"no_authorization", ""},
		{"bearer_anything", "Bearer not-the-real-token"},
		{"basic_auth", "Basic dXNlcjpwYXNz"},
		{"malformed", "garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if err := verifyBootstrapToken(req, ""); err != nil {
				t.Errorf("warn-mode pass-through: expected nil, got %v", err)
			}
		})
	}
}

func TestVerifyBootstrapToken_MatchingBearer_Accepts(t *testing.T) {
	expected := "secret-token-with-some-entropy-12345"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+expected)

	if err := verifyBootstrapToken(req, expected); err != nil {
		t.Errorf("matching Bearer: expected nil, got %v", err)
	}
}

func TestVerifyBootstrapToken_MissingHeader_Rejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	err := verifyBootstrapToken(req, "configured-token")
	if !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Errorf("missing Authorization: expected ErrBootstrapTokenInvalid, got %v", err)
	}
}

func TestVerifyBootstrapToken_WrongScheme_Rejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	err := verifyBootstrapToken(req, "configured-token")
	if !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Errorf("wrong scheme: expected ErrBootstrapTokenInvalid, got %v", err)
	}
}

func TestVerifyBootstrapToken_EmptyBearerToken_Rejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer ")
	err := verifyBootstrapToken(req, "configured-token")
	if !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Errorf("empty bearer: expected ErrBootstrapTokenInvalid, got %v", err)
	}
}

func TestVerifyBootstrapToken_WrongToken_Rejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	err := verifyBootstrapToken(req, "configured-token")
	if !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Errorf("wrong token: expected ErrBootstrapTokenInvalid, got %v", err)
	}
}

func TestVerifyBootstrapToken_LengthMismatch_Rejects(t *testing.T) {
	// Different length than expected — must fail. Ensures we don't accidentally
	// short-circuit before the constant-time compare.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer x")
	err := verifyBootstrapToken(req, "much-longer-configured-token-value")
	if !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Errorf("length mismatch: expected ErrBootstrapTokenInvalid, got %v", err)
	}
}

// TestRegisterAgent_BootstrapTokenGate_E2E confirms the handler-level
// integration: when AgentHandler.BootstrapToken is set, requests without
// the matching Bearer header get 401 BEFORE the body is parsed.
func TestRegisterAgent_BootstrapTokenGate_E2E(t *testing.T) {
	// Mock service returns success — proves the 401 path runs BEFORE service.
	mock := &MockAgentService{}
	h := NewAgentHandler(mock, "the-real-token")

	t.Run("missing_token_returns_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
		w := httptest.NewRecorder()
		h.RegisterAgent(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("missing token: expected 401, got %d", w.Code)
		}
	})

	t.Run("wrong_token_returns_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		h.RegisterAgent(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("wrong token: expected 401, got %d", w.Code)
		}
	})
}

// TestRegisterAgent_WarnModeAcceptsWithoutToken confirms the v2.0.x
// backwards-compat path: empty bootstrap-token + no Authorization header
// must NOT 401 — the handler proceeds to body parse / validation.
func TestRegisterAgent_WarnModeAcceptsWithoutToken(t *testing.T) {
	mock := &MockAgentService{}
	h := NewAgentHandler(mock, "") // warn-mode

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	w := httptest.NewRecorder()
	h.RegisterAgent(w, req)
	// Body is empty, so the JSON decode will fail with 400. The point of this
	// test is that we DON'T see 401 — the gate let the request through.
	if w.Code == http.StatusUnauthorized {
		t.Errorf("warn-mode: gate should not reject; got 401")
	}
}
