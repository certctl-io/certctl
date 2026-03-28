package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuth_MultiKeyAcceptsBothKeys(t *testing.T) {
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "key-one,key-two",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First key should work
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req1.Header.Set("Authorization", "Bearer key-one")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("expected 200 for first key, got %d", rr1.Code)
	}

	// Second key should work
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req2.Header.Set("Authorization", "Bearer key-two")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 for second key, got %d", rr2.Code)
	}
}

func TestNewAuth_MultiKeyRejectsInvalidKey(t *testing.T) {
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "key-one,key-two",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Invalid key should be rejected
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid key, got %d", rr.Code)
	}
}

func TestNewAuth_MultiKeyWithSpaces(t *testing.T) {
	// Keys with leading/trailing spaces should be trimmed
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: " key-one , key-two ",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer key-one")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for trimmed key, got %d", rr.Code)
	}
}

func TestNewAuth_SingleKeyStillWorks(t *testing.T) {
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "my-single-key",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer my-single-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for single key, got %d", rr.Code)
	}
}

func TestNewAuth_NoneMode(t *testing.T) {
	cfg := AuthConfig{
		Type:   "none",
		Secret: "",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No auth header needed in none mode
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 in none mode, got %d", rr.Code)
	}
}

func TestNewAuth_MissingAuthHeader(t *testing.T) {
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "test-key",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth, got %d", rr.Code)
	}
}

func TestNewAuth_InvalidBearerFormat(t *testing.T) {
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "test-key",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-Bearer auth, got %d", rr.Code)
	}
}

func TestNewAuth_RemovedKeyIsRejected(t *testing.T) {
	// Simulate key rotation: only key-two is configured (key-one was removed)
	cfg := AuthConfig{
		Type:   "api-key",
		Secret: "key-two",
	}

	mw := NewAuth(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Old key should be rejected
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer key-one")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for removed key, got %d", rr.Code)
	}

	// New key should work
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req2.Header.Set("Authorization", "Bearer key-two")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 for current key, got %d", rr2.Code)
	}
}
