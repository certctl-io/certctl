package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRecovery_CatchesPanic verifies that panic recovery middleware catches panics
// and returns a 500 error response.
func TestRecovery_CatchesPanic(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	// Verify error response is present
	if w.Body.Len() == 0 {
		t.Error("expected error response body, got empty")
	}
}

// TestRecovery_CatchesNilPanic verifies that recovery middleware handles nil panics.
func TestRecovery_CatchesNilPanic(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is unusual but valid in Go
		panic(nil)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// TestRecovery_NoPanicPasses verifies that non-panicking handlers pass through normally.
func TestRecovery_NoPanicPasses(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "success")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("X-Test") != "success" {
		t.Error("expected custom header to be set")
	}
}

// TestRecovery_StringPanic verifies recovery from string panics.
func TestRecovery_StringPanic(t *testing.T) {
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("string panic message")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// TestRecovery_ErrorPanic verifies recovery from error type panics.
func TestRecovery_ErrorPanic(t *testing.T) {
	testErr := &customError{msg: "test error"}
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(testErr)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// customError is a simple error type for testing.
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}
