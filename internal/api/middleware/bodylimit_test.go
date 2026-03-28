// Tests for the request body size limit middleware (TICKET-010).
// Covers under/over/exact limit, nil body, default size, GET requests,
// and custom limits.
package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyLimit_UnderLimit(t *testing.T) {
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 1024})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("unexpected read error: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		}),
	)

	body := bytes.NewReader([]byte("small body"))
	req := httptest.NewRequest(http.MethodPost, "/test", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_OverLimit(t *testing.T) {
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 10})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			if err != nil {
				// MaxBytesReader returns an error when limit exceeded
				http.Error(w, `{"error":"Request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	)

	body := bytes.NewReader([]byte("this body exceeds ten bytes"))
	req := httptest.NewRequest(http.MethodPost, "/test", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimit_ExactLimit(t *testing.T) {
	data := "exactly10!" // 10 bytes
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 10})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"error":"Request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(data))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_NilBody(t *testing.T) {
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 1024})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_DefaultSize(t *testing.T) {
	// When MaxBytes is 0, should use default (1MB)
	mw := NewBodyLimit(BodyLimitConfig{MaxBytes: 0})

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	body := bytes.NewReader([]byte("test"))
	req := httptest.NewRequest(http.MethodPost, "/test", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_GETRequest_NoBody(t *testing.T) {
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 10})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_ContentLengthZero(t *testing.T) {
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: 10})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.ContentLength = 0
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_CustomMaxBytes(t *testing.T) {
	// Test with 512KB limit
	const maxSize = 512 * 1024
	handler := NewBodyLimit(BodyLimitConfig{MaxBytes: maxSize})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"error":"Request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			w.Header().Set("Content-Length", string(rune(len(body))))
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Create a body just under the limit
	bodyData := make([]byte, maxSize-1)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(bodyData))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for body just under limit", w.Code, http.StatusOK)
	}
}
