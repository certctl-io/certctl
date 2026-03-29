package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockDigestService implements DigestServicer for testing.
type mockDigestService struct {
	previewHTML string
	previewErr  error
	sendErr     error
	sendCalled  bool
}

func (m *mockDigestService) PreviewDigest(ctx context.Context) (string, error) {
	if m.previewErr != nil {
		return "", m.previewErr
	}
	return m.previewHTML, nil
}

func (m *mockDigestService) SendDigest(ctx context.Context) error {
	m.sendCalled = true
	return m.sendErr
}

func TestDigestHandler_PreviewDigest_Success(t *testing.T) {
	svc := &mockDigestService{
		previewHTML: "<html><body>Digest Preview</body></html>",
	}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/digest/preview", nil)
	w := httptest.NewRecorder()

	h.PreviewDigest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type text/html, got %s", w.Header().Get("Content-Type"))
	}

	if w.Body.String() != "<html><body>Digest Preview</body></html>" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestDigestHandler_PreviewDigest_MethodNotAllowed(t *testing.T) {
	svc := &mockDigestService{}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/digest/preview", nil)
	w := httptest.NewRecorder()

	h.PreviewDigest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestDigestHandler_PreviewDigest_ServiceError(t *testing.T) {
	svc := &mockDigestService{
		previewErr: errors.New("stats unavailable"),
	}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/digest/preview", nil)
	w := httptest.NewRecorder()

	h.PreviewDigest(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestDigestHandler_PreviewDigest_NotConfigured(t *testing.T) {
	h := NewDigestHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/digest/preview", nil)
	w := httptest.NewRecorder()

	h.PreviewDigest(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestDigestHandler_SendDigest_Success(t *testing.T) {
	svc := &mockDigestService{}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/digest/send", nil)
	w := httptest.NewRecorder()

	h.SendDigest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if !svc.sendCalled {
		t.Error("expected SendDigest to be called")
	}
}

func TestDigestHandler_SendDigest_MethodNotAllowed(t *testing.T) {
	svc := &mockDigestService{}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/digest/send", nil)
	w := httptest.NewRecorder()

	h.SendDigest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestDigestHandler_SendDigest_ServiceError(t *testing.T) {
	svc := &mockDigestService{
		sendErr: errors.New("SMTP connection refused"),
	}
	h := NewDigestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/digest/send", nil)
	w := httptest.NewRecorder()

	h.SendDigest(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestDigestHandler_SendDigest_NotConfigured(t *testing.T) {
	h := NewDigestHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/digest/send", nil)
	w := httptest.NewRecorder()

	h.SendDigest(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}
