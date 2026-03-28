package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/service"
)

// MockExportService is a mock implementation of ExportService interface.
type MockExportService struct {
	ExportPEMFn    func(ctx context.Context, certID string) (*service.ExportPEMResult, error)
	ExportPKCS12Fn func(ctx context.Context, certID string, password string) ([]byte, error)
}

func (m *MockExportService) ExportPEM(ctx context.Context, certID string) (*service.ExportPEMResult, error) {
	if m.ExportPEMFn != nil {
		return m.ExportPEMFn(ctx, certID)
	}
	return nil, nil
}

func (m *MockExportService) ExportPKCS12(ctx context.Context, certID string, password string) ([]byte, error) {
	if m.ExportPKCS12Fn != nil {
		return m.ExportPKCS12Fn(ctx, certID, password)
	}
	return nil, nil
}

func TestExportPEM_Success(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPEMFn: func(_ context.Context, certID string) (*service.ExportPEMResult, error) {
			if certID != "mc-test-1" {
				t.Errorf("expected certID mc-test-1, got %s", certID)
			}
			return &service.ExportPEMResult{
				CertPEM:  "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
				ChainPEM: "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
				FullPEM:  "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
			}, nil
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-test-1/export/pem", nil)
	w := httptest.NewRecorder()

	h.ExportPEM(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json content type, got %s", ct)
	}

	var result service.ExportPEMResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.CertPEM == "" {
		t.Error("expected non-empty CertPEM")
	}
	if result.ChainPEM == "" {
		t.Error("expected non-empty ChainPEM")
	}
	if result.FullPEM == "" {
		t.Error("expected non-empty FullPEM")
	}
}

func TestExportPEM_Download(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPEMFn: func(_ context.Context, _ string) (*service.ExportPEMResult, error) {
			return &service.ExportPEMResult{
				CertPEM:  "cert",
				ChainPEM: "chain",
				FullPEM:  "full-pem-content",
			}, nil
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-test-1/export/pem?download=true", nil)
	w := httptest.NewRecorder()

	h.ExportPEM(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("expected application/x-pem-file, got %s", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="certificate.pem"` {
		t.Errorf("expected Content-Disposition attachment, got %s", cd)
	}
	if w.Body.String() != "full-pem-content" {
		t.Errorf("expected full-pem-content body, got %s", w.Body.String())
	}
}

func TestExportPEM_NotFound(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPEMFn: func(_ context.Context, _ string) (*service.ExportPEMResult, error) {
			return nil, fmt.Errorf("certificate not found")
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/nonexistent/export/pem", nil)
	w := httptest.NewRecorder()

	h.ExportPEM(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestExportPEM_ServiceError(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPEMFn: func(_ context.Context, _ string) (*service.ExportPEMResult, error) {
			return nil, fmt.Errorf("internal error")
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-test-1/export/pem", nil)
	w := httptest.NewRecorder()

	h.ExportPEM(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestExportPEM_MethodNotAllowed(t *testing.T) {
	h := NewExportHandler(&MockExportService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-test-1/export/pem", nil)
	w := httptest.NewRecorder()

	h.ExportPEM(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestExportPKCS12_Success(t *testing.T) {
	pfxData := []byte{0x30, 0x82, 0x01, 0x00} // mock PKCS#12 data
	mockSvc := &MockExportService{
		ExportPKCS12Fn: func(_ context.Context, certID string, password string) ([]byte, error) {
			if certID != "mc-test-1" {
				t.Errorf("expected certID mc-test-1, got %s", certID)
			}
			if password != "mysecret" {
				t.Errorf("expected password mysecret, got %s", password)
			}
			return pfxData, nil
		},
	}
	h := NewExportHandler(mockSvc)

	body := strings.NewReader(`{"password":"mysecret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-test-1/export/pkcs12", body)
	w := httptest.NewRecorder()

	h.ExportPKCS12(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pkcs12" {
		t.Errorf("expected application/x-pkcs12, got %s", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="certificate.p12"` {
		t.Errorf("expected Content-Disposition attachment, got %s", cd)
	}
	if len(w.Body.Bytes()) != len(pfxData) {
		t.Errorf("expected %d bytes, got %d", len(pfxData), len(w.Body.Bytes()))
	}
}

func TestExportPKCS12_EmptyPassword(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPKCS12Fn: func(_ context.Context, _ string, password string) ([]byte, error) {
			if password != "" {
				t.Errorf("expected empty password, got %s", password)
			}
			return []byte{0x30}, nil
		},
	}
	h := NewExportHandler(mockSvc)

	// Empty body — password defaults to ""
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-test-1/export/pkcs12", nil)
	w := httptest.NewRecorder()

	h.ExportPKCS12(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestExportPKCS12_NotFound(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPKCS12Fn: func(_ context.Context, _ string, _ string) ([]byte, error) {
			return nil, fmt.Errorf("certificate not found")
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/nonexistent/export/pkcs12", nil)
	w := httptest.NewRecorder()

	h.ExportPKCS12(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestExportPKCS12_ServiceError(t *testing.T) {
	mockSvc := &MockExportService{
		ExportPKCS12Fn: func(_ context.Context, _ string, _ string) ([]byte, error) {
			return nil, fmt.Errorf("encoding error")
		},
	}
	h := NewExportHandler(mockSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-test-1/export/pkcs12", nil)
	w := httptest.NewRecorder()

	h.ExportPKCS12(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestExportPKCS12_MethodNotAllowed(t *testing.T) {
	h := NewExportHandler(&MockExportService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mc-test-1/export/pkcs12", nil)
	w := httptest.NewRecorder()

	h.ExportPKCS12(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestExtractCertIDFromExportPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/certificates/mc-test-1/export/pem", "mc-test-1"},
		{"/api/v1/certificates/mc-api-prod/export/pkcs12", "mc-api-prod"},
		{"/api/v1/certificates//export/pem", ""},
		{"/api/v1/other/mc-test-1/export/pem", ""},
		{"/api/v1/certificates/mc-test-1", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractCertIDFromExportPath(tt.path)
		if got != tt.expected {
			t.Errorf("extractCertIDFromExportPath(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}
