package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8443", "test-key")
	if c.baseURL != "http://localhost:8443" {
		t.Errorf("expected baseURL http://localhost:8443, got %s", c.baseURL)
	}
	if c.apiKey != "test-key" {
		t.Errorf("expected apiKey test-key, got %s", c.apiKey)
	}
	if c.httpClient == nil {
		t.Fatal("expected httpClient to be non-nil")
	}
}

func TestClient_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key auth, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept application/json, got %s", r.Header.Get("Accept"))
		}
		if r.URL.Query().Get("status") != "Active" {
			t.Errorf("expected status=Active query param, got %s", r.URL.Query().Get("status"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  []interface{}{},
			"total": 0,
		})
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, err := c.Get("/api/v1/certificates", map[string][]string{"status": {"Active"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response data")
	}
}

func TestClient_Get_NoAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("expected no auth header, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "")
	_, err := c.Get("/api/v1/certificates", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_Post(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if parsed["name"] != "test-cert" {
			t.Errorf("expected name=test-cert, got %v", parsed["name"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "mc-test"})
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, err := c.Post("/api/v1/certificates", map[string]string{"name": "test-cert"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["id"] != "mc-test" {
		t.Errorf("expected id=mc-test, got %s", result["id"])
	}
}

func TestClient_Put(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"mc-test","name":"updated"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, err := c.Put("/api/v1/certificates/mc-test", map[string]string{"name": "updated"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response data")
	}
}

func TestClient_Delete_204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, err := c.Delete("/api/v1/certificates/mc-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["status"] != "deleted" {
		t.Errorf("expected status=deleted for 204, got %s", result["status"])
	}
}

func TestClient_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	_, err := c.Get("/api/v1/certificates/nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	expected := "API error (HTTP 404)"
	if !containsStr(err.Error(), expected) {
		t.Errorf("expected error containing %q, got %q", expected, err.Error())
	}
}

func TestClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	_, err := c.Post("/api/v1/certificates", map[string]string{"name": "test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	expected := "API error (HTTP 500)"
	if !containsStr(err.Error(), expected) {
		t.Errorf("expected error containing %q, got %q", expected, err.Error())
	}
}

func TestClient_GetRaw(t *testing.T) {
	derData := []byte{0x30, 0x82, 0x01, 0x00} // fake DER bytes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(derData)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, contentType, err := c.GetRaw("/api/v1/crl/iss-local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contentType != "application/pkix-crl" {
		t.Errorf("expected content-type application/pkix-crl, got %s", contentType)
	}
	if len(data) != len(derData) {
		t.Errorf("expected %d bytes, got %d", len(derData), len(data))
	}
}

func TestClient_GetRaw_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("issuer not found"))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	_, _, err := c.GetRaw("/api/v1/crl/nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c := NewClient("http://localhost:1", "test-key")
	_, err := c.Get("/api/v1/certificates", nil)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestClient_PostNilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "" {
			t.Errorf("expected no Content-Type for nil body, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	data, err := c.Post("/api/v1/certificates/mc-test/renew", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestClient_QueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("expected page=2, got %s", r.URL.Query().Get("page"))
		}
		if r.URL.Query().Get("per_page") != "10" {
			t.Errorf("expected per_page=10, got %s", r.URL.Query().Get("per_page"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[],"total":0}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-key")
	q := paginationQuery(2, 10)
	_, err := c.Get("/api/v1/certificates", q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// containsStr is a simple helper to avoid importing strings in tests.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
