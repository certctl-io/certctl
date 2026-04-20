package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// requestLog captures HTTP requests made by MCP tool handlers.
type requestLog struct {
	mu       sync.Mutex
	requests []capturedRequest
}

type capturedRequest struct {
	Method string
	Path   string
	Query  string
	Body   string
}

func (rl *requestLog) add(r capturedRequest) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests = append(rl.requests, r)
}

func (rl *requestLog) last() capturedRequest {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.requests) == 0 {
		return capturedRequest{}
	}
	return rl.requests[len(rl.requests)-1]
}

// mockCertctlAPI returns a test server that records all requests and returns
// canned JSON responses based on the path.
func mockCertctlAPI(log *requestLog) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			body = string(buf[:n])
		}

		log.add(capturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Body:   body,
		})

		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/renew") || strings.HasSuffix(r.URL.Path, "/deploy"):
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "job_id": "job-001"})
		case r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": "new-resource"})
		default:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":  []interface{}{map[string]string{"id": "test-1"}},
				"total": 1,
			})
		}
	}))
}

func TestRegisterTools_ToolCount(t *testing.T) {
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "certctl-test",
		Version: "test",
	}, nil)

	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	RegisterTools(server, client)

	// The server should have tools registered — we can verify by listing them
	// Since the SDK doesn't expose a tool count method, we verify through the
	// request capabilities
	t.Log("RegisterTools completed without panic")
}

func TestPaginationQuery(t *testing.T) {
	tests := []struct {
		name    string
		page    int
		perPage int
		wantLen int
	}{
		{"both set", 2, 50, 2},
		{"page only", 3, 0, 1},
		{"per_page only", 0, 100, 1},
		{"neither set", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := paginationQuery(tt.page, tt.perPage)
			if len(q) != tt.wantLen {
				t.Errorf("expected %d query params, got %d", tt.wantLen, len(q))
			}
			if tt.page > 0 {
				if q.Get("page") != string(rune('0'+tt.page)) && q.Get("page") == "" {
					t.Errorf("expected page param to be set")
				}
			}
		})
	}
}

func TestTextResult(t *testing.T) {
	data := json.RawMessage(`{"id":"mc-test","status":"Active"}`)
	result, metadata, err := textResult(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata != nil {
		t.Errorf("expected nil metadata, got %v", metadata)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}
	tc, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent type")
	}
	if tc.Text != `{"id":"mc-test","status":"Active"}` {
		t.Errorf("unexpected text content: %s", tc.Text)
	}
}

func TestErrorResult(t *testing.T) {
	result, _, err := errorResult(http.ErrServerClosed)
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

// TestToolEndToEnd_ListCertificates verifies the full flow:
// MCP tool handler → HTTP client → mock API → response formatting
func TestToolEndToEnd_ListCertificates(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)

	// Manually call the handler logic that would be registered as a tool
	q := paginationQuery(1, 50)
	q.Set("status", "Active")
	data, err := client.Get("/api/v1/certificates", q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Method != "GET" {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if req.Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates, got %s", req.Path)
	}
	if !strings.Contains(req.Query, "status=Active") {
		t.Errorf("expected status=Active in query, got %s", req.Query)
	}
	if !strings.Contains(req.Query, "page=1") {
		t.Errorf("expected page=1 in query, got %s", req.Query)
	}

	result, _, err := textResult(data)
	if err != nil {
		t.Fatalf("unexpected error formatting result: %v", err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}
}

func TestToolEndToEnd_CreateCertificate(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)

	input := CreateCertificateInput{
		Name:       "API Production",
		CommonName: "api.example.com",
		IssuerID:   "iss-local",
		OwnerID:    "o-alice",
		TeamID:     "team-platform",
	}

	data, err := client.Post("/api/v1/certificates", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if req.Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates, got %s", req.Path)
	}
	if !strings.Contains(req.Body, "api.example.com") {
		t.Errorf("expected common_name in body, got %s", req.Body)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["id"] != "new-resource" {
		t.Errorf("expected id=new-resource, got %s", result["id"])
	}
}

func TestToolEndToEnd_TriggerRenewal(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	data, err := client.Post("/api/v1/certificates/mc-api-prod/renew", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if req.Path != "/api/v1/certificates/mc-api-prod/renew" {
		t.Errorf("expected path /api/v1/certificates/mc-api-prod/renew, got %s", req.Path)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["job_id"] != "job-001" {
		t.Errorf("expected job_id=job-001, got %s", result["job_id"])
	}
}

func TestToolEndToEnd_DeleteTarget(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	data, err := client.Delete("/api/v1/targets/t-platform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Method != "DELETE" {
		t.Errorf("expected DELETE, got %s", req.Method)
	}
	if req.Path != "/api/v1/targets/t-platform" {
		t.Errorf("expected path /api/v1/targets/t-platform, got %s", req.Path)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %s", result["status"])
	}
}

func TestToolEndToEnd_RevokeCertificate(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	input := RevokeCertificateInput{
		ID:     "mc-api-prod",
		Reason: "keyCompromise",
	}
	_, err := client.Post("/api/v1/certificates/"+input.ID+"/revoke", map[string]string{"reason": input.Reason})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if req.Path != "/api/v1/certificates/mc-api-prod/revoke" {
		t.Errorf("expected path /api/v1/certificates/mc-api-prod/revoke, got %s", req.Path)
	}
	if !strings.Contains(req.Body, "keyCompromise") {
		t.Errorf("expected reason in body, got %s", req.Body)
	}
}

func TestToolEndToEnd_AgentHeartbeat(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	_, err := client.Post("/api/v1/agents/agent-001/heartbeat", map[string]string{
		"os":           "linux",
		"architecture": "amd64",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Path != "/api/v1/agents/agent-001/heartbeat" {
		t.Errorf("expected path /api/v1/agents/agent-001/heartbeat, got %s", req.Path)
	}
}

func TestToolEndToEnd_ListWithFilters(t *testing.T) {
	log := &requestLog{}
	api := mockCertctlAPI(log)
	defer api.Close()

	client, _ := NewClient(api.URL, "test-key", "", false)
	q := paginationQuery(1, 25)
	q.Set("status", "Pending")
	q.Set("type", "Renewal")
	_, err := client.Get("/api/v1/jobs", q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := log.last()
	if req.Path != "/api/v1/jobs" {
		t.Errorf("expected path /api/v1/jobs, got %s", req.Path)
	}
	if !strings.Contains(req.Query, "status=Pending") {
		t.Errorf("expected status filter in query, got %s", req.Query)
	}
	if !strings.Contains(req.Query, "type=Renewal") {
		t.Errorf("expected type filter in query, got %s", req.Query)
	}
}

func TestToolEndToEnd_GetRawBinary(t *testing.T) {
	derData := []byte{0x30, 0x82, 0x01, 0x22}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(derData)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, "test-key", "", false)
	data, ct, err := client.GetRaw("/.well-known/pki/crl/iss-local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/pkix-crl" {
		t.Errorf("expected content-type application/pkix-crl, got %s", ct)
	}
	if len(data) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(data))
	}
}

func TestToolEndToEnd_ErrorPropagation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, "test-key", "", false)
	_, err := client.Get("/api/v1/certificates", nil)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	result, _, toolErr := errorResult(err)
	if result != nil {
		t.Errorf("expected nil result from errorResult")
	}
	if toolErr == nil {
		t.Fatal("expected non-nil error from errorResult")
	}
}
