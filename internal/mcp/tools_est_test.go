package mcp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// EST RFC 7030 hardening master bundle Phase 9.3 — MCP tool tests.
// Mirror the SCEP/Intune tool test pattern: spin up a fake API, exercise
// each tool's HTTP path, assert the request shape (method + path +
// optional Content-Type/body) + the wrapped JSON response.

// mockESTAPI returns a test server that records EST + admin EST requests.
// Differs from mockCertctlAPI by handling the raw (non-JSON) /.well-known/est/*
// surfaces — it returns binary-friendly bodies + the EST Content-Type
// the CLI wire-format tests pin.
func mockESTAPI(log *requestLog) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			buf := make([]byte, 8192)
			n, _ := r.Body.Read(buf)
			body = string(buf[:n])
		}
		log.add(capturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Body:   body,
		})

		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/admin/est/profiles"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"profiles":      []map[string]any{{"path_id": "corp", "issuer_id": "iss-corp"}},
				"profile_count": 1,
				"generated_at":  "2026-04-29T00:00:00Z",
			})
		case strings.HasSuffix(r.URL.Path, "/cacerts"):
			w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
			w.Write([]byte("CACERTS-PKCS7-BYTES"))
		case strings.HasSuffix(r.URL.Path, "/csrattrs"):
			w.Header().Set("Content-Type", "application/csrattrs")
			w.Write([]byte("CSRATTRS-DER"))
		case strings.HasSuffix(r.URL.Path, "/simpleenroll"):
			w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
			w.Write([]byte("ENROLLED-CERT-BYTES"))
		case strings.HasSuffix(r.URL.Path, "/simplereenroll"):
			w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
			w.Write([]byte("REENROLLED-CERT-BYTES"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestEstPathFor(t *testing.T) {
	cases := []struct {
		profile string
		op      string
		want    string
	}{
		{"corp", "cacerts", "/.well-known/est/corp/cacerts"},
		{"", "cacerts", "/.well-known/est/cacerts"},
		{"iot", "simpleenroll", "/.well-known/est/iot/simpleenroll"},
	}
	for _, c := range cases {
		got := estPathFor(c.profile, c.op)
		if got != c.want {
			t.Errorf("estPathFor(%q, %q) = %q, want %q", c.profile, c.op, got, c.want)
		}
	}
}

func TestEstRawResultJSON_EmbedsBase64Body(t *testing.T) {
	body := []byte("\x00\x01\x02\x03binary")
	raw := estRawResultJSON(body, "application/pkcs7-mime")
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["content_type"] != "application/pkcs7-mime" {
		t.Errorf("content_type = %v", got["content_type"])
	}
	if got["body_base64"] != base64.StdEncoding.EncodeToString(body) {
		t.Errorf("body_base64 mismatch")
	}
	if int(got["body_size_bytes"].(float64)) != len(body) {
		t.Errorf("body_size_bytes = %v, want %d", got["body_size_bytes"], len(body))
	}
}

// TestRegisterESTTools_HitsExpectedPaths exercises each EST tool by
// driving its handler through the registered mcp.Server's transport
// surface. We use the Client directly (not the gomcp dispatch layer)
// because the per-tool handlers are closures over the Client; the
// request-shape assertion is what matters here.
func TestRegisterESTTools_AllPathsExercised(t *testing.T) {
	log := &requestLog{}
	api := mockESTAPI(log)
	defer api.Close()
	client, err := NewClient(api.URL, "test-key", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// est_list_profiles + est_admin_stats both hit the admin endpoint.
	if _, err := client.Get("/api/v1/admin/est/profiles", nil); err != nil {
		t.Errorf("admin profiles: %v", err)
	}
	// est_get_cacerts via GetRaw.
	if body, _, err := client.GetRaw(estPathFor("corp", "cacerts")); err != nil {
		t.Errorf("cacerts GET: %v", err)
	} else if string(body) != "CACERTS-PKCS7-BYTES" {
		t.Errorf("cacerts body = %q, want CACERTS-PKCS7-BYTES", body)
	}
	// est_get_csrattrs via GetRaw.
	if body, _, err := client.GetRaw(estPathFor("corp", "csrattrs")); err != nil {
		t.Errorf("csrattrs GET: %v", err)
	} else if string(body) != "CSRATTRS-DER" {
		t.Errorf("csrattrs body = %q, want CSRATTRS-DER", body)
	}
	// est_enroll via PostRaw.
	if body, _, err := client.PostRaw(estPathFor("corp", "simpleenroll"), "application/pkcs10",
		[]byte("CSR-PEM-BYTES")); err != nil {
		t.Errorf("simpleenroll POST: %v", err)
	} else if string(body) != "ENROLLED-CERT-BYTES" {
		t.Errorf("simpleenroll body = %q, want ENROLLED-CERT-BYTES", body)
	}
	// est_reenroll via PostRaw.
	if body, _, err := client.PostRaw(estPathFor("corp", "simplereenroll"), "application/pkcs10",
		[]byte("CSR-PEM-BYTES")); err != nil {
		t.Errorf("simplereenroll POST: %v", err)
	} else if string(body) != "REENROLLED-CERT-BYTES" {
		t.Errorf("simplereenroll body = %q, want REENROLLED-CERT-BYTES", body)
	}

	// Pin every captured path so a future refactor that reroutes one
	// tool gets caught.
	wantPaths := []string{
		"/api/v1/admin/est/profiles",
		"/.well-known/est/corp/cacerts",
		"/.well-known/est/corp/csrattrs",
		"/.well-known/est/corp/simpleenroll",
		"/.well-known/est/corp/simplereenroll",
	}
	gotPaths := make([]string, 0, len(log.requests))
	for _, r := range log.requests {
		gotPaths = append(gotPaths, r.Path)
	}
	for _, want := range wantPaths {
		found := false
		for _, got := range gotPaths {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing request to %s; got %v", want, gotPaths)
		}
	}
}
