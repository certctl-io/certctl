package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EST RFC 7030 hardening master bundle Phase 9.3 — CLI subcommand tests.
// Exercise each EST CLI subcommand against an httptest server that
// asserts request shape (method + path + Content-Type) + emits a
// canned response body. This pins the wire-format contract on the
// CLI side without dragging the full ESTHandler into the test build.

func newESTTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	// CLI defaults to TLS-1.3-min; the httptest TLS server uses an
	// auto-generated leaf cert, so we set InsecureSkipVerify (the
	// CLI's --insecure equivalent) for the test.
	c := &Client{
		baseURL:    server.URL,
		apiKey:     "",
		format:     "table",
		httpClient: server.Client(),
	}
	// Force TLS 1.3 to mirror NewClient's production setting.
	if t, ok := c.httpClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		t.TLSClientConfig.MinVersion = tls.VersionTLS13
	}
	return c
}

func TestEstCacerts_GetsBaseRoute(t *testing.T) {
	wantPath := "/.well-known/est/corp/cacerts"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != wantPath {
			t.Errorf("got %s %s, want GET %s", r.Method, r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		w.Write([]byte("MIIBaseinPKCS7Body"))
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	tmp := filepath.Join(t.TempDir(), "ca.p7")
	if err := c.EstCacerts([]string{"--profile", "corp", "--out", tmp}); err != nil {
		t.Fatalf("EstCacerts: %v", err)
	}
	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(got) != "MIIBaseinPKCS7Body" {
		t.Errorf("body = %q, want MIIBaseinPKCS7Body", got)
	}
}

func TestEstCsrattrs_204IsNotAnError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/est/corp/csrattrs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	if err := c.EstCsrattrs([]string{"--profile", "corp"}); err != nil {
		t.Errorf("204 should not surface as an error: %v", err)
	}
}

func TestEstEnroll_PostsCSRAsApplicationPKCS10(t *testing.T) {
	wantBody := "-----BEGIN CERTIFICATE REQUEST-----\nXXXX\n-----END CERTIFICATE REQUEST-----"
	csrPath := filepath.Join(t.TempDir(), "device.csr")
	if err := os.WriteFile(csrPath, []byte(wantBody), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/.well-known/est/corp/simpleenroll" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/pkcs10" {
			t.Errorf("Content-Type = %q, want application/pkcs10", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != wantBody {
			t.Errorf("body = %q, want %q", body, wantBody)
		}
		w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		w.Write([]byte("ISSUEDCERT"))
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	out := filepath.Join(t.TempDir(), "issued.p7")
	if err := c.EstEnroll([]string{"--profile", "corp", "--csr", csrPath, "--out", out}); err != nil {
		t.Fatalf("EstEnroll: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "ISSUEDCERT" {
		t.Errorf("issued body = %q, want ISSUEDCERT", got)
	}
}

func TestEstReEnroll_HitsRenewalPath(t *testing.T) {
	csrPath := filepath.Join(t.TempDir(), "device.csr")
	os.WriteFile(csrPath, []byte("dummy-csr"), 0o600)
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/est/corp/simplereenroll" {
			t.Errorf("path = %s", r.URL.Path)
		}
		called = true
		w.Write([]byte("RENEWED"))
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	out := filepath.Join(t.TempDir(), "renewed.p7")
	if err := c.EstReEnroll([]string{"--profile", "corp", "--csr", csrPath, "--out", out}); err != nil {
		t.Fatalf("EstReEnroll: %v", err)
	}
	if !called {
		t.Error("server never received the request")
	}
}

func TestEstEnroll_RequiresCSR(t *testing.T) {
	c := newESTTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	err := c.EstEnroll([]string{"--profile", "corp"})
	if err == nil || !strings.Contains(err.Error(), "csr") {
		t.Errorf("expected --csr-required error, got %v", err)
	}
}

func TestEstEnroll_ServerErrorMappedToFailure(t *testing.T) {
	csrPath := filepath.Join(t.TempDir(), "device.csr")
	os.WriteFile(csrPath, []byte("dummy"), 0o600)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	err := c.EstEnroll([]string{"--profile", "corp", "--csr", csrPath, "--out", filepath.Join(t.TempDir(), "out")})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected HTTP 500 error, got %v", err)
	}
}

func TestSplitServerKeygenMultipart_RoundTrip(t *testing.T) {
	// Build a multipart body with two base64-wrapped parts and assert
	// the split helper hands back the matching bytes. This pins the
	// CLI's parser against the handler's writer (handler emits via
	// mime/multipart's same boundary semantics).
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	certPart, _ := w.CreatePart(textproto("application/pkcs7-mime; smime-type=certs-only"))
	certPart.Write([]byte(base64.StdEncoding.EncodeToString([]byte("CERT_BYTES"))))
	keyPart, _ := w.CreatePart(textproto("application/pkcs7-mime; smime-type=enveloped-data"))
	keyPart.Write([]byte(base64.StdEncoding.EncodeToString([]byte("KEY_BYTES"))))
	w.Close()
	contentType := fmt.Sprintf("multipart/mixed; boundary=%s", w.Boundary())
	cert, key, err := splitServerKeygenMultipart(buf.Bytes(), contentType)
	if err != nil {
		t.Fatalf("splitServerKeygenMultipart: %v", err)
	}
	if string(cert) != "CERT_BYTES" {
		t.Errorf("cert part = %q, want CERT_BYTES", cert)
	}
	if string(key) != "KEY_BYTES" {
		t.Errorf("key part = %q, want KEY_BYTES", key)
	}
}

func TestEstTest_HitsBothEndpoints(t *testing.T) {
	hits := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		if strings.HasSuffix(r.URL.Path, "/csrattrs") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()
	c := newESTTestClient(t, server)
	if err := c.EstTest([]string{"--profile", "corp"}); err != nil {
		t.Fatalf("EstTest: %v", err)
	}
	if hits["/.well-known/est/corp/cacerts"] != 1 {
		t.Errorf("cacerts hit count = %d, want 1", hits["/.well-known/est/corp/cacerts"])
	}
	if hits["/.well-known/est/corp/csrattrs"] != 1 {
		t.Errorf("csrattrs hit count = %d, want 1", hits["/.well-known/est/corp/csrattrs"])
	}
}

// textproto builds the small multipart-header form mime/multipart's
// CreatePart wants (it's a textproto.MIMEHeader). Pulled out as a tiny
// helper so the test reads cleanly.
func textproto(contentType string) map[string][]string {
	return map[string][]string{"Content-Type": {contentType}}
}
