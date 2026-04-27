package gcpsm

// Bundle M.Cloud (GCP-SM portion) — GCP Secret Manager discovery
// realclient failure-mode coverage. Closes finding H-004 (gcpsm portion).
//
// Strategy: write a fixture service-account JSON file at a t.TempDir()
// path with token_uri pointing at our httptest.Server. This means
// getAccessToken's hardcoded path (s.saKey.TokenURI) lands on the test
// server. For the secretmanager.googleapis.com URLs, use a custom
// http.RoundTripper that rewrites Host to the test server. Then exercise
// ListSecrets / AccessSecretVersion / getAccessToken end-to-end.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/config"
)

// rewritingTransport rewrites every request to the test server while
// preserving path + query.
type rewritingTransport struct {
	target *httptest.Server
}

func (rt *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := *req.URL
	newURL.Scheme = "http"
	newURL.Host = rt.target.Listener.Addr().String()
	newReq := req.Clone(req.Context())
	newReq.URL = &newURL
	newReq.Host = newURL.Host
	return rt.target.Client().Transport.RoundTrip(newReq)
}

func quietGCPLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// generateTestRSAKey returns an RSA private key + its PEM encoding (PKCS#8).
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return priv, string(pemBytes)
}

// writeServiceAccountJSON writes a fake service-account credentials file
// at t.TempDir()/sa.json with token_uri pointing at the given test server.
// Returns the path.
func writeServiceAccountJSON(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	_, pemKey := generateTestRSAKey(t)
	tokenURI := ts.URL + "/token"
	saJSON := `{
		"type": "service_account",
		"project_id": "test-project",
		"private_key": ` + jsonString(pemKey) + `,
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"token_uri": "` + tokenURI + `"
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	if err := os.WriteFile(path, []byte(saJSON), 0o600); err != nil {
		t.Fatalf("write sa.json: %v", err)
	}
	return path
}

// jsonString returns the JSON-quoted form of s (escapes \n, etc.).
func jsonString(s string) string {
	// Simple escape: backslash + double quote + newlines.
	out := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
	).Replace(s)
	return `"` + out + `"`
}

// newTestGCPSource builds a Source pointing at the given test server,
// using a TempDir-backed service-account credentials file.
func newTestGCPSource(t *testing.T, ts *httptest.Server) *Source {
	t.Helper()
	saPath := writeServiceAccountJSON(t, ts)
	httpClient := &http.Client{
		Transport: &rewritingTransport{target: ts},
		Timeout:   30 * time.Second,
	}
	return &Source{
		cfg: &config.GCPSecretMgrDiscoveryConfig{
			Project:     "test-project",
			Credentials: saPath,
		},
		httpClient: httpClient,
		logger:     quietGCPLogger(),
	}
}

// ---------------------------------------------------------------------------
// loadServiceAccountKey
// ---------------------------------------------------------------------------

func TestLoadServiceAccountKey_HappyPath(t *testing.T) {
	dir := t.TempDir()
	_, pemKey := generateTestRSAKey(t)
	saJSON := `{
		"type": "service_account",
		"project_id": "x",
		"private_key": ` + jsonString(pemKey) + `,
		"client_email": "x@x.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`
	path := filepath.Join(dir, "sa.json")
	if err := os.WriteFile(path, []byte(saJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	saKey, rsaKey, err := loadServiceAccountKey(path)
	if err != nil {
		t.Fatalf("loadServiceAccountKey: %v", err)
	}
	if saKey.ClientEmail != "x@x.iam.gserviceaccount.com" {
		t.Errorf("ClientEmail = %q", saKey.ClientEmail)
	}
	if rsaKey == nil {
		t.Error("rsaKey nil")
	}
}

func TestLoadServiceAccountKey_FileNotFound(t *testing.T) {
	_, _, err := loadServiceAccountKey("/nonexistent/sa.json")
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("expected file-not-found error, got: %v", err)
	}
}

func TestLoadServiceAccountKey_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	_ = os.WriteFile(path, []byte(`{not json`), 0o600)
	_, _, err := loadServiceAccountKey(path)
	if err == nil || !strings.Contains(err.Error(), "parse credentials") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestLoadServiceAccountKey_BadPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	saJSON := `{
		"type": "service_account",
		"private_key": "not-a-pem-block",
		"client_email": "x@x.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`
	_ = os.WriteFile(path, []byte(saJSON), 0o600)
	_, _, err := loadServiceAccountKey(path)
	if err == nil || !strings.Contains(err.Error(), "decode private key") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

func TestLoadServiceAccountKey_EmptyPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	saJSON := `{
		"type": "service_account",
		"private_key": "",
		"client_email": "x@x.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`
	_ = os.WriteFile(path, []byte(saJSON), 0o600)
	saKey, rsaKey, err := loadServiceAccountKey(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if saKey == nil {
		t.Error("saKey nil with empty private_key")
	}
	if rsaKey != nil {
		t.Error("rsaKey should be nil with empty private_key")
	}
}

// ---------------------------------------------------------------------------
// getAccessToken
// ---------------------------------------------------------------------------

func TestGCPGetAccessToken_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"gcp-tok","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	tok, err := s.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if tok != "gcp-tok" {
		t.Errorf("token = %q", tok)
	}
}

func TestGCPGetAccessToken_CachedReuse(t *testing.T) {
	count := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	if _, err := s.getAccessToken(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := s.getAccessToken(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if count.Load() != 1 {
		t.Errorf("token endpoint hit %d times; want 1 (cache miss)", count.Load())
	}
}

func TestGCPGetAccessToken_4xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	_, err := s.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("expected 401 error, got: %v", err)
	}
}

func TestGCPGetAccessToken_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	_, err := s.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse token") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestGCPGetAccessToken_EmptyToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"","expires_in":3600}`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	_, err := s.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("expected empty-token error, got: %v", err)
	}
}

func TestGCPGetAccessToken_LoadCredentialsFails(t *testing.T) {
	s := &Source{
		cfg: &config.GCPSecretMgrDiscoveryConfig{
			Project:     "x",
			Credentials: "/nonexistent/sa.json",
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     quietGCPLogger(),
	}
	_, err := s.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "load credentials") {
		t.Fatalf("expected load-credentials error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListSecrets / AccessSecretVersion
// ---------------------------------------------------------------------------

func TestGCPListSecrets_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/secrets"):
			_, _ = io.WriteString(w, `{"secrets":[{"name":"projects/p/secrets/cert1","labels":{"type":"certificate"}}]}`)
		default:
			http.Error(w, "wrong path", http.StatusNotFound)
		}
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	secrets, err := cli.ListSecrets(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets))
	}
}

func TestGCPListSecrets_TokenFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	_, err := cli.ListSecrets(context.Background(), "p")
	if err == nil || !strings.Contains(err.Error(), "access token") {
		t.Fatalf("expected token error, got: %v", err)
	}
}

func TestGCPListSecrets_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	_, err := cli.ListSecrets(context.Background(), "p")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestGCPListSecrets_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	_, err := cli.ListSecrets(context.Background(), "p")
	if err == nil || !strings.Contains(err.Error(), "parse list") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestGCPAccessSecretVersion_HappyPath(t *testing.T) {
	want := "secret payload data"
	encoded := base64.StdEncoding.EncodeToString([]byte(want))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, ":access"):
			_, _ = io.WriteString(w, `{"payload":{"data":"`+encoded+`"}}`)
		}
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	data, err := cli.AccessSecretVersion(context.Background(), "p", "mycert")
	if err != nil {
		t.Fatalf("AccessSecretVersion: %v", err)
	}
	if string(data) != want {
		t.Errorf("data = %q; want %q", data, want)
	}
}

func TestGCPAccessSecretVersion_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	_, err := cli.AccessSecretVersion(context.Background(), "p", "missing")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected 404 error, got: %v", err)
	}
}

func TestGCPAccessSecretVersion_BadBase64(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"payload":{"data":"!!!not-base64!!!"}}`)
	}))
	defer ts.Close()
	s := newTestGCPSource(t, ts)
	cli := &httpSMClient{source: s, logger: quietGCPLogger()}
	_, err := cli.AccessSecretVersion(context.Background(), "p", "mycert")
	if err == nil || !strings.Contains(err.Error(), "base64-decode") {
		t.Fatalf("expected base64 error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Name / Type
// ---------------------------------------------------------------------------

func TestGCPNameAndType(t *testing.T) {
	s := New(&config.GCPSecretMgrDiscoveryConfig{}, quietGCPLogger())
	if s.Name() != "GCP Secret Manager" {
		t.Errorf("Name() = %q", s.Name())
	}
	if s.Type() != "gcp-sm" {
		t.Errorf("Type() = %q", s.Type())
	}
}
