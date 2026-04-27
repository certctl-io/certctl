package azurekv

// Bundle M.Cloud (AzureKV portion) — Azure Key Vault discovery realclient
// failure-mode coverage. Closes finding H-004 (azurekv portion).
//
// Strategy: the existing azurekv_test.go tests Source via the KVClient
// interface using a mock; httpKVClient methods (ListCertificates,
// GetCertificate, getAccessToken) sit at 0%. Bundle M.Cloud builds a
// custom http.RoundTripper that rewrites Microsoft Azure URLs
// (login.microsoftonline.com + the configured vault URL) to a test server,
// then exercises the realclient methods end-to-end.
//
// Pattern mirrors Bundle M.F5 (httptest.Server with canned REST responses).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rewritingTransport is an http.RoundTripper that rewrites every request's
// host to the test server's host. This lets us point httpKVClient at a
// real-looking VaultURL (https://myvault.vault.azure.net) and still have
// the requests land on httptest.Server.
type rewritingTransport struct {
	target *httptest.Server
}

func (rt *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Build a new URL that targets the test server but preserves path + query.
	newURL := *req.URL
	newURL.Scheme = "http" // httptest is plain http
	newURL.Host = rt.target.Listener.Addr().String()
	newReq := req.Clone(req.Context())
	newReq.URL = &newURL
	newReq.Host = newURL.Host
	return rt.target.Client().Transport.RoundTrip(newReq)
}

func newTestAzureClient(t *testing.T, ts *httptest.Server) *httpKVClient {
	t.Helper()
	httpClient := &http.Client{
		Transport: &rewritingTransport{target: ts},
		Timeout:   30 * time.Second,
	}
	return &httpKVClient{
		config: Config{
			VaultURL:     "https://myvault.vault.azure.net",
			TenantID:     "tenant-id-1234",
			ClientID:     "client-id-1234",
			ClientSecret: "client-secret-12345",
		},
		httpClient: httpClient,
	}
}

func quietAzureLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// makeAzureCertCER builds a base64-encoded DER certificate suitable as the
// "cer" field in an Azure certificateBundle response.
func makeAzureCertCER(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// ---------------------------------------------------------------------------
// getAccessToken
// ---------------------------------------------------------------------------

func TestAzureGetAccessToken_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok-abc","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	tok, err := c.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if tok != "tok-abc" {
		t.Errorf("token = %q; want 'tok-abc'", tok)
	}
}

func TestAzureGetAccessToken_CachedReuse(t *testing.T) {
	count := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok-cached","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)

	// First call hits the token endpoint.
	if _, err := c.getAccessToken(context.Background()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call should reuse cache (5-min buffer not expired).
	if _, err := c.getAccessToken(context.Background()); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if count.Load() != 1 {
		t.Errorf("token endpoint hit %d times; want exactly 1 (cache miss)", count.Load())
	}
}

func TestAzureGetAccessToken_4xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("expected 401 error, got: %v", err)
	}
}

func TestAzureGetAccessToken_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse token") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestAzureGetAccessToken_EmptyToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"","expires_in":3600}`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.getAccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("expected empty-token error, got: %v", err)
	}
}

func TestAzureGetAccessToken_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := newTestAzureClient(t, ts)
	ts.Close()
	_, err := c.getAccessToken(context.Background())
	if err == nil {
		t.Fatal("expected network error")
	}
}

// ---------------------------------------------------------------------------
// ListCertificates
// ---------------------------------------------------------------------------

func TestAzureListCertificates_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/certificates"):
			_, _ = io.WriteString(w, `{"value":[{"id":"https://myvault.vault.azure.net/certificates/cert1/v1","attributes":{"exp":1735689600}}]}`)
		default:
			http.Error(w, "wrong path", http.StatusNotFound)
		}
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	certs, err := c.ListCertificates(context.Background(), c.config.VaultURL)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("certs count = %d; want 1", len(certs))
	}
	if certs[0].ID != "https://myvault.vault.azure.net/certificates/cert1/v1" {
		t.Errorf("cert ID = %q", certs[0].ID)
	}
}

func TestAzureListCertificates_TokenFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Error(w, "unreached", http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.ListCertificates(context.Background(), c.config.VaultURL)
	if err == nil || !strings.Contains(err.Error(), "access token") {
		t.Fatalf("expected token error, got: %v", err)
	}
}

func TestAzureListCertificates_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `vault upstream broken`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.ListCertificates(context.Background(), c.config.VaultURL)
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestAzureListCertificates_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.ListCertificates(context.Background(), c.config.VaultURL)
	if err == nil || !strings.Contains(err.Error(), "parse list") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestAzureListCertificates_Pagination(t *testing.T) {
	pageNum := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/certificates") {
			n := pageNum.Add(1)
			if n == 1 {
				// First page returns one cert + nextLink
				_, _ = io.WriteString(w, `{"value":[{"id":"https://myvault.vault.azure.net/certificates/cert1/v1","attributes":{"exp":0}}],"nextLink":"http://`+r.Host+`/certificates?page=2"}`)
				return
			}
			// Second page (no nextLink) returns the second cert
			_, _ = io.WriteString(w, `{"value":[{"id":"https://myvault.vault.azure.net/certificates/cert2/v1","attributes":{"exp":0}}]}`)
		}
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	certs, err := c.ListCertificates(context.Background(), c.config.VaultURL)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs across 2 pages, got %d", len(certs))
	}
}

// ---------------------------------------------------------------------------
// GetCertificate
// ---------------------------------------------------------------------------

func TestAzureGetCertificate_HappyPath(t *testing.T) {
	cer := makeAzureCertCER(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		// /certificates/{name}/{version}
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{
			"id":  "https://myvault.vault.azure.net/certificates/mycert/v1",
			"cer": cer,
		})
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	bundle, err := c.GetCertificate(context.Background(), c.config.VaultURL, "mycert", "v1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if bundle == nil || bundle.CER != cer {
		t.Errorf("bundle = %+v", bundle)
	}
}

func TestAzureGetCertificate_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.GetCertificate(context.Background(), c.config.VaultURL, "missing", "v1")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected 404 error, got: %v", err)
	}
}

func TestAzureGetCertificate_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer ts.Close()
	c := newTestAzureClient(t, ts)
	_, err := c.GetCertificate(context.Background(), c.config.VaultURL, "mycert", "v1")
	if err == nil || !strings.Contains(err.Error(), "parse certificate") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// New (constructor)
// ---------------------------------------------------------------------------

func TestNew_ConstructsHttpClient(t *testing.T) {
	cfg := Config{
		VaultURL:     "https://myvault.vault.azure.net",
		TenantID:     "t",
		ClientID:     "c",
		ClientSecret: "s",
	}
	src := New(cfg, quietAzureLogger())
	if src == nil {
		t.Fatal("New returned nil")
	}
	if src.client == nil {
		t.Error("client not initialized")
	}
}
