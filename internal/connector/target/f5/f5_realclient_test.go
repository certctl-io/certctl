package f5

// Bundle M.F5 (Coverage Audit Closure) — F5 BIG-IP iControl REST realclient
// failure-mode coverage. Closes finding H-001.
//
// The existing f5_test.go tests the Connector layer via the F5Client interface
// using a hand-rolled mockF5Client. Every realF5Client HTTP method (~11 of
// them) sits at 0% coverage because the existing tests bypass HTTP entirely.
//
// This file exercises every realF5Client method end-to-end against an
// httptest.Server returning canned iControl REST responses. The mock
// recognizes the F5 endpoints (auth, file-transfer/uploads, crypto/cert,
// crypto/key, transaction, ltm/profile/client-ssl) and routes accordingly.
// Pattern mirrors Bundle J's hermetic-via-httptest approach.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestRealClient builds a realF5Client pointing at the given test server,
// using its TLS-friendly client (httptest.NewServer is plain HTTP — we use
// its Client() for matching dialer settings even though F5 normally uses HTTPS).
func newTestRealClient(ts *httptest.Server) *realF5Client {
	return &realF5Client{
		baseURL:    ts.URL,
		username:   "admin",
		password:   "secret",
		httpClient: ts.Client(),
		logger:     testLogger(),
		token:      "pre-set-test-token",
	}
}

// ---------------------------------------------------------------------------
// Authenticate
// ---------------------------------------------------------------------------

func TestRealF5Client_Authenticate_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mgmt/shared/authn/login" || r.Method != http.MethodPost {
			http.Error(w, "wrong path/method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":{"token":"new-token-abc"}}`)
	}))
	defer ts.Close()

	c := newTestRealClient(ts)
	c.token = "" // start unauthenticated
	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.token != "new-token-abc" {
		t.Errorf("token = %q; want 'new-token-abc'", c.token)
	}
}

func TestRealF5Client_Authenticate_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `boom`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRealF5Client_Authenticate_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := newTestRealClient(ts)
	ts.Close()
	err := c.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "auth request failed") {
		t.Fatalf("expected auth-request-failed error, got: %v", err)
	}
}

func TestRealF5Client_Authenticate_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{bad json`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode auth response") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

func TestRealF5Client_Authenticate_EmptyToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":{"token":""}}`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("expected no-token error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// doRequest 401 retry path
// ---------------------------------------------------------------------------

func TestRealF5Client_DoRequest_401TriggersReAuth(t *testing.T) {
	var firstReq atomic.Bool
	authCount := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mgmt/shared/authn/login":
			authCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":{"token":"refreshed-token"}}`)
		case "/test-target":
			if !firstReq.Load() {
				firstReq.Store(true)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := newTestRealClient(ts)
	resp, err := c.doRequest(context.Background(), http.MethodGet, ts.URL+"/test-target", nil, nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200 (after 401 retry)", resp.StatusCode)
	}
	if authCount.Load() != 1 {
		t.Errorf("auth invoked %d times; want exactly 1 (re-auth)", authCount.Load())
	}
}

func TestRealF5Client_DoRequest_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := newTestRealClient(ts)
	ts.Close()
	_, err := c.doRequest(context.Background(), http.MethodGet, ts.URL+"/x", nil, nil)
	if err == nil {
		t.Fatal("expected network error")
	}
}

// ---------------------------------------------------------------------------
// UploadFile / InstallCert / InstallKey
// ---------------------------------------------------------------------------

func TestRealF5Client_UploadFile_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/") {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Content-Range") == "" {
			http.Error(w, "missing Content-Range", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.UploadFile(context.Background(), "test.crt", []byte("data")); err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
}

func TestRealF5Client_UploadFile_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.UploadFile(context.Background(), "test.crt", []byte("data"))
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRealF5Client_InstallCert_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mgmt/tm/sys/crypto/cert" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.InstallCert(context.Background(), "mycert", "/var/config/rest/downloads/test.crt"); err != nil {
		t.Fatalf("InstallCert: %v", err)
	}
}

func TestRealF5Client_InstallCert_403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.InstallCert(context.Background(), "x", "y")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected 403 error, got: %v", err)
	}
}

func TestRealF5Client_InstallKey_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mgmt/tm/sys/crypto/key" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.InstallKey(context.Background(), "mykey", "/var/config/rest/downloads/test.key"); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
}

func TestRealF5Client_InstallKey_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.InstallKey(context.Background(), "x", "y")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateTransaction / CommitTransaction
// ---------------------------------------------------------------------------

func TestRealF5Client_CreateTransaction_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mgmt/tm/transaction" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"transId":12345}`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	id, err := c.CreateTransaction(context.Background())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	if id != "12345" {
		t.Errorf("id = %q; want '12345'", id)
	}
}

func TestRealF5Client_CreateTransaction_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	_, err := c.CreateTransaction(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRealF5Client_CreateTransaction_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{bad json`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	_, err := c.CreateTransaction(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode transaction") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

func TestRealF5Client_CreateTransaction_EmptyID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Empty body -> json.Number zero-value, which String() returns "".
		_, _ = io.WriteString(w, `{}`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	_, err := c.CreateTransaction(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty transaction ID") {
		t.Fatalf("expected empty-ID error, got: %v", err)
	}
}

func TestRealF5Client_CommitTransaction_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/mgmt/tm/transaction/") {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPatch {
			http.Error(w, "wrong method", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.CommitTransaction(context.Background(), "12345"); err != nil {
		t.Fatalf("CommitTransaction: %v", err)
	}
}

func TestRealF5Client_CommitTransaction_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.CommitTransaction(context.Background(), "12345")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateSSLProfile / GetSSLProfile
// ---------------------------------------------------------------------------

func TestRealF5Client_UpdateSSLProfile_HappyPath_NoChain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/") {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.UpdateSSLProfile(context.Background(), "Common", "myprofile", "mycert", "mykey", "", ""); err != nil {
		t.Fatalf("UpdateSSLProfile: %v", err)
	}
}

func TestRealF5Client_UpdateSSLProfile_WithChainAndTransID(t *testing.T) {
	var sawHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("X-F5-REST-Overriding-Collection")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.UpdateSSLProfile(context.Background(), "Common", "myprofile", "mycert", "mykey", "mychain", "tx-789"); err != nil {
		t.Fatalf("UpdateSSLProfile: %v", err)
	}
	if !strings.Contains(sawHeader, "tx-789") {
		t.Errorf("X-F5-REST-Overriding-Collection header missing tx-789; saw: %q", sawHeader)
	}
}

func TestRealF5Client_UpdateSSLProfile_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.UpdateSSLProfile(context.Background(), "Common", "myprofile", "mycert", "mykey", "", "")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRealF5Client_GetSSLProfile_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"myprofile","cert":"/Common/mycert","key":"/Common/mykey","chain":"/Common/mychain"}`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	info, err := c.GetSSLProfile(context.Background(), "Common", "myprofile")
	if err != nil {
		t.Fatalf("GetSSLProfile: %v", err)
	}
	if info == nil || info.Name != "myprofile" {
		t.Errorf("info = %+v", info)
	}
}

func TestRealF5Client_GetSSLProfile_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	_, err := c.GetSSLProfile(context.Background(), "Common", "nonexistent")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected 404 error, got: %v", err)
	}
}

func TestRealF5Client_GetSSLProfile_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{bad`)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	_, err := c.GetSSLProfile(context.Background(), "Common", "myprofile")
	if err == nil || !strings.Contains(err.Error(), "decode SSL profile") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteCert / DeleteKey
// ---------------------------------------------------------------------------

func TestRealF5Client_DeleteCert_HappyPath_204(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "wrong method", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.DeleteCert(context.Background(), "Common", "mycert"); err != nil {
		t.Fatalf("DeleteCert: %v", err)
	}
}

func TestRealF5Client_DeleteCert_HappyPath_200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.DeleteCert(context.Background(), "Common", "mycert"); err != nil {
		t.Fatalf("DeleteCert: %v", err)
	}
}

func TestRealF5Client_DeleteCert_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.DeleteCert(context.Background(), "Common", "mycert")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRealF5Client_DeleteKey_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	if err := c.DeleteKey(context.Background(), "Common", "mykey"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
}

func TestRealF5Client_DeleteKey_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	err := c.DeleteKey(context.Background(), "Common", "mykey")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestRealF5Client_ContextCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the request long enough for context to cancel
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	c := newTestRealClient(ts)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := c.UploadFile(ctx, "test.crt", []byte("data"))
	if err == nil {
		t.Fatal("expected context cancel error")
	}
}
