package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/cms"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/ratelimit"
	"github.com/certctl-io/certctl/internal/trustanchor"
)

// EST RFC 7030 hardening master bundle Phases 2-4 tests.
// Covers: mTLS sibling route gates, HTTP Basic enrollment-password auth,
// per-source-IP failed-auth rate limit, RFC 9266 channel binding, and
// per-(CN, sourceIP) per-principal sliding-window rate limit.

// hardeningTestSetup is a per-test fixture: a mock service that always
// succeeds, plus a CA + issued client cert that an mTLS test can attach
// to its synthetic *http.Request.TLS.
type hardeningTestSetup struct {
	svc       *mockESTService
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	clientCrt *x509.Certificate
	clientKey *ecdsa.PrivateKey
	trustPool *trustanchor.Holder
	bundleDir string
}

func newHardeningTestSetup(t *testing.T) *hardeningTestSetup {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "est-mtls-test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca create: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-device-001"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client create: %v", err)
	}
	clientCrt, _ := x509.ParseCertificate(clientDER)

	// Persist the CA bundle on disk so trustanchor.New can load it.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(bundlePath, body, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	holder, err := trustanchor.New(bundlePath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("trustanchor.New: %v", err)
	}

	svc := &mockESTService{
		CACertPEM: pemCertString(caDER),
		EnrollResult: &domain.ESTEnrollResult{
			CertPEM: pemCertString(clientDER),
		},
	}
	return &hardeningTestSetup{
		svc:       svc,
		caCert:    caCert,
		caKey:     caKey,
		clientCrt: clientCrt,
		clientKey: clientKey,
		trustPool: holder,
		bundleDir: dir,
	}
}

func pemCertString(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// makeMTLSRequest synthesises a POST against `path` with PEM CSR body and
// r.TLS populated with the given peer cert chain + handshake state. Used
// by the mTLS path tests where a real TLS handshake would force us into a
// full httptest.NewTLSServer setup.
func makeMTLSRequest(t *testing.T, path, csrPEM string, peerCerts []*x509.Certificate, version uint16) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		Version:           version,
		PeerCertificates:  peerCerts,
	}
	return req
}

// ----- mTLS handler gate -----

func TestSimpleEnrollMTLS_NoTrustPool_500(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc) // intentionally do NOT call SetMTLSTrust
	req := makeMTLSRequest(t, "/.well-known/est-mtls/corp/simpleenroll",
		generateTestCSRPEM(t), []*x509.Certificate{s.clientCrt}, tls.VersionTLS13)
	w := httptest.NewRecorder()
	h.SimpleEnrollMTLS(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (handler missing trust pool)", w.Code)
	}
}

func TestSimpleEnrollMTLS_NoClientCert_401(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est-mtls/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnrollMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no client cert)", w.Code)
	}
}

func TestSimpleEnrollMTLS_CertNotInPool_401(t *testing.T) {
	s := newHardeningTestSetup(t)
	other := newHardeningTestSetup(t) // different CA, unrelated to s.trustPool
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	req := makeMTLSRequest(t, "/.well-known/est-mtls/corp/simpleenroll",
		generateTestCSRPEM(t), []*x509.Certificate{other.clientCrt}, tls.VersionTLS13)
	w := httptest.NewRecorder()
	h.SimpleEnrollMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (cert not trusted by this profile)", w.Code)
	}
}

func TestSimpleEnrollMTLS_HappyPath_200(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	req := makeMTLSRequest(t, "/.well-known/est-mtls/corp/simpleenroll",
		generateTestCSRPEM(t), []*x509.Certificate{s.clientCrt}, tls.VersionTLS13)
	w := httptest.NewRecorder()
	h.SimpleEnrollMTLS(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// ----- channel binding (Phase 2.4) -----

func TestSimpleReEnrollMTLS_ChannelBindingRequired_AbsentRejected(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	h.SetChannelBindingRequired(true)
	// CSR has no binding attribute. Synthetic ConnectionState — exporter
	// extraction will fail (no real TLS secret), and required=true makes
	// VerifyChannelBinding propagate that as the missing-binding error.
	req := makeMTLSRequest(t, "/.well-known/est-mtls/corp/simplereenroll",
		generateTestCSRPEM(t), []*x509.Certificate{s.clientCrt}, tls.VersionTLS13)
	w := httptest.NewRecorder()
	h.SimpleReEnrollMTLS(w, req)
	// Either 400 (missing) or 426 (TLS 1.3 unavailable on synthetic state).
	// Both are correct refusals; pin to "non-2xx" so the test isn't fragile
	// against ConnectionState evolution.
	if w.Code/100 == 2 {
		t.Errorf("required + absent must reject; got 2xx (%d)", w.Code)
	}
}

func TestSimpleReEnrollMTLS_ChannelBindingNotRequired_AbsentAllowed(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	h.SetChannelBindingRequired(false)
	// CSR has no binding, profile is opt-in only. The handler must allow.
	req := makeMTLSRequest(t, "/.well-known/est-mtls/corp/simplereenroll",
		generateTestCSRPEM(t), []*x509.Certificate{s.clientCrt}, tls.VersionTLS13)
	w := httptest.NewRecorder()
	h.SimpleReEnrollMTLS(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("required=false + absent must allow; got %d (%s)", w.Code, w.Body.String())
	}
}

func TestWriteChannelBindingError_KnownErrorsMapped(t *testing.T) {
	// Smoke test the error-to-status mapping so a future cms sentinel rename
	// gets caught at compile time + we hit each branch.
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	cases := []struct {
		err  error
		want int
	}{
		{cms.ErrChannelBindingMissing, http.StatusBadRequest},
		{cms.ErrChannelBindingMismatch, http.StatusConflict},
		{cms.ErrChannelBindingNotTLS13, http.StatusUpgradeRequired},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		h.writeChannelBindingError(w, "req-id", c.err)
		if w.Code != c.want {
			t.Errorf("error=%v → status %d, want %d", c.err, w.Code, c.want)
		}
	}
}

// ----- HTTP Basic enrollment-password (Phase 3) -----

func TestSimpleEnroll_BasicAuth_NoHeader_401(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetEnrollmentPassword("super-secret")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (Basic required, header absent)", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want to contain 'Basic'", got)
	}
}

func TestSimpleEnroll_BasicAuth_WrongPassword_401(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetEnrollmentPassword("super-secret")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req.SetBasicAuth("device", "wrong-password")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (wrong password)", w.Code)
	}
}

func TestSimpleEnroll_BasicAuth_CorrectPassword_200(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetEnrollmentPassword("super-secret")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req.SetBasicAuth("device", "super-secret")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (correct password); body=%q", w.Code, w.Body.String())
	}
}

func TestSimpleEnroll_BasicAuth_NoPassword_NoGate(t *testing.T) {
	// When the per-profile enrollment password is empty, the Basic gate is
	// off and the handler reverts to the v2.0.x anonymous behavior.
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc) // SetEnrollmentPassword not called
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no Basic gate)", w.Code)
	}
}

// ----- source-IP failed-auth rate limit (Phase 3.3) -----

func TestSimpleEnroll_BasicAuth_FailedAttemptLimitedAfterThreshold(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetEnrollmentPassword("super-secret")
	// Cap of 2 failed attempts before the IP gets locked. Each failed
	// attempt records a slot; the 3rd request should be 429.
	limiter := ratelimit.NewSlidingWindowLimiter(2, time.Hour, 10)
	h.SetSourceIPRateLimiter(limiter)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
			strings.NewReader(generateTestCSRPEM(t)))
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		req.RemoteAddr = "10.0.0.42:12345"
		req.SetBasicAuth("device", "WRONG")
		w := httptest.NewRecorder()
		h.SimpleEnroll(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// The 3rd attempt — even with a correct password — must be rate limited.
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req.RemoteAddr = "10.0.0.42:12345"
	req.SetBasicAuth("device", "super-secret")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("post-lockout status = %d, want 429 (correct password should still be locked out)", w.Code)
	}
}

// ----- per-principal sliding-window rate limit (Phase 4.2) -----

func TestSimpleEnroll_PerPrincipalLimit_BlocksAfterCap(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	limiter := ratelimit.NewSlidingWindowLimiter(2, 24*time.Hour, 100)
	h.SetPerPrincipalRateLimiter(limiter)

	// First 2 enrollments from same (CN, IP) — pass.
	csrPEM := generateTestCSRPEM(t)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
			strings.NewReader(csrPEM))
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		req.RemoteAddr = "10.0.0.7:5555"
		w := httptest.NewRecorder()
		h.SimpleEnroll(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: want 200, got %d", i, w.Code)
		}
	}
	// Third enrollment from same (CN, IP) — limited.
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
		strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req.RemoteAddr = "10.0.0.7:5555"
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("3rd same-principal enrollment status = %d, want 429", w.Code)
	}
}

func TestSimpleEnroll_PerPrincipalLimit_DifferentPrincipalsIndependent(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	limiter := ratelimit.NewSlidingWindowLimiter(1, 24*time.Hour, 100)
	h.SetPerPrincipalRateLimiter(limiter)

	csrPEM1 := generateTestCSRPEM(t)
	csrPEM2 := generateTestCSRPEM(t) // different key + (default) different CN

	req1 := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll", strings.NewReader(csrPEM1))
	req1.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req1.RemoteAddr = "10.0.0.10:1111"
	w1 := httptest.NewRecorder()
	h.SimpleEnroll(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("principal 1 first call: want 200, got %d", w1.Code)
	}

	// Same CN as csrPEM1 but different IP — independent bucket.
	req2 := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll", strings.NewReader(csrPEM2))
	req2.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	req2.RemoteAddr = "10.0.0.20:2222"
	w2 := httptest.NewRecorder()
	h.SimpleEnroll(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("principal 2 first call: want 200, got %d", w2.Code)
	}
}

// ----- per-handler smoke test for the un-rolled mTLS variants -----

func TestCACertsMTLS_RequiresClientCert(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/est-mtls/corp/cacerts", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.CACertsMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("CACertsMTLS no-cert status = %d, want 401", w.Code)
	}
}

func TestCSRAttrsMTLS_RequiresClientCert(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc)
	h.SetMTLSTrust(s.trustPool)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/est-mtls/corp/csrattrs", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.CSRAttrsMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("CSRAttrsMTLS no-cert status = %d, want 401", w.Code)
	}
}

// ----- ensure the per-principal limit fires only when configured -----

func TestSimpleEnroll_NoPerPrincipalLimiter_AllUnbounded(t *testing.T) {
	s := newHardeningTestSetup(t)
	h := NewESTHandler(s.svc) // SetPerPrincipalRateLimiter not called
	csrPEM := generateTestCSRPEM(t)
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/simpleenroll",
			strings.NewReader(csrPEM))
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		w := httptest.NewRecorder()
		h.SimpleEnroll(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: want 200, got %d", i, w.Code)
		}
	}
}

// silenceUnused keeps the "declared and not used" linter happy when we add
// helpers that future tests may invoke (asn1, atomic).
var _ = asn1.RawValue{}
var _ atomic.Int32
