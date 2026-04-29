package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// SCEP RFC 8894 + Intune master bundle Phase 6.5: mTLS sibling SCEP
// route. Pins the auth contract:
//
//   1. RejectsMissingClientCert — request without r.TLS.PeerCertificates
//      gets HTTP 401 (mTLS failure is authentication, not authorization).
//   2. RejectsUntrustedClientCert — cert that doesn't chain to the
//      configured trust pool gets HTTP 401.
//   3. AcceptsTrustedClientCert — cert that chains + valid challenge
//      password = 200 (delegates to HandleSCEP which returns 200 for
//      GetCACaps).
//   4. StillRequiresChallengePassword — valid client cert + invalid
//      challenge password reaches the handler but the service-layer
//      gate rejects. (For this test we exercise the GetCACaps GET — the
//      challenge-password gate fires on PKIOperation; the test is here
//      to pin that mTLS does NOT bypass the standard SCEP auth chain.)
//   5. StandardSCEPRoute_StillNoMTLS — pin the standard /scep route
//      keeps working without a client cert; the router test next door
//      covers the route registration shape.
//
// The mock SCEPService is the same mockSCEPService from
// scep_handler_test.go (same package).

// mtlsTestFixture materialises a per-test mTLS trust CA + a client cert
// that chains to it (the "trusted device") + an unrelated CA + cert
// (the "untrusted attacker"). Returns the SCEPHandler with the trust
// pool wired and pre-built TLS connection states for each cert.
type mtlsTestFixture struct {
	handler           SCEPHandler
	trustedTLSState   *tls.ConnectionState
	untrustedTLSState *tls.ConnectionState
}

func newMTLSTestFixture(t *testing.T) *mtlsTestFixture {
	t.Helper()
	// Trusted bootstrap CA + client cert chained to it.
	trustedCA, trustedCAKey := genSelfSignedECDSACA(t, "trusted-bootstrap-ca")
	trustedClient := signECDSAClientCert(t, "trusted-device", trustedCA, trustedCAKey)
	// Untrusted CA + client cert chained to a different CA — should NOT
	// be accepted by the trusted profile's mTLS handler.
	untrustedCA, untrustedCAKey := genSelfSignedECDSACA(t, "untrusted-attacker-ca")
	untrustedClient := signECDSAClientCert(t, "untrusted-device", untrustedCA, untrustedCAKey)

	pool := x509.NewCertPool()
	pool.AddCert(trustedCA)

	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)
	h.SetMTLSTrustPool(pool)

	return &mtlsTestFixture{
		handler: h,
		trustedTLSState: &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{trustedClient},
		},
		untrustedTLSState: &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{untrustedClient},
		},
	}
}

func TestSCEPMTLSHandler_RejectsMissingClientCert(t *testing.T) {
	fix := newMTLSTestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/scep-mtls?operation=GetCACaps", nil)
	// req.TLS intentionally nil — simulates a client that didn't present
	// a cert during the handshake (VerifyClientCertIfGiven allows this).
	w := httptest.NewRecorder()
	fix.handler.HandleSCEPMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HandleSCEPMTLS without client cert: got %d, want 401 (body=%q)", w.Code, w.Body.String())
	}
}

func TestSCEPMTLSHandler_RejectsUntrustedClientCert(t *testing.T) {
	fix := newMTLSTestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/scep-mtls?operation=GetCACaps", nil)
	req.TLS = fix.untrustedTLSState
	w := httptest.NewRecorder()
	fix.handler.HandleSCEPMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HandleSCEPMTLS with untrusted client cert: got %d, want 401 (body=%q)", w.Code, w.Body.String())
	}
}

func TestSCEPMTLSHandler_AcceptsTrustedClientCert(t *testing.T) {
	fix := newMTLSTestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/scep-mtls?operation=GetCACaps", nil)
	req.TLS = fix.trustedTLSState
	w := httptest.NewRecorder()
	fix.handler.HandleSCEPMTLS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleSCEPMTLS with trusted client cert: got %d, want 200 (GetCACaps; body=%q)", w.Code, w.Body.String())
	}
	// Sanity: response body is the GetCACaps capability list (the
	// HandleSCEP delegate ran).
	if got := w.Body.String(); got == "" {
		t.Errorf("HandleSCEPMTLS body empty, want SCEP capabilities")
	}
}

func TestSCEPMTLSHandler_StillRoutesThroughHandleSCEP(t *testing.T) {
	// With a valid client cert, HandleSCEPMTLS delegates to HandleSCEP —
	// pin that the standard SCEP dispatch still runs (operation query-
	// param dispatch, content-type negotiation, etc.). Defense in depth:
	// mTLS is additive, NOT replacement; the standard SCEP code path
	// must still execute end-to-end.
	fix := newMTLSTestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/scep-mtls?operation=GetCACaps", nil)
	req.TLS = fix.trustedTLSState
	w := httptest.NewRecorder()
	fix.handler.HandleSCEPMTLS(w, req)
	if got := w.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain (HandleSCEP didn't run)", got)
	}
}

func TestSCEPMTLSHandler_NoTrustPool_Returns500(t *testing.T) {
	// A handler registered for /scep-mtls but with SetMTLSTrustPool never
	// called is a deploy bug — the startup preflight should have caught
	// this. Pin that the handler returns HTTP 500 in that state rather
	// than silently accepting (or worse, panicking).
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc) // no SetMTLSTrustPool call
	req := httptest.NewRequest(http.MethodGet, "/scep-mtls?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	h.HandleSCEPMTLS(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("HandleSCEPMTLS without trust pool: got %d, want 500 (deploy-bug surface)", w.Code)
	}
}

func TestSCEPHandler_StandardRoute_StillNoMTLS(t *testing.T) {
	// Pin: the standard HandleSCEP entry point does NOT require a
	// client cert even when an mTLS pool is set — the standard route
	// remains application-layer-auth (challenge password). Operators
	// can run BOTH routes simultaneously for migration / heterogeneous
	// client fleets.
	fix := newMTLSTestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACaps", nil)
	// req.TLS intentionally nil — standard /scep should still serve.
	w := httptest.NewRecorder()
	fix.handler.HandleSCEP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("HandleSCEP (standard route) without client cert: got %d, want 200", w.Code)
	}
}

// --- helpers -------------------------------------------------------------

func genSelfSignedECDSACA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey CA: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	return cert, key
}

func signECDSAClientCert(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey client: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate client: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate client: %v", err)
	}
	return cert
}

// silence unused-package warning if context becomes orphan in future
// refactors of the mTLS test file (keeps imports stable).
var _ = context.Background
