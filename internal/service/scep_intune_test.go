package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/scep/intune"
)

// SCEP RFC 8894 + Intune master bundle Phase 8.9 — service-layer dispatcher
// tests. Exercises the looksIntuneShaped pre-check, the validator + claim
// binding, the replay cache + per-device rate limiter integration, and the
// nil-default compliance hook seam.

// ------------------------------------------------------------------
// Test plumbing.
// ------------------------------------------------------------------

func newTestSCEPLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// intuneTestConn manufactures an ephemeral RSA Connector signing cert + key
// for tests that build challenges by hand. Mirrors challenge_test.go's
// helper but lives in the service package so tests can exercise the full
// dispatcher path.
type intuneTestConn struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newIntuneTestConn(t *testing.T) intuneTestConn {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-intune-connector"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return intuneTestConn{key: key, cert: cert}
}

// signTestChallenge hand-builds a signed Intune-shaped challenge with the
// caller-supplied claim payload. Returns the wire-format string ready to
// pass as the "challenge password" argument to PKCSReq.
func (c intuneTestConn) signTestChallenge(t *testing.T, payload any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// holderFromCerts wraps a static slice of certs as a TrustAnchorHolder
// without going through the on-disk loader. Used for tests that drive
// validation without writing a temp PEM file.
func holderFromCerts(t *testing.T, certs []*x509.Certificate) *intune.TrustAnchorHolder {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/intune-trust.pem"
	// Write a real bundle so the holder can Reload later if the test wants.
	body := []byte{}
	for _, c := range certs {
		body = append(body, []byte("-----BEGIN CERTIFICATE-----\n")...)
		b64 := base64.StdEncoding.EncodeToString(c.Raw)
		// Wrap to 64-char lines per PEM convention.
		for len(b64) > 64 {
			body = append(body, []byte(b64[:64]+"\n")...)
			b64 = b64[64:]
		}
		body = append(body, []byte(b64+"\n-----END CERTIFICATE-----\n")...)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile trust bundle: %v", err)
	}
	holder, err := intune.NewTrustAnchorHolder(path, newTestSCEPLogger())
	if err != nil {
		t.Fatalf("NewTrustAnchorHolder: %v", err)
	}
	return holder
}

// validIntunePayload returns a v1 challenge payload whose claim matches a
// CSR generated via generateCSRPEM(t, "device.example.com", []string{...}).
// Tests can mutate it before signing to exercise individual failure modes.
func validIntunePayload(now time.Time) map[string]any {
	return map[string]any{
		"iss":         "test-intune-connector-installation",
		"sub":         "device-guid-001",
		"aud":         "https://certctl.example.com/scep/corp",
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(59 * time.Minute).Unix(),
		"nonce":       "nonce-001",
		"device_name": "device.example.com",
		"san_dns":     []string{"device.example.com"},
	}
}

// ------------------------------------------------------------------
// Dispatcher behavior.
// ------------------------------------------------------------------

func TestSCEPService_LooksIntuneShaped(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"short static password", "secret123", false},
		{"long but no dots", strings.Repeat("a", 300), false},
		{"long with two dots (intune-shaped)", strings.Repeat("a", 80) + "." + strings.Repeat("b", 80) + "." + strings.Repeat("c", 80), true},
		{"long with three dots (not intune)", "a.b.c.d", false},
		{"exactly 200 bytes (boundary, not intune)", strings.Repeat("a", 100) + "." + strings.Repeat("a", 99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksIntuneShaped(tc.in); got != tc.want {
				t.Errorf("looksIntuneShaped(%q) = %v, want %v", tc.in[:min(40, len(tc.in))]+"…", got, tc.want)
			}
		})
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_Success(t *testing.T) {
	conn := newIntuneTestConn(t)
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)

	// Service has the legacy challenge password set (we want to verify the
	// dispatcher takes precedence over the static path when intune-shaped).
	svc := NewSCEPService("iss-local", mockIssuer, auditSvc, newTestSCEPLogger(), "static-secret")
	holder := holderFromCerts(t, []*x509.Certificate{conn.cert})
	svc.SetIntuneIntegration(
		holder,
		"https://certctl.example.com/scep/corp",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))

	result, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-intune-001")
	if err != nil {
		t.Fatalf("PKCSReq: %v", err)
	}
	if result == nil || result.CertPEM == "" {
		t.Fatalf("expected non-empty cert; got %#v", result)
	}

	// The audit event should carry the Intune-specific action code so
	// operators can grep the audit log to count Intune enrollments
	// distinct from static-challenge enrollments.
	if len(auditRepo.Events) == 0 {
		t.Fatalf("expected an audit event")
	}
	if got := auditRepo.Events[0].Action; got != "scep_pkcsreq_intune" {
		t.Errorf("audit action = %q, want scep_pkcsreq_intune (Phase 8.4)", got)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_StaticChallengeStillWorks(t *testing.T) {
	// Operator deploy that has Intune enabled on a profile but a device
	// sends a SHORT static challenge — must still work via the fallback path.
	conn := newIntuneTestConn(t)
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"https://certctl.example.com/scep/corp",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	if _, err := svc.PKCSReq(context.Background(), csrPEM, "static-secret", "txn-static-001"); err != nil {
		t.Fatalf("static-challenge fallback should still work when Intune enabled: %v", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_TamperedChallengeRejected(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	good := conn.signTestChallenge(t, validIntunePayload(time.Now()))
	parts := strings.Split(good, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")

	_, err := svc.PKCSReq(context.Background(), csrPEM, tampered, "txn-tamper-001")
	if err == nil {
		t.Fatal("expected tampered challenge to be rejected")
	}
	if !errors.Is(err, intune.ErrChallengeSignature) {
		t.Errorf("got %v, want errors.Is(ErrChallengeSignature)", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_ClaimMismatchRejected(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)

	// CSR's CN ("attacker-host.example.com") does NOT match the claim's
	// device_name ("device.example.com").
	csrPEM := generateCSRPEM(t, "attacker-host.example.com", []string{"attacker-host.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))

	_, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-mismatch-001")
	if err == nil {
		t.Fatal("expected claim mismatch to be rejected")
	}
	if !errors.Is(err, intune.ErrClaimCNMismatch) {
		t.Errorf("got %v, want ErrClaimCNMismatch", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_ReplayDetected(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(0, 24*time.Hour, 100), // disable rate limit so we don't trip THAT first
	)

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))

	if _, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-001"); err != nil {
		t.Fatalf("first call should succeed: %v", err)
	}
	_, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-002")
	if !errors.Is(err, intune.ErrChallengeReplay) {
		t.Fatalf("got %v, want ErrChallengeReplay on the second call", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_RateLimited(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		// Replay cache must not block us — use disjoint nonces per call.
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(2, 24*time.Hour, 100), // limit = 2
	)

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})

	for i := 0; i < 2; i++ {
		pl := validIntunePayload(time.Now())
		pl["nonce"] = "nonce-" + string(rune('a'+i))
		ch := conn.signTestChallenge(t, pl)
		if _, err := svc.PKCSReq(context.Background(), csrPEM, ch, "txn-allow"); err != nil {
			t.Fatalf("call %d should succeed: %v", i+1, err)
		}
	}
	// 3rd call same (Subject, Issuer) → rate limited.
	pl := validIntunePayload(time.Now())
	pl["nonce"] = "nonce-third"
	third := conn.signTestChallenge(t, pl)
	_, err := svc.PKCSReq(context.Background(), csrPEM, third, "txn-block")
	if !errors.Is(err, intune.ErrRateLimited) {
		t.Fatalf("got %v, want ErrRateLimited on 3rd call (cap=2)", err)
	}
}

// ------------------------------------------------------------------
// Compliance-hook seam (Phase 8.7).
// ------------------------------------------------------------------

func TestSCEPService_PKCSReq_IntuneDispatcher_ComplianceHookNilDefault(t *testing.T) {
	// Default state: no hook installed, enrollments proceed.
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)
	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))
	if _, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-nil-hook"); err != nil {
		t.Fatalf("nil-default compliance hook should be a no-op: %v", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_ComplianceHookDeniesNonCompliant(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)
	svc.SetComplianceCheck(func(ctx context.Context, claim *intune.ChallengeClaim) (bool, string, error) {
		return false, "device under remediation", nil
	})

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))
	_, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-noncompliant")
	if err == nil {
		t.Fatal("non-compliant device must be rejected")
	}
	if !strings.Contains(err.Error(), "intune compliance") {
		t.Errorf("error should reference compliance reason: %v", err)
	}
	if !strings.Contains(err.Error(), "device under remediation") {
		t.Errorf("error should preserve compliance reason for audit: %v", err)
	}
}

func TestSCEPService_PKCSReq_IntuneDispatcher_ComplianceHookErrorFailsClosed(t *testing.T) {
	conn := newIntuneTestConn(t)
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (no grace) keeps these tests deterministic
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)
	svc.SetComplianceCheck(func(ctx context.Context, claim *intune.ChallengeClaim) (bool, string, error) {
		return false, "", errors.New("graph API down")
	})

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	challenge := conn.signTestChallenge(t, validIntunePayload(time.Now()))
	_, err := svc.PKCSReq(context.Background(), csrPEM, challenge, "txn-compl-err")
	if err == nil {
		t.Fatal("compliance API error must fail closed (deny)")
	}
}

// ------------------------------------------------------------------
// IntuneEnabled accessor + miscellaneous wiring.
// ------------------------------------------------------------------

func TestSCEPService_IntuneEnabled_AccessorReflectsState(t *testing.T) {
	svc := NewSCEPService("iss-local", &mockIssuerConnector{}, nil, newTestSCEPLogger(), "static")
	if svc.IntuneEnabled() {
		t.Fatal("freshly-built service must report IntuneEnabled=false")
	}
	conn := newIntuneTestConn(t)
	svc.SetIntuneIntegration(
		holderFromCerts(t, []*x509.Certificate{conn.cert}),
		"",
		0,
		0, // ClockSkewTolerance — strict (no grace)
		nil,
		nil,
	)
	if !svc.IntuneEnabled() {
		t.Fatal("after SetIntuneIntegration, IntuneEnabled() must report true")
	}
}

func TestSCEPService_PKCSReq_IntuneDisabled_StaticPathUnchanged(t *testing.T) {
	// Sanity: a service that NEVER had SetIntuneIntegration called must
	// behave exactly like the pre-Phase-8 service. This pins the no-regression
	// guarantee for the broad set of profiles that won't enable Intune.
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, NewAuditService(newMockAuditRepository()), newTestSCEPLogger(), "static-secret")

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	// Submit something Intune-shaped — without SetIntuneIntegration this
	// must NOT route through the dispatcher (looksIntuneShaped + intuneEnabled
	// are AND-gated). It will fall through to the static compare and reject.
	intuneShaped := strings.Repeat("a", 80) + "." + strings.Repeat("b", 80) + "." + strings.Repeat("c", 80)
	if _, err := svc.PKCSReq(context.Background(), csrPEM, intuneShaped, "txn-noop"); err == nil {
		t.Fatal("static path with wrong password must reject (we passed an intune-shaped string but Intune is off)")
	}
	// Now submit the right static password — must succeed.
	if _, err := svc.PKCSReq(context.Background(), csrPEM, "static-secret", "txn-noop-2"); err != nil {
		t.Fatalf("static path with right password must work: %v", err)
	}
}

// ------------------------------------------------------------------
// IntuneFailReason mapping.
// ------------------------------------------------------------------

func TestIntuneFailReason_AllTypedErrorsMapped(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "success"},
		{intune.ErrChallengeSignature, "signature_invalid"},
		{intune.ErrChallengeExpired, "expired"},
		{intune.ErrChallengeNotYetValid, "not_yet_valid"},
		{intune.ErrChallengeWrongAudience, "wrong_audience"},
		{intune.ErrChallengeReplay, "replay"},
		{intune.ErrChallengeUnknownVersion, "unknown_version"},
		{intune.ErrChallengeMalformed, "malformed"},
		{intune.ErrRateLimited, "rate_limited"},
		{intune.ErrClaimCNMismatch, "claim_mismatch"},
		{intune.ErrClaimSANDNSMismatch, "claim_mismatch"},
		{intune.ErrClaimSANRFC822Mismatch, "claim_mismatch"},
		{intune.ErrClaimSANUPNMismatch, "claim_mismatch"},
		{errors.New("something else"), "malformed"}, // default bucket
	}
	for _, tc := range cases {
		got := intuneFailReason(tc.err)
		if got != tc.want {
			t.Errorf("intuneFailReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// asn1 unused but imported by sibling tests; this package-level guard keeps
// future changes that introduce ASN.1 fixtures here from breaking the build.
func init() {
	_ = ecdsa.GenerateKey
	_ = elliptic.P256
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
