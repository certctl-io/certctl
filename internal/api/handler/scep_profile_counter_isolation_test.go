package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/pkcs7"
	"github.com/shankar0123/certctl/internal/scep/intune"
	"github.com/shankar0123/certctl/internal/service"
)

// SCEP RFC 8894 + Intune master prompt §13 line 1851 acceptance —
// "Per-profile dispatch test must prove per-profile counters in
// metrics." Closed in the 2026-04-29 audit-closure bundle (Phase E).
//
// Why this test exists separately from the existing router-level
// /scep/<pathID> dispatch test (TestRouter_RegisterSCEPHandlers_
// MultipleProfilesNoCrossBleed): that test proves the route table
// doesn't bleed; this one proves the in-memory observability state
// (intuneCounterTab) is per-SCEPService, not shared. The bug class
// it guards against is a future cmd/server/main.go refactor that
// constructs a single shared *intuneCounterTab and injects it into
// every per-profile service — that would compile cleanly, pass the
// existing route-table test, and silently inflate one profile's
// counters with another's traffic.

// TestSCEPHandler_PerProfileIntuneCountersIsolated wires two real
// SCEPService instances, each with its OWN trust anchor + audience.
// A success on profile "corp" MUST NOT tick "iot"'s success counter,
// and vice versa for the failure path. The test constructs the
// fixtures hermetically (no shared state between the two profiles
// except the test's t.TempDir + selfSignedRSACert helpers).
func TestSCEPHandler_PerProfileIntuneCountersIsolated(t *testing.T) {
	corpFix := buildPerProfileIntuneFixture(t, "corp", "https://certctl.example.com/scep/corp")
	iotFix := buildPerProfileIntuneFixture(t, "iot", "https://certctl.example.com/scep/iot")
	now := time.Now()

	// --- Drive a SUCCESS through CORP ---
	corpChallenge := signIntuneChallengeES256(t, corpFix.connectorKey, map[string]any{
		"iss":         "intune-connector-corp-fixture",
		"sub":         "device-guid-corp-001",
		"aud":         "https://certctl.example.com/scep/corp",
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(59 * time.Minute).Unix(),
		"nonce":       "iso-corp-nonce-001",
		"device_name": "device-corp-001.example.com",
	})
	corpMsg := buildIntuneE2EPKIMessage(t, corpFix, "txn-iso-corp", corpChallenge, "device-corp-001.example.com")
	w, body := postPKIOperation(t, corpFix.handler, corpMsg)
	if w.Code != http.StatusOK {
		t.Fatalf("corp success: HTTP %d (body=%q)", w.Code, body)
	}

	// --- Drive an EXPIRED challenge through IOT ---
	iotChallenge := signIntuneChallengeES256(t, iotFix.connectorKey, map[string]any{
		"iss":         "intune-connector-iot-fixture",
		"sub":         "device-guid-iot-001",
		"aud":         "https://certctl.example.com/scep/iot",
		"iat":         now.Add(-2 * time.Hour).Unix(),
		"exp":         now.Add(-1 * time.Hour).Unix(), // expired
		"nonce":       "iso-iot-nonce-001",
		"device_name": "device-iot-001.example.com",
	})
	iotMsg := buildIntuneE2EPKIMessage(t, iotFix, "txn-iso-iot", iotChallenge, "device-iot-001.example.com")
	w, body = postPKIOperation(t, iotFix.handler, iotMsg)
	if w.Code != http.StatusOK {
		t.Fatalf("iot expired: HTTP %d — RFC 8894 §3.3 mandates a CertRep on every PKIOperation including failures; body=%q", w.Code, body)
	}
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("iot expired: ParseSignedData: %v", err)
	}
	statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Errorf("iot expired pkiStatus = %q, want FAILURE", statusStr)
	}

	// --- Assert per-service counter isolation ---
	corpStats := corpFix.scepService.IntuneStats(time.Now())
	iotStats := iotFix.scepService.IntuneStats(time.Now())

	if got, want := corpStats.PathID, "corp"; got != want {
		t.Errorf("corp PathID = %q, want %q", got, want)
	}
	if got, want := iotStats.PathID, "iot"; got != want {
		t.Errorf("iot PathID = %q, want %q", got, want)
	}

	// CORP should have exactly one success and zero of every other label.
	if got := corpStats.Counters["success"]; got != 1 {
		t.Errorf("corp.Counters[success] = %d, want 1", got)
	}
	if got := corpStats.Counters["expired"]; got != 0 {
		t.Errorf("corp.Counters[expired] = %d, want 0 (iot's expired traffic must NOT bleed into corp)", got)
	}
	// IOT should have exactly one expired and zero successes.
	if got := iotStats.Counters["expired"]; got != 1 {
		t.Errorf("iot.Counters[expired] = %d, want 1", got)
	}
	if got := iotStats.Counters["success"]; got != 0 {
		t.Errorf("iot.Counters[success] = %d, want 0 (corp's success traffic must NOT bleed into iot)", got)
	}

	// And the issuer-side state — corp's mock issuer saw the issuance,
	// iot's did not. This pins that the per-profile dispatch reaches
	// the per-profile issuer connector too (not just the counter tab).
	if got, want := len(corpFix.issuer.issued), 1; got != want {
		t.Errorf("corp issuances = %d, want %d", got, want)
	}
	if got, want := len(iotFix.issuer.issued), 0; got != want {
		t.Errorf("iot issuances = %d, want %d (iot's expired challenge must NOT have produced issuance)", got, want)
	}
}

// buildPerProfileIntuneFixture builds an Intune-enabled SCEPService for
// the given pathID + audience, with its own freshly-generated trust
// anchor + RA pair + issuer mock. Mirrors newIntuneE2EFixture but
// parameterized so the per-profile-isolation test can stand up two
// independent stacks side-by-side.
func buildPerProfileIntuneFixture(t *testing.T, pathID, audience string) *intuneE2EFixture {
	t.Helper()

	connectorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("connector key (%s): %v", pathID, err)
	}
	connectorCert := selfSignedECCertForIntuneE2E(t, connectorKey, "intune-connector-"+pathID)

	dir := t.TempDir()
	trustPath := filepath.Join(dir, "intune-trust-"+pathID+".pem")
	if err := os.WriteFile(trustPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: connectorCert.Raw}), 0o600); err != nil {
		t.Fatalf("write trust anchor (%s): %v", pathID, err)
	}
	trustHolder, err := intune.NewTrustAnchorHolder(trustPath, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10})))
	if err != nil {
		t.Fatalf("NewTrustAnchorHolder (%s): %v", pathID, err)
	}

	raKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ra key (%s): %v", pathID, err)
	}
	raCert := selfSignedRSACert(t, raKey, "ra-iso-"+pathID)

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key (%s): %v", pathID, err)
	}
	caCert := selfSignedRSACert(t, caKey, "test-fixture-ca-"+pathID)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	issuer := &intuneE2EIssuerConnector{
		caPEM:   string(caPEM),
		signKey: caKey,
		caCert:  caCert,
	}

	auditRepo := &intuneE2EAuditRepo{}
	auditSvc := service.NewAuditService(auditRepo)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
	scepSvc := service.NewSCEPService("iss-"+pathID, issuer, auditSvc, logger, "static-fallback-"+pathID)
	scepSvc.SetPathID(pathID)
	scepSvc.SetIntuneIntegration(
		trustHolder,
		audience,
		60*time.Minute,
		0, // ClockSkewTolerance — strict
		intune.NewReplayCache(60*time.Minute, 100),
		intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100),
	)

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("device key (%s): %v", pathID, err)
	}
	deviceCert := selfSignedRSACert(t, deviceKey, "device-iso-"+pathID)

	handler := NewSCEPHandler(scepSvc)
	handler.SetRAPair(raCert, raKey)

	return &intuneE2EFixture{
		connectorKey: connectorKey,
		connectorDir: dir,
		trustPath:    trustPath,
		trustHolder:  trustHolder,
		raKey:        raKey,
		raCert:       raCert,
		deviceKey:    deviceKey,
		deviceCert:   deviceCert,
		issuer:       issuer,
		auditRepo:    auditRepo,
		scepService:  scepSvc,
		handler:      handler,
	}
}

// silence unused-import for httptest (only needed if a future test in
// this file constructs requests directly — kept here to avoid a
// goimports-driven churn the next time the file gains a test).
var _ = httptest.NewRecorder
