package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/pkcs7"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/scep/intune"
	"github.com/certctl-io/certctl/internal/service"
)

// SCEP RFC 8894 + Intune master bundle Phase 10.2 — hermetic end-to-end
// test for the Intune dispatcher running through the full handler →
// service → validator → CertRep wire path.
//
// What this test exercises (top to bottom):
//
//   1. Real SCEPService instance with SetIntuneIntegration wired to a
//      real intune.TrustAnchorHolder (loaded from a temp PEM file).
//   2. Real intune.ReplayCache + intune.PerDeviceRateLimiter.
//   3. Real SCEPHandler with RA cert/key + service injected.
//   4. Real PKIMessage built via the existing chromeOS-shape builders
//      (SignedData wrapping EnvelopedData wrapping a CSR carrying the
//      Intune-shaped challengePassword attribute).
//   5. POST through HandleSCEP — handler runs tryParseRFC8894 →
//      service.PKCSReqWithEnvelope → dispatchIntuneChallenge →
//      ValidateChallenge → DeviceMatchesCSR → replay → rate-limit →
//      processEnrollment → CertRep PKIMessage response.
//   6. Decode the CertRep response and assert pkiStatus=Success.
//
// What this test deliberately does NOT do:
//
//   - Boot docker-compose.test.yml. The spec's deploy/test/ variant
//     reserves that for a future enhancement that mounts a fixture
//     trust anchor into the running container; this hermetic version
//     runs in the default `go test ./...` sweep so every CI run
//     exercises the full Intune chain.
//   - Hit a real issuer connector. The IssuerConnector is a fixture
//     mock (intuneE2EIssuerConnector below) that returns a deterministic
//     issued cert so the test can assert its own CN/SANs without
//     spinning up a CA.

// intuneE2EFixture wires up a real SCEPService with the Intune dispatcher
// enabled, a real handler, plus a forged Intune Connector signing
// keypair the test uses to mint valid challenges.
type intuneE2EFixture struct {
	connectorKey *ecdsa.PrivateKey
	connectorDir string // dir holding the trust-anchor PEM (for SIGHUP-reload tests)
	trustPath    string // PEM file the holder watches; rewriting + Reload simulates SIGHUP
	trustHolder  *intune.TrustAnchorHolder
	raKey        *rsa.PrivateKey
	raCert       *x509.Certificate
	deviceKey    *rsa.PrivateKey
	deviceCert   *x509.Certificate
	issuer       *intuneE2EIssuerConnector
	auditRepo    *intuneE2EAuditRepo
	scepService  *service.SCEPService
	handler      SCEPHandler
}

// intuneE2EIssuerConnector is a minimal IssuerConnector that returns a
// deterministic fake-issued cert. We don't need a real CA for this test
// — the goal is to verify the handler→service→dispatcher chain end to
// end, NOT to verify cert issuance (which is covered in the local
// issuer's own tests).
type intuneE2EIssuerConnector struct {
	mu      sync.Mutex
	caPEM   string
	signKey *rsa.PrivateKey
	caCert  *x509.Certificate
	issued  []intuneE2EIssuance
}

type intuneE2EIssuance struct {
	commonName string
	sans       []string
	mustStaple bool
}

func (i *intuneE2EIssuerConnector) GetCACertPEM(_ context.Context) (string, error) {
	return i.caPEM, nil
}

func (i *intuneE2EIssuerConnector) IssueCertificate(_ context.Context, commonName string, sans []string, _ string, _ []string, _ int, mustStaple bool) (*service.IssuanceResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.issued = append(i.issued, intuneE2EIssuance{commonName: commonName, sans: sans, mustStaple: mustStaple})
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(i.issued)) + 1),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, &i.signKey.PublicKey, i.signKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &service.IssuanceResult{
		CertPEM:  string(certPEM),
		ChainPEM: i.caPEM,
		Serial:   tmpl.SerialNumber.String(),
		NotAfter: tmpl.NotAfter,
	}, nil
}

func (i *intuneE2EIssuerConnector) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*service.IssuanceResult, error) {
	return i.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
}

func (i *intuneE2EIssuerConnector) RevokeCertificate(_ context.Context, _ string, _ string) error {
	return nil
}

func (i *intuneE2EIssuerConnector) GenerateCRL(_ context.Context, _ []service.CRLEntry) ([]byte, error) {
	return nil, nil
}

func (i *intuneE2EIssuerConnector) SignOCSPResponse(_ context.Context, _ service.OCSPSignRequest) ([]byte, error) {
	return nil, nil
}

func (i *intuneE2EIssuerConnector) GetRenewalInfo(_ context.Context, _ string) (*service.RenewalInfoResult, error) {
	return nil, nil
}

// intuneE2EAuditRepo captures audit events so the test can assert the
// dispatcher emitted scep_pkcsreq_intune.
type intuneE2EAuditRepo struct {
	mu     sync.Mutex
	events []domain.AuditEvent
}

func (r *intuneE2EAuditRepo) Create(_ context.Context, e *domain.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, *e)
	return nil
}

// CreateWithTx mirrors Create — handler-test mocks have no DB; the
// Querier is ignored.
func (r *intuneE2EAuditRepo) CreateWithTx(ctx context.Context, _ repository.Querier, e *domain.AuditEvent) error {
	return r.Create(ctx, e)
}

func (r *intuneE2EAuditRepo) List(_ context.Context, _ *repository.AuditFilter) ([]*domain.AuditEvent, error) {
	return nil, nil
}

func (r *intuneE2EAuditRepo) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Action)
	}
	return out
}

// newIntuneE2EFixture wires up the full Intune-mode SCEP stack.
func newIntuneE2EFixture(t *testing.T) *intuneE2EFixture {
	t.Helper()

	// 1. Forge a Connector signing keypair + self-signed cert. This is
	//    what an operator would extract from their installed Intune
	//    Certificate Connector and configure as INTUNE_CONNECTOR_CERT_PATH.
	connectorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("connector key: %v", err)
	}
	connectorCert := selfSignedECCertForIntuneE2E(t, connectorKey, "intune-connector-test")

	// 2. Write the Connector cert to a temp PEM file so the
	//    TrustAnchorHolder loads it the same way it would in production.
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "intune-trust.pem")
	if err := os.WriteFile(trustPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: connectorCert.Raw}), 0o600); err != nil {
		t.Fatalf("write trust anchor: %v", err)
	}
	trustHolder, err := intune.NewTrustAnchorHolder(trustPath, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10})))
	if err != nil {
		t.Fatalf("NewTrustAnchorHolder: %v", err)
	}

	// 3. Build a fixture issuer + RA pair (RA cert/key the SCEP handler
	//    uses to decrypt EnvelopedData). The RA cert and the issuer's
	//    fake CA are independent — RA is a SCEP-protocol artifact, the
	//    CA cert is what the issuer connector returns from GetCACertPEM.
	raKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ra key: %v", err)
	}
	raCert := selfSignedRSACert(t, raKey, "ra-intune-e2e")

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caCert := selfSignedRSACert(t, caKey, "test-fixture-ca")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	issuer := &intuneE2EIssuerConnector{
		caPEM:   string(caPEM),
		signKey: caKey,
		caCert:  caCert,
	}

	// 4. Build a real SCEPService with intune integration wired in.
	auditRepo := &intuneE2EAuditRepo{}
	auditSvc := service.NewAuditService(auditRepo)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
	scepSvc := service.NewSCEPService("iss-test", issuer, auditSvc, logger, "static-fallback-secret")
	scepSvc.SetPathID("test")

	replayCache := intune.NewReplayCache(60*time.Minute, 100)
	rateLimiter := intune.NewPerDeviceRateLimiter(3, 24*time.Hour, 100)
	scepSvc.SetIntuneIntegration(
		trustHolder,
		"https://certctl.example.com/scep/test",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (the e2e fixture uses time.Now() consistently so no drift to absorb)
		replayCache,
		rateLimiter,
	)

	// 5. Build a transient device cert/key. The device wraps its CSR in
	//    EnvelopedData and signs the SCEP signerInfo with this transient
	//    key (the same shape ChromeOS / Intune-managed devices use).
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	deviceCert := selfSignedRSACert(t, deviceKey, "device-transient-intune")

	// 6. Build the SCEP handler.
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

// selfSignedECCertForIntuneE2E mirrors the existing selfSignedRSACert
// helper for an ECDSA P-256 keypair. Used for the fixture Connector
// signing cert. Distinct name to avoid colliding with selfSignedRSACert
// in the same package.
func selfSignedECCertForIntuneE2E(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// signIntuneChallengeES256 builds a real Intune-shaped challenge that
// the Connector would emit. RFC 7515 §3.4 fixed-width r||s ES256 form
// because that's the canonical JOSE shape.
func signIntuneChallengeES256(t *testing.T, connectorKey *ecdsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, connectorKey, h[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validIntuneE2EClaim returns a claim payload that matches a CSR with
// CN=device-corp-001.example.com — the dispatcher's DeviceMatchesCSR
// uses set-equality semantics, so we only pin device_name (CN). The
// CSR builder helper buildTestCSR doesn't populate DNSNames so we
// deliberately leave san_dns out of the claim — adding it would trip
// ErrClaimSANDNSMismatch (claim says ['x'], CSR has no DNS SANs).
// The claim_mismatch sibling test exercises the SAN-dimension failure
// path via the claim_mismatch counter.
func validIntuneE2EClaim(now time.Time, nonce string) map[string]any {
	return map[string]any{
		"iss":         "intune-connector-installation-fixture",
		"sub":         "device-guid-corp-001",
		"aud":         "https://certctl.example.com/scep/test",
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(59 * time.Minute).Unix(),
		"nonce":       nonce,
		"device_name": "device-corp-001.example.com",
	}
}

// TestSCEPIntuneEnrollment_E2E walks the full Phase 10.2 spec scenario:
// boot the stack (in-process), forge a valid challenge, build a CSR
// matching the claim, POST through the handler, decode the CertRep
// response, assert success + audit log + counter increment.
func TestSCEPIntuneEnrollment_E2E(t *testing.T) {
	fix := newIntuneE2EFixture(t)
	now := time.Now()

	intuneChallenge := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-nonce-001"))
	if !strings.Contains(intuneChallenge, ".") || len(intuneChallenge) <= 200 {
		t.Fatalf("forged challenge doesn't satisfy looksIntuneShaped: len=%d", len(intuneChallenge))
	}

	pkiMessage := buildIntuneE2EPKIMessage(t, fix, "txn-intune-e2e-001", intuneChallenge, "device-corp-001.example.com")

	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation: got %d, want 200 (body=%q)", w.Code, body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pki-message" {
		t.Errorf("Content-Type = %q, want application/x-pki-message", got)
	}

	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("ParseSignedData(CertRep): %v", err)
	}
	if len(certRep.SignerInfos) != 1 {
		t.Fatalf("CertRep has %d signers, want 1", len(certRep.SignerInfos))
	}
	statusRV, ok := certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()]
	if !ok {
		t.Fatal("CertRep missing pkiStatus auth-attr")
	}
	statusStr := decodeFirstSetMember(t, statusRV)
	if statusStr != string(domain.SCEPStatusSuccess) {
		t.Errorf("pkiStatus = %q, want %q (SUCCESS)", statusStr, domain.SCEPStatusSuccess)
	}

	if len(fix.issuer.issued) != 1 {
		t.Fatalf("issuer received %d issuances, want 1", len(fix.issuer.issued))
	}
	if fix.issuer.issued[0].commonName != "device-corp-001.example.com" {
		t.Errorf("issued CN = %q, want device-corp-001.example.com", fix.issuer.issued[0].commonName)
	}

	foundIntune := false
	for _, a := range fix.auditRepo.actions() {
		if a == "scep_pkcsreq_intune" {
			foundIntune = true
			break
		}
	}
	if !foundIntune {
		t.Errorf("expected an audit_event with action=scep_pkcsreq_intune; got actions=%v", fix.auditRepo.actions())
	}

	stats := fix.scepService.IntuneStats(time.Now())
	if got := stats.Counters["success"]; got != 1 {
		t.Errorf("IntuneStats.counters[success] = %d, want 1", got)
	}
}

// TestSCEPIntuneEnrollment_ClaimMismatchRejected_E2E builds a CSR whose
// CN does NOT match the claim's device_name. The dispatcher should
// reject with a CertRep FAILURE+BadRequest rather than issuing the
// cert. Per Phase 8 + the spec's claim-mismatch failInfo mapping
// (mapIntuneErrorToFailInfo).
func TestSCEPIntuneEnrollment_ClaimMismatchRejected_E2E(t *testing.T) {
	fix := newIntuneE2EFixture(t)
	now := time.Now()

	intuneChallenge := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-mismatch-001"))
	pkiMessage := buildIntuneE2EPKIMessage(t, fix, "txn-intune-mismatch", intuneChallenge, "attacker-host.example.com")

	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation (mismatch): got %d, want 200 (CertRep+failInfo wire shape, body=%q)", w.Code, body)
	}

	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("ParseSignedData(CertRep): %v", err)
	}
	statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Fatalf("pkiStatus = %q, want %q (FAILURE) for claim-mismatched CSR", statusStr, domain.SCEPStatusFailure)
	}

	failRV, ok := certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPFailInfo.String()]
	if !ok {
		t.Fatal("CertRep missing failInfo auth-attr on a FAILURE response")
	}
	failStr := decodeFirstSetMember(t, failRV)
	if failStr != string(domain.SCEPFailBadRequest) {
		t.Errorf("failInfo = %q, want %q (BadRequest) for claim mismatch", failStr, domain.SCEPFailBadRequest)
	}

	if len(fix.issuer.issued) != 0 {
		t.Errorf("issuer should NOT have issued a cert for a claim-mismatched CSR; got %d issuances", len(fix.issuer.issued))
	}
	stats := fix.scepService.IntuneStats(time.Now())
	if got := stats.Counters["claim_mismatch"]; got != 1 {
		t.Errorf("IntuneStats.counters[claim_mismatch] = %d, want 1", got)
	}
}

// TestSCEPIntuneEnrollment_TamperedSignature_E2E flips a byte in the
// JWT signature segment of the Intune challenge before wrapping it in
// the PKIMessage. The dispatcher should reject with FAILURE+BadMessageCheck
// (mapIntuneErrorToFailInfo: signature errors → BadMessageCheck).
func TestSCEPIntuneEnrollment_TamperedSignature_E2E(t *testing.T) {
	fix := newIntuneE2EFixture(t)
	now := time.Now()

	good := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-tamper-001"))
	parts := strings.Split(good, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")

	pkiMessage := buildIntuneE2EPKIMessage(t, fix, "txn-intune-tamper", tampered, "device-corp-001.example.com")
	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation (tampered): got %d, want 200 with FAILURE pkiStatus (body=%q)", w.Code, body)
	}
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Errorf("pkiStatus = %q, want FAILURE for tampered Intune sig", statusStr)
	}
	failStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPFailInfo.String()])
	if failStr != string(domain.SCEPFailBadMessageCheck) {
		t.Errorf("failInfo = %q, want BadMessageCheck for tampered Intune sig", failStr)
	}
}

// buildIntuneE2EPKIMessage builds a real SCEP PKIMessage that wraps the
// given Intune-shaped challenge as challengePassword inside an
// EnvelopedData(KTRI(raCert), AES-256-CBC(CSR + challengePassword)).
// Mirrors buildChromeOSStylePKIMessage but lets the test override the
// challengePassword to an Intune-shaped JWT-like blob.
func buildIntuneE2EPKIMessage(t *testing.T, fix *intuneE2EFixture, transactionID, challengePassword, csrCN string) []byte {
	t.Helper()

	csrDER := buildTestCSR(t, fix.deviceKey, csrCN, challengePassword)

	symKey := aesKeyForOID(pkcs7.OIDAES256CBC)
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := aesCBCEncrypt(t, symKey, iv, csrDER)

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fix.raCert.PublicKey.(*rsa.PublicKey), symKey)
	if err != nil {
		t.Fatalf("rsa encrypt symKey: %v", err)
	}
	envelopedData := buildEnvelopedDataForTest(t, fix.raCert, encryptedKey, iv, ciphertext, oidForAESKeyLen(t, len(symKey)))
	signedData := buildSignedDataForTest(t, fix.deviceKey, fix.deviceCert, domain.SCEPMessageTypePKCSReq, transactionID, []byte("0123456789abcdef"), envelopedData)
	return signedData
}

// =============================================================================
// SCEP RFC 8894 + Intune master-prompt §13 line 1849 acceptance — the two
// remaining e2e named tests: _RateLimited_E2E + _TrustAnchorSIGHUPReload_E2E.
// Closed in the 2026-04-29 audit-closure bundle.
// =============================================================================

// TestSCEPIntuneEnrollment_RateLimited_E2E exercises the full
// handler→service→dispatcher chain past the per-device rate-limit cap.
// The fixture's default cap (3) is too high for a quick test; we
// re-inject a fresh limiter with cap=2 so the 3rd attempt for the same
// (Subject, Issuer) returns FAILURE+BadRequest with rate_limited
// counter ticked. Each PKIMessage carries a distinct nonce (replay
// cache otherwise rejects on duplicate-nonce well before the limiter
// fires), and a distinct transactionID so the audit-log shape is
// inspectable per attempt.
func TestSCEPIntuneEnrollment_RateLimited_E2E(t *testing.T) {
	fix := newIntuneE2EFixture(t)

	// Re-wire SetIntuneIntegration with a stricter cap so the test
	// stays fast. Also a fresh replay cache so a previous attempt's
	// state doesn't leak into this test if Go ever reorders test
	// execution within the package.
	tightLimiter := intune.NewPerDeviceRateLimiter(2, 24*time.Hour, 100)
	freshReplay := intune.NewReplayCache(60*time.Minute, 100)
	fix.scepService.SetIntuneIntegration(
		fix.trustHolder,
		"https://certctl.example.com/scep/test",
		60*time.Minute,
		0, // ClockSkewTolerance — strict (we mint claims at time.Now())
		freshReplay,
		tightLimiter,
	)

	now := time.Now()

	// First two attempts succeed (cap=2 means ≤2 issuances per 24h).
	for i := 0; i < 2; i++ {
		nonce := "e2e-rate-allow-" + string(rune('a'+i))
		ch := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, nonce))
		txn := "txn-rate-allow-" + string(rune('a'+i))
		pkiMessage := buildIntuneE2EPKIMessage(t, fix, txn, ch, "device-corp-001.example.com")
		w, body := postPKIOperation(t, fix.handler, pkiMessage)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: HTTP %d (body=%q)", i+1, w.Code, body)
		}
		certRep, err := pkcs7.ParseSignedData(body)
		if err != nil {
			t.Fatalf("attempt %d: ParseSignedData: %v", i+1, err)
		}
		statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
		if statusStr != string(domain.SCEPStatusSuccess) {
			t.Fatalf("attempt %d: pkiStatus = %q, want SUCCESS (the allowed first %d/%d)", i+1, statusStr, i+1, 2)
		}
	}

	// 3rd attempt for the SAME (Subject, Issuer) MUST be rate-limited.
	tripCh := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-rate-deny-c"))
	tripMsg := buildIntuneE2EPKIMessage(t, fix, "txn-rate-deny-c", tripCh, "device-corp-001.example.com")
	w, body := postPKIOperation(t, fix.handler, tripMsg)
	if w.Code != http.StatusOK {
		t.Fatalf("rate-limited attempt: HTTP %d (body=%q) — RFC 8894 §3.3 mandates a CertRep on every PKIOperation, including failures", w.Code, body)
	}
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("rate-limited attempt: ParseSignedData: %v", err)
	}
	statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Fatalf("rate-limited pkiStatus = %q, want FAILURE", statusStr)
	}
	failRV, ok := certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPFailInfo.String()]
	if !ok {
		t.Fatal("rate-limited CertRep missing failInfo auth-attr")
	}
	failStr := decodeFirstSetMember(t, failRV)
	if failStr != string(domain.SCEPFailBadRequest) {
		t.Errorf("rate-limited failInfo = %q, want BadRequest (mapIntuneErrorToFailInfo: rate_limit → BadRequest)", failStr)
	}

	// The fixture's issuer should have seen exactly 2 issuances (the
	// allowed pair) — the 3rd was blocked at the dispatcher gate.
	if got, want := len(fix.issuer.issued), 2; got != want {
		t.Errorf("issuer issuances = %d, want %d (rate-limited 3rd should not reach the issuer)", got, want)
	}

	// Audit log — at least one rate-limited entry. The dispatcher's
	// audit action is "scep_pkcsreq_intune" for both successes and
	// failures; we inspect the counter table for the rate_limited tick.
	stats := fix.scepService.IntuneStats(time.Now())
	if got := stats.Counters["rate_limited"]; got != 1 {
		t.Errorf("IntuneStats.counters[rate_limited] = %d, want 1", got)
	}
	if got := stats.Counters["success"]; got != 2 {
		t.Errorf("IntuneStats.counters[success] = %d, want 2 (cap=2 allowed pair)", got)
	}
}

// TestSCEPIntuneEnrollment_TrustAnchorSIGHUPReload_E2E proves the full
// SIGHUP-reload contract end-to-end: an enrollment that succeeds against
// the original trust anchor MUST fail after the operator rotates the
// on-disk file + reloads, when the device tries to enroll with the OLD
// connector key.
//
// Why we call holder.Reload() directly instead of os.Process.Signal(SIGHUP):
// signal delivery in tests is flaky (signals to the test process can
// race with t.Parallel(), and signal.Notify is global). The SIGHUP
// goroutine's only job is to call Reload, so calling Reload directly is
// the equivalent contract — and stable in tests. Phase B frozen
// decision #3 in cowork/scep-bundle-gap-closure-prompt.md.
func TestSCEPIntuneEnrollment_TrustAnchorSIGHUPReload_E2E(t *testing.T) {
	fix := newIntuneE2EFixture(t)
	now := time.Now()

	// Step 1: a valid enrollment against the original trust anchor.
	originalCh := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-sighup-pre"))
	originalMsg := buildIntuneE2EPKIMessage(t, fix, "txn-sighup-pre", originalCh, "device-corp-001.example.com")
	w, body := postPKIOperation(t, fix.handler, originalMsg)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-rotation enrollment: HTTP %d (body=%q)", w.Code, body)
	}
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("pre-rotation ParseSignedData: %v", err)
	}
	statusStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusSuccess) {
		t.Fatalf("pre-rotation pkiStatus = %q, want SUCCESS", statusStr)
	}

	// Step 2: operator rotates the trust anchor — write a fresh signing
	// cert from a NEW key into the same path. Holder.Reload() then
	// swaps the in-memory pool to the new bundle. The OLD key
	// (fix.connectorKey) is now disowned.
	rotatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	rotatedCert := selfSignedECCertForIntuneE2E(t, rotatedKey, "intune-connector-rotated")
	if err := os.WriteFile(fix.trustPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rotatedCert.Raw}), 0o600); err != nil {
		t.Fatalf("rewrite trust anchor file: %v", err)
	}
	if err := fix.trustHolder.Reload(); err != nil {
		t.Fatalf("trustHolder.Reload (post-rotation): %v", err)
	}

	// Step 3: a device that signs with the OLD connector key MUST be
	// rejected — the holder no longer recognizes the signature.
	staleCh := signIntuneChallengeES256(t, fix.connectorKey, validIntuneE2EClaim(now, "e2e-sighup-stale"))
	staleMsg := buildIntuneE2EPKIMessage(t, fix, "txn-sighup-stale", staleCh, "device-corp-001.example.com")
	w, body = postPKIOperation(t, fix.handler, staleMsg)
	if w.Code != http.StatusOK {
		t.Fatalf("stale-key enrollment: HTTP %d (body=%q) — RFC 8894 §3.3 mandates a CertRep+failInfo wire shape", w.Code, body)
	}
	certRep, err = pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("stale-key ParseSignedData: %v", err)
	}
	statusStr = decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()])
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Fatalf("stale-key pkiStatus = %q, want FAILURE after trust-anchor rotation", statusStr)
	}
	failStr := decodeFirstSetMember(t, certRep.SignerInfos[0].AuthAttributes[pkcs7.OIDSCEPFailInfo.String()])
	if failStr != string(domain.SCEPFailBadMessageCheck) {
		t.Errorf("stale-key failInfo = %q, want BadMessageCheck (mapIntuneErrorToFailInfo: sig errors → BadMessageCheck)", failStr)
	}

	stats := fix.scepService.IntuneStats(time.Now())
	if got := stats.Counters["signature_invalid"]; got != 1 {
		t.Errorf("IntuneStats.counters[signature_invalid] = %d, want 1 (post-rotation stale-key attempt)", got)
	}
	if got := stats.Counters["success"]; got != 1 {
		t.Errorf("IntuneStats.counters[success] = %d, want 1 (only the pre-rotation attempt)", got)
	}
}
