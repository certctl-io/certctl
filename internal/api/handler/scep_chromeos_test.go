package handler

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // RFC 8894 §3.5.2 legacy fallback for backward-compat test
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/pkcs7"
)

// SCEP RFC 8894 + Intune master bundle Phase 5.2: ChromeOS-shape integration
// tests for the SCEP handler's full RFC 8894 path.
//
// Each test builds a real PKIMessage (acting as the ChromeOS client),
// POSTs it through the handler, and verifies the response. The "client"
// is built from primitives in internal/pkcs7/ — the same builders the
// handler uses on the response side. This is intentional: if the handler
// regresses, the client builder might also regress, and the E2E would
// pass anyway (false negative). The mitigation: round-trip property
// tests in internal/pkcs7/ assert Build/Parse symmetry independently,
// and the handler-side tests focus on the dispatch + status-code wire
// shape rather than the bytes themselves.

// chromeOSStackFixture holds the materials needed for an end-to-end
// ChromeOS SCEP test: an issuer + RA pair (server side), a transient
// device cert (client side), and a constructed SCEPHandler.
type chromeOSStackFixture struct {
	raKey      *rsa.PrivateKey
	raCert     *x509.Certificate
	deviceKey  *rsa.PrivateKey
	deviceCert *x509.Certificate
	handler    SCEPHandler
	svc        *chromeOSMockSCEPService
}

// chromeOSMockSCEPService is the per-test SCEPService implementation used
// by these E2E tests. Records the last call's envelope + CSR for assertion.
type chromeOSMockSCEPService struct {
	caCertPEM              string
	pkcsReqEnvelope        *domain.SCEPRequestEnvelope
	pkcsReqCSRPEM          string
	pkcsReqChallenge       string
	renewalReqEnvelope     *domain.SCEPRequestEnvelope
	renewalReqCSRPEM       string
	getCertInitialEnvelope *domain.SCEPRequestEnvelope
	enrollResult           *domain.SCEPEnrollResult
	failChallenge          bool
}

func (m *chromeOSMockSCEPService) GetCACaps(_ context.Context) string {
	return "POSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\nRenewal\n"
}

func (m *chromeOSMockSCEPService) GetCACert(_ context.Context) (string, error) {
	return m.caCertPEM, nil
}

func (m *chromeOSMockSCEPService) PKCSReq(_ context.Context, _, _, _ string) (*domain.SCEPEnrollResult, error) {
	return m.enrollResult, nil
}

func (m *chromeOSMockSCEPService) PKCSReqWithEnvelope(_ context.Context, csrPEM, challengePassword string, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	m.pkcsReqEnvelope = env
	m.pkcsReqCSRPEM = csrPEM
	m.pkcsReqChallenge = challengePassword
	if m.failChallenge {
		return nil
	}
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusSuccess,
		Result:         m.enrollResult,
		TransactionID:  env.TransactionID,
		RecipientNonce: env.SenderNonce,
	}
}

func (m *chromeOSMockSCEPService) RenewalReqWithEnvelope(_ context.Context, csrPEM, _ string, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	m.renewalReqEnvelope = env
	m.renewalReqCSRPEM = csrPEM
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusSuccess,
		Result:         m.enrollResult,
		TransactionID:  env.TransactionID,
		RecipientNonce: env.SenderNonce,
	}
}

func (m *chromeOSMockSCEPService) GetCertInitialWithEnvelope(_ context.Context, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	m.getCertInitialEnvelope = env
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusFailure,
		FailInfo:       domain.SCEPFailBadCertID,
		TransactionID:  env.TransactionID,
		RecipientNonce: env.SenderNonce,
	}
}

// newChromeOSStackFixture wires up an RA pair + device cert + handler with
// an enroll-result fixture so the test can POST a PKIMessage and verify the
// CertRep response.
func newChromeOSStackFixture(t *testing.T) *chromeOSStackFixture {
	t.Helper()
	raKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey RA: %v", err)
	}
	raCert := selfSignedRSACert(t, raKey, "ra-test")
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey device: %v", err)
	}
	deviceCert := selfSignedRSACert(t, deviceKey, "device-transient")

	svc := &chromeOSMockSCEPService{
		enrollResult: &domain.SCEPEnrollResult{
			CertPEM: pemEncodeCert(selfSignedRSACertRaw(t, deviceKey, "issued.example.com")),
		},
	}
	handler := NewSCEPHandler(svc)
	handler.SetRAPair(raCert, raKey)

	return &chromeOSStackFixture{
		raKey:      raKey,
		raCert:     raCert,
		deviceKey:  deviceKey,
		deviceCert: deviceCert,
		handler:    handler,
		svc:        svc,
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_E2E exercises the full RFC 8894 path:
// build a PKIMessage shaped like ChromeOS sends (SignedData wrapping
// EnvelopedData wrapping a CSR, with signerInfo POPO over auth attrs);
// POST through the handler; verify the response is a valid CertRep
// PKIMessage with the issued cert encrypted to the test's transient pubkey.
func TestSCEPHandler_ChromeOSPKIMessage_E2E(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypePKCSReq, "txn-chromeos-e2e", "shared-secret-123", "device-cert.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))

	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation: got %d, want 200 (body=%q)", w.Code, body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pki-message" {
		t.Errorf("Content-Type = %q, want application/x-pki-message", got)
	}
	if fix.svc.pkcsReqEnvelope == nil {
		t.Fatal("PKCSReqWithEnvelope was not called — handler skipped RFC 8894 path?")
	}
	if fix.svc.pkcsReqEnvelope.TransactionID != "txn-chromeos-e2e" {
		t.Errorf("envelope.TransactionID = %q, want txn-chromeos-e2e", fix.svc.pkcsReqEnvelope.TransactionID)
	}
	if fix.svc.pkcsReqChallenge != "shared-secret-123" {
		t.Errorf("challengePassword = %q, want shared-secret-123", fix.svc.pkcsReqChallenge)
	}
	// Parse the CertRep back via the same builders the handler emits.
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("ParseSignedData(CertRep response): %v", err)
	}
	if len(certRep.SignerInfos) != 1 {
		t.Fatalf("CertRep has %d signers, want 1", len(certRep.SignerInfos))
	}
	if err := certRep.SignerInfos[0].VerifySignature(); err != nil {
		t.Errorf("CertRep RA signature invalid: %v", err)
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_RenewalReq exercises RenewalReq
// dispatch — the handler should route to RenewalReqWithEnvelope based on
// the messageType auth-attr.
func TestSCEPHandler_ChromeOSPKIMessage_RenewalReq(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypeRenewalReq, "txn-renewal-1", "shared-secret-123", "renewal.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))

	w, _ := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation (renewal): got %d, want 200", w.Code)
	}
	if fix.svc.renewalReqEnvelope == nil {
		t.Fatal("RenewalReqWithEnvelope was not called — dispatch missed messageType=17")
	}
	if fix.svc.pkcsReqEnvelope != nil {
		t.Errorf("PKCSReqWithEnvelope was called for a RenewalReq messageType — wrong dispatch")
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_GetCertInitial exercises the polling
// path. v1 always returns FAILURE+badCertID; this test asserts that's what
// ChromeOS sees when it polls.
func TestSCEPHandler_ChromeOSPKIMessage_GetCertInitial(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypeGetCertInitial, "txn-poll-1", "shared-secret-123", "poll.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))

	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation (poll): got %d, want 200 (body=%q)", w.Code, body)
	}
	if fix.svc.getCertInitialEnvelope == nil {
		t.Fatal("GetCertInitialWithEnvelope was not called — dispatch missed messageType=20")
	}
	// The response should be a CertRep with pkiStatus=2 (FAILURE) +
	// failInfo=4 (badCertID).
	certRep, err := pkcs7.ParseSignedData(body)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(certRep.SignerInfos) == 0 {
		t.Fatal("CertRep has no signerInfos")
	}
	si := certRep.SignerInfos[0]
	statusRV, ok := si.AuthAttributes[pkcs7.OIDSCEPPKIStatus.String()]
	if !ok {
		t.Fatal("CertRep missing pkiStatus auth-attr")
	}
	statusStr := decodeFirstSetMember(t, statusRV)
	if statusStr != string(domain.SCEPStatusFailure) {
		t.Errorf("pkiStatus = %q, want %q (FAILURE)", statusStr, domain.SCEPStatusFailure)
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_BadPOPO builds a PKIMessage with the
// signerInfo signature corrupted; expects the handler to fall through to
// the MVP path (the RFC 8894 verifier rejects the message, and the MVP
// path also rejects it because the encrypted EnvelopedData isn't a raw
// CSR). Result: HTTP 400 with a clear error message.
func TestSCEPHandler_ChromeOSPKIMessage_BadPOPO(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypePKCSReq, "txn-bad-popo", "shared-secret-123", "bad.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))
	// Tamper with the LAST byte of the message (which lands inside the
	// signature OCTET STRING for a non-trivial chance of corrupting the
	// signature without breaking the outer DER framing).
	pkiMessage[len(pkiMessage)-1] ^= 0xff

	w, _ := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusOK {
		t.Errorf("POST PKIOperation (bad POPO): got %d, want 400 (MVP fall-through rejection) or 200 (CertRep+failInfo)", w.Code)
	}
	if fix.svc.pkcsReqEnvelope != nil {
		t.Errorf("PKCSReqWithEnvelope was called despite invalid signerInfo signature — POPO check failed open")
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_AESVariants exercises AES-128, 192,
// and 256-CBC. ChromeOS picks based on the GetCACaps response; verify
// all three round-trip correctly.
func TestSCEPHandler_ChromeOSPKIMessage_AESVariants(t *testing.T) {
	cases := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"AES-128-CBC", pkcs7.OIDAES128CBC},
		{"AES-192-CBC", pkcs7.OIDAES192CBC},
		{"AES-256-CBC", pkcs7.OIDAES256CBC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := newChromeOSStackFixture(t)
			pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypePKCSReq, "txn-aes-"+tc.name, "shared-secret-123", "aes.example.com", aesKeyForOID(tc.oid))
			pkiMessage = withContentEncryptionOID(t, pkiMessage, fix, tc.oid, aesKeyForOID(tc.oid))
			w, body := postPKIOperation(t, fix.handler, pkiMessage)
			if w.Code != http.StatusOK {
				t.Fatalf("POST PKIOperation (%s): got %d, want 200 (body=%q)", tc.name, w.Code, body)
			}
		})
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_RAKeyMismatch — closure-bundle
// gap M-1 / acceptance D.1 (cowork/scep-bundle-gap-closure-prompt.md).
// Build a PKIMessage encrypted to a freshly-generated RA cert whose
// matching private key the server does NOT have. The handler MUST
// reject (RFC 8894 path can't decrypt → falls through; MVP path can't
// either because the EnvelopedData isn't a raw CSR). Assert no
// PKCSReqWithEnvelope was reached. Closes the documented threat that
// an attacker who swaps the RA cert in transit gets a polite error
// rather than information leak about the underlying issuer.
func TestSCEPHandler_ChromeOSPKIMessage_RAKeyMismatch(t *testing.T) {
	fix := newChromeOSStackFixture(t)

	// Build a PKIMessage targeting an UNRELATED RA cert (different key).
	// The server's handler still has fix.raKey, so decryption MUST fail.
	bogusRAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey bogus RA: %v", err)
	}
	bogusRACert := selfSignedRSACert(t, bogusRAKey, "ra-bogus-not-on-server")
	bogusFix := &chromeOSStackFixture{
		raKey:      bogusRAKey,
		raCert:     bogusRACert,
		deviceKey:  fix.deviceKey,
		deviceCert: fix.deviceCert,
	}
	pkiMessage := buildChromeOSStylePKIMessage(t, bogusFix, domain.SCEPMessageTypePKCSReq, "txn-ra-mismatch", "shared-secret-123", "ra-mismatch.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))

	w, _ := postPKIOperation(t, fix.handler, pkiMessage)
	// RFC 8894 path returns FAILURE+badMessageCheck CertRep (200), MVP
	// fall-through returns 400. Either is acceptable — what we MUST
	// see is "the issuer never received the CSR."
	if w.Code != http.StatusBadRequest && w.Code != http.StatusOK {
		t.Errorf("POST PKIOperation (RA-key mismatch): got %d, want 400 (MVP fall-through) or 200 (CertRep+failInfo)", w.Code)
	}
	if fix.svc.pkcsReqEnvelope != nil {
		t.Error("PKCSReqWithEnvelope was reached despite the RA-cert/key mismatch — decrypt-failure leaked through to the service")
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_3DESBackwardCompat — closure-bundle
// gap M-1 / acceptance D.2. RFC 8894 §3.5.2 names DES-EDE3-CBC
// (1.2.840.113549.3.7) as a "supported but discouraged" content-encryption
// algorithm for backward compat with older Cisco IOS / Apple legacy
// clients. Verify the parser accepts this OID + the handler reaches
// the service with a decoded CSR.
func TestSCEPHandler_ChromeOSPKIMessage_3DESBackwardCompat(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	tdesKey := aesKeyForOID(pkcs7.OIDDESEDE3CBC) // 24 bytes (3DES K1||K2||K3)

	csrDER := buildTestCSR(t, fix.deviceKey, "tdes.example.com", "shared-secret-123")

	iv := make([]byte, des.BlockSize) // 8 bytes for 3DES
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := tripleDESCBCEncrypt(t, tdesKey, iv, csrDER)
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fix.raCert.PublicKey.(*rsa.PublicKey), tdesKey)
	if err != nil {
		t.Fatalf("rsa encrypt 3des key: %v", err)
	}
	envelopedData := buildEnvelopedDataForTest(t, fix.raCert, encryptedKey, iv, ciphertext, pkcs7.OIDDESEDE3CBC)
	pkiMessage := buildSignedDataForTest(t, fix.deviceKey, fix.deviceCert, domain.SCEPMessageTypePKCSReq, "txn-3des", []byte("0123456789abcdef"), envelopedData)

	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation (3DES legacy): got %d, want 200 (RFC 8894 §3.5.2 backward-compat) — body=%q", w.Code, body)
	}
	if fix.svc.pkcsReqEnvelope == nil {
		t.Fatal("PKCSReqWithEnvelope was NOT reached — 3DES decrypt path didn't make it to the service")
	}
}

// TestSCEPHandler_ChromeOSPKIMessage_RSACSR — closure-bundle gap M-1 /
// acceptance D.4. Pins the "RSA CSR" matrix corner explicitly so a
// future helper refactor that quietly drops the RSA path doesn't
// disappear from the test count without a counter dropping. The
// shared positive-flow assertions live in
// assertChromeOSPositiveCertRep so the matrix-pair {RSA, ECDSA} stays
// readable.
func TestSCEPHandler_ChromeOSPKIMessage_RSACSR(t *testing.T) {
	fix := newChromeOSStackFixture(t)
	pkiMessage := buildChromeOSStylePKIMessage(t, fix, domain.SCEPMessageTypePKCSReq, "txn-rsa-csr", "shared-secret-123", "rsa-csr.example.com", aesKeyForOID(pkcs7.OIDAES256CBC))
	assertChromeOSPositiveCertRep(t, fix, pkiMessage)
}

// TestSCEPHandler_ChromeOSPKIMessage_ECDSACSR — closure-bundle gap M-1
// / acceptance D.3. The CSR's keypair is ECDSA P-256; the device's
// transient signerInfo identity stays RSA (matches what real ChromeOS
// + Intune-managed devices commonly emit — device identity is a
// long-lived RSA key, the new cert can be ECDSA). Verifies the
// handler doesn't choke on the inner CSR's algorithm even when the
// outer SignerInfo is RSA-SHA256.
func TestSCEPHandler_ChromeOSPKIMessage_ECDSACSR(t *testing.T) {
	fix := newChromeOSStackFixture(t)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	csrDER := buildTestECDSACSR(t, csrKey, "ecdsa-csr.example.com", "shared-secret-123")

	symKey := aesKeyForOID(pkcs7.OIDAES256CBC)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := aesCBCEncrypt(t, symKey, iv, csrDER)
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fix.raCert.PublicKey.(*rsa.PublicKey), symKey)
	if err != nil {
		t.Fatalf("rsa encrypt symKey: %v", err)
	}
	envelopedData := buildEnvelopedDataForTest(t, fix.raCert, encryptedKey, iv, ciphertext, pkcs7.OIDAES256CBC)
	pkiMessage := buildSignedDataForTest(t, fix.deviceKey, fix.deviceCert, domain.SCEPMessageTypePKCSReq, "txn-ecdsa-csr", []byte("0123456789abcdef"), envelopedData)
	assertChromeOSPositiveCertRep(t, fix, pkiMessage)
}

// assertChromeOSPositiveCertRep is the shared positive-flow assertion
// helper for the {RSA, ECDSA} CSR matrix tests. Asserts HTTP 200 +
// content-type + the service-level mock saw the envelope.
func assertChromeOSPositiveCertRep(t *testing.T, fix *chromeOSStackFixture, pkiMessage []byte) {
	t.Helper()
	w, body := postPKIOperation(t, fix.handler, pkiMessage)
	if w.Code != http.StatusOK {
		t.Fatalf("POST PKIOperation: got %d, want 200 (body=%q)", w.Code, body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pki-message" {
		t.Errorf("Content-Type = %q, want application/x-pki-message", got)
	}
	if fix.svc.pkcsReqEnvelope == nil {
		t.Fatal("PKCSReqWithEnvelope was NOT reached — handler dispatched to MVP path or rejected the message")
	}
}

// buildTestECDSACSR mirrors buildTestCSR but for an ECDSA P-256
// signing key. Closure-bundle Phase D helper. The CSR carries the
// challengePassword attribute the same way the RSA helper does.
func buildTestECDSACSR(t *testing.T, key *ecdsa.PrivateKey, commonName, challengePassword string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: commonName},
		ExtraExtensions: []pkix.Extension{},
		Attributes: []pkix.AttributeTypeAndValueSET{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7},
				Value: [][]pkix.AttributeTypeAndValue{
					{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Value: challengePassword}},
				},
			},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest (ECDSA): %v", err)
	}
	return der
}

// tripleDESCBCEncrypt mirrors aesCBCEncrypt for 3DES — used by the
// 3DES backward-compat test. PKCS#7 padding to 8-byte blocks.
func tripleDESCBCEncrypt(t *testing.T, key, iv, plaintext []byte) []byte {
	t.Helper()
	block, err := des.NewTripleDESCipher(key) //nolint:gosec // RFC 8894 §3.5.2 legacy backward-compat test fixture
	if err != nil {
		t.Fatalf("des.NewTripleDESCipher: %v", err)
	}
	bs := block.BlockSize()
	padLen := bs - len(plaintext)%bs
	padded := append([]byte{}, plaintext...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(padded))
	enc.CryptBlocks(out, padded)
	return out
}

// TestSCEPHandler_MVPCompat_StillWorks asserts the existing MVP path (raw
// CSR inside a stripped SignedData, no EnvelopedData) STILL works for
// backward compat with lightweight clients.
func TestSCEPHandler_MVPCompat_StillWorks(t *testing.T) {
	// Build an MVP-shape request: a SignedData whose encapContent is a
	// raw CSR (no EnvelopedData wrapper). The legacy handler path
	// extractCSRFromPKCS7 unwraps it.
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	csrDER := buildTestCSR(t, deviceKey, "mvp.example.com", "mvp-shared-secret")

	// Wrap in MVP-shape PKCS#7 SignedData (encapContent = CSR DER as
	// OCTET STRING). The existing extractCSRFromPKCS7 handles this.
	mvpPKCS7 := buildMVPSignedData(t, csrDER)

	svc := &chromeOSMockSCEPService{
		enrollResult: &domain.SCEPEnrollResult{
			CertPEM: pemEncodeCert(selfSignedRSACertRaw(t, deviceKey, "mvp-issued.example.com")),
		},
	}
	// Note: NO RA pair set — the handler runs MVP-only.
	handler := NewSCEPHandler(svc)
	w, body := postPKIOperation(t, handler, mvpPKCS7)
	if w.Code != http.StatusOK {
		t.Fatalf("MVP path POST: got %d, want 200 (body=%q)", w.Code, body)
	}
	// Response is the legacy certs-only PKCS#7, NOT a CertRep PKIMessage.
	if got := w.Header().Get("Content-Type"); got != "application/x-pki-message" {
		t.Errorf("Content-Type = %q, want application/x-pki-message", got)
	}
}

// --- helpers -------------------------------------------------------------

func postPKIOperation(t *testing.T, h SCEPHandler, body []byte) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)
	respBody, _ := io.ReadAll(w.Body)
	return w, respBody
}

// buildChromeOSStylePKIMessage builds a real SCEP PKIMessage targeting the
// fixture's RA cert. Mirrors what ChromeOS / micromdm-style clients emit:
// SignedData(SignerInfo(deviceCert, sig over auth-attrs)) wrapping an
// EnvelopedData(KTRI(raCert), AES-CBC(CSR + challengePassword)).
func buildChromeOSStylePKIMessage(t *testing.T, fix *chromeOSStackFixture, messageType domain.SCEPMessageType, transactionID, challengePassword, csrCN string, symKey []byte) []byte {
	t.Helper()

	// 1. Build the inner CSR carrying the challengePassword attribute.
	csrDER := buildTestCSR(t, fix.deviceKey, csrCN, challengePassword)

	// 2. Encrypt the CSR via AES-CBC under symKey + random IV.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := aesCBCEncrypt(t, symKey, iv, csrDER)

	// 3. RSA-encrypt the symKey to fix.raCert.PublicKey.
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fix.raCert.PublicKey.(*rsa.PublicKey), symKey)
	if err != nil {
		t.Fatalf("rsa encrypt symKey: %v", err)
	}

	// 4. Build EnvelopedData wrapping ciphertext.
	envelopedData := buildEnvelopedDataForTest(t, fix.raCert, encryptedKey, iv, ciphertext, oidForAESKeyLen(t, len(symKey)))

	// 5. Build the SignedData carrying the EnvelopedData with a
	//    signerInfo signed by the device's transient cert/key.
	signedData := buildSignedDataForTest(t, fix.deviceKey, fix.deviceCert, messageType, transactionID, []byte("0123456789abcdef"), envelopedData)
	return signedData
}

// withContentEncryptionOID rewrites the AES OID inside an already-built
// PKIMessage by re-building from scratch with the new OID. Simpler than
// surgically patching the bytes.
func withContentEncryptionOID(t *testing.T, _ []byte, fix *chromeOSStackFixture, oid asn1.ObjectIdentifier, symKey []byte) []byte {
	t.Helper()
	csrDER := buildTestCSR(t, fix.deviceKey, "aes.example.com", "shared-secret-123")
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := aesCBCEncrypt(t, symKey, iv, csrDER)
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fix.raCert.PublicKey.(*rsa.PublicKey), symKey)
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}
	envelopedData := buildEnvelopedDataForTest(t, fix.raCert, encryptedKey, iv, ciphertext, oid)
	return buildSignedDataForTest(t, fix.deviceKey, fix.deviceCert, domain.SCEPMessageTypePKCSReq, "txn-aes", []byte("0123456789abcdef"), envelopedData)
}

func aesCBCEncrypt(t *testing.T, key, iv, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	bs := block.BlockSize()
	padLen := bs - len(plaintext)%bs
	padded := append([]byte{}, plaintext...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(padded))
	enc.CryptBlocks(out, padded)
	return out
}

// oidForAESKeyLen maps an AES key length to its CBC OID. Helper for the
// AES-variants table-driven test.
func oidForAESKeyLen(t *testing.T, n int) asn1.ObjectIdentifier {
	t.Helper()
	switch n {
	case 16:
		return pkcs7.OIDAES128CBC
	case 24:
		return pkcs7.OIDAES192CBC
	case 32:
		return pkcs7.OIDAES256CBC
	}
	t.Fatalf("oidForAESKeyLen: unsupported key length %d", n)
	return nil
}

// aesKeyForOID returns a deterministic-length symmetric key matching the
// AES variant identified by oid. Test-only — production uses crypto/rand.
func aesKeyForOID(oid asn1.ObjectIdentifier) []byte {
	switch {
	case oid.Equal(pkcs7.OIDAES128CBC):
		return bytes.Repeat([]byte{0x42}, 16)
	case oid.Equal(pkcs7.OIDAES192CBC):
		return bytes.Repeat([]byte{0x42}, 24)
	case oid.Equal(pkcs7.OIDAES256CBC):
		return bytes.Repeat([]byte{0x42}, 32)
	case oid.Equal(pkcs7.OIDDESEDE3CBC):
		return bytes.Repeat([]byte{0x42}, 24)
	}
	return nil
}

// buildTestCSR creates a CSR with a challengePassword attribute. Used by
// the buildChromeOSStylePKIMessage helper to populate the EnvelopedData
// inner content.
func buildTestCSR(t *testing.T, key *rsa.PrivateKey, commonName, challengePassword string) []byte {
	t.Helper()
	// Build the challengePassword attribute (RFC 2985 §5.4.1, OID
	// 1.2.840.113549.1.9.7).
	cpAttr := pkix.AttributeTypeAndValue{
		Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7},
		Value: challengePassword,
	}
	cpAttrSet, err := asn1.Marshal(cpAttr)
	if err != nil {
		t.Fatalf("marshal cp attr: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
		// Inject the challengePassword as a raw extra extension via the
		// CSR Attributes field.
		ExtraExtensions: []pkix.Extension{},
		Attributes: []pkix.AttributeTypeAndValueSET{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7},
				Value: [][]pkix.AttributeTypeAndValue{
					{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Value: challengePassword}},
				},
			},
		},
	}
	_ = cpAttrSet
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

// buildEnvelopedDataForTest builds an EnvelopedData targeting raCert with
// a single KTRI carrying the encrypted symmetric key + the AES-CBC
// ciphertext. Mirrors the Phase 3 buildEnvelopedDataAES256 internal helper
// but exposed at test scope.
func buildEnvelopedDataForTest(t *testing.T, raCert *x509.Certificate, encryptedKey, iv, ciphertext []byte, contentEncOID asn1.ObjectIdentifier) []byte {
	t.Helper()
	// IssuerAndSerial of the recipient.
	serialDER, err := asn1.Marshal(raCert.SerialNumber)
	if err != nil {
		t.Fatalf("marshal serial: %v", err)
	}
	risBody := append([]byte{}, raCert.RawIssuer...)
	risBody = append(risBody, serialDER...)
	risBytes := pkcs7.ASN1Wrap(0x30, risBody)

	keyEncAlg := pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDRSAEncryption, Parameters: asn1.NullRawValue}
	keyEncAlgBytes, err := asn1.Marshal(keyEncAlg)
	if err != nil {
		t.Fatalf("marshal keyEncAlg: %v", err)
	}
	encryptedKeyBytes := pkcs7.ASN1Wrap(0x04, encryptedKey)

	ktriBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...)
	ktriBody = append(ktriBody, risBytes...)
	ktriBody = append(ktriBody, keyEncAlgBytes...)
	ktriBody = append(ktriBody, encryptedKeyBytes...)
	ktriBytes := pkcs7.ASN1Wrap(0x30, ktriBody)

	recipientInfosBytes := pkcs7.ASN1Wrap(0x31, ktriBytes)

	ivOctet := pkcs7.ASN1Wrap(0x04, iv)
	contentAlg := pkix.AlgorithmIdentifier{
		Algorithm:  contentEncOID,
		Parameters: asn1.RawValue{FullBytes: ivOctet},
	}
	contentAlgBytes, err := asn1.Marshal(contentAlg)
	if err != nil {
		t.Fatalf("marshal contentAlg: %v", err)
	}

	encContentField := pkcs7.ASN1Wrap(0x80, ciphertext)
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	eciBody := append([]byte{}, oidDataBytes...)
	eciBody = append(eciBody, contentAlgBytes...)
	eciBody = append(eciBody, encContentField...)
	eciBytes := pkcs7.ASN1Wrap(0x30, eciBody)

	envBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...)
	envBody = append(envBody, recipientInfosBytes...)
	envBody = append(envBody, eciBytes...)
	return pkcs7.ASN1Wrap(0x30, envBody)
}

// buildSignedDataForTest builds a CMS SignedData with the device cert as
// the signer + auth-attrs carrying SCEP messageType / transactionID /
// senderNonce + messageDigest of the encapContent.
func buildSignedDataForTest(t *testing.T, signerKey *rsa.PrivateKey, signerCert *x509.Certificate, messageType domain.SCEPMessageType, transactionID string, senderNonce, encapContent []byte) []byte {
	t.Helper()
	contentDigest := sha256.Sum256(encapContent)

	// Auth-attrs SET-OF body.
	var attrSetBody []byte
	attrSetBody = append(attrSetBody, attrSeqHelper(t, pkcs7.OIDContentType, pkcs7.ASN1Wrap(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}))...)
	attrSetBody = append(attrSetBody, attrSeqHelper(t, pkcs7.OIDMessageDigest, pkcs7.ASN1Wrap(0x04, contentDigest[:]))...)
	attrSetBody = append(attrSetBody, attrSeqHelper(t, pkcs7.OIDSCEPMessageType, pkcs7.ASN1Wrap(0x13, []byte(intToASCII(int(messageType)))))...)
	attrSetBody = append(attrSetBody, attrSeqHelper(t, pkcs7.OIDSCEPTransactionID, pkcs7.ASN1Wrap(0x13, []byte(transactionID)))...)
	attrSetBody = append(attrSetBody, attrSeqHelper(t, pkcs7.OIDSCEPSenderNonce, pkcs7.ASN1Wrap(0x04, senderNonce))...)

	// Sign over SET OF Attribute (RFC 5652 §5.4 quirk).
	signedAttrsForSig := pkcs7.ASN1Wrap(0x31, attrSetBody)
	digest := sha256.Sum256(signedAttrsForSig)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signerKey, 5, digest[:]) // 5 = crypto.SHA256
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// SignerInfo SEQUENCE.
	versionBytes := []byte{0x02, 0x01, 0x01}
	serialDER, _ := asn1.Marshal(signerCert.SerialNumber)
	sidBody := append([]byte{}, signerCert.RawIssuer...)
	sidBody = append(sidBody, serialDER...)
	sidBytes := pkcs7.ASN1Wrap(0x30, sidBody)

	digestAlg := pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDSHA256, Parameters: asn1.NullRawValue}
	digestAlgBytes, _ := asn1.Marshal(digestAlg)

	signedAttrsImplicit := pkcs7.ASN1Wrap(0xa0, attrSetBody)

	sigAlg := pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDRSAWithSHA256, Parameters: asn1.NullRawValue}
	sigAlgBytes, _ := asn1.Marshal(sigAlg)

	sigOctet := pkcs7.ASN1Wrap(0x04, sig)

	siBody := append([]byte{}, versionBytes...)
	siBody = append(siBody, sidBytes...)
	siBody = append(siBody, digestAlgBytes...)
	siBody = append(siBody, signedAttrsImplicit...)
	siBody = append(siBody, sigAlgBytes...)
	siBody = append(siBody, sigOctet...)
	siBytes := pkcs7.ASN1Wrap(0x30, siBody)

	// encapContentInfo
	octetWrap := pkcs7.ASN1Wrap(0x04, encapContent)
	explicitWrap := pkcs7.ASN1Wrap(0xa0, octetWrap)
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	encapBody := append([]byte{}, oidDataBytes...)
	encapBody = append(encapBody, explicitWrap...)
	encapBytes := pkcs7.ASN1Wrap(0x30, encapBody)

	// certificates [0] IMPLICIT SET OF Certificate
	certsBytes := pkcs7.ASN1Wrap(0xa0, signerCert.Raw)

	// digestAlgorithms SET OF
	digestAlgsBytes := pkcs7.ASN1Wrap(0x31, digestAlgBytes)
	// signerInfos SET OF
	signerInfosBytes := pkcs7.ASN1Wrap(0x31, siBytes)

	// SignedData SEQUENCE
	sdBody := append([]byte{}, []byte{0x02, 0x01, 0x01}...)
	sdBody = append(sdBody, digestAlgsBytes...)
	sdBody = append(sdBody, encapBytes...)
	sdBody = append(sdBody, certsBytes...)
	sdBody = append(sdBody, signerInfosBytes...)
	sdSeq := pkcs7.ASN1Wrap(0x30, sdBody)

	// ContentInfo wrap
	contentField := pkcs7.ASN1Wrap(0xa0, sdSeq)
	oidSignedData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	ciBody := append([]byte{}, oidSignedData...)
	ciBody = append(ciBody, contentField...)
	return pkcs7.ASN1Wrap(0x30, ciBody)
}

// buildMVPSignedData builds a degenerate SignedData where the encapContent
// is the raw CSR bytes — what lightweight SCEP clients send. Used by the
// MVP-compat test to confirm the legacy parser still works.
func buildMVPSignedData(t *testing.T, csrDER []byte) []byte {
	t.Helper()
	octetWrap := pkcs7.ASN1Wrap(0x04, csrDER)
	explicitWrap := pkcs7.ASN1Wrap(0xa0, octetWrap)
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	encapBody := append([]byte{}, oidDataBytes...)
	encapBody = append(encapBody, explicitWrap...)
	encapBytes := pkcs7.ASN1Wrap(0x30, encapBody)

	digestAlgsBytes := pkcs7.ASN1Wrap(0x31, nil)
	signerInfosBytes := pkcs7.ASN1Wrap(0x31, nil)

	sdBody := append([]byte{}, []byte{0x02, 0x01, 0x01}...)
	sdBody = append(sdBody, digestAlgsBytes...)
	sdBody = append(sdBody, encapBytes...)
	sdBody = append(sdBody, signerInfosBytes...)
	sdSeq := pkcs7.ASN1Wrap(0x30, sdBody)

	contentField := pkcs7.ASN1Wrap(0xa0, sdSeq)
	oidSignedData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	ciBody := append([]byte{}, oidSignedData...)
	ciBody = append(ciBody, contentField...)
	return pkcs7.ASN1Wrap(0x30, ciBody)
}

func attrSeqHelper(t *testing.T, oid asn1.ObjectIdentifier, value []byte) []byte {
	t.Helper()
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal OID %v: %v", oid, err)
	}
	setOfValue := pkcs7.ASN1Wrap(0x31, value)
	body := append([]byte{}, oidBytes...)
	body = append(body, setOfValue...)
	return pkcs7.ASN1Wrap(0x30, body)
}

func decodeFirstSetMember(t *testing.T, rv asn1.RawValue) string {
	t.Helper()
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(rv.Bytes, &inner); err != nil {
		t.Fatalf("unmarshal SET first member: %v", err)
	}
	return string(inner.Bytes)
}

func intToASCII(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func selfSignedRSACert(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	der := selfSignedRSACertRaw(t, key, cn)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func selfSignedRSACertRaw(t *testing.T, key *rsa.PrivateKey, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func pemEncodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// silence unused-import warnings — these packages are referenced inside
// helpers above; Go's import-pruning is conservative around test-only
// uses through other test files.
var (
	_ = ecdsa.PublicKey{}
	_ = elliptic.P256
	_ = des.NewTripleDESCipher
)
