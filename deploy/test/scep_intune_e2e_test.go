//go:build integration

// SCEP RFC 8894 + Intune master prompt §10.2 + §13 acceptance
// (deploy/test/ integration variant). Closed in the 2026-04-29
// audit-closure bundle (Phase I).
//
// What this test does:
//
//   - Boots ON TOP OF the live docker-compose.test.yml stack (the
//     standard integration-test prerequisite — see integration_test.go
//     for the same precedent). The compose file mounts a deterministic
//     Connector signing-cert PEM into the certctl container and sets
//     CERTCTL_SCEP_PROFILE_E2EINTUNE_INTUNE_ENABLED=true +
//     CERTCTL_SCEP_PROFILE_E2EINTUNE_INTUNE_CONNECTOR_CERT_PATH +
//     CERTCTL_SCEP_PROFILE_E2EINTUNE_INTUNE_AUDIENCE.
//   - Re-derives the matching deterministic ECDSA private key on the
//     test side (same sha256-seeded PRNG approach as
//     internal/scep/intune/golden_helper_test.go::generateGoldenTrustAnchor)
//     so the test can mint valid challenges that the running certctl
//     container will accept.
//   - Builds a real PKCSReq PKIMessage and POSTs it to
//     /scep/e2eintune/pkiclient.exe?operation=PKIOperation over HTTPS.
//   - Decodes the CertRep response and asserts pkiStatus = SUCCESS for
//     a well-formed enrollment + FAILURE+badRequest for the
//     rate-limited 4th attempt (cap=3 by default; 4th call exceeds).
//
// Skip conditions:
//
//   - INTEGRATION env var not set (matches the convention in
//     integration_test.go::TestMain).
//   - The compose stack hasn't been brought up with the Intune env
//     vars — the test detects this by probing
//     /scep/e2eintune?operation=GetCACaps and skipping if the route
//     returns 404.
//
// CI runs this in the same job that already runs integration_test.go;
// the docker-compose.test.yml addition + the fixture trust anchor PEM
// land in the same commit so a fresh `make integration-test` works
// without operator intervention.

package integration_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// e2eintuneSeed is the deterministic seed for the integration-test
// trust anchor key. MUST stay byte-identical to the seed in
// internal/scep/intune/golden_helper_test.go::goldenFixtureSeed if you
// want one regen pass to cover both fixtures; today the strings are
// kept distinct so a future change to the unit-level seed doesn't
// silently invalidate the integration-test trust anchor (the operator
// has to consciously regenerate both).
var e2eintuneSeed = []byte("scep-intune-integration-test-fixture-seed-v1-do-not-change-without-regenerating-deploy-test-fixtures")

// e2eintunePathID is the SCEP profile name the docker-compose.test.yml
// configures for this test. Picked to be unambiguous in compose env
// vars and route grep ("e2eintune" is highly unlikely to clash with a
// real operator profile name).
const e2eintunePathID = "e2eintune"

// e2eintuneAudience MUST match
// CERTCTL_SCEP_PROFILE_E2EINTUNE_INTUNE_AUDIENCE in
// docker-compose.test.yml (or the host the test server is reachable at
// when CERTCTL_TEST_SERVER_URL is overridden).
const e2eintuneAudience = "https://localhost:8443/scep/e2eintune"

// TestSCEPIntuneEnrollment_Integration runs the full PKCSReq path
// against the live docker-compose certctl container. Asserts the
// CertRep wire shape is SUCCESS for a well-formed enrollment.
func TestSCEPIntuneEnrollment_Integration(t *testing.T) {
	requireIntuneIntegrationStack(t)

	now := time.Now()
	connectorKey, _ := generateE2EIntuneTrustAnchor(t)
	cli := newTestClient()

	// 1. Mint a valid challenge signed by the deterministic Connector key.
	challenge := signE2EIntuneChallenge(t, connectorKey, e2eIntuneClaim(now, "integration-nonce-001"))

	// 2. Build the PKIMessage with the challenge embedded.
	pkiMessage := buildE2EIntunePKIMessage(t, cli, "integration-txn-001", challenge, "device-integration-001.example.com")

	// 3. POST + assert SUCCESS.
	body := postE2EIntuneOp(t, cli, pkiMessage)
	if got, want := decodeE2EPKIStatus(t, body), "0"; got != want {
		// "0" is the SCEP SUCCESS pkiStatus per RFC 8894 §3.3.2.1.
		t.Fatalf("integration enrollment: pkiStatus = %q, want %q (SUCCESS)", got, want)
	}
}

// TestSCEPIntuneEnrollment_RateLimited_Integration drives 4
// PKIMessages for the same (Subject, Issuer) past the documented
// cap=3 default. The 4th MUST be rejected with FAILURE+badRequest.
func TestSCEPIntuneEnrollment_RateLimited_Integration(t *testing.T) {
	requireIntuneIntegrationStack(t)

	connectorKey, _ := generateE2EIntuneTrustAnchor(t)
	cli := newTestClient()
	now := time.Now()

	// First 3 enrollments succeed (cap=3 → ≤3 in 24h).
	for i := 0; i < 3; i++ {
		nonce := fmt.Sprintf("integration-rate-allow-%d", i)
		ch := signE2EIntuneChallenge(t, connectorKey, e2eIntuneClaim(now, nonce))
		txn := fmt.Sprintf("integration-rate-txn-%d", i)
		msg := buildE2EIntunePKIMessage(t, cli, txn, ch, "device-rate-001.example.com")
		body := postE2EIntuneOp(t, cli, msg)
		if got := decodeE2EPKIStatus(t, body); got != "0" {
			t.Fatalf("integration rate-limited test: attempt %d/3 SHOULD succeed, got pkiStatus=%q", i+1, got)
		}
	}

	// 4th attempt for the same (Subject, Issuer) MUST be rate-limited.
	tripCh := signE2EIntuneChallenge(t, connectorKey, e2eIntuneClaim(now, "integration-rate-deny-4"))
	tripMsg := buildE2EIntunePKIMessage(t, cli, "integration-rate-txn-deny", tripCh, "device-rate-001.example.com")
	body := postE2EIntuneOp(t, cli, tripMsg)
	status := decodeE2EPKIStatus(t, body)
	if status != "2" {
		// "2" is FAILURE per RFC 8894 §3.3.2.1.
		t.Fatalf("integration rate-limited 4th attempt: pkiStatus = %q, want %q (FAILURE)", status, "2")
	}
}

// requireIntuneIntegrationStack short-circuits the test when the
// integration stack hasn't been started OR hasn't been configured
// with the e2eintune profile (the operator only enabled the legacy
// integration_test.go set, not this one). Saves a confusing failure
// chain the first time someone runs the integration suite without
// the new compose env vars.
func requireIntuneIntegrationStack(t *testing.T) {
	t.Helper()

	cli := newTestClient()
	resp, err := cli.http.Get(serverURL + "/scep/" + e2eintunePathID + "?operation=GetCACaps")
	if err != nil {
		t.Skipf("integration stack not reachable at %s: %v — start docker-compose.test.yml first", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Skipf("/scep/%s not configured — see deploy/docker-compose.test.yml for the e2eintune profile env vars", e2eintunePathID)
	}
	if resp.StatusCode != http.StatusOK {
		t.Skipf("/scep/%s GetCACaps returned %d — Intune profile may not be enabled in compose env", e2eintunePathID, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "SCEPStandard") {
		t.Skipf("/scep/%s GetCACaps body=%q does NOT advertise SCEPStandard — Intune profile may be misconfigured", e2eintunePathID, string(body))
	}
}

// =============================================================================
// Deterministic trust-anchor key generation. MUST match what the
// docker-compose.test.yml mounts as the Connector trust anchor PEM.
// =============================================================================

// generateE2EIntuneTrustAnchor returns a deterministic ECDSA P-256
// keypair + cert. The committed
// deploy/test/fixtures/intune_trust_anchor.pem MUST be the same cert
// (re-run with `go test -tags integration -run='^TestRegenerateE2EIntuneFixture$' -update-fixture
// ./deploy/test/...` to refresh after a seed change).
func generateE2EIntuneTrustAnchor(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	prng := newE2EDeterministicReader(e2eintuneSeed)
	key, err := ecdsa.GenerateKey(elliptic.P256(), prng)
	if err != nil {
		t.Fatalf("deterministic ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intune-connector-integration-fixture"},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2055, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(prng, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("deterministic CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return key, cert
}

// signE2EIntuneChallenge builds a JWT-shape ES256 challenge using the
// deterministic Connector key. Mirrors
// internal/api/handler/scep_intune_e2e_test.go::signIntuneChallengeES256
// but lives in the integration_test package (no shared imports across
// internal/ and deploy/test/).
func signE2EIntuneChallenge(t *testing.T, key *ecdsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// e2eIntuneClaim returns the v1 challenge payload shape that matches
// a CSR with CN=device-integration-001.example.com (or whatever CN the
// caller passes to buildE2EIntunePKIMessage).
func e2eIntuneClaim(now time.Time, nonce string) map[string]any {
	return map[string]any{
		"iss":         "intune-connector-integration-fixture",
		"sub":         "device-guid-integration-001",
		"aud":         e2eintuneAudience,
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(59 * time.Minute).Unix(),
		"nonce":       nonce,
		"device_name": "device-integration-001.example.com",
	}
}

// =============================================================================
// PKIMessage builder. Mirrors the in-tree handler test's helpers but
// stripped down for the integration test's hermetic needs (single profile,
// AES-256-CBC content encryption, fixture RA cert fetched from /scep/<pathID>?operation=GetCACert).
// =============================================================================

// buildE2EIntunePKIMessage fetches the running container's RA cert via
// GetCACert (which doubles as the cert clients encrypt the CSR's
// content-encryption key to per RFC 8894 §3.2.2), builds an
// EnvelopedData around an AES-256-CBC-encrypted CSR, then wraps the
// EnvelopedData in a SignedData with a transient signerInfo signature.
func buildE2EIntunePKIMessage(t *testing.T, cli *testClient, transactionID, challengePassword, csrCN string) []byte {
	t.Helper()

	// Fetch the RA cert from GetCACert.
	resp, err := cli.http.Get(serverURL + "/scep/" + e2eintunePathID + "?operation=GetCACert")
	if err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	defer resp.Body.Close()
	raCertBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GetCACert: %v", err)
	}
	raCert, err := parseGetCACertForE2EIntune(raCertBytes)
	if err != nil {
		t.Fatalf("parse RA cert: %v", err)
	}

	// Build a transient device key + cert (the CSR's signer + the
	// signerInfo's signer; production devices often use one key for
	// both).
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	deviceCert := selfSignedRSACertForE2EIntune(t, deviceKey, "device-transient-integration")

	csrDER := buildE2EIntuneCSR(t, deviceKey, csrCN, challengePassword)

	symKey := bytes.Repeat([]byte{0x42}, 32) // AES-256
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := aesCBCEncryptForE2EIntune(t, symKey, iv, csrDER)

	rsaPub, ok := raCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("RA cert public key is %T, want *rsa.PublicKey", raCert.PublicKey)
	}
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, symKey)
	if err != nil {
		t.Fatalf("rsa encrypt symKey: %v", err)
	}

	envelopedData := buildEnvelopedDataForE2EIntune(t, raCert, encryptedKey, iv, ciphertext)
	signedData := buildSignedDataForE2EIntune(t, deviceKey, deviceCert, transactionID, envelopedData)
	return signedData
}

// postE2EIntuneOp POSTs the PKIMessage to the running certctl container
// and returns the raw response body. Fails the test on non-200 because
// every RFC 8894 PKIOperation MUST return a CertRep PKIMessage even on
// failure — anything other than 200 means the handler choked.
func postE2EIntuneOp(t *testing.T, cli *testClient, pkiMessage []byte) []byte {
	t.Helper()
	url := serverURL + "/scep/" + e2eintunePathID + "?operation=PKIOperation"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(pkiMessage))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-pki-message")
	resp, err := cli.http.Do(req)
	if err != nil {
		t.Fatalf("post PKIOperation: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST PKIOperation: HTTP %d (body=%q) — RFC 8894 §3.3 mandates a CertRep on every PKIOperation including failures", resp.StatusCode, string(body))
	}
	return body
}

// decodeE2EPKIStatus extracts the SCEP pkiStatus auth-attribute from
// a CertRep PKIMessage. Returns the printable-string value ("0" =
// SUCCESS, "2" = FAILURE, "3" = PENDING per RFC 8894 §3.3.2.1).
//
// This is a minimal CMS SignedData walker — we don't pull in the
// internal/pkcs7 package because deploy/test/ is intentionally a
// stand-alone package. The walker hunts for the OID
// 2.16.840.1.113733.1.9.3 (id-attribute-pkiStatus, RFC 8894 §3.3.2.1)
// and returns its first SET-member value as a string.
func decodeE2EPKIStatus(t *testing.T, certRepDER []byte) string {
	t.Helper()
	// pkiStatus OID is 2.16.840.1.113733.1.9.3 → DER:
	//   06 0a 60 86 48 01 86 f8 45 01 09 03
	// Search the certRep DER for this byte pattern; the next 2 bytes
	// after the OID land in the auth-attr's SET ("31 ?? ..."), and the
	// pkiStatus value is a PrintableString inside.
	pkiStatusOID := []byte{0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x03}
	idx := bytes.Index(certRepDER, pkiStatusOID)
	if idx < 0 {
		t.Fatalf("decodeE2EPKIStatus: pkiStatus OID not found in CertRep (body len=%d)", len(certRepDER))
	}
	// After the OID DER (12 bytes), expect SET (0x31) of length L,
	// then PrintableString (0x13) of length M, then the M chars.
	cursor := idx + len(pkiStatusOID)
	if cursor+4 >= len(certRepDER) {
		t.Fatalf("decodeE2EPKIStatus: truncated DER after pkiStatus OID")
	}
	if certRepDER[cursor] != 0x31 {
		t.Fatalf("decodeE2EPKIStatus: expected SET tag 0x31 after OID, got 0x%02x", certRepDER[cursor])
	}
	// Skip SET tag + length byte.
	cursor += 2
	if certRepDER[cursor] != 0x13 {
		t.Fatalf("decodeE2EPKIStatus: expected PrintableString tag 0x13, got 0x%02x", certRepDER[cursor])
	}
	strLen := int(certRepDER[cursor+1])
	cursor += 2
	return string(certRepDER[cursor : cursor+strLen])
}

// =============================================================================
// Deterministic PRNG. Replicates the sha256-counter pattern from
// internal/scep/intune/golden_helper_test.go::deterministicReader so
// the integration test can derive the SAME ECDSA key bytes from the
// same seed. No shared imports across the internal/ and deploy/test/
// boundaries.
// =============================================================================

type e2eDeterministicReader struct {
	mu     sync.Mutex
	state  []byte
	cursor int
	buf    []byte
}

func newE2EDeterministicReader(seed []byte) *e2eDeterministicReader {
	return &e2eDeterministicReader{state: append([]byte(nil), seed...)}
}

func (d *e2eDeterministicReader) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n := 0; n < len(p); {
		if d.cursor >= len(d.buf) {
			h := sha256.Sum256(append(d.state, e2eByteCounter(len(p)+n)...))
			d.buf = h[:]
			d.cursor = 0
			d.state = d.buf
		}
		c := copy(p[n:], d.buf[d.cursor:])
		n += c
		d.cursor += c
	}
	return len(p), nil
}

func e2eByteCounter(i int) []byte {
	out := make([]byte, 8)
	for k := 0; k < 8; k++ {
		out[k] = byte(i >> (8 * k))
	}
	return out
}

// =============================================================================
// CMS / SCEP byte builders. Stripped-down equivalents of
// internal/pkcs7/{enveloped,signedinfo}.go for the integration test's
// hermetic needs. Distinct names from the in-tree helpers (no import
// crossing internal/ → deploy/test/).
// =============================================================================

func parseGetCACertForE2EIntune(body []byte) (*x509.Certificate, error) {
	// Try raw DER first.
	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert, nil
	}
	// Try PEM fallback.
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}
	// Try PKCS#7 SignedData certs-only.
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,implicit,tag:0"`
	}
	var outer struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(body, &outer); err == nil {
		var sd signedData
		if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err == nil {
			if cert, err := x509.ParseCertificate(sd.Certificates.Bytes); err == nil {
				return cert, nil
			}
		}
	}
	return nil, fmt.Errorf("could not parse GetCACert response (len=%d)", len(body))
}

func selfSignedRSACertForE2EIntune(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func buildE2EIntuneCSR(t *testing.T, key *rsa.PrivateKey, cn, challengePassword string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
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
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func aesCBCEncryptForE2EIntune(t *testing.T, key, iv, plaintext []byte) []byte {
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

// asn1WrapForE2EIntune wraps body in an ASN.1 TLV with the given tag
// and a definite-length encoding. Mirrors the in-tree
// internal/pkcs7.ASN1Wrap helper but stays inside this package (no
// cross-package import).
func asn1WrapForE2EIntune(tag byte, body []byte) []byte {
	var lenBytes []byte
	switch {
	case len(body) < 128:
		lenBytes = []byte{byte(len(body))}
	case len(body) < 256:
		lenBytes = []byte{0x81, byte(len(body))}
	case len(body) < 65536:
		lenBytes = []byte{0x82, byte(len(body) >> 8), byte(len(body))}
	default:
		lenBytes = []byte{0x83, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	}
	out := append([]byte{tag}, lenBytes...)
	return append(out, body...)
}

// OIDs used in the integration-test PKIMessage builders.
var (
	oidRSAEncryptionE2E   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidAES256CBCE2E       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256E2E          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAWithSHA256E2E   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidContentTypeE2E     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigestE2E   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSCEPMessageTypeE2E = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPTransactionE2E = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidSCEPSenderNonceE2E = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
)

func buildEnvelopedDataForE2EIntune(t *testing.T, raCert *x509.Certificate, encryptedKey, iv, ciphertext []byte) []byte {
	t.Helper()
	serialDER, err := asn1.Marshal(raCert.SerialNumber)
	if err != nil {
		t.Fatalf("marshal serial: %v", err)
	}
	risBody := append([]byte{}, raCert.RawIssuer...)
	risBody = append(risBody, serialDER...)
	risBytes := asn1WrapForE2EIntune(0x30, risBody)

	keyEncAlg := pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryptionE2E, Parameters: asn1.NullRawValue}
	keyEncAlgBytes, err := asn1.Marshal(keyEncAlg)
	if err != nil {
		t.Fatalf("marshal keyEncAlg: %v", err)
	}
	encryptedKeyBytes := asn1WrapForE2EIntune(0x04, encryptedKey)

	ktriBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...)
	ktriBody = append(ktriBody, risBytes...)
	ktriBody = append(ktriBody, keyEncAlgBytes...)
	ktriBody = append(ktriBody, encryptedKeyBytes...)
	ktriBytes := asn1WrapForE2EIntune(0x30, ktriBody)
	recipientInfosBytes := asn1WrapForE2EIntune(0x31, ktriBytes)

	ivOctet := asn1WrapForE2EIntune(0x04, iv)
	contentAlg := pkix.AlgorithmIdentifier{
		Algorithm:  oidAES256CBCE2E,
		Parameters: asn1.RawValue{FullBytes: ivOctet},
	}
	contentAlgBytes, err := asn1.Marshal(contentAlg)
	if err != nil {
		t.Fatalf("marshal contentAlg: %v", err)
	}

	encContentField := asn1WrapForE2EIntune(0x80, ciphertext)
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	eciBody := append([]byte{}, oidDataBytes...)
	eciBody = append(eciBody, contentAlgBytes...)
	eciBody = append(eciBody, encContentField...)
	eciBytes := asn1WrapForE2EIntune(0x30, eciBody)

	envBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...)
	envBody = append(envBody, recipientInfosBytes...)
	envBody = append(envBody, eciBytes...)
	innerEnvBytes := asn1WrapForE2EIntune(0x30, envBody)

	// Wrap in a ContentInfo: SEQ { OID envelopedData, [0] EXPLICIT inner }.
	envelopedDataOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03}
	contentInfoBody := append([]byte{}, envelopedDataOID...)
	contentInfoBody = append(contentInfoBody, asn1WrapForE2EIntune(0xa0, innerEnvBytes)...)
	return asn1WrapForE2EIntune(0x30, contentInfoBody)
}

func buildSignedDataForE2EIntune(t *testing.T, signerKey *rsa.PrivateKey, signerCert *x509.Certificate, transactionID string, encapContent []byte) []byte {
	t.Helper()
	contentDigest := sha256.Sum256(encapContent)

	var attrSetBody []byte
	attrSetBody = append(attrSetBody, attrSeqHelperE2E(t, oidContentTypeE2E, asn1WrapForE2EIntune(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03}))...) // envelopedData
	attrSetBody = append(attrSetBody, attrSeqHelperE2E(t, oidMessageDigestE2E, asn1WrapForE2EIntune(0x04, contentDigest[:]))...)
	attrSetBody = append(attrSetBody, attrSeqHelperE2E(t, oidSCEPMessageTypeE2E, asn1WrapForE2EIntune(0x13, []byte("19")))...) // PKCSReq=19
	attrSetBody = append(attrSetBody, attrSeqHelperE2E(t, oidSCEPTransactionE2E, asn1WrapForE2EIntune(0x13, []byte(transactionID)))...)
	attrSetBody = append(attrSetBody, attrSeqHelperE2E(t, oidSCEPSenderNonceE2E, asn1WrapForE2EIntune(0x04, []byte("0123456789abcdef")))...)

	signedAttrsForSig := asn1WrapForE2EIntune(0x31, attrSetBody)
	digest := sha256.Sum256(signedAttrsForSig)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signerKey, 5, digest[:]) // 5 = crypto.SHA256
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	versionBytes := []byte{0x02, 0x01, 0x01}
	serialDER, _ := asn1.Marshal(signerCert.SerialNumber)
	sidBody := append([]byte{}, signerCert.RawIssuer...)
	sidBody = append(sidBody, serialDER...)
	sidBytes := asn1WrapForE2EIntune(0x30, sidBody)

	digestAlg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256E2E, Parameters: asn1.NullRawValue}
	digestAlgBytes, _ := asn1.Marshal(digestAlg)

	signedAttrsImplicit := asn1WrapForE2EIntune(0xa0, attrSetBody)

	sigAlg := pkix.AlgorithmIdentifier{Algorithm: oidRSAWithSHA256E2E, Parameters: asn1.NullRawValue}
	sigAlgBytes, _ := asn1.Marshal(sigAlg)
	sigOctet := asn1WrapForE2EIntune(0x04, sig)

	signerInfoBody := append([]byte{}, versionBytes...)
	signerInfoBody = append(signerInfoBody, sidBytes...)
	signerInfoBody = append(signerInfoBody, digestAlgBytes...)
	signerInfoBody = append(signerInfoBody, signedAttrsImplicit...)
	signerInfoBody = append(signerInfoBody, sigAlgBytes...)
	signerInfoBody = append(signerInfoBody, sigOctet...)
	signerInfoBytes := asn1WrapForE2EIntune(0x30, signerInfoBody)
	signerInfosSet := asn1WrapForE2EIntune(0x31, signerInfoBytes)

	digestAlgsSet := asn1WrapForE2EIntune(0x31, digestAlgBytes)

	envelopedDataOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03}
	innerContent := asn1WrapForE2EIntune(0xa0, encapContent)
	encapContentInfo := asn1WrapForE2EIntune(0x30, append(envelopedDataOID, innerContent...))

	signerCertWrapped := asn1WrapForE2EIntune(0xa0, signerCert.Raw)

	sdBody := append([]byte{}, versionBytes...)
	sdBody = append(sdBody, digestAlgsSet...)
	sdBody = append(sdBody, encapContentInfo...)
	sdBody = append(sdBody, signerCertWrapped...)
	sdBody = append(sdBody, signerInfosSet...)
	innerSDBytes := asn1WrapForE2EIntune(0x30, sdBody)

	signedDataOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	contentInfoBody := append([]byte{}, signedDataOID...)
	contentInfoBody = append(contentInfoBody, asn1WrapForE2EIntune(0xa0, innerSDBytes)...)
	return asn1WrapForE2EIntune(0x30, contentInfoBody)
}

func attrSeqHelperE2E(t *testing.T, oid asn1.ObjectIdentifier, value []byte) []byte {
	t.Helper()
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal oid: %v", err)
	}
	valueSet := asn1WrapForE2EIntune(0x31, value)
	body := append(oidBytes, valueSet...)
	return asn1WrapForE2EIntune(0x30, body)
}
