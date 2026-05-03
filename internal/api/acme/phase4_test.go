// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/domain"
)

// --- Test fixtures + helpers -------------------------------------------

func newTestRSAJWK(t *testing.T) (*rsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.RS256), Use: "sig"}
	return priv, jwk
}

func newTestECDSAJWK(t *testing.T) (*ecdsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	return priv, jwk
}

// signWithEmbeddedJWK builds an RFC-7515-compatible compact-serialized JWS with
// the given protected header + payload, signed by signer. Used for
// constructing inner-key-change blobs in tests.
func signWithEmbeddedJWK(t *testing.T, signer interface{}, alg jose.SignatureAlgorithm, payload []byte, headers map[jose.HeaderKey]interface{}, embedJWK *jose.JSONWebKey) string {
	t.Helper()
	opts := &jose.SignerOptions{ExtraHeaders: headers}
	if embedJWK != nil {
		opts = opts.WithHeader("jwk", embedJWK)
	}
	sigSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signer}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := sigSigner.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

// --- KeyChange tests ----------------------------------------------------

func TestParseAndVerifyKeyChangeInner_HappyPath(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)

	url := "https://example.com/acme/profile/p1/key-change"
	kid := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	payloadJSON, err := json.Marshal(KeyChangeInnerPayload{
		Account: kid,
		OldKey:  oldJWK,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	headers := map[jose.HeaderKey]interface{}{"url": url}
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, headers, newJWK)

	got, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), kid, url, oldJWK)
	if err != nil {
		t.Fatalf("ParseAndVerifyKeyChangeInner: %v", err)
	}
	if got.Payload.Account != kid {
		t.Errorf("payload.Account = %q, want %q", got.Payload.Account, kid)
	}
	if got.URL != url {
		t.Errorf("URL = %q, want %q", got.URL, url)
	}
	if got.NewJWK == nil {
		t.Errorf("NewJWK is nil")
	}
}

func TestParseAndVerifyKeyChangeInner_OldKeyMismatch(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	_, otherJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)

	url := "https://example.com/acme/profile/p1/key-change"
	kid := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	// payload claims an oldKey that doesn't match what's registered.
	payloadJSON, _ := json.Marshal(KeyChangeInnerPayload{Account: kid, OldKey: otherJWK})
	headers := map[jose.HeaderKey]interface{}{"url": url}
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, headers, newJWK)

	_, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), kid, url, oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerOldKeyMismatch) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerOldKeyMismatch", err)
	}
}

func TestParseAndVerifyKeyChangeInner_AccountMismatch(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)

	url := "https://example.com/acme/profile/p1/key-change"
	outerKID := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	// payload.Account does NOT equal outer.kid.
	payloadJSON, _ := json.Marshal(KeyChangeInnerPayload{
		Account: "https://example.com/acme/profile/p1/account/acme-acc-DIFFERENT",
		OldKey:  oldJWK,
	})
	headers := map[jose.HeaderKey]interface{}{"url": url}
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, headers, newJWK)

	_, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), outerKID, url, oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerAccountMismatch) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerAccountMismatch", err)
	}
}

func TestParseAndVerifyKeyChangeInner_URLMismatch(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)

	innerURL := "https://example.com/acme/profile/p1/key-change"
	outerURL := "https://example.com/acme/profile/p1/key-change-different"
	kid := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	payloadJSON, _ := json.Marshal(KeyChangeInnerPayload{Account: kid, OldKey: oldJWK})
	headers := map[jose.HeaderKey]interface{}{"url": innerURL}
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, headers, newJWK)

	_, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), kid, outerURL, oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerURLMismatch) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerURLMismatch", err)
	}
}

func TestParseAndVerifyKeyChangeInner_BadSignature(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)
	_, otherJWK := newTestECDSAJWK(t) // different key embedded vs. signer

	url := "https://example.com/acme/profile/p1/key-change"
	kid := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	payloadJSON, _ := json.Marshal(KeyChangeInnerPayload{Account: kid, OldKey: oldJWK})
	headers := map[jose.HeaderKey]interface{}{"url": url}
	// Sign with newPriv but embed otherJWK — verification against the
	// embedded jwk will fail since the signer didn't possess otherJWK's
	// private key.
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, headers, otherJWK)

	_, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), kid, url, oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerSignatureBad) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerSignatureBad", err)
	}
	_ = newJWK
}

func TestParseAndVerifyKeyChangeInner_MalformedJWS(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	_, err := ParseAndVerifyKeyChangeInner([]byte("not-a-jws"), "kid", "url", oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerMalformed) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerMalformed", err)
	}
}

func TestParseAndVerifyKeyChangeInner_MissingURL(t *testing.T) {
	_, oldJWK := newTestRSAJWK(t)
	newPriv, newJWK := newTestECDSAJWK(t)

	url := "https://example.com/acme/profile/p1/key-change"
	kid := "https://example.com/acme/profile/p1/account/acme-acc-abc"
	payloadJSON, _ := json.Marshal(KeyChangeInnerPayload{Account: kid, OldKey: oldJWK})
	// No `url` header.
	innerBytes := signWithEmbeddedJWK(t, newPriv, jose.ES256, payloadJSON, nil, newJWK)

	_, err := ParseAndVerifyKeyChangeInner([]byte(innerBytes), kid, url, oldJWK)
	if !errors.Is(err, ErrKeyChangeInnerURLMissing) {
		t.Errorf("got err=%v, want ErrKeyChangeInnerURLMissing", err)
	}
}

func TestMapKeyChangeErrorToProblem_Coverage(t *testing.T) {
	cases := []struct {
		err      error
		wantType string
	}{
		{ErrKeyChangeInnerSignatureBad, "urn:ietf:params:acme:error:unauthorized"},
		{ErrKeyChangeInnerOldKeyMismatch, "urn:ietf:params:acme:error:unauthorized"},
		{ErrKeyChangeInnerAccountMismatch, "urn:ietf:params:acme:error:malformed"},
		{ErrKeyChangeInnerForbidsKID, "urn:ietf:params:acme:error:malformed"},
		{ErrKeyChangeInnerMissingJWK, "urn:ietf:params:acme:error:malformed"},
		{ErrKeyChangeInnerOldKeyMissing, "urn:ietf:params:acme:error:malformed"},
		{ErrKeyChangeInnerURLMismatch, "urn:ietf:params:acme:error:unauthorized"},
		{ErrKeyChangeInnerMalformed, "urn:ietf:params:acme:error:malformed"},
	}
	for _, c := range cases {
		got := MapKeyChangeErrorToProblem(c.err)
		if got.Type != c.wantType {
			t.Errorf("err=%v: got type %q, want %q", c.err, got.Type, c.wantType)
		}
	}
}

// --- ARI tests ----------------------------------------------------------

func TestParseARICertID_Roundtrip(t *testing.T) {
	aki := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	serial := []byte{0x12, 0x34, 0x56, 0x78}
	certID := base64.RawURLEncoding.EncodeToString(aki) + "." + base64.RawURLEncoding.EncodeToString(serial)

	got, err := ParseARICertID(certID)
	if err != nil {
		t.Fatalf("ParseARICertID: %v", err)
	}
	if string(got.AKI) != string(aki) {
		t.Errorf("AKI: got %x, want %x", got.AKI, aki)
	}
	if string(got.Serial) != string(serial) {
		t.Errorf("Serial: got %x, want %x", got.Serial, serial)
	}
	// SerialHex must match canonical certctl shape.
	wantSerialHex := "12345678"
	if got.SerialHex() != wantSerialHex {
		t.Errorf("SerialHex: got %q, want %q", got.SerialHex(), wantSerialHex)
	}
}

func TestParseARICertID_Malformed(t *testing.T) {
	cases := []struct {
		name    string
		certID  string
		wantErr error
	}{
		{"missing dot", "abc123nodot", ErrARICertIDMalformed},
		{"too many dots", "a.b.c", ErrARICertIDMalformed},
		{"empty aki", ".YWJj", ErrARICertIDEmpty},
		{"empty serial", "YWJj.", ErrARICertIDEmpty},
		{"non-base64 aki", "!!!!.YWJj", ErrARICertIDDecodeAKI},
		{"non-base64 serial", "YWJj.!!!!", ErrARICertIDDecodeSeria},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseARICertID(c.certID)
			if !errors.Is(err, c.wantErr) {
				t.Errorf("got err=%v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestBuildARICertID_FromGeneratedCert(t *testing.T) {
	// Build a self-signed cert with an explicit AKI and serial.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x12345678),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		AuthorityKeyId:        []byte{0xde, 0xad, 0xbe, 0xef},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	certID, err := BuildARICertID(certPEM)
	if err != nil {
		t.Fatalf("BuildARICertID: %v", err)
	}
	parts := strings.Split(certID, ".")
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2", len(parts))
	}
	wantAKI := base64.RawURLEncoding.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})
	if parts[0] != wantAKI {
		t.Errorf("AKI part: got %q, want %q", parts[0], wantAKI)
	}
}

func TestComputeRenewalWindow_WithPolicy(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) // 61 days out
	cert := &domain.ManagedCertificate{ExpiresAt: notAfter}
	version := &domain.CertificateVersion{
		NotBefore: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  notAfter,
	}
	policy := &domain.RenewalPolicy{RenewalWindowDays: 30}

	start, end := ComputeRenewalWindow(cert, version, policy, now)
	wantStart := notAfter.Add(-30 * 24 * time.Hour) // 2026-06-01
	wantEnd := wantStart.Add(15 * 24 * time.Hour)   // 2026-06-16
	if !start.Equal(wantStart) {
		t.Errorf("start: got %v, want %v", start, wantStart)
	}
	if !end.Equal(wantEnd) {
		t.Errorf("end: got %v, want %v", end, wantEnd)
	}
}

func TestComputeRenewalWindow_NoPolicy_LastThird(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) // 91-day validity
	cert := &domain.ManagedCertificate{ExpiresAt: notAfter}
	version := &domain.CertificateVersion{NotBefore: notBefore, NotAfter: notAfter}

	start, end := ComputeRenewalWindow(cert, version, nil, now)
	// Validity = 91 days; thirty3 ~30d, end_offset = 10d. Start is in
	// the future from `now` (Jun 2026), so no clamp.
	if start.Before(now) {
		t.Errorf("start before now: got %v", start)
	}
	if !end.After(start) && !end.Equal(start) {
		t.Errorf("end before start: start=%v end=%v", start, end)
	}
}

func TestComputeRenewalWindow_PastExpiry_RenewNow(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) // 1 month ago
	cert := &domain.ManagedCertificate{ExpiresAt: notAfter}

	start, end := ComputeRenewalWindow(cert, nil, nil, now)
	// Expect a "renew now" 1-day window starting at now.
	if !start.Equal(now) {
		t.Errorf("start: got %v, want %v", start, now)
	}
	if want := now.Add(24 * time.Hour); !end.Equal(want) {
		t.Errorf("end: got %v, want %v", end, want)
	}
}
