// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/domain"
)

// --- test fixtures + helpers --------------------------------------------

// stubAccounts implements AccountLookup with a static map.
type stubAccounts struct {
	byID map[string]*domain.ACMEAccount
}

func (s *stubAccounts) LookupAccount(accountID string) (*domain.ACMEAccount, error) {
	acct, ok := s.byID[accountID]
	if !ok {
		return nil, ErrJWSAccountNotFound
	}
	return acct, nil
}

// stubNonces implements NonceConsumer with a one-shot map. Used == true
// after first Consume.
type stubNonces struct {
	known map[string]bool // nonce → consumed?
}

func newStubNonces(nonces ...string) *stubNonces {
	s := &stubNonces{known: make(map[string]bool, len(nonces))}
	for _, n := range nonces {
		s.known[n] = false
	}
	return s
}

func (s *stubNonces) ConsumeNonce(nonce string) error {
	used, ok := s.known[nonce]
	if !ok {
		return errors.New("not found")
	}
	if used {
		return errors.New("already used")
	}
	s.known[nonce] = true
	return nil
}

const testKID = "https://server/acme/profile/prof-corp/account/acme-acc-test123"
const testURL = "https://server/acme/profile/prof-corp/new-account"

func testAccountKID(accountID string) string {
	return "https://server/acme/profile/prof-corp/account/" + accountID
}

// genRSAKey, genECKey, genEdKey return a freshly-generated keypair
// suitable for signing JWS objects. Tests share the same key per-case
// to keep failures localized to the verifier rather than cross-test
// state.
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return k
}

func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	return k
}

func genEdKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pub, priv
}

// signWithKID builds a flattened JWS using kid (registered-account flow).
func signWithKID(t *testing.T, key interface{}, alg jose.SignatureAlgorithm, kid, url, nonce string, payload interface{}) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).
			WithHeader(jose.HeaderKey("url"), url).
			WithHeader("kid", kid).
			WithHeader("nonce", nonce),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := jws.FullSerialize()
	return out
}

// signWithJWK builds a flattened JWS embedding the public JWK
// (new-account flow). The Signer with EmbedJWK=true attaches the
// JSONWebKey to the protected header.
func signWithJWK(t *testing.T, key interface{}, alg jose.SignatureAlgorithm, url, nonce string, payload interface{}) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).
			WithHeader(jose.HeaderKey("url"), url).
			WithHeader("nonce", nonce),
	)
	if err != nil {
		t.Fatalf("new signer (embed jwk): %v", err)
	}
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return jws.FullSerialize()
}

// --- JWK round-trip helpers --------------------------------------------

func TestJWKRoundTrip_RSA(t *testing.T) {
	k := genRSAKey(t)
	jwk := &jose.JSONWebKey{Key: &k.PublicKey}
	pem, err := JWKToPEM(jwk)
	if err != nil {
		t.Fatalf("JWKToPEM: %v", err)
	}
	if !strings.Contains(pem, "BEGIN ACME ACCOUNT JWK") {
		t.Fatalf("PEM missing header: %s", pem)
	}
	parsed, err := ParseJWKFromPEM(pem)
	if err != nil {
		t.Fatalf("ParseJWKFromPEM: %v", err)
	}
	if !parsed.Valid() {
		t.Fatal("parsed jwk is not valid")
	}
}

func TestJWKThumbprint_StableAcrossKeyTypes(t *testing.T) {
	rsaJWK := &jose.JSONWebKey{Key: &genRSAKey(t).PublicKey}
	rsaThumb1, err := JWKThumbprint(rsaJWK)
	if err != nil {
		t.Fatalf("rsa thumb: %v", err)
	}
	rsaThumb2, err := JWKThumbprint(rsaJWK)
	if err != nil {
		t.Fatalf("rsa thumb 2: %v", err)
	}
	if rsaThumb1 != rsaThumb2 {
		t.Errorf("thumbprint not stable: %q vs %q", rsaThumb1, rsaThumb2)
	}
	// Different keys produce different thumbprints.
	otherJWK := &jose.JSONWebKey{Key: &genRSAKey(t).PublicKey}
	otherThumb, err := JWKThumbprint(otherJWK)
	if err != nil {
		t.Fatalf("other thumb: %v", err)
	}
	if rsaThumb1 == otherThumb {
		t.Error("two distinct keys collided on thumbprint")
	}
}

// --- VerifyJWS happy paths ---------------------------------------------

func TestVerifyJWS_Happy_RS256_KID(t *testing.T) {
	key := genRSAKey(t)
	jwk := &jose.JSONWebKey{Key: &key.PublicKey}
	pem, _ := JWKToPEM(jwk)
	thumb, _ := JWKThumbprint(jwk)

	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-test123": {
				AccountID: "acme-acc-test123", JWKPEM: pem, JWKThumbprint: thumb,
				Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
		}},
		Nonces:     newStubNonces("nonce-001"),
		AccountKID: testAccountKID,
	}
	body := signWithKID(t, key, jose.RS256, testKID, testURL, "nonce-001", map[string]any{"hello": "world"})

	v, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: false})
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if v.Account == nil || v.Account.AccountID != "acme-acc-test123" {
		t.Errorf("account = %+v, want acme-acc-test123", v.Account)
	}
	if v.JWK != nil {
		t.Errorf("JWK should be nil on kid path; got %+v", v.JWK)
	}
	if v.Nonce != "nonce-001" {
		t.Errorf("nonce = %q", v.Nonce)
	}
	if v.URL != testURL {
		t.Errorf("url = %q", v.URL)
	}
	if v.Algorithm != "RS256" {
		t.Errorf("algorithm = %q", v.Algorithm)
	}
	var payload map[string]any
	if err := json.Unmarshal(v.Payload, &payload); err != nil {
		t.Fatalf("payload not json: %v", err)
	}
	if payload["hello"] != "world" {
		t.Errorf("payload = %+v", payload)
	}
}

func TestVerifyJWS_Happy_ES256_JWK(t *testing.T) {
	key := genECKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("nonce-002"),
		AccountKID: testAccountKID,
	}
	body := signWithJWK(t, key, jose.ES256, testURL, "nonce-002", map[string]any{"new": "account"})
	v, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true})
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if v.JWK == nil {
		t.Fatal("JWK should be populated on jwk path")
	}
	if v.Account != nil {
		t.Errorf("Account should be nil on jwk path; got %+v", v.Account)
	}
	if v.Algorithm != "ES256" {
		t.Errorf("algorithm = %q", v.Algorithm)
	}
}

func TestVerifyJWS_Happy_EdDSA_KID(t *testing.T) {
	pub, priv := genEdKey(t)
	jwk := &jose.JSONWebKey{Key: pub}
	pem, _ := JWKToPEM(jwk)
	thumb, _ := JWKThumbprint(jwk)

	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-ed1": {
				AccountID: "acme-acc-ed1", JWKPEM: pem, JWKThumbprint: thumb,
				Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
		}},
		Nonces:     newStubNonces("nonce-003"),
		AccountKID: testAccountKID,
	}
	kid := testAccountKID("acme-acc-ed1")
	body := signWithKID(t, priv, jose.EdDSA, kid, testURL, "nonce-003", struct{}{})

	v, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: false})
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if v.Algorithm != "EdDSA" {
		t.Errorf("algorithm = %q, want EdDSA", v.Algorithm)
	}
}

// --- VerifyJWS rejection paths -----------------------------------------

func TestVerifyJWS_Reject_AlgNotInAllowList(t *testing.T) {
	// HS256 (HMAC-SHA256, symmetric) is forbidden by RFC 8555 §6.2.
	key := []byte("supersecretkey32byteslongforhmac")
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).
			WithHeader(jose.HeaderKey("url"), testURL).
			WithHeader("kid", testKID).
			WithHeader("nonce", "n"),
	)
	if err != nil {
		t.Fatalf("hs256 signer: %v", err)
	}
	jws, _ := signer.Sign([]byte("{}"))
	body := jws.FullSerialize()

	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("n"),
		AccountKID: testAccountKID,
	}
	_, err = VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{})
	if err == nil {
		t.Fatal("expected algorithm-rejected error; got nil")
	}
	// ParseSigned filters the alg before we ever see the JWS, so the
	// error wraps ErrJWSMalformed (the verifier can't distinguish
	// "wrong format" from "bad alg" at this layer — both manifest as
	// malformed).
	if !errors.Is(err, ErrJWSMalformed) && !errors.Is(err, ErrJWSAlgorithmRejected) {
		t.Errorf("err = %v; want ErrJWSMalformed or ErrJWSAlgorithmRejected", err)
	}
}

func TestVerifyJWS_Reject_BadSignature(t *testing.T) {
	signingKey := genRSAKey(t)
	// The verifier resolves the account row's stored JWK and uses its
	// public component as the verify key. Register an account whose
	// stored JWK is a DIFFERENT key — same shape, different material.
	// The JWS parses cleanly but Verify returns "verification failed".
	storedKey := genRSAKey(t)
	storedJWK := &jose.JSONWebKey{Key: &storedKey.PublicKey}
	storedPEM, _ := JWKToPEM(storedJWK)
	storedThumb, _ := JWKThumbprint(storedJWK)

	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-test123": {
				AccountID: "acme-acc-test123", JWKPEM: storedPEM, JWKThumbprint: storedThumb,
				Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
		}},
		Nonces:     newStubNonces("n1"),
		AccountKID: testAccountKID,
	}
	body := signWithKID(t, signingKey, jose.RS256, testKID, testURL, "n1", map[string]any{"x": 1})

	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{})
	if err == nil {
		t.Fatal("expected signature-invalid error; got nil")
	}
	if !errors.Is(err, ErrJWSSignatureInvalid) {
		t.Errorf("err = %v; want ErrJWSSignatureInvalid wrapper", err)
	}
}

func TestVerifyJWS_Reject_NonceMissingFromHeader(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces(),
		AccountKID: testAccountKID,
	}
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).
			WithHeader(jose.HeaderKey("url"), testURL),
		// nonce omitted intentionally
	)
	jws, _ := signer.Sign([]byte("{}"))
	body := jws.FullSerialize()

	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true})
	if !errors.Is(err, ErrJWSMissingNonce) {
		t.Errorf("err = %v; want ErrJWSMissingNonce", err)
	}
}

func TestVerifyJWS_Reject_NonceUnknown(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces(), // no nonces issued
		AccountKID: testAccountKID,
	}
	body := signWithJWK(t, key, jose.RS256, testURL, "ghost-nonce", map[string]any{})
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true})
	if !errors.Is(err, ErrJWSBadNonce) {
		t.Errorf("err = %v; want ErrJWSBadNonce", err)
	}
}

func TestVerifyJWS_Reject_NonceReplay(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("n-replay"),
		AccountKID: testAccountKID,
	}
	body := signWithJWK(t, key, jose.RS256, testURL, "n-replay", map[string]any{})
	if _, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Replay — same JWS, second time.
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true})
	if !errors.Is(err, ErrJWSBadNonce) {
		t.Errorf("err = %v; want ErrJWSBadNonce on replay", err)
	}
}

func TestVerifyJWS_Reject_URLMismatch(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("n-url"),
		AccountKID: testAccountKID,
	}
	body := signWithJWK(t, key, jose.RS256, testURL, "n-url", map[string]any{})
	// Hand the verifier a different URL than the one signed.
	_, err := VerifyJWS(cfg, []byte(body), "https://server/acme/different", VerifyOptions{ExpectNewAccount: true})
	if !errors.Is(err, ErrJWSURLMismatch) {
		t.Errorf("err = %v; want ErrJWSURLMismatch", err)
	}
}

func TestVerifyJWS_Reject_ExpectKidGotJWK(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("n-mix1"),
		AccountKID: testAccountKID,
	}
	body := signWithJWK(t, key, jose.RS256, testURL, "n-mix1", map[string]any{})
	// New-account expects jwk; we set ExpectNewAccount=false so this
	// flow demands kid.
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: false})
	if !errors.Is(err, ErrJWSExpectKidGotJWK) {
		t.Errorf("err = %v; want ErrJWSExpectKidGotJWK", err)
	}
}

func TestVerifyJWS_Reject_ExpectJWKGotKid(t *testing.T) {
	key := genRSAKey(t)
	jwk := &jose.JSONWebKey{Key: &key.PublicKey}
	pem, _ := JWKToPEM(jwk)
	thumb, _ := JWKThumbprint(jwk)
	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-test123": {
				AccountID: "acme-acc-test123", JWKPEM: pem, JWKThumbprint: thumb,
				Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
		}},
		Nonces:     newStubNonces("n-mix2"),
		AccountKID: testAccountKID,
	}
	body := signWithKID(t, key, jose.RS256, testKID, testURL, "n-mix2", map[string]any{})
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{ExpectNewAccount: true})
	if !errors.Is(err, ErrJWSExpectJWKGotKid) {
		t.Errorf("err = %v; want ErrJWSExpectJWKGotKid", err)
	}
}

func TestVerifyJWS_Reject_AccountUnknown(t *testing.T) {
	key := genRSAKey(t)
	cfg := VerifierConfig{
		Accounts:   &stubAccounts{},
		Nonces:     newStubNonces("n-acct"),
		AccountKID: testAccountKID,
	}
	body := signWithKID(t, key, jose.RS256, testKID, testURL, "n-acct", map[string]any{})
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{})
	if !errors.Is(err, ErrJWSAccountNotFound) {
		t.Errorf("err = %v; want ErrJWSAccountNotFound", err)
	}
}

func TestVerifyJWS_Reject_AccountDeactivated(t *testing.T) {
	key := genRSAKey(t)
	jwk := &jose.JSONWebKey{Key: &key.PublicKey}
	pem, _ := JWKToPEM(jwk)
	thumb, _ := JWKThumbprint(jwk)
	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-test123": {
				AccountID: "acme-acc-test123", JWKPEM: pem, JWKThumbprint: thumb,
				Status:    domain.ACMEAccountStatusDeactivated, // ← deactivated
				ProfileID: "prof-corp",
			},
		}},
		Nonces:     newStubNonces("n-deact"),
		AccountKID: testAccountKID,
	}
	body := signWithKID(t, key, jose.RS256, testKID, testURL, "n-deact", map[string]any{})
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{})
	if !errors.Is(err, ErrJWSAccountInactive) {
		t.Errorf("err = %v; want ErrJWSAccountInactive", err)
	}
}

func TestVerifyJWS_Reject_KIDMismatchesProfile(t *testing.T) {
	key := genRSAKey(t)
	jwk := &jose.JSONWebKey{Key: &key.PublicKey}
	pem, _ := JWKToPEM(jwk)
	thumb, _ := JWKThumbprint(jwk)
	cfg := VerifierConfig{
		Accounts: &stubAccounts{byID: map[string]*domain.ACMEAccount{
			"acme-acc-test123": {
				AccountID: "acme-acc-test123", JWKPEM: pem, JWKThumbprint: thumb,
				Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
		}},
		Nonces: newStubNonces("n-cross"),
		// AccountKID expects prof-corp; the test JWS uses a kid that
		// claims prof-corp BUT we're going to feed an off-canonical
		// kid that doesn't match.
		AccountKID: testAccountKID,
	}
	// Sign with a kid that points at a different host. The verifier's
	// AccountKID round-trip-check should reject it.
	wrongKID := "https://different-host/acme/profile/prof-corp/account/acme-acc-test123"
	body := signWithKID(t, key, jose.RS256, wrongKID, testURL, "n-cross", map[string]any{})
	_, err := VerifyJWS(cfg, []byte(body), testURL, VerifyOptions{})
	if err == nil {
		t.Fatal("expected error from kid round-trip mismatch")
	}
	if !errors.Is(err, ErrJWSMalformed) {
		t.Errorf("err = %v; want ErrJWSMalformed (round-trip mismatch)", err)
	}
}

// MapJWSErrorToProblem coverage check: every exported sentinel maps
// to a typed Problem (not the default malformed catch-all).
func TestMapJWSErrorToProblem_KnownSentinels(t *testing.T) {
	cases := []struct {
		err     error
		wantTyp string
	}{
		{ErrJWSBadNonce, "urn:ietf:params:acme:error:badNonce"},
		{ErrJWSMissingNonce, "urn:ietf:params:acme:error:badNonce"},
		{ErrJWSAccountNotFound, "urn:ietf:params:acme:error:accountDoesNotExist"},
		{ErrJWSAccountInactive, "urn:ietf:params:acme:error:unauthorized"},
		{ErrJWSURLMismatch, "urn:ietf:params:acme:error:unauthorized"},
		{ErrJWSSignatureInvalid, "urn:ietf:params:acme:error:unauthorized"},
		{ErrJWSAlgorithmRejected, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSExpectJWKGotKid, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSExpectKidGotJWK, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSBothKidAndJWK, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSNeitherKidNorJWK, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSInvalidJWK, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSWrongType, "urn:ietf:params:acme:error:malformed"},
		{ErrJWSPayloadMismatch, "urn:ietf:params:acme:error:serverInternal"},
		{ErrJWSMalformed, "urn:ietf:params:acme:error:malformed"},
	}
	for _, tc := range cases {
		p := MapJWSErrorToProblem(tc.err)
		if p.Type != tc.wantTyp {
			t.Errorf("err=%v: type = %q, want %q", tc.err, p.Type, tc.wantTyp)
		}
		if p.Status == 0 {
			t.Errorf("err=%v: status was 0", tc.err)
		}
	}
}
