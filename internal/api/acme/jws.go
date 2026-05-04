// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/certctl-io/certctl/internal/domain"
)

// AllowedSignatureAlgorithms is the closed allow-list per RFC 8555 §6.2.
// ParseSigned takes this slice and rejects every other algorithm —
// in particular HS256 (symmetric — RFC 8555 forbids) and "none"
// (RFC 7515 §6.1 — alg confusion attack).
//
// Order is not load-bearing; the slice is value-copied by go-jose.
var AllowedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.ES256,
	jose.EdDSA,
}

// JWS-verifier sentinel errors. Each maps to an RFC 8555 §6.7
// problem type via mapJWSError below; handlers render via
// WriteProblem(w, p) on err.
var (
	ErrJWSMalformed         = errors.New("acme jws: malformed")
	ErrJWSWrongType         = errors.New("acme jws: protected header `typ` must be `application/jose+json` or absent")
	ErrJWSAlgorithmRejected = errors.New("acme jws: signature algorithm not in {RS256, ES256, EdDSA}")
	ErrJWSMissingNonce      = errors.New("acme jws: protected header `nonce` is required")
	ErrJWSBadNonce          = errors.New("acme jws: nonce missing, replayed, or expired")
	ErrJWSMissingURL        = errors.New("acme jws: protected header `url` is required")
	ErrJWSURLMismatch       = errors.New("acme jws: protected header `url` does not match request URL")
	ErrJWSBothKidAndJWK     = errors.New("acme jws: protected header MUST contain exactly one of `kid` or `jwk`")
	ErrJWSNeitherKidNorJWK  = errors.New("acme jws: protected header MUST contain exactly one of `kid` or `jwk`")
	ErrJWSExpectKidGotJWK   = errors.New("acme jws: this endpoint requires `kid` (registered account); got `jwk`")
	ErrJWSExpectJWKGotKid   = errors.New("acme jws: this endpoint requires `jwk` (new account); got `kid`")
	ErrJWSInvalidJWK        = errors.New("acme jws: embedded JWK is invalid")
	ErrJWSSignatureInvalid  = errors.New("acme jws: signature did not verify")
	ErrJWSPayloadMismatch   = errors.New("acme jws: post-verify payload differs from pre-verify payload")
	ErrJWSAccountNotFound   = errors.New("acme jws: kid points at unknown account")
	ErrJWSAccountInactive   = errors.New("acme jws: account status is not `valid`")
)

// VerifiedRequest is the JWS-verified envelope a handler hands to its
// service-layer entry point. Fields are populated based on the auth
// path: `kid` requests carry Account (and AccountKey is the registered
// JWK); `jwk` requests (new-account only) carry JWK.
//
// Payload is the bytes the JWS signed — the handler json.Unmarshals
// into the per-endpoint payload struct.
type VerifiedRequest struct {
	// Payload is the signed body bytes (post-Verify).
	Payload []byte
	// Algorithm is the negotiated alg (RS256 / ES256 / EdDSA), echoed
	// from sig.Protected.Algorithm post-allow-list-check.
	Algorithm string
	// URL is the protected-header `url` value, asserted equal to the
	// inbound request URL.
	URL string
	// Nonce is the protected-header `nonce` value, asserted consumed
	// from the nonce store.
	Nonce string
	// Account is non-nil on the `kid` path (registered account
	// authenticating). Always nil on the `jwk` path.
	Account *domain.ACMEAccount
	// JWK is non-nil on the `jwk` path (new-account flow). Always nil
	// on the `kid` path.
	JWK *jose.JSONWebKey
}

// AccountLookup is the minimum surface VerifyJWS needs to resolve a
// `kid` request's account. The repository layer satisfies this; tests
// inject in-memory fakes.
type AccountLookup interface {
	// LookupAccount returns the account by ID. Returns
	// ErrJWSAccountNotFound if the row doesn't exist.
	LookupAccount(accountID string) (*domain.ACMEAccount, error)
}

// NonceConsumer is the minimum surface the verifier needs to consume
// the protected-header `nonce`. Returns nil on success, or an error
// (typically sql.ErrNoRows from the postgres repo) on missing /
// replayed / expired. The verifier wraps any non-nil error in
// ErrJWSBadNonce so handlers don't need to distinguish.
type NonceConsumer interface {
	ConsumeNonce(nonce string) error
}

// VerifierConfig wires the verifier's runtime dependencies + policy.
// Constructed by the handler/service layer once at startup; one
// instance per ACMEService is sufficient.
type VerifierConfig struct {
	// Accounts looks up registered accounts on the kid path.
	Accounts AccountLookup
	// Nonces consumes the protected-header nonce.
	Nonces NonceConsumer
	// AccountKID returns the canonical kid URL the server expects
	// inbound requests to use for a given account ID. The verifier
	// asserts the request's `kid` matches what AccountKID(acct.ID)
	// produces — this prevents a stolen account-id-from-one-server
	// from being replayed against another. The handler computes
	// the URL from the inbound request's scheme + host + profile.
	AccountKID func(accountID string) string
}

// VerifyOptions bound a single verify call. ExpectNewAccount inverts
// the kid-vs-jwk default: new-account demands jwk, every other
// endpoint demands kid.
type VerifyOptions struct {
	// ExpectNewAccount=true means "expect jwk in the protected header,
	// reject kid." Used by /new-account.
	// ExpectNewAccount=false means "expect kid in the protected header,
	// reject jwk." Used by everything else.
	ExpectNewAccount bool
}

// VerifyJWS is the canonical entry point. It enforces:
//
//  1. Body parses as a flattened JWS with exactly one signature
//     (RFC 8555 §6.2 forbids multi-sig).
//  2. Algorithm is in the {RS256, ES256, EdDSA} allow-list.
//  3. Protected header carries exactly one of `kid` / `jwk` per
//     ExpectNewAccount.
//  4. Protected header carries `url` matching the inbound request URL
//     exactly.
//  5. Protected header carries `nonce` that consumes successfully
//     against the nonce store (badNonce on miss/replay/expiry).
//  6. Signature verifies against the resolved key (registered
//     account's stored JWK on kid path; embedded jwk on jwk path).
//  7. Post-verify payload bytes equal pre-verify
//     UnsafePayloadWithoutVerification (defense in depth — go-jose
//     guarantees this, but assert anyway).
//
// On success returns VerifiedRequest; the handler json.Unmarshals
// Payload into the per-endpoint payload struct.
//
// The `requestURL` argument is what the handler computed from the
// inbound *http.Request (scheme + host + path). VerifyJWS does NOT
// see r itself — keeping net/http out of the package surface lets
// the verifier be tested without httptest.
func VerifyJWS(cfg VerifierConfig, body []byte, requestURL string, opts VerifyOptions) (*VerifiedRequest, error) {
	jws, err := jose.ParseSigned(string(body), AllowedSignatureAlgorithms)
	if err != nil {
		// ParseSigned errors lump together "wrong format" and "alg
		// not in allow-list." Both are operator-meaningful as
		// "malformed" — the alg case is not exploitable by leaking
		// the allow-list.
		return nil, fmt.Errorf("%w: %v", ErrJWSMalformed, err)
	}
	// RFC 8555 §6.2: ACME forbids JWS multi-signature. Reject anything
	// other than exactly one signature so a maliciously-crafted
	// multi-sig blob can't trigger ambiguous downstream behavior.
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: multi-signature JWS rejected", ErrJWSMalformed)
	}
	sig := jws.Signatures[0]

	// Defense-in-depth: ParseSigned rejected non-allow-list algs
	// already, but a corrupted Signatures slice could still slip
	// through. Verify the field directly.
	if !algorithmAllowed(sig.Protected.Algorithm) {
		return nil, fmt.Errorf("%w: %s", ErrJWSAlgorithmRejected, sig.Protected.Algorithm)
	}

	// Protected-header `typ` (RFC 8555 §6.2): when present, must be
	// "application/jose+json". Many ACME clients (including
	// cert-manager) omit it; treat absent as OK.
	if typ := sig.Protected.ExtraHeaders[jose.HeaderKey("typ")]; typ != nil {
		typStr, ok := typ.(string)
		if !ok || (typStr != "application/jose+json" && typStr != "") {
			return nil, fmt.Errorf("%w: got %q", ErrJWSWrongType, typ)
		}
	}

	// Protected-header `url` is mandatory per RFC 8555 §6.4. Compare
	// to the inbound request URL exactly (scheme+host+path); a
	// mismatch indicates either a bug in the client or an attempt to
	// replay a JWS signed for a different URL.
	urlVal, err := extractStringHeader(sig.Protected.ExtraHeaders, "url")
	if err != nil {
		return nil, ErrJWSMissingURL
	}
	if urlVal == "" {
		return nil, ErrJWSMissingURL
	}
	if urlVal != requestURL {
		return nil, fmt.Errorf("%w: header=%q request=%q", ErrJWSURLMismatch, urlVal, requestURL)
	}

	// Protected-header `nonce` is mandatory (RFC 8555 §6.5). Check
	// it BEFORE running Verify — if the nonce is bad we don't want to
	// burn CPU on signature verification.
	nonce := sig.Protected.Nonce
	if nonce == "" {
		return nil, ErrJWSMissingNonce
	}
	if err := cfg.Nonces.ConsumeNonce(nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWSBadNonce, err)
	}

	// Protected header MUST contain exactly one of kid / jwk per
	// RFC 8555 §6.2. Both-set or neither-set are rejected.
	hasKid := sig.Protected.KeyID != ""
	hasJWK := sig.Protected.JSONWebKey != nil
	if hasKid && hasJWK {
		return nil, ErrJWSBothKidAndJWK
	}
	if !hasKid && !hasJWK {
		return nil, ErrJWSNeitherKidNorJWK
	}

	// Per-endpoint kid-vs-jwk policy.
	if opts.ExpectNewAccount && hasKid {
		return nil, ErrJWSExpectJWKGotKid
	}
	if !opts.ExpectNewAccount && hasJWK {
		return nil, ErrJWSExpectKidGotJWK
	}

	// Resolve the verification key and (kid path) the corresponding
	// account row.
	var (
		verifyKey interface{}
		account   *domain.ACMEAccount
		jwkOut    *jose.JSONWebKey
	)
	if hasKid {
		accountID, err := accountIDFromKID(sig.Protected.KeyID, cfg)
		if err != nil {
			return nil, err
		}
		acct, err := cfg.Accounts.LookupAccount(accountID)
		if err != nil {
			return nil, err
		}
		if acct.Status != domain.ACMEAccountStatusValid {
			return nil, fmt.Errorf("%w: status=%s", ErrJWSAccountInactive, acct.Status)
		}
		// The account's stored JWK is what we verify against. The
		// JWKPEM round-trips through ParseJWKFromPEM; tests inject
		// pre-parsed keys to keep the unit suite hermetic.
		key, err := ParseJWKFromPEM(acct.JWKPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJWSInvalidJWK, err)
		}
		verifyKey = key.Key
		account = acct
	} else {
		jwk := sig.Protected.JSONWebKey
		if !jwk.Valid() {
			return nil, ErrJWSInvalidJWK
		}
		verifyKey = jwk.Key
		jwkOut = jwk
	}

	// Run the actual signature verification. go-jose returns the
	// post-verify payload bytes; we sanity-check them against the
	// pre-verify view.
	verified, err := jws.Verify(verifyKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWSSignatureInvalid, err)
	}
	preVerify := jws.UnsafePayloadWithoutVerification()
	if string(verified) != string(preVerify) {
		// Should be impossible under correct go-jose use; fail loudly.
		return nil, ErrJWSPayloadMismatch
	}

	return &VerifiedRequest{
		Payload:   verified,
		Algorithm: sig.Protected.Algorithm,
		URL:       urlVal,
		Nonce:     nonce,
		Account:   account,
		JWK:       jwkOut,
	}, nil
}

// MapJWSErrorToProblem renders a JWS verifier error as an RFC 7807 +
// RFC 8555 §6.7 Problem the handler emits via WriteProblem.
//
// All errors map to a documented ACME error type — no internal-state
// leakage per master-prompt criterion #10. Operator-actionable detail
// strings carry the failure category (badNonce, malformed, etc.) but
// not raw err.Error() output.
func MapJWSErrorToProblem(err error) Problem {
	switch {
	case errors.Is(err, ErrJWSBadNonce):
		return BadNonce("nonce missing, replayed, or expired")
	case errors.Is(err, ErrJWSMissingNonce):
		return BadNonce("protected header `nonce` is required")
	case errors.Is(err, ErrJWSURLMismatch), errors.Is(err, ErrJWSMissingURL):
		return Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "protected header `url` mismatch or missing",
			Status: http.StatusUnauthorized,
		}
	case errors.Is(err, ErrJWSAccountNotFound):
		return AccountDoesNotExist("kid points at unknown account")
	case errors.Is(err, ErrJWSAccountInactive):
		return Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "account status is not `valid`",
			Status: http.StatusUnauthorized,
		}
	case errors.Is(err, ErrJWSSignatureInvalid):
		return Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "signature did not verify",
			Status: http.StatusUnauthorized,
		}
	case errors.Is(err, ErrJWSAlgorithmRejected):
		return Malformed("signature algorithm not allowed (RFC 8555 §6.2: RS256, ES256, EdDSA only)")
	case errors.Is(err, ErrJWSExpectJWKGotKid):
		return Malformed("this endpoint requires `jwk` (new-account flow); got `kid`")
	case errors.Is(err, ErrJWSExpectKidGotJWK):
		return Malformed("this endpoint requires `kid` (registered account); got `jwk`")
	case errors.Is(err, ErrJWSBothKidAndJWK), errors.Is(err, ErrJWSNeitherKidNorJWK):
		return Malformed("protected header MUST contain exactly one of `kid` or `jwk`")
	case errors.Is(err, ErrJWSInvalidJWK):
		return Malformed("invalid or unsupported JWK")
	case errors.Is(err, ErrJWSWrongType):
		return Malformed("protected header `typ` must be `application/jose+json`")
	case errors.Is(err, ErrJWSPayloadMismatch):
		return ServerInternal("JWS payload integrity check failed")
	case errors.Is(err, ErrJWSMalformed):
		return Malformed("malformed JWS")
	default:
		return Malformed("malformed request")
	}
}

// algorithmAllowed verifies the post-parse algorithm is in the
// approved set. ParseSigned already rejects non-allow-list algs but
// re-checking here protects against go-jose contract changes.
func algorithmAllowed(alg string) bool {
	for _, a := range AllowedSignatureAlgorithms {
		if string(a) == alg {
			return true
		}
	}
	return false
}

// extractStringHeader pulls a string-typed entry from ExtraHeaders.
// Returns ("", nil) when the key is absent so the caller can
// distinguish absent (empty string) from non-string-shaped (error).
func extractStringHeader(extra map[jose.HeaderKey]interface{}, name string) (string, error) {
	v, ok := extra[jose.HeaderKey(name)]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("acme jws: header %q is not a string: %T", name, v)
	}
	return s, nil
}

// accountIDFromKID extracts the account ID from a kid URL. RFC 8555
// §6.2 says kid is the URL the server returned in the Location
// header on new-account; we expect the canonical
//
//	<scheme>://<host>/acme/profile/<profile-id>/account/<account-id>
//
// shape and trust the verifier-config-supplied AccountKID to round-
// trip the full URL match. Phase 1b: extract the account ID by
// trimming the URL prefix; Phase 1b's caller asserts the round-trip
// equals the original kid.
func accountIDFromKID(kid string, cfg VerifierConfig) (string, error) {
	// Trim off everything up to the last "/account/" — the suffix is
	// the account ID. The Phase-1b account-id format is
	// "acme-acc-<...>" (alphanumeric + hyphen), so we don't need to
	// URL-unescape.
	idx := strings.LastIndex(kid, "/account/")
	if idx < 0 {
		return "", fmt.Errorf("%w: kid does not match expected /account/<id> shape", ErrJWSMalformed)
	}
	accountID := kid[idx+len("/account/"):]
	if accountID == "" {
		return "", fmt.Errorf("%w: kid has empty account id", ErrJWSMalformed)
	}
	// Round-trip: confirm the canonical kid for this account-id
	// matches what the client sent. Catches accidental cross-profile
	// replay.
	if cfg.AccountKID != nil {
		expected := cfg.AccountKID(accountID)
		if expected != kid {
			return "", fmt.Errorf("%w: kid does not match canonical URL", ErrJWSMalformed)
		}
	}
	return accountID, nil
}

// ParseJWKFromPEM parses a JWK previously serialized by JWKToPEM.
// Used by the verifier on the kid path: the registered account row's
// JWKPEM column round-trips through here to recover the key bytes
// used for signature verification.
//
// The PEM block is JSON-encoded JWK (we use PEM as the wire format
// for the column to keep the schema text-shaped + line-friendly for
// SQL diffs). Block type is "ACME ACCOUNT JWK".
func ParseJWKFromPEM(pemString string) (*jose.JSONWebKey, error) {
	// Strip the PEM header / footer; everything between is base64.
	const header = "-----BEGIN ACME ACCOUNT JWK-----"
	const footer = "-----END ACME ACCOUNT JWK-----"
	s := strings.TrimSpace(pemString)
	if !strings.HasPrefix(s, header) {
		return nil, fmt.Errorf("acme jws: pem missing header")
	}
	s = strings.TrimPrefix(s, header)
	idx := strings.Index(s, footer)
	if idx < 0 {
		return nil, fmt.Errorf("acme jws: pem missing footer")
	}
	body := strings.TrimSpace(s[:idx])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("acme jws: decode pem body: %w", err)
	}
	jwk := new(jose.JSONWebKey)
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("acme jws: parse jwk json: %w", err)
	}
	if !jwk.Valid() {
		return nil, fmt.Errorf("acme jws: jwk did not validate")
	}
	return jwk, nil
}

// JWKToPEM is the inverse of ParseJWKFromPEM. Used at account creation
// time to persist the public-only JWK to the acme_accounts row.
func JWKToPEM(jwk *jose.JSONWebKey) (string, error) {
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("acme jws: marshal jwk json: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	// Wrap to 64-char lines for diff-friendliness.
	var buf strings.Builder
	buf.WriteString("-----BEGIN ACME ACCOUNT JWK-----\n")
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteByte('\n')
	}
	buf.WriteString("-----END ACME ACCOUNT JWK-----\n")
	return buf.String(), nil
}

// JWKThumbprint computes the RFC 7638 thumbprint of jwk and returns
// it as a base64url-no-padding string. The (profile_id, thumbprint)
// pair uniquely identifies an account per profile; new-account uses
// it for idempotency (RFC 8555 §7.3.1).
func JWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	raw, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("acme jws: thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// AccountID derives the canonical certctl account ID from a JWK
// thumbprint: "acme-acc-" + base64url-no-pad-thumbprint. The output is
// stable across clients (same JWK → same ID) so the new-account
// idempotency check at RFC 8555 §7.3.1 holds without an additional
// lookup.
func AccountID(thumbprint string) string {
	// base64url-no-pad already produces alphanumeric + `-_`; we keep
	// `-_` as part of the certctl-readable prefix shape.
	return "acme-acc-" + thumbprint
}
