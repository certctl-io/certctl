// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// Phase 4 — RFC 8555 §7.3.5 key rollover.
//
// The wire shape is a doubly-signed JWS:
//
//	JWS-outer  signed by the OLD account key (kid = account URL):
//	  protected: { alg, kid, nonce, url }
//	  payload:   <JWS-inner-as-bytes>
//
//	JWS-inner  signed by the NEW account key (jwk = newkey):
//	  protected: { alg, jwk, url=<same key-change URL> }
//	  payload:   { account: <kid-URL>, oldKey: <OLD JWK> }
//
// The handler runs the existing VerifyJWS pipeline against the outer
// (kid path), then hands the resulting Payload bytes to ParseAndVerify-
// KeyChangeInner so the inner is processed in isolation. Two key
// distinctions vs. the outer:
//
//   - The inner JWS does NOT carry a `nonce` header. Per RFC 8555 §7.3.5
//     the outer's nonce is the only nonce; the inner is a self-contained
//     proof-of-possession blob.
//   - The inner JWS uses `jwk` not `kid` and the verifier must succeed
//     when the embedded `jwk` itself is the verification key.
//
// This matches what go-jose's lego implementation, cert-manager, and
// boulder all expect.

// KeyChangeInnerPayload is the parsed body of the inner JWS — RFC 8555
// §7.3.5 mandates exactly two fields.
type KeyChangeInnerPayload struct {
	// Account is the kid URL of the account whose key is being rotated.
	// MUST equal the outer's `kid` header. Mismatch → keyChange's
	// "account" field doesn't match outer.kid.
	Account string `json:"account"`

	// OldKey is the JWK currently on file for the account. The server
	// asserts this matches what we have in the database (byte-equal
	// canonicalized) so a stale rollover request can't slip through.
	OldKey *jose.JSONWebKey `json:"oldKey"`
}

// KeyChangeInner is the verified inner JWS — fields the service layer
// needs to commit the rollover.
type KeyChangeInner struct {
	// NewJWK is the JWK the inner JWS is signed by. After verification
	// this is the key the account's row will be updated to.
	NewJWK *jose.JSONWebKey

	// Payload is the inner's parsed JSON: { account, oldKey }.
	Payload KeyChangeInnerPayload

	// URL is the inner protected-header `url` value, asserted equal to
	// the outer's URL.
	URL string

	// Algorithm is the negotiated alg the inner was signed with.
	Algorithm string
}

// Sentinel errors. Each maps to an RFC 8555 §6.7 problem type via the
// service's writeServiceError; tests assert via errors.Is.
var (
	ErrKeyChangeInnerMalformed       = errors.New("acme keychange: inner JWS malformed")
	ErrKeyChangeInnerAlgRejected     = errors.New("acme keychange: inner JWS uses disallowed signature algorithm")
	ErrKeyChangeInnerMissingJWK      = errors.New("acme keychange: inner JWS protected header MUST contain `jwk`")
	ErrKeyChangeInnerForbidsKID      = errors.New("acme keychange: inner JWS MUST NOT contain `kid` (use `jwk`)")
	ErrKeyChangeInnerInvalidJWK      = errors.New("acme keychange: inner JWS embedded JWK is invalid")
	ErrKeyChangeInnerURLMissing      = errors.New("acme keychange: inner JWS protected header `url` is required")
	ErrKeyChangeInnerURLMismatch     = errors.New("acme keychange: inner JWS `url` does not match outer JWS `url`")
	ErrKeyChangeInnerSignatureBad    = errors.New("acme keychange: inner JWS signature did not verify against embedded JWK")
	ErrKeyChangeInnerPayloadParse    = errors.New("acme keychange: inner JWS payload is not parseable JSON")
	ErrKeyChangeInnerAccountMismatch = errors.New("acme keychange: inner JWS payload `account` does not match outer JWS `kid`")
	ErrKeyChangeInnerOldKeyMissing   = errors.New("acme keychange: inner JWS payload missing `oldKey`")
	ErrKeyChangeInnerOldKeyMismatch  = errors.New("acme keychange: inner JWS payload `oldKey` does not match registered account key")
)

// ParseAndVerifyKeyChangeInner parses the inner JWS bytes (i.e. the
// outer JWS's verified payload), runs the same allow-list +
// signature-verification pipeline as VerifyJWS, and asserts the inner-
// only invariants from RFC 8555 §7.3.5 (must use `jwk`, must NOT use
// `kid`, URL must match).
//
// Caller passes:
//
//   - innerBytes: the outer JWS's verified payload (the inner JWS in
//     compact serialization).
//   - outerKID: the outer JWS's `kid` header value. The inner's payload
//     `account` field MUST equal this.
//   - outerURL: the outer JWS's `url` header value. The inner's
//     protected-header `url` MUST equal this.
//   - registeredOldJWK: the JWK currently stored on the account row.
//     The inner's payload `oldKey` MUST canonicalize-equal this.
//
// Returns the verified KeyChangeInner on success, or one of the
// sentinel errors above on any validation failure.
func ParseAndVerifyKeyChangeInner(innerBytes []byte, outerKID, outerURL string, registeredOldJWK *jose.JSONWebKey) (*KeyChangeInner, error) {
	// Parse against the same allow-list that VerifyJWS uses.
	jws, err := jose.ParseSigned(string(innerBytes), AllowedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyChangeInnerMalformed, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: multi-signature inner JWS", ErrKeyChangeInnerMalformed)
	}
	sig := jws.Signatures[0]
	if !algorithmAllowed(sig.Protected.Algorithm) {
		return nil, fmt.Errorf("%w: %s", ErrKeyChangeInnerAlgRejected, sig.Protected.Algorithm)
	}

	// RFC 8555 §7.3.5: the inner MUST use `jwk` and MUST NOT use `kid`.
	if sig.Protected.KeyID != "" {
		return nil, ErrKeyChangeInnerForbidsKID
	}
	jwk := sig.Protected.JSONWebKey
	if jwk == nil {
		return nil, ErrKeyChangeInnerMissingJWK
	}
	if !jwk.Valid() {
		return nil, ErrKeyChangeInnerInvalidJWK
	}

	// URL header MUST equal the outer's URL.
	innerURL, err := extractStringHeader(sig.Protected.ExtraHeaders, "url")
	if err != nil {
		return nil, ErrKeyChangeInnerURLMissing
	}
	if innerURL == "" {
		return nil, ErrKeyChangeInnerURLMissing
	}
	if innerURL != outerURL {
		return nil, fmt.Errorf("%w: inner=%q outer=%q", ErrKeyChangeInnerURLMismatch, innerURL, outerURL)
	}

	// Verify the inner signature against the embedded jwk.
	verifiedPayload, err := jws.Verify(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyChangeInnerSignatureBad, err)
	}

	// Parse the inner payload.
	var payload KeyChangeInnerPayload
	if err := json.Unmarshal(verifiedPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyChangeInnerPayloadParse, err)
	}

	// `account` MUST equal outer's kid.
	if payload.Account != outerKID {
		return nil, fmt.Errorf("%w: payload=%q outer.kid=%q",
			ErrKeyChangeInnerAccountMismatch, payload.Account, outerKID)
	}

	// `oldKey` MUST be present and canonicalize-equal to registered.
	if payload.OldKey == nil {
		return nil, ErrKeyChangeInnerOldKeyMissing
	}
	if !payload.OldKey.Valid() {
		return nil, fmt.Errorf("%w: oldKey did not validate", ErrKeyChangeInnerOldKeyMismatch)
	}
	eq, err := jwksThumbprintEqual(payload.OldKey, registeredOldJWK)
	if err != nil {
		return nil, fmt.Errorf("%w: thumbprint compare: %v", ErrKeyChangeInnerOldKeyMismatch, err)
	}
	if !eq {
		return nil, ErrKeyChangeInnerOldKeyMismatch
	}

	return &KeyChangeInner{
		NewJWK:    jwk,
		Payload:   payload,
		URL:       innerURL,
		Algorithm: sig.Protected.Algorithm,
	}, nil
}

// jwksThumbprintEqual compares two JWKs by RFC 7638 thumbprint, which
// is the canonical identity for a public key. We deliberately compare
// thumbprints rather than serialized bytes because go-jose may emit
// fields in different orders for "equal" keys.
//
// Returns (true, nil) when both thumbprints exist and match in
// constant time; (false, err) on any thumbprint computation error;
// (false, nil) when the thumbprints differ.
func jwksThumbprintEqual(a, b *jose.JSONWebKey) (bool, error) {
	if a == nil || b == nil {
		return false, nil
	}
	tA, err := JWKThumbprint(a)
	if err != nil {
		return false, err
	}
	tB, err := JWKThumbprint(b)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(tA), []byte(tB)) == 1, nil
}

// MapKeyChangeErrorToProblem renders an inner-JWS validation error as
// an RFC 7807 + RFC 8555 §6.7 Problem the handler emits via
// WriteProblem.
//
// All inner-JWS errors map to operator-friendly problem types. The
// detail string is a concise summary; the full err.Error() context is
// suppressed to avoid leaking internal-state details (master-prompt
// criterion #10).
func MapKeyChangeErrorToProblem(err error) Problem {
	switch {
	case errors.Is(err, ErrKeyChangeInnerSignatureBad),
		errors.Is(err, ErrKeyChangeInnerOldKeyMismatch):
		// Both indicate "you don't actually possess the rollover key
		// pair" — treat as unauthorized per RFC 8555 §7.3.5.
		return Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "key rollover proof failed: " + plainCause(err),
			Status: 401,
		}
	case errors.Is(err, ErrKeyChangeInnerURLMismatch),
		errors.Is(err, ErrKeyChangeInnerURLMissing):
		return Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "key rollover inner URL: " + plainCause(err),
			Status: 401,
		}
	case errors.Is(err, ErrKeyChangeInnerAlgRejected):
		return Malformed("key rollover inner JWS uses disallowed algorithm")
	case errors.Is(err, ErrKeyChangeInnerForbidsKID):
		return Malformed("key rollover inner JWS MUST use `jwk`, not `kid`")
	case errors.Is(err, ErrKeyChangeInnerMissingJWK),
		errors.Is(err, ErrKeyChangeInnerInvalidJWK):
		return Malformed("key rollover inner JWS missing or invalid `jwk`")
	case errors.Is(err, ErrKeyChangeInnerAccountMismatch):
		return Malformed("key rollover inner `account` does not match outer kid")
	case errors.Is(err, ErrKeyChangeInnerOldKeyMissing):
		return Malformed("key rollover inner missing `oldKey`")
	case errors.Is(err, ErrKeyChangeInnerPayloadParse):
		return Malformed("key rollover inner payload is not valid JSON")
	case errors.Is(err, ErrKeyChangeInnerMalformed):
		return Malformed("key rollover inner JWS malformed")
	default:
		return Malformed("key rollover request rejected")
	}
}

// plainCause extracts the leaf error text without leaking the full
// wrap chain. Used by MapKeyChangeErrorToProblem to keep the operator-
// facing detail concise.
func plainCause(err error) string {
	if err == nil {
		return ""
	}
	// Walk to the leaf cause; emit its message verbatim.
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}
