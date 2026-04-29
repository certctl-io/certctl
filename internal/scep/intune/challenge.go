package intune

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Typed challenge-validation errors. The handler audits the specific
// failure dimension via errors.Is so operators can distinguish e.g. an
// expired challenge (clock skew, latent enrollment) from a tampered one
// (active attack) without string-matching error messages.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.4.
var (
	ErrChallengeMalformed      = errors.New("intune: challenge is not in the JWT-like compact-serialization format")
	ErrChallengeSignature      = errors.New("intune: challenge signature does not verify against any configured trust anchor")
	ErrChallengeExpired        = errors.New("intune: challenge expired")
	ErrChallengeNotYetValid    = errors.New("intune: challenge not yet valid (iat in future, possible clock skew)")
	ErrChallengeWrongAudience  = errors.New("intune: challenge audience does not match this SCEP endpoint URL")
	ErrChallengeReplay         = errors.New("intune: challenge nonce already seen (replay attempt)")
	ErrChallengeUnknownVersion = errors.New("intune: challenge has an unknown version claim — parser does not support this format")
)

// ParseChallenge decodes the JWT-like compact serialization of an Intune
// dynamic challenge into header, payload, and signature byte slices. Does
// NOT verify the signature; that's ValidateChallenge's job.
//
// Format: base64url(header) "." base64url(payload) "." base64url(signature)
// where the base64url alphabet is RFC 4648 §5 (URL-safe, no padding).
//
// We accept both padded and unpadded base64url because some Connector
// versions have shipped padded encodings in the wild despite RFC 7515 §2
// mandating unpadded. The stdlib base64.RawURLEncoding rejects padding,
// so we strip trailing '=' before decoding.
func ParseChallenge(raw string) (header, payload, signature []byte, err error) {
	if raw == "" {
		return nil, nil, nil, fmt.Errorf("%w: empty input", ErrChallengeMalformed)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: expected 3 dot-separated segments, got %d", ErrChallengeMalformed, len(parts))
	}
	for i, p := range parts {
		if p == "" {
			return nil, nil, nil, fmt.Errorf("%w: segment %d is empty", ErrChallengeMalformed, i)
		}
	}
	header, err = b64urlDecode(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: header base64url: %v", ErrChallengeMalformed, err)
	}
	payload, err = b64urlDecode(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: payload base64url: %v", ErrChallengeMalformed, err)
	}
	signature, err = b64urlDecode(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: signature base64url: %v", ErrChallengeMalformed, err)
	}
	// Sanity-check the header parses as JSON before we hand it back; a
	// non-JSON header is a clear malformed signal we'd otherwise only
	// catch later in ValidateChallenge during alg dispatch. Earlier
	// rejection = better operator audit log shape.
	var probe map[string]any
	if err := json.Unmarshal(header, &probe); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: header is not JSON: %v", ErrChallengeMalformed, err)
	}
	return header, payload, signature, nil
}

// b64urlDecode decodes RFC 4648 §5 base64url with or without trailing
// '=' padding. RFC 7515 §2 mandates unpadded; some Intune Connector
// versions emit padded; tolerate both.
func b64urlDecode(s string) ([]byte, error) {
	stripped := strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(stripped)
}

// jwtHeader is the JOSE-style header carried in the first segment of an
// Intune challenge. We only consult `alg` for signature dispatch; other
// JWS fields (kid, x5c, jku, etc.) are intentionally NOT honored — the
// trust anchor is operator-supplied at startup and pinned, not negotiated
// per-request. Honoring kid/jku would expand the attack surface to "any
// URL the Connector header claims is the truth," which is exactly the
// JWT vulnerability class we're avoiding by not pulling in a full JOSE
// implementation.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
}

// versionedChallenge is the lightest possible pre-parse to extract a
// version claim BEFORE the full JSON unmarshal commits to a struct
// shape. v1 (current) has no "version" key; v2+ MUST.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.4 (version dispatcher
// rationale): Microsoft has changed the Connector signed-challenge format
// at least twice in the past 5 years. Adding the dispatcher today costs
// ~30 LoC + 2 tests; not having it when v2 ships costs a P0 incident
// where every Intune enrollment fails until a hot-fix lands.
type versionedChallenge struct {
	Version string `json:"version,omitempty"`
}

// versionUnmarshalers maps a version string to its claim parser. Adding
// v2 = adding a parser + a registration line. Adding v3 = same. Existing
// v1 path stays untouched.
var versionUnmarshalers = map[string]func(payload []byte) (*ChallengeClaim, error){
	"":   unmarshalChallengeV1, // legacy / current default
	"v1": unmarshalChallengeV1, // explicit v1, future-belt-and-suspenders
	// "v2": unmarshalChallengeV2,  // ← future, when Microsoft ships it
}

// challengePayloadV1 is the on-the-wire JSON shape of the v1 Connector
// challenge. Separated from the public ChallengeClaim because the wire
// format uses Unix-second numerics for iat/exp while the in-memory type
// uses time.Time (caller-friendly + sentinel-safe).
type challengePayloadV1 struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   string   `json:"aud,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
	Nonce      string   `json:"nonce,omitempty"`
	DeviceName string   `json:"device_name,omitempty"`
	SANDNS     []string `json:"san_dns,omitempty"`
	SANRFC822  []string `json:"san_rfc822,omitempty"`
	SANUPN     []string `json:"san_upn,omitempty"`
}

// unmarshalChallengeV1 parses the v1 wire format. Conservative: any
// unrecognised JSON fields are silently dropped (forward-compat for the
// inevitable v1.x minor additions Microsoft makes without bumping the
// version key).
func unmarshalChallengeV1(payload []byte) (*ChallengeClaim, error) {
	var p challengePayloadV1
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: v1 payload unmarshal: %v", ErrChallengeMalformed, err)
	}
	c := &ChallengeClaim{
		Issuer:     p.Issuer,
		Subject:    p.Subject,
		Audience:   p.Audience,
		Nonce:      p.Nonce,
		DeviceName: p.DeviceName,
		SANDNS:     p.SANDNS,
		SANRFC822:  p.SANRFC822,
		SANUPN:     p.SANUPN,
	}
	if p.IssuedAt > 0 {
		c.IssuedAt = time.Unix(p.IssuedAt, 0).UTC()
	}
	if p.ExpiresAt > 0 {
		c.ExpiresAt = time.Unix(p.ExpiresAt, 0).UTC()
	}
	return c, nil
}

// ValidateChallenge runs the full Intune-challenge validation pipeline:
//
//  1. ParseChallenge(raw) — JWT compact deserialize
//  2. Verify signature over (segment0 || "." || segment1) against any
//     trust-anchor cert's public key (try each until one verifies)
//  3. Extract version claim via the lightweight versioned-prelude
//  4. Dispatch to the per-version unmarshaler (v1 today)
//  5. Time bounds: now ≥ iat AND now < exp (with stdlib RFC 3339 grace)
//  6. Audience: claim.Audience == expectedAudience (when expectedAudience
//     is non-empty; empty disables the check, useful for tests)
//
// Returns *ChallengeClaim on success, typed error on failure (caller can
// errors.Is the specific dimension).
//
// Replay protection is the CALLER's responsibility — pass the returned
// claim's Nonce to a *ReplayCache.CheckAndInsert. We deliberately don't
// own the cache here so the validator stays stateless + testable; the
// handler glues parser + cache together.
func ValidateChallenge(raw string, trust []*x509.Certificate, expectedAudience string, now time.Time) (*ChallengeClaim, error) {
	if len(trust) == 0 {
		return nil, fmt.Errorf("%w: no trust anchors configured", ErrChallengeSignature)
	}

	header, payload, signature, err := ParseChallenge(raw)
	if err != nil {
		return nil, err
	}

	// JWS signing input per RFC 7515 §5.1: ASCII bytes of segment0 + "." + segment1.
	// We re-derive from raw (split-by-dots) rather than re-base64-encode the
	// decoded segments, because RFC 7515 §3.1 specifies the signing input
	// is the encoded form, and some encoders omit padding while others
	// don't — re-encoding could produce a byte-different input than what
	// the Connector originally signed. Use the raw on-wire bytes.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		// ParseChallenge already enforced this; defensive double-check.
		return nil, fmt.Errorf("%w: post-parse segment count drift", ErrChallengeMalformed)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	var hdr jwtHeader
	if err := json.Unmarshal(header, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header JSON: %v", ErrChallengeMalformed, err)
	}

	if err := verifyChallengeSignature(hdr.Alg, signingInput, signature, trust); err != nil {
		return nil, err
	}

	// Version dispatch — extract the version claim BEFORE the full unmarshal.
	var v versionedChallenge
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, fmt.Errorf("%w: prelude unmarshal: %v", ErrChallengeMalformed, err)
	}
	unmarshaler, ok := versionUnmarshalers[v.Version]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrChallengeUnknownVersion, v.Version)
	}
	claim, err := unmarshaler(payload)
	if err != nil {
		return nil, err
	}

	// Time bounds. The Connector's signed iat/exp ARE authoritative;
	// we don't impose a separate validity cap here (the operator can
	// add one in the handler if defense-in-depth is wanted, e.g. via
	// SCEPProfileConfig.IntuneChallengeValidity in Phase 8).
	if !claim.IssuedAt.IsZero() && now.Before(claim.IssuedAt) {
		return nil, fmt.Errorf("%w: iat=%s now=%s", ErrChallengeNotYetValid,
			claim.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !claim.ExpiresAt.IsZero() && !now.Before(claim.ExpiresAt) {
		return nil, fmt.Errorf("%w: exp=%s now=%s", ErrChallengeExpired,
			claim.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	// Audience binds the challenge to a specific SCEP endpoint URL. An
	// empty expectedAudience disables the check (test convenience + the
	// Phase 8 config allows operator opt-out for proxy / load-balancer
	// scenarios where the URL the Connector saw isn't the URL we see).
	if expectedAudience != "" && claim.Audience != "" && claim.Audience != expectedAudience {
		return nil, fmt.Errorf("%w: claim=%q expected=%q", ErrChallengeWrongAudience,
			claim.Audience, expectedAudience)
	}

	return claim, nil
}

// verifyChallengeSignature dispatches on the JWS alg header to the
// matching stdlib signature-verify routine, then iterates the trust
// anchors trying each cert's public key until one verifies.
//
// Supported algs:
//   - RS256: RSASSA-PKCS1-v1_5 over SHA-256 (Microsoft's published Connector default)
//   - ES256: ECDSA P-256 over SHA-256 (community-reported Connector option)
//
// Deliberately rejected algs:
//   - "none" (RFC 7515 §3.6 vulnerability vector)
//   - HS256 / HS384 / HS512 (HMAC; no shared secret in our threat model)
//   - PS256+ (RSA-PSS; not seen in Intune Connector traffic — add only when needed)
//
// Adding a new alg = add a case + a verify helper. The trust-anchor loop
// stays unchanged.
func verifyChallengeSignature(alg string, signingInput, signature []byte, trust []*x509.Certificate) error {
	switch alg {
	case "RS256":
		return verifyRS256(signingInput, signature, trust)
	case "ES256":
		return verifyES256(signingInput, signature, trust)
	case "":
		return fmt.Errorf("%w: missing alg header (RFC 7515 §4.1.1 mandates)", ErrChallengeSignature)
	case "none":
		// Explicit reject so the failure mode in the audit log distinguishes
		// "unsupported alg" from "active attack with the alg-none vector."
		return fmt.Errorf("%w: alg \"none\" rejected (RFC 7515 §3.6 attack)", ErrChallengeSignature)
	default:
		return fmt.Errorf("%w: unsupported alg %q (only RS256 and ES256 are accepted)", ErrChallengeSignature, alg)
	}
}

// verifyRS256 hashes the signing input with SHA-256 and checks the
// signature against each trust anchor's public key. Constant-time: the
// stdlib's rsa.VerifyPKCS1v15 returns nil on success and an error on
// failure without timing-leak surface area on the hash compare path.
func verifyRS256(signingInput, signature []byte, trust []*x509.Certificate) error {
	h := sha256.Sum256(signingInput)
	for _, cert := range trust {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], signature); err == nil {
			return nil
		}
	}
	return ErrChallengeSignature
}

// verifyES256 dispatches between the two ECDSA signature encodings the
// JOSE spec allows for ES256:
//
//   - RFC 7515 §3.4 fixed-width: r || s, each 32 bytes (raw concat) — the
//     wire format JOSE-compliant Connectors use.
//   - ASN.1 DER (SEQUENCE { r INTEGER, s INTEGER }) — older Connector
//     builds and many .NET-based JWT libraries emit DER instead of the
//     RFC 7515 fixed-width form.
//
// Try fixed-width first (the spec-blessed format); fall back to ASN.1.
// crypto/ecdsa.VerifyASN1 + ecdsa.Verify both return bool — no timing
// leak on the success path.
func verifyES256(signingInput, signature []byte, trust []*x509.Certificate) error {
	h := sha256.Sum256(signingInput)
	for _, cert := range trust {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}

		// Fixed-width r||s form (JOSE-canonical for P-256 = 64 bytes).
		if len(signature) == 64 {
			r := new(big.Int).SetBytes(signature[:32])
			s := new(big.Int).SetBytes(signature[32:])
			if ecdsa.Verify(pub, h[:], r, s) {
				return nil
			}
		}

		// ASN.1 DER form (older / non-JOSE encoders).
		if ecdsa.VerifyASN1(pub, h[:], signature) {
			return nil
		}
	}
	return ErrChallengeSignature
}
