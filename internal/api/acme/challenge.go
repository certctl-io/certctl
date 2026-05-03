// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// KeyAuthorization computes the canonical RFC 8555 §8.1 key authorization
// string: <token> + "." + base64url(JWK-thumbprint).
//
// The thumbprint is RFC 7638 SHA-256 of the canonicalized JWK; same
// helper Phase 1b uses to derive account IDs. Phase 3's HTTP-01 +
// DNS-01 + TLS-ALPN-01 validators all consume this string.
func KeyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	if jwk == nil {
		return "", errors.New("acme: nil jwk for key authorization")
	}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("acme: thumbprint: %w", err)
	}
	return token + "." + base64.RawURLEncoding.EncodeToString(thumb), nil
}

// DNS01TXTRecordValue computes the value an authoritative DNS server
// must serve for `_acme-challenge.<domain>` per RFC 8555 §8.4.
//
// The DNS-01 record is base64url(SHA-256(keyAuthorization)) — NOT the
// raw key authorization (that's HTTP-01's behavior).
func DNS01TXTRecordValue(keyAuthorization string) string {
	h := sha256.Sum256([]byte(keyAuthorization))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// TLSALPN01ExtensionValue computes the SHA-256 hash of the key
// authorization that the validator looks for in the responding TLS
// cert's id-pe-acmeIdentifier extension (RFC 8737 §3).
//
// The ASN.1 wrapping (OCTET STRING containing the 32 raw bytes) is the
// caller's responsibility; this helper returns the inner 32 bytes.
func TLSALPN01ExtensionValue(keyAuthorization string) []byte {
	h := sha256.Sum256([]byte(keyAuthorization))
	return h[:]
}

// IDPEAcmeIdentifierOID is the ObjectIdentifier RFC 8737 §3 mandates for
// the id-pe-acmeIdentifier extension carried in the responding TLS
// cert during TLS-ALPN-01 validation. Exported so the validator can
// .Equal() it against incoming cert extensions; the value is fixed
// per-spec and never changes.
var IDPEAcmeIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ChallengeProblemFromError maps a validator error into the RFC 7807
// Problem the challenge row's `error` column should record. Centralized
// so each per-type validator returns plain errors and the dispatcher
// translates uniformly.
//
// The Problem types align with RFC 8555 §6.7:
//   - connection / TCP-level → urn:ietf:params:acme:error:connection
//   - DNS / TXT mismatch → urn:ietf:params:acme:error:dns
//   - TLS handshake / cert mismatch → urn:ietf:params:acme:error:tls
//   - all others → urn:ietf:params:acme:error:incorrectResponse (the
//     RFC-canonical "challenge response was wrong" type)
func ChallengeProblemFromError(challengeType string, err error) *Problem {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrChallengeConnection):
		return &Problem{Type: "urn:ietf:params:acme:error:connection", Detail: err.Error(), Status: 400}
	case errors.Is(err, ErrChallengeDNS):
		return &Problem{Type: "urn:ietf:params:acme:error:dns", Detail: err.Error(), Status: 400}
	case errors.Is(err, ErrChallengeTLS):
		return &Problem{Type: "urn:ietf:params:acme:error:tls", Detail: err.Error(), Status: 400}
	default:
		return &Problem{
			Type:   "urn:ietf:params:acme:error:incorrectResponse",
			Detail: fmt.Sprintf("%s validation failed: %s", challengeType, err.Error()),
			Status: 403,
		}
	}
}

// Validator-side sentinel errors. Each one maps to a specific RFC 8555
// §6.7 problem type via ChallengeProblemFromError above. Per-validator
// implementations wrap their failures with these.
var (
	ErrChallengeConnection = errors.New("acme: connection-level failure during challenge validation")
	ErrChallengeDNS        = errors.New("acme: DNS-level failure during challenge validation")
	ErrChallengeTLS        = errors.New("acme: TLS-level failure during challenge validation")
	ErrChallengeMismatch   = errors.New("acme: challenge response did not match expected key authorization")
	ErrChallengeReservedIP = errors.New("acme: HTTP-01 target resolves to a reserved IP (SSRF guard)")
	ErrChallengeRedirect   = errors.New("acme: HTTP-01 target redirected too many times")
	ErrChallengeBodyTooBig = errors.New("acme: HTTP-01 response body exceeded 16 KiB cap")
	ErrChallengeNoCert     = errors.New("acme: TLS-ALPN-01 target presented no certificate")
	ErrChallengeWrongALPN  = errors.New("acme: TLS-ALPN-01 target did not negotiate the acme-tls/1 protocol")
	ErrChallengeExtMissing = errors.New("acme: TLS-ALPN-01 target's certificate did not carry the id-pe-acmeIdentifier extension")
)
