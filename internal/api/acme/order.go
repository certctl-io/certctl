// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// OrderResponseJSON is the wire shape RFC 8555 §7.1.3 mandates for the
// new-order response + the per-order POST-as-GET response.
//
// Each URL field is the per-profile path the handler computes from the
// inbound request; service-layer code does not see *http.Request, so
// the handler does the URL composition.
type OrderResponseJSON struct {
	Status         string           `json:"status"`
	Expires        string           `json:"expires,omitempty"`
	NotBefore      string           `json:"notBefore,omitempty"`
	NotAfter       string           `json:"notAfter,omitempty"`
	Identifiers    []IdentifierJSON `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
	Error          *Problem         `json:"error,omitempty"`
}

// IdentifierJSON is the wire shape for an identifier (RFC 8555 §9.7.7).
// Wire field names differ from the domain struct's JSON tags only on
// case, so we keep separate types to keep the protocol surface clean.
type IdentifierJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// MarshalOrder renders an ACMEOrder in RFC 8555 §7.1.3 wire shape.
//
// authzURLs / finalizeURL / certURL are computed by the handler from
// the inbound request (scheme + host + per-profile path). Phase 2:
// authzURLs has one entry per identifier; finalizeURL is the order's
// finalize endpoint; certURL is populated only when status=valid.
func MarshalOrder(order *domain.ACMEOrder, authzURLs []string, finalizeURL, certURL string) OrderResponseJSON {
	out := OrderResponseJSON{
		Status:         string(order.Status),
		Expires:        order.ExpiresAt.UTC().Format(time.RFC3339),
		Identifiers:    make([]IdentifierJSON, 0, len(order.Identifiers)),
		Authorizations: authzURLs,
		Finalize:       finalizeURL,
	}
	if order.NotBefore != nil {
		out.NotBefore = order.NotBefore.UTC().Format(time.RFC3339)
	}
	if order.NotAfter != nil {
		out.NotAfter = order.NotAfter.UTC().Format(time.RFC3339)
	}
	for _, id := range order.Identifiers {
		out.Identifiers = append(out.Identifiers, IdentifierJSON{Type: id.Type, Value: id.Value})
	}
	if certURL != "" && order.Status == domain.ACMEOrderStatusValid {
		out.Certificate = certURL
	}
	if order.Error != nil {
		out.Error = &Problem{
			Type:   order.Error.Type,
			Detail: order.Error.Detail,
			Status: order.Error.Status,
		}
	}
	return out
}

// NewOrderRequest is the payload shape RFC 8555 §7.4 mandates for a
// new-order POST. The handler json.Unmarshals VerifiedRequest.Payload
// into this struct after JWS verify succeeds.
type NewOrderRequest struct {
	Identifiers []IdentifierJSON `json:"identifiers"`
	NotBefore   string           `json:"notBefore,omitempty"`
	NotAfter    string           `json:"notAfter,omitempty"`
}

// FinalizeRequest is the payload shape RFC 8555 §7.4 mandates for the
// finalize POST. csr is the base64url-encoded DER of a PKCS#10 CSR.
type FinalizeRequest struct {
	CSR string `json:"csr"`
}

// AuthorizationResponseJSON is the wire shape RFC 8555 §7.1.4 mandates
// for the authz GET (POST-as-GET) response.
type AuthorizationResponseJSON struct {
	Identifier IdentifierJSON          `json:"identifier"`
	Status     string                  `json:"status"`
	Expires    string                  `json:"expires,omitempty"`
	Wildcard   bool                    `json:"wildcard,omitempty"`
	Challenges []ChallengeResponseJSON `json:"challenges"`
}

// ChallengeResponseJSON is the wire shape RFC 8555 §8 mandates for a
// challenge object (embedded in authz, or returned by POST to a
// challenge URL).
type ChallengeResponseJSON struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

// MarshalAuthorization renders an ACMEAuthorization in RFC 8555 wire shape.
// challengeURLBuilder maps each challenge ID to its per-profile URL
// (handler-computed); identifiers stay as-is.
func MarshalAuthorization(authz *domain.ACMEAuthorization, challengeURLBuilder func(challengeID string) string) AuthorizationResponseJSON {
	out := AuthorizationResponseJSON{
		Identifier: IdentifierJSON{Type: authz.Identifier.Type, Value: authz.Identifier.Value},
		Status:     string(authz.Status),
		Expires:    authz.ExpiresAt.UTC().Format(time.RFC3339),
		Wildcard:   authz.Wildcard,
		Challenges: make([]ChallengeResponseJSON, 0, len(authz.Challenges)),
	}
	for i := range authz.Challenges {
		ch := &authz.Challenges[i]
		j := ChallengeResponseJSON{
			Type:   string(ch.Type),
			URL:    challengeURLBuilder(ch.ChallengeID),
			Status: string(ch.Status),
			Token:  ch.Token,
		}
		if ch.ValidatedAt != nil {
			j.Validated = ch.ValidatedAt.UTC().Format(time.RFC3339)
		}
		if ch.Error != nil {
			j.Error = &Problem{Type: ch.Error.Type, Detail: ch.Error.Detail, Status: ch.Error.Status}
		}
		out.Challenges = append(out.Challenges, j)
	}
	return out
}

// ErrIdentifierTypeUnsupported is returned when ValidateIdentifiers
// encounters a non-DNS identifier type. RFC 8555 §9.7.7 reserves
// `type` for future expansion; Phase 2 supports `dns` only.
var ErrIdentifierTypeUnsupported = errors.New("acme: identifier type not supported (Phase 2: dns only)")

// ErrIdentifierEmpty is returned for an identifier with an empty
// value; the spec requires non-empty strings.
var ErrIdentifierEmpty = errors.New("acme: identifier value is empty")

// ValidateIdentifiers checks the structural invariants RFC 8555 §7.4
// requires (non-empty value, supported type) and returns per-identifier
// rejected entries on failure. Per-profile-policy rejection (SAN
// allowlist, lifetime cap) is the service layer's job; this function
// is the syntactic check only.
//
// Returns nil + nil ids on full acceptance. On rejection, returns the
// list of rejected identifiers with their reason as RFC 8555 §6.7
// subproblems (rejectedIdentifier).
func ValidateIdentifiers(ids []IdentifierJSON) []Problem {
	if len(ids) == 0 {
		return []Problem{Malformed("new-order requires at least one identifier")}
	}
	var problems []Problem
	for _, id := range ids {
		switch strings.ToLower(id.Type) {
		case "dns":
			if id.Value == "" {
				problems = append(problems, Problem{
					Type:       "urn:ietf:params:acme:error:rejectedIdentifier",
					Detail:     "identifier value is empty",
					Status:     400,
					Identifier: &Identifier{Type: id.Type, Value: id.Value},
				})
			}
		default:
			problems = append(problems, Problem{
				Type:       "urn:ietf:params:acme:error:rejectedIdentifier",
				Detail:     fmt.Sprintf("identifier type %q is not supported (Phase 2: dns only)", id.Type),
				Status:     400,
				Identifier: &Identifier{Type: id.Type, Value: id.Value},
			})
		}
	}
	return problems
}

// CSRMatchesIdentifiers asserts the CSR's DNS-name set (Subject CN +
// Subject Alternative Names) equals the order's identifier set,
// case-folded for DNS comparison.
//
// RFC 8555 §7.4 finalize: "The CSR MUST indicate the exact same set of
// requested identifiers as the initial newOrder request." Case-fold
// the comparison so a CSR with `Example.com` matches an order with
// `example.com` (DNS is case-insensitive per RFC 1035 §2.3.3).
//
// Returns nil on match. On mismatch, returns a Problem typed as
// urn:ietf:params:acme:error:badCSR.
func CSRMatchesIdentifiers(csr *x509.CertificateRequest, identifiers []domain.ACMEIdentifier) *Problem {
	csrSet := make(map[string]struct{})
	if csr.Subject.CommonName != "" {
		csrSet[strings.ToLower(csr.Subject.CommonName)] = struct{}{}
	}
	for _, dns := range csr.DNSNames {
		csrSet[strings.ToLower(dns)] = struct{}{}
	}

	orderSet := make(map[string]struct{})
	for _, id := range identifiers {
		if id.Type != "dns" {
			continue
		}
		orderSet[strings.ToLower(id.Value)] = struct{}{}
	}

	if len(csrSet) != len(orderSet) {
		p := Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: fmt.Sprintf("CSR identifier count (%d) differs from order identifier count (%d)", len(csrSet), len(orderSet)),
			Status: 400,
		}
		return &p
	}
	for k := range orderSet {
		if _, ok := csrSet[k]; !ok {
			p := Problem{
				Type:   "urn:ietf:params:acme:error:badCSR",
				Detail: fmt.Sprintf("CSR is missing the order identifier %q", k),
				Status: 400,
			}
			return &p
		}
	}
	return nil
}

// HasWildcard returns true when any identifier is a wildcard. RFC 8555
// §7.1.3 marks the order's authz wildcard:true when the corresponding
// identifier starts with "*."; Phase 2 supports the trust_authenticated
// path (which auto-marks authz valid), so wildcard-aware challenge
// dispatch is Phase 3's concern.
func HasWildcard(ids []domain.ACMEIdentifier) bool {
	for _, id := range ids {
		if strings.HasPrefix(id.Value, "*.") {
			return true
		}
	}
	return false
}
