// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

// Package acme implements the ACME server-side protocol surface (RFC 8555
// + RFC 9773 ARI). It is deliberately separate from
// internal/connector/issuer/acme/ which is the consumer surface (certctl
// talks UP to Let's Encrypt / ZeroSSL / pebble). The two surfaces share
// no types — the consumer's data model is client-shaped; the server's
// is request-handler-shaped.
//
// Phase 1a: directory + nonce + JSON-Problem (RFC 7807) error envelopes
// only. JWS verification, account resource, orders, challenges, key
// rollover, revocation, ARI all land in subsequent phases (1b → 4).
package acme

import "fmt"

// Directory is the JSON document RFC 8555 §7.1.1 mandates the server
// publish at /acme/profile/<id>/directory (and at /acme/directory when
// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID is set).
//
// Each URL is the per-profile path the ACME client POSTs against. Even
// though Phase 1a only wires up new-nonce, the directory advertises
// the full surface — RFC 8555 doesn't permit a partial directory and
// clients use the directory's URL fields exclusively (they don't
// hand-construct paths from a base URL).
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	// RenewalInfo (RFC 9773 ARI) lands in Phase 4. Omitted now via the
	// `,omitempty` tag so the JSON output stays clean for clients that
	// don't yet support ARI.
	RenewalInfo string `json:"renewalInfo,omitempty"`
	Meta        *Meta  `json:"meta,omitempty"`
}

// Meta is the optional metadata block per RFC 8555 §7.1.1. Every field
// is operator-supplied via CERTCTL_ACME_SERVER_* env vars; an empty
// Meta is omitted from the marshaled directory.
type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// BuildDirectory constructs the per-profile directory document.
//
// baseURL is the per-profile base path (no trailing slash, e.g.
// "https://certctl.example.com/acme/profile/prof-corp"). The default-
// profile shorthand path passes the same baseURL — clients writing
// their config against the shorthand naturally re-derive the per-
// profile URLs from the directory.
//
// All five canonical RFC 8555 endpoints are populated; renewalInfo is
// populated only when ARIEnabled=true so Phase 1a (where ARI is
// non-functional) doesn't advertise a 404-returning URL. ARI flips on
// in Phase 4 along with the actual handler.
func BuildDirectory(baseURL, tos, website string, caa []string, eabRequired, ariEnabled bool) *Directory {
	dir := &Directory{
		NewNonce:   fmt.Sprintf("%s/new-nonce", baseURL),
		NewAccount: fmt.Sprintf("%s/new-account", baseURL),
		NewOrder:   fmt.Sprintf("%s/new-order", baseURL),
		RevokeCert: fmt.Sprintf("%s/revoke-cert", baseURL),
		KeyChange:  fmt.Sprintf("%s/key-change", baseURL),
	}
	if ariEnabled {
		// RFC 9773 §4.1 publishes ARI as `renewalInfo`. Phase 4 wires
		// the actual handler; until then, BuildDirectory callers pass
		// ariEnabled=false.
		dir.RenewalInfo = fmt.Sprintf("%s/renewal-info", baseURL)
	}
	if tos != "" || website != "" || len(caa) > 0 || eabRequired {
		dir.Meta = &Meta{
			TermsOfService:          tos,
			Website:                 website,
			CAAIdentities:           caa,
			ExternalAccountRequired: eabRequired,
		}
	}
	return dir
}
