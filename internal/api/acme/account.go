// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"github.com/certctl-io/certctl/internal/domain"
)

// AccountResponseJSON is the wire shape RFC 8555 §7.1.2 mandates for
// account-resource responses (new-account success, account update,
// per-account GET POST-as-GET).
//
// The orders URL is mandatory per RFC 8555 §7.1.2.1; it points at the
// per-account orders list endpoint that Phase 2 implements. Phase 1b
// emits it as an empty placeholder ("orders not yet implemented") so
// the directory + new-account flow round-trips against ACME clients
// that expect the field present.
type AccountResponseJSON struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

// MarshalAccount renders an ACMEAccount in RFC 8555 §7.1.2 wire shape.
// `ordersURL` is the per-account orders list URL the handler computes
// from the inbound request (scheme + host + profile path + account
// id); Phase 1b's handler passes it but Phase 2 wires the actual
// /acme/profile/<id>/account/<acc-id>/orders endpoint.
func MarshalAccount(acct *domain.ACMEAccount, ordersURL string) AccountResponseJSON {
	contact := acct.Contact
	if contact == nil {
		// RFC 8555 doesn't require contact be present, but cert-manager
		// + lego both expect a stable shape. Emit [] rather than null.
		contact = []string{}
	}
	return AccountResponseJSON{
		Status:  string(acct.Status),
		Contact: contact,
		Orders:  ordersURL,
	}
}

// NewAccountRequest is the payload shape RFC 8555 §7.3 mandates for
// new-account requests. The handler json.Unmarshals VerifiedRequest.Payload
// into this struct after JWS verify succeeds.
type NewAccountRequest struct {
	// Contact is a list of mailto: / tel: URIs. Optional per RFC 8555
	// but operators typically supply at least one mailto:.
	Contact []string `json:"contact,omitempty"`
	// TermsOfServiceAgreed signals client consent to the operator's
	// ToS document (advertised via meta.termsOfService). Phase 1b
	// records the value but does NOT enforce — the meta field is
	// informational only at this stage.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`
	// OnlyReturnExisting, when true, asks the server to return the
	// existing account row for this JWK (RFC 8555 §7.3.1). When
	// true and no account exists, the server MUST return 400 +
	// urn:ietf:params:acme:error:accountDoesNotExist.
	OnlyReturnExisting bool `json:"onlyReturnExisting,omitempty"`
	// ExternalAccountBinding (EAB) is RFC 8555 §7.3.4. Phase 1b
	// accepts the field but does NOT validate — EAB enforcement is
	// a deliberate out-of-scope per the master prompt and lands as a
	// follow-up if there's demand. Storing the raw envelope means a
	// future phase can backfill validation against historical accounts.
	ExternalAccountBinding map[string]interface{} `json:"externalAccountBinding,omitempty"`
}

// AccountUpdateRequest is the payload shape for the account-update
// endpoint POST /acme/profile/<id>/account/<acc-id> (RFC 8555 §7.3.2 +
// §7.3.6). Only `contact` and `status` are mutable per the spec.
type AccountUpdateRequest struct {
	// Contact, when non-nil, replaces the account's contact list.
	// nil means "leave unchanged" (distinct from empty []string{}
	// which means "clear contacts" — cert-manager doesn't issue
	// either, but the spec permits both).
	Contact []string `json:"contact,omitempty"`
	// Status, when set to "deactivated", retires the account per
	// RFC 8555 §7.3.6. Other values are rejected — the operator
	// path for revoked is via certctl's API, not via ACME.
	Status string `json:"status,omitempty"`
}
