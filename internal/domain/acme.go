// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package domain

import "time"

// ACMEAccount mirrors a row in the acme_accounts table (RFC 8555 §7.1.2).
// The (ProfileID, JWKThumbprint) pair is unique per the migration's
// UNIQUE constraint — RFC 8555 §7.3.1 idempotent semantics — so the
// new-account endpoint maps a re-registration of an existing key onto
// the original account row rather than creating a duplicate.
//
// JWKPEM is the public-only JWK serialized via api/acme.JWKToPEM (a
// PEM-wrapped JSON envelope). Stored as TEXT in the column for diff-
// friendliness; the verifier round-trips through ParseJWKFromPEM at
// request time.
type ACMEAccount struct {
	AccountID     string            `json:"account_id"`
	JWKThumbprint string            `json:"jwk_thumbprint"`
	JWKPEM        string            `json:"jwk_pem"`
	Contact       []string          `json:"contact,omitempty"`
	Status        ACMEAccountStatus `json:"status"`
	ProfileID     string            `json:"profile_id"`
	OwnerID       string            `json:"owner_id,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// ACMEAccountStatus is the closed enum for acme_accounts.status. The
// migration's CHECK constraint is implicit (the migration uses TEXT
// without a CHECK; service-layer validation owns the value-set).
type ACMEAccountStatus string

const (
	// ACMEAccountStatusValid is the default for newly-created accounts.
	// JWS-authenticated requests are accepted only when the bound
	// account is `valid`.
	ACMEAccountStatusValid ACMEAccountStatus = "valid"
	// ACMEAccountStatusDeactivated marks an account the client
	// voluntarily retired via POST /acme/.../account/<id> with
	// payload {"status": "deactivated"} (RFC 8555 §7.3.6). Future
	// JWS-authenticated requests using this account's kid are
	// rejected with `unauthorized`.
	ACMEAccountStatusDeactivated ACMEAccountStatus = "deactivated"
	// ACMEAccountStatusRevoked marks an account the operator
	// administratively retired (e.g. after detecting a compromised
	// JWK). Same access semantics as deactivated.
	ACMEAccountStatusRevoked ACMEAccountStatus = "revoked"
)
