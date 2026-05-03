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

// ACMEOrder mirrors a row in the acme_orders table (RFC 8555 §7.1.3).
// Identifiers stored as a slice; the postgres layer JSON-encodes into
// the JSONB column at write time and decodes on read.
type ACMEOrder struct {
	OrderID       string           `json:"order_id"`
	AccountID     string           `json:"account_id"`
	Identifiers   []ACMEIdentifier `json:"identifiers"`
	Status        ACMEOrderStatus  `json:"status"`
	ExpiresAt     time.Time        `json:"expires_at"`
	NotBefore     *time.Time       `json:"not_before,omitempty"`
	NotAfter      *time.Time       `json:"not_after,omitempty"`
	Error         *ACMEProblem     `json:"error,omitempty"`
	CSRPEM        string           `json:"csr_pem,omitempty"`
	CertificateID string           `json:"certificate_id,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// ACMEOrderStatus is the closed state-machine for the `status` column
// per RFC 8555 §7.1.6.
type ACMEOrderStatus string

const (
	ACMEOrderStatusPending    ACMEOrderStatus = "pending"
	ACMEOrderStatusReady      ACMEOrderStatus = "ready"
	ACMEOrderStatusProcessing ACMEOrderStatus = "processing"
	ACMEOrderStatusValid      ACMEOrderStatus = "valid"
	ACMEOrderStatusInvalid    ACMEOrderStatus = "invalid"
)

// ACMEIdentifier is the {type, value} pair RFC 8555 §7.1.4 mandates.
// Phase 2 supports `dns` only; Phase 3 will not extend (RFC 8555
// extensions for IP / email identifier types are out of scope).
type ACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACMEProblem mirrors the RFC 7807 + RFC 8555 §6.7 error envelope
// when stored on an order/authz row. Kept in domain (rather than
// importing api/acme.Problem) so the persistence layer doesn't take
// a dependency on the protocol package.
type ACMEProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// ACMEAuthorization mirrors a row in the acme_authorizations table
// (RFC 8555 §7.1.4). One authz per order identifier; the linked
// challenges live in acme_challenges.
type ACMEAuthorization struct {
	AuthzID    string          `json:"authz_id"`
	OrderID    string          `json:"order_id"`
	Identifier ACMEIdentifier  `json:"identifier"`
	Status     ACMEAuthzStatus `json:"status"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Wildcard   bool            `json:"wildcard"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Challenges []ACMEChallenge `json:"challenges,omitempty"` // populated by repo on read
}

// ACMEAuthzStatus is the closed enum for acme_authorizations.status
// per RFC 8555 §7.1.6.
type ACMEAuthzStatus string

const (
	ACMEAuthzStatusPending     ACMEAuthzStatus = "pending"
	ACMEAuthzStatusValid       ACMEAuthzStatus = "valid"
	ACMEAuthzStatusInvalid     ACMEAuthzStatus = "invalid"
	ACMEAuthzStatusDeactivated ACMEAuthzStatus = "deactivated"
	ACMEAuthzStatusExpired     ACMEAuthzStatus = "expired"
	ACMEAuthzStatusRevoked     ACMEAuthzStatus = "revoked"
)

// ACMEChallenge mirrors a row in the acme_challenges table (RFC 8555 §8).
type ACMEChallenge struct {
	ChallengeID string              `json:"challenge_id"`
	AuthzID     string              `json:"authz_id"`
	Type        ACMEChallengeType   `json:"type"`
	Status      ACMEChallengeStatus `json:"status"`
	Token       string              `json:"token"`
	ValidatedAt *time.Time          `json:"validated_at,omitempty"`
	Error       *ACMEProblem        `json:"error,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
}

// ACMEChallengeType is the closed set of challenge types Phase 3 will
// implement. Phase 2 emits only `http-01` placeholders since challenge
// validation isn't wired yet — RFC 8555 §8 mandates at least one
// challenge per authz.
type ACMEChallengeType string

const (
	ACMEChallengeTypeHTTP01    ACMEChallengeType = "http-01"
	ACMEChallengeTypeDNS01     ACMEChallengeType = "dns-01"
	ACMEChallengeTypeTLSALPN01 ACMEChallengeType = "tls-alpn-01"
)

// ACMEChallengeStatus is the closed enum for acme_challenges.status
// per RFC 8555 §7.1.6 + §8.2.
type ACMEChallengeStatus string

const (
	ACMEChallengeStatusPending    ACMEChallengeStatus = "pending"
	ACMEChallengeStatusProcessing ACMEChallengeStatus = "processing"
	ACMEChallengeStatusValid      ACMEChallengeStatus = "valid"
	ACMEChallengeStatusInvalid    ACMEChallengeStatus = "invalid"
)
