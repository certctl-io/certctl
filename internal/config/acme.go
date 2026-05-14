// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import "time"

// Phase 9 ARCH-M2 closure Sprint 2 (2026-05-14): extracted from
// config.go to reduce its change-risk hotspot footprint. Three
// related types live here:
//
//	ACMEConfig                — the issuer-connector (consumer) side:
//	                            we are a CLIENT talking UP to an ACME
//	                            CA (Let's Encrypt, pebble, step-ca).
//	                            CERTCTL_ACME_* prefix.
//	ACMEServerConfig          — the server-side ACME (RFC 8555 + RFC
//	                            9773) configuration: we ARE the ACME
//	                            server, exposing /acme/profile/<id>/*
//	                            to cert-manager / lego / acme.sh
//	                            clients. CERTCTL_ACME_SERVER_* prefix
//	                            (deliberately distinct from the
//	                            consumer namespace).
//	ACMEServerDirectoryMeta   — the optional `meta` block of the ACME
//	                            directory document, populated from
//	                            CERTCTL_ACME_SERVER_TOS_URL / WEBSITE
//	                            / CAA_IDENTITIES / EAB_REQUIRED.
//
// Every field, doc-comment, and exported name is byte-identical to
// the pre-split form. The structs live in the same `config` package
// so every caller's `config.ACMEConfig` etc. import path is
// preserved without modification.
//
// Public-surface invariant: `go doc internal/config ACMEConfig` and
// `go doc internal/config ACMEServerConfig` produce identical output
// before and after this split.

// ACMEConfig contains ACME issuer connector configuration.
type ACMEConfig struct {
	// DirectoryURL is the ACME directory URL for certificate issuance.
	// Examples: "https://acme-v02.api.letsencrypt.org/directory" (Let's Encrypt),
	// "https://acme.zerossl.com/v2/DV90" (ZeroSSL), or custom CA directory.
	DirectoryURL string

	// Email is the email address for ACME account registration.
	// Used for certificate expiration notices and account recovery by ACME CA.
	Email string

	// ChallengeType selects the ACME challenge mechanism for domain validation.
	// Valid values: "http-01" (default, requires public HTTP endpoint),
	// "dns-01" (DNS TXT record per renewal), or "dns-persist-01" (standing DNS record).
	// Default: "http-01".
	ChallengeType string

	// DNSPresentScript is the path to a shell script that creates DNS TXT records.
	// Required for dns-01 and dns-persist-01 challenge types.
	// Script receives these environment variables:
	// - CERTCTL_DNS_DOMAIN: domain being validated (e.g., "example.com")
	// - CERTCTL_DNS_FQDN: full record name (e.g., "_acme-challenge.example.com" or "_validation-persist.example.com")
	// - CERTCTL_DNS_VALUE: TXT record value (key authorization digest for dns-01, or issuer domain info for dns-persist-01)
	// - CERTCTL_DNS_TOKEN: ACME challenge token
	// Example: /opt/dns-scripts/add-record.sh
	DNSPresentScript string

	// DNSCleanUpScript is the path to a shell script that removes DNS TXT records.
	// Used only for dns-01 challenges to clean up temporary validation records.
	// Script receives the same environment variables as DNSPresentScript.
	// Leave empty if cleanup is not needed (e.g., dns-persist-01).
	DNSCleanUpScript string

	// DNSPersistIssuerDomain is the issuer domain for dns-persist-01 standing records.
	// Example: "letsencrypt.org" or "zerossl.com". Only used if ChallengeType is "dns-persist-01".
	// The record value becomes: "<issuer_domain>; accounturi=<acme_account_uri>"
	DNSPersistIssuerDomain string

	// Profile selects the ACME certificate profile for newOrder requests.
	// Let's Encrypt supports "tlsserver" (standard TLS) and "shortlived" (6-day certs).
	// Leave empty for the CA's default profile (backward-compatible).
	// Setting: CERTCTL_ACME_PROFILE environment variable.
	Profile string

	// ARIEnabled enables ACME Renewal Information (RFC 9773) support.
	// When enabled, the renewal scheduler queries the CA for suggested renewal windows
	// instead of relying solely on static expiration thresholds.
	// Default: false. Requires a CA that supports ARI (e.g., Let's Encrypt).
	// Setting: CERTCTL_ACME_ARI_ENABLED environment variable.
	ARIEnabled bool

	// Insecure skips TLS certificate verification when connecting to the ACME directory.
	// Only use for testing with self-signed ACME servers like Pebble. Never in production.
	// Setting: CERTCTL_ACME_INSECURE environment variable.
	Insecure bool

	// InsecureAck is the Phase 2 SEC-M4 closure (2026-05-13): when
	// Insecure=true, Validate() refuses to start unless InsecureAck is
	// also true. Pre-Phase-2 the Insecure flag only emitted a boot-time
	// WARN log; this guard converts that to a hard fail-closed gate so
	// the dev-only escape hatch cannot be flipped accidentally in
	// production via a copy-pasted Pebble runbook.
	//
	// Acknowledged (Insecure=true + InsecureAck=true): boot proceeds + WARN logs.
	// Unack'd      (Insecure=true + InsecureAck=false): ErrACMEInsecureWithoutAck.
	// Off          (Insecure=false): InsecureAck is ignored entirely.
	//
	// Setting: CERTCTL_ACME_INSECURE_ACK environment variable.
	InsecureAck bool
}

// ACMEServerConfig is the SERVER-side ACME (RFC 8555 + RFC 9773 ARI)
// configuration. Distinct from ACMEConfig (the consumer-side issuer
// connector that talks UP to Let's Encrypt / pebble). Server uses
// CERTCTL_ACME_SERVER_* prefix throughout to avoid colliding with
// the existing CERTCTL_ACME_* consumer namespace (DIRECTORY_URL /
// PROFILE / CHALLENGE_TYPE / etc.).
//
// Phase 1a wires Enabled / DefaultAuthMode / DefaultProfileID /
// NonceTTL / DirectoryMeta. Order/Authz TTLs + the per-challenge-type
// concurrency caps + DNS01 resolver are reserved fields populated for
// Phases 2/3 — exposing them now keeps the env-var surface stable
// from day one (operators can set CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY
// today; it's a no-op until Phase 3 reads it).
type ACMEServerConfig struct {
	// Enabled is the master toggle. When false, the ACME handler is
	// constructed (so the registry-shape stays stable) but no routes
	// are registered. Operators flip this on after configuring the
	// per-profile auth_mode column on certificate_profiles.
	// Setting: CERTCTL_ACME_SERVER_ENABLED.
	Enabled bool

	// DefaultAuthMode sets the default value of certificate_profiles.acme_auth_mode
	// for NEWLY-created profiles (e.g. via API). Existing profile rows
	// retain whatever value they were created with — per-profile
	// values, once set, override this default. Architecture decision:
	// auth mode is per-profile, not server-wide.
	// Valid: "trust_authenticated" (default) or "challenge".
	// Setting: CERTCTL_ACME_SERVER_DEFAULT_AUTH_MODE.
	DefaultAuthMode string

	// DefaultProfileID, when set, activates the /acme/* shorthand
	// path family — /acme/directory mirrors
	// /acme/profile/<DefaultProfileID>/directory etc. When empty,
	// requests to the shorthand return RFC 7807
	// userActionRequired with a hint pointing at the per-profile
	// path. Single-profile deployments can set this for ergonomic
	// client config; multi-profile deployments leave it empty.
	// Setting: CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID.
	DefaultProfileID string

	// NonceTTL is how long an issued ACME nonce remains valid before
	// the server rejects it as expired. RFC 8555 §6.5.1 allows the
	// server to set any TTL; 5 minutes is the operator-friendly
	// default (clock-skew tolerant without enabling long-replay
	// attacks). Setting: CERTCTL_ACME_SERVER_NONCE_TTL.
	NonceTTL time.Duration

	// OrderTTL is the lifetime of an unfulfilled ACME order. Phase 2
	// reads; Phase 1a reserves the field. Default: 24h.
	// Setting: CERTCTL_ACME_SERVER_ORDER_TTL.
	OrderTTL time.Duration

	// AuthzTTL is the lifetime of an unfulfilled authorization. Phase 2
	// reads; Phase 1a reserves. Default: 24h.
	// Setting: CERTCTL_ACME_SERVER_AUTHZ_TTL.
	AuthzTTL time.Duration

	// HTTP01ConcurrencyMax is the bound on concurrent HTTP-01 validators
	// (semaphore weight). Phase 3 reads; Phase 1a reserves. Default: 10.
	// Setting: CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY.
	HTTP01ConcurrencyMax int

	// DNS01Resolver is the resolver address used by the DNS-01 validator.
	// Phase 3 reads; Phase 1a reserves. Default: "8.8.8.8:53".
	// Setting: CERTCTL_ACME_SERVER_DNS01_RESOLVER.
	DNS01Resolver string

	// DNS01ConcurrencyMax bounds concurrent DNS-01 validators. Default: 10.
	// Setting: CERTCTL_ACME_SERVER_DNS01_CONCURRENCY.
	DNS01ConcurrencyMax int

	// TLSALPN01ConcurrencyMax bounds concurrent TLS-ALPN-01 validators.
	// Default: 10. Setting: CERTCTL_ACME_SERVER_TLSALPN01_CONCURRENCY.
	TLSALPN01ConcurrencyMax int

	// ARIEnabled toggles RFC 9773 ACME Renewal Information surface
	// (the `renewalInfo` directory entry + GET
	// /acme/profile/<id>/renewal-info/<cert-id>). Default: true.
	// Operators wanting Phase-1a-style "directory + nonce + accounts +
	// orders + finalize + challenges only" can flip this off; doing so
	// drops the renewalInfo URL from the directory document so ACME
	// clients fall back to their static renewal scheduler. Phase 4 wires.
	// Setting: CERTCTL_ACME_SERVER_ARI_ENABLED.
	ARIEnabled bool

	// ARIPollInterval is the value the server returns in the Retry-After
	// response header on a 200 ARI response — i.e., the suggested gap
	// between successive ARI polls a client should respect. RFC 9773 §4.2
	// leaves this server-policy. Default: 6h. Tighter intervals (e.g. 1h)
	// suit short-lived certs; looser intervals (24h) suit standard 90-day
	// certs. Setting: CERTCTL_ACME_SERVER_ARI_POLL_INTERVAL.
	ARIPollInterval time.Duration

	// RateLimitOrdersPerHour caps new-order requests per ACME account per
	// rolling hour. 0 disables (no limit). Default: 100. Hits return RFC
	// 7807 + RFC 8555 §6.7 `urn:ietf:params:acme:error:rateLimited` with
	// a Retry-After header. In-memory token-bucket — restart wipes the
	// counter, which is acceptable for orders/hour caps (eventual-
	// consistency anyway). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR.
	RateLimitOrdersPerHour int

	// RateLimitConcurrentOrders caps the number of orders an ACME account
	// can have in pending/ready/processing state simultaneously. 0
	// disables. Default: 5. Same Problem shape as the per-hour limit.
	// Setting: CERTCTL_ACME_SERVER_RATE_LIMIT_CONCURRENT_ORDERS.
	RateLimitConcurrentOrders int

	// RateLimitKeyChangePerHour caps account-key rollovers per account
	// per rolling hour. 0 disables. Default: 5 (rollovers should be rare;
	// a flood is an attack signal). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_KEY_CHANGE_PER_HOUR.
	RateLimitKeyChangePerHour int

	// RateLimitChallengeRespondsPerHour caps challenge-respond requests
	// per challenge per rolling hour. 0 disables. Default: 60 (defends
	// against retry storms from a misbehaving client). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR.
	RateLimitChallengeRespondsPerHour int

	// GCInterval is the tick interval for the ACME GC scheduler loop.
	// On each tick the loop sweeps expired nonces, transitions expired
	// pending authzs to `expired`, transitions expired
	// pending/ready/processing orders to `invalid`, and reaps Phase-2
	// atomicity-window orphans (orders without a linked cert when one
	// should exist). 0 disables the loop entirely. Default: 1m. Setting:
	// CERTCTL_ACME_SERVER_GC_INTERVAL.
	GCInterval time.Duration

	// DirectoryMeta is the optional metadata advertised in the directory
	// document per RFC 8555 §7.1.1.
	DirectoryMeta ACMEServerDirectoryMeta
}

// ACMEServerDirectoryMeta holds the optional fields of the directory
// `meta` block. Each is populated from a CERTCTL_ACME_SERVER_*
// env var; an all-empty struct produces an omitempty-suppressed JSON
// `meta` field on the directory.
type ACMEServerDirectoryMeta struct {
	// TermsOfService is a URL pointing to the operator's ToS document.
	// Setting: CERTCTL_ACME_SERVER_TOS_URL.
	TermsOfService string
	// Website is a URL pointing to the operator's homepage.
	// Setting: CERTCTL_ACME_SERVER_WEBSITE.
	Website string
	// CAAIdentities is the list of CAA-record domain values clients
	// should authorize for this server. Setting:
	// CERTCTL_ACME_SERVER_CAA_IDENTITIES (comma-separated).
	CAAIdentities []string
	// ExternalAccountRequired, when true, signals to clients that
	// new-account requires an EAB token (RFC 8555 §7.3.4). Phase 1a
	// advertises but does not enforce; EAB enforcement is a follow-up.
	// Setting: CERTCTL_ACME_SERVER_EAB_REQUIRED.
	ExternalAccountRequired bool
}
