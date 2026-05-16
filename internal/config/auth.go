// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Phase 9 ARCH-M2 closure Sprint 5 (2026-05-14): extracted from
// config.go. The largest split so far and the first to move
// EXPORTED helpers — every external importer of
// config.AuthType / config.AuthTypeNone / config.AuthTypeAPIKey /
// config.AuthTypeOIDC / config.ValidAuthTypes / config.ParseNamedAPIKeys
// resolves the same after the move because the package name stays
// `config`. Public-surface invariant is verified by:
//
//   - broader-importer build: cmd/server/main.go + auth_backfill.go
//     reference config.AuthType + config.AuthTypeNone +
//     config.AuthTypeAPIKey + config.AuthTypeOIDC +
//     config.ValidAuthTypes — all compile clean after the move.
//   - internal/auth/middleware.go and internal/api/handler/health.go
//     reference config.AuthType in doc comments + type fields.
//   - go test ./internal/config/... — package tests (including
//     config_test.go which pins "jwt" out of ValidAuthTypes per G-1)
//     stay green.
//
// What lives here
// ===============
// Five types (one ergonomic enum + four config structs):
//
//   NamedAPIKey         — one named API-key entry with optional
//                         admin flag. Used by the authentication
//                         middleware for actor attribution in the
//                         audit trail (M-002 / M-003).
//   AuthType (+ const)  — the discriminator for the API auth
//                         middleware shape, with three named
//                         constants (AuthTypeAPIKey / AuthTypeNone /
//                         AuthTypeOIDC). The G-1 invariant pins
//                         "jwt" OUT of this set forever.
//   AuthConfig          — the top-level authentication configuration
//                         (Type, Secret, NamedKeys, AgentBootstrapToken,
//                         DemoModeAck + TS, OIDC pre-login binding
//                         knobs, embedded Session + Breakglass +
//                         the bootstrap-admin-group surface).
//   SessionConfig       — Auth Bundle 2 Phase 4 session-service
//                         tunables (idle / absolute / signing-key
//                         retention / GC / SameSite / IP+UA bind).
//   BreakglassConfig    — Auth Bundle 2 Phase 7.5 local-password
//                         break-glass tunables (enabled gate +
//                         lockout-threshold / duration / reset).
//
// Two exported helpers (FIRST sprint to move public-API helpers):
//
//   ValidAuthTypes()      — single source of truth for the allowed
//                           CERTCTL_AUTH_TYPE set. Called from:
//                             - cmd/server/main.go (runtime guard)
//                             - the validator below in config.go
//                             - the helm chart template
//                             - the property test in config_test.go
//                                 that pins "jwt" out of the slice.
//   ParseNamedAPIKeys()   — parses the CERTCTL_API_KEYS_NAMED env-var
//                           into a []NamedAPIKey with rotation-aware
//                           duplicate-name handling (L-004 contract).
//
// One unexported helper:
//
//   isValidKeyName()      — alphanumeric + hyphen + underscore
//                           validator for the Name field of
//                           NamedAPIKey. Only called from
//                           ParseNamedAPIKeys (intra-file edge
//                           after the move).
//
// What stayed in config.go
// ========================
// - ErrAgentBootstrapTokenRequired sentinel (top of config.go, in
//   the Phase-2 sentinel block) — tied to Validate()'s behavior,
//   not to AuthConfig's struct shape. Same precedent as Sprint 2's
//   ErrACMEInsecureWithoutAck (which also stayed in config.go).
//   ErrDemoModeAckExpired likewise (same reasoning).
// - The Validate() body that branches on AuthType / DemoModeAck /
//   AgentBootstrapTokenDenyEmpty — cross-cutting validation that
//   stays where the other Validate() branches live.
// - The Load() body that calls ParseNamedAPIKeys() and synthesizes
//   the AuthConfig + SessionConfig + BreakglassConfig zero-values.
// - The shared getEnv / getEnvBool / getEnvInt / getEnvDuration
//   helpers + splitComma + trimSpace (used by ParseNamedAPIKeys),
//   shared across every config family.
//
// Public-surface invariant: go doc internal/config AuthConfig /
// SessionConfig / BreakglassConfig / NamedAPIKey / AuthType /
// AuthTypeAPIKey / AuthTypeNone / AuthTypeOIDC / ValidAuthTypes /
// ParseNamedAPIKeys all produce identical output before and after
// this split.

// NamedAPIKey represents a single named API key with an optional admin flag.
// Named keys allow real actor attribution in the audit trail (M-002) and provide
// the admin-gate basis for privileged endpoints like bulk revocation (M-003).
type NamedAPIKey struct {
	// Name is the identifier for the key (alphanumeric, hyphens, underscores).
	// This value is recorded as the actor on every audit event the key authenticates.
	Name string
	// Key is the raw API-key secret the client presents as `Authorization: Bearer <key>`.
	Key string
	// Admin controls whether the key has admin privileges (bulk revocation, etc.).
	Admin bool
}

// AuthType is the discriminator for the API auth middleware shape. The
// string alias preserves env-var roundtrip (the value flows through getEnv
// as a plain string) while giving us a typed surface for switches and
// validation. Use the named constants below rather than string literals
// so future enum additions/removals are caught at compile time.
//
// G-1 (P1): the pre-G-1 validAuthTypes map literal accepted "jwt" with no
// JWT middleware behind it (silent auth downgrade — the configured type
// was logged as "jwt" but every request routed through the api-key bearer
// middleware regardless). Operators who set CERTCTL_AUTH_TYPE=jwt thought
// they had JWT auth; they didn't. The typed alias + ValidAuthTypes()
// helper make the allowed set the single source of truth across config
// validation, the runtime defense-in-depth switch in main.go, and the
// helm-chart template guard (`certctl.validateAuthType`).
type AuthType string

const (
	// AuthTypeAPIKey routes requests through the api-key bearer middleware.
	// CERTCTL_AUTH_SECRET (or CERTCTL_API_KEYS_NAMED) is required.
	AuthTypeAPIKey AuthType = "api-key"

	// AuthTypeNone disables authentication entirely. Development only —
	// the server logs a loud Warn at startup. Operators who need
	// JWT/OIDC/mTLS run an authenticating gateway (oauth2-proxy / Envoy
	// ext_authz / Traefik ForwardAuth / Pomerium) in front of certctl
	// and set this value on the upstream certctl process. See
	// docs/architecture.md "Authenticating-gateway pattern".
	AuthTypeNone AuthType = "none"

	// AuthTypeOIDC drives the OIDC SSO handler chain (Bundle 2 Phase 5+6).
	// ARCH-002 closure (Sprint 4, 2026-05-16): the Phase-0 runtime guard
	// at cmd/server/main.go that refused to boot on this literal has
	// been relaxed — every prerequisite (session.NewService,
	// oidcsvc.NewService, ChainAuthSessionThenBearer, the OIDC handler
	// routes) ships, so CERTCTL_AUTH_TYPE=oidc is now a fully-supported
	// production auth mode alongside api-key + none.
	//
	// Note: this is the AUTH-TYPE literal value, NOT the JWT alg literal.
	// ID tokens are JWTs internally but the auth-type config string is
	// "oidc". The G-1 closure test (TestValidAuthTypesDoesNotContainJWT)
	// stays passing because "jwt" is never added back to the slice.
	AuthTypeOIDC AuthType = "oidc"
)

// ValidAuthTypes returns the allowed CERTCTL_AUTH_TYPE values. The set is
// intentionally narrow — JWT was accepted pre-G-1 with no middleware
// implementation behind it. Single source of truth referenced by the
// validator below, the runtime guard in cmd/server/main.go, the helm
// chart template (`certctl.validateAuthType`), and the property test in
// config_test.go that pins "jwt" out of the slice forever.
//
// Bundle 2 Phase 0 adds AuthTypeOIDC to the slice. The G-1 invariant
// remains: "jwt" stays out of the allowed set forever; OIDC ID tokens
// are JWTs internally but the auth-type literal is "oidc", so the
// silent-downgrade attack surface that "jwt" represented does not
// regress.
func ValidAuthTypes() []AuthType {
	return []AuthType{AuthTypeAPIKey, AuthTypeNone, AuthTypeOIDC}
}

// IsRuntimeSupportedAuthType reports whether the cmd/server/main.go
// runtime guard accepts this auth-type literal at boot. ARCH-002
// closure (Sprint 4, 2026-05-16): post-fix this returns true for
// every entry in ValidAuthTypes() — the Bundle-2-Phase-0 stale guard
// that exited on AuthTypeOIDC has been relaxed, since the full
// session middleware + OIDC handler chain ships. The helper exists
// as a single source of truth so the test suite can pin the
// invariant `ValidAuthTypes ⊆ runtime-supported` (which protects
// against future drift in either direction).
func IsRuntimeSupportedAuthType(t AuthType) bool {
	switch t {
	case AuthTypeAPIKey, AuthTypeNone, AuthTypeOIDC:
		return true
	default:
		return false
	}
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Type sets the authentication mechanism for the REST API.
	// Valid values: "api-key" (default, production) and "none" (development
	// only — disables authentication on the API and logs a loud Warn at
	// startup). For JWT/OIDC, run an authenticating gateway (oauth2-proxy /
	// Envoy / Traefik ForwardAuth / Pomerium) in front of certctl and set
	// CERTCTL_AUTH_TYPE=none on the upstream — see docs/architecture.md
	// "Authenticating-gateway pattern" and docs/upgrade-to-v2-jwt-removal.md.
	// Setting: CERTCTL_AUTH_TYPE environment variable. Default: "api-key".
	// Use the AuthType constants (AuthTypeAPIKey / AuthTypeNone) for typed
	// comparisons; the field stays `string` to preserve env-var roundtrip
	// shape used by getEnv() and downstream Helm/compose interpolation.
	Type string

	// Secret is the legacy authentication secret (comma-separated API keys).
	// DEPRECATED in favor of NamedKeys — retained for backward compatibility.
	// When NamedKeys is empty and Secret is set, each comma-separated key is
	// registered as a synthesized named key (legacy-key-0, legacy-key-1, ...)
	// with actor attribution defaulting to "legacy-key-<index>".
	// Setting: CERTCTL_AUTH_SECRET environment variable.
	Secret string

	// NamedKeys is the parsed set of named API keys. Populated from
	// CERTCTL_API_KEYS_NAMED via ParseNamedAPIKeys during Load(). When
	// non-empty, this takes precedence over the legacy Secret field.
	// Setting: CERTCTL_API_KEYS_NAMED="name1:key1,name2:key2:admin"
	NamedKeys []NamedAPIKey

	// AgentBootstrapToken is the pre-shared secret enforced on the agent
	// registration endpoint (POST /api/v1/agents). Bundle-5 / Audit H-007 /
	// CWE-306 + CWE-288: pre-Bundle-5, any host with network reach to the
	// server could self-register an agent and start polling for work — no
	// shared secret required. Post-Bundle-5: when this field is non-empty,
	// the registration handler requires `Authorization: Bearer <token>`
	// (constant-time comparison via crypto/subtle.ConstantTimeCompare); 401
	// on missing/wrong/malformed.
	//
	// Backwards compatibility: when empty (the v2.0.x default), the server
	// logs a startup WARN announcing the v2.2.0 deprecation — the field
	// will become required in v2.2.0 and unset will fail-loud — and accepts
	// registrations as today. Existing demo deploys that don't set it keep
	// working through v2.1.x.
	//
	// Generation guidance: `openssl rand -hex 32` (256-bit entropy).
	// Setting: CERTCTL_AGENT_BOOTSTRAP_TOKEN environment variable.
	AgentBootstrapToken string

	// AgentBootstrapTokenDenyEmpty is the staged feature flag for SEC-H1
	// (Phase 2, 2026-05-13). When true AND AgentBootstrapToken is empty,
	// Validate() returns ErrAgentBootstrapTokenRequired and the server
	// refuses to start. Default: false (warn-mode pass-through preserved
	// for backward compatibility with operators on the v2.1.x line).
	// WORKSPACE-ROADMAP.md schedules the default flip to true for the
	// v2.2.0 cut — operators get one upgrade-window to set a real token.
	// Setting: CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY environment variable.
	AgentBootstrapTokenDenyEmpty bool

	// Session holds the Auth Bundle 2 Phase 4 session-service tunables.
	// Defaults are documented on the SessionConfig fields. The session
	// service is wired into cmd/server/main.go alongside the OIDC
	// service in Phase 5; pre-Phase-5 deployments that run with the
	// legacy `api-key` auth type ignore this struct entirely.
	Session SessionConfig

	// TrustedProxies is the comma-separated list of CIDR ranges from
	// which X-Forwarded-For is honored. Empty (default) disables XFF
	// trust entirely — every request's source IP is read from
	// r.RemoteAddr regardless of XFF headers. Audit 2026-05-10 LOW-5
	// closure: pre-fix the audit subsystem trusted any caller-supplied
	// XFF for IP attribution, letting an attacker inject arbitrary IPs
	// into audit rows + session IP-binding. Post-fix XFF is read only
	// when the direct connection's RemoteAddr is in this allowlist.
	// Setting: CERTCTL_TRUSTED_PROXIES (e.g. "10.0.0.0/8,192.168.0.0/16").
	TrustedProxies []string

	// DemoModeAck must be true to allow CERTCTL_AUTH_TYPE=none with a
	// non-loopback listen address. Default false. Audit 2026-05-10
	// HIGH-12 closure: pre-fix, an operator who flipped Type=none
	// "temporarily" or via misconfig exposed admin functions to anyone
	// reachable on port 8443 — the demo-mode synthetic actor
	// `actor-demo-anon` is wired with `AdminKey=true`, so every
	// request was served as a full admin. The control plane is
	// HTTPS-only but a misconfigured ingress / public bind meant
	// unauthenticated full admin. Post-fix: Validate() refuses to
	// start when Type=none AND the listener binds to a non-loopback
	// address (0.0.0.0, ::, or a routable IP) UNLESS the operator
	// also sets DemoModeAck=true to acknowledge the bypass. Production
	// deployments MUST set Type to a real authn type (api-key | oidc).
	// Setting: CERTCTL_DEMO_MODE_ACK environment variable.
	DemoModeAck bool

	// DemoModeAckTS is the unix-epoch timestamp at which DemoModeAck was
	// last acknowledged. Phase 2 SEC-H3 closure (2026-05-13): the sticky
	// DemoModeAck bit now expires after 24h. When DemoModeAck=true,
	// Validate() requires DemoModeAckTS to be set AND parse as a unix
	// epoch within the last demoModeAckMaxAge (24h); otherwise
	// ErrDemoModeAckExpired fires and the server refuses to start.
	//
	// This catches the canonical "demo deployment accidentally
	// promoted to production and forgotten about" failure mode: the
	// container restart that re-loads config now refuses unless the
	// operator re-supplies a fresh timestamp.
	//
	// Setting: CERTCTL_DEMO_MODE_ACK_TS (unix epoch, e.g. `$(date +%s)`).
	// The demo compose helper sets this automatically at compose-up.
	DemoModeAckTS string

	// DemoModeResidualStrict refuses startup when Auth.Type != none
	// and `actor-demo-anon` has residual role grants in actor_roles.
	// Default false (emit WARN log + audit row instead). Audit
	// 2026-05-11 A-8 closure — closes the deferred Phase 2 leg of
	// HIGH-12 (cowork/auth-bundles-fixes-2026-05-10/11-high-12-...).
	//
	// Note: migration 000029 unconditionally seeds the
	// `ar-demo-anon-admin` grant of `r-admin` to `actor-demo-anon`
	// for every install, so production deploys will see this WARN
	// out of the box. The intended workflow at production cutover is:
	//   1. POST /api/v1/auth/demo-residual/cleanup (or run the
	//      DELETE FROM actor_roles WHERE actor_id='actor-demo-anon'
	//      SQL emitted by the WARN).
	//   2. Optionally set this flag for subsequent boots to refuse
	//      startup if the rows somehow get re-seeded.
	//
	// Setting: CERTCTL_DEMO_MODE_RESIDUAL_STRICT environment variable.
	DemoModeResidualStrict bool

	// OIDCBCLMaxAgeSeconds is the iat-freshness skew window for OIDC
	// back-channel-logout tokens. logout_tokens with iat outside the
	// window are rejected with audit outcome=iat_stale (in the past)
	// or iat_future (in the future). Audit 2026-05-10 HIGH-3 closure.
	// Default 60s matches the ID-token skew tolerance in
	// internal/auth/oidc/service.go. Range: 10-300; values outside
	// this window indicate IdP clock misconfiguration that warrants
	// operator attention.
	// Setting: CERTCTL_OIDC_BCL_MAX_AGE_SECONDS environment variable.
	OIDCBCLMaxAgeSeconds int

	// OIDCPreLoginRequireUA enables the RFC 9700 §4.7.1 user-agent
	// binding check on /auth/oidc/callback. Audit 2026-05-10 MED-16.
	// Default true. Operators on enterprise proxies that rewrite the
	// UA header set this false; the binding value is still persisted
	// + audited even when enforcement is off so retroactive forensics
	// remain possible.
	// Setting: CERTCTL_OIDC_PRELOGIN_REQUIRE_UA environment variable.
	OIDCPreLoginRequireUA bool

	// OIDCPreLoginRequireIP enables the RFC 9700 §4.7.1 source-IP
	// binding check on /auth/oidc/callback. Audit 2026-05-10 MED-16.
	// Default true. Operators on dual-stack v4/v6 or mobile
	// carrier-grade NAT where source IP routinely flips set this
	// false; persistence + audit behave the same as UA above.
	// Setting: CERTCTL_OIDC_PRELOGIN_REQUIRE_IP environment variable.
	OIDCPreLoginRequireIP bool

	// Breakglass holds the Auth Bundle 2 Phase 7.5 break-glass admin
	// tunables. Default-OFF; the entire surface is invisible (404
	// instead of 403) when CERTCTL_BREAKGLASS_ENABLED is not true.
	// Threat model: enabling break-glass is a deliberate bypass of
	// the SSO security boundary; operators turn it on during SSO
	// incidents and turn it off after recovery.
	Breakglass BreakglassConfig

	// BootstrapAdminGroups is the comma-separated list of IdP group
	// names that grant the FIRST OIDC-authenticated user the r-admin
	// role. Auth Bundle 2 Phase 7 / Decision 3. Empty (default)
	// disables the OIDC-first-admin bootstrap path; the env-var-token
	// path (BootstrapToken below) remains the fallback for fresh
	// deployments without OIDC. When both are configured, OIDC wins
	// on group match.
	// Setting: CERTCTL_BOOTSTRAP_ADMIN_GROUPS environment variable.
	BootstrapAdminGroups []string

	// BootstrapOIDCProviderID restricts the OIDC-first-admin bootstrap
	// path to a specific provider id (matches the seeded provider
	// name in oidc_providers.id). Empty (default) accepts a match
	// from any configured provider. Useful when an operator
	// configures multiple IdPs and wants only the corporate IdP to
	// be eligible for bootstrap.
	// Setting: CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID environment variable.
	BootstrapOIDCProviderID string

	// BootstrapToken is the one-shot pre-shared secret that gates the
	// Bundle 1 Phase 6 bootstrap endpoint (POST /v1/auth/bootstrap). When
	// set at server startup AND no admin-roled actors exist, the
	// bootstrap endpoint becomes callable: an operator POSTs the token
	// and a desired admin-key name; the server mints a fresh API key,
	// grants it the r-admin role, and returns the key value once. The
	// token is then invalidated in memory; subsequent calls return 410
	// Gone. The endpoint also returns 410 Gone when admin actors already
	// exist (no need for the bootstrap path).
	//
	// Server NEVER logs this token. The minted admin key is returned in
	// the HTTP response body only; not logged. Operators who lose track
	// of the minted key can rotate it via the regular RBAC API after
	// bootstrap.
	//
	// Generation guidance: `openssl rand -hex 32` (256-bit entropy).
	// Setting: CERTCTL_BOOTSTRAP_TOKEN environment variable.
	BootstrapToken string
}

// SessionConfig contains the Auth Bundle 2 Phase 4 session-service
// tunables. Every field is operator-overridable via the documented
// CERTCTL_SESSION_* env var; defaults are the conservative values from
// the Phase 4 spec.
//
// Bundle 2 Phase 4 / OWASP ASVS V3 (Session Management). The defaults
// (1h idle / 8h absolute / 24h key retention / 1h GC / Lax cookies /
// no IP-or-UA bind) are the conservative starting point that matches
// the prompt; tightening to Strict + IP/UA bind suits high-security
// environments at the cost of breaking inbound deep-links from external
// apps and login-from-mobile-on-cellular flows.
type SessionConfig struct {
	// IdleTimeout: maximum time between authenticated requests on a
	// session before re-auth is required. Default 1h. Wire:
	// CERTCTL_SESSION_IDLE_TIMEOUT.
	IdleTimeout time.Duration

	// AbsoluteTimeout: maximum lifetime of a session regardless of
	// activity. Default 8h. Wire: CERTCTL_SESSION_ABSOLUTE_TIMEOUT.
	AbsoluteTimeout time.Duration

	// SigningKeyRetention: time a retired signing key stays valid for
	// verification before being purged from the keys table. Default
	// 24h. Wire: CERTCTL_SESSION_SIGNING_KEY_RETENTION.
	SigningKeyRetention time.Duration

	// GCInterval: scheduler tick interval for the session-GC sweep.
	// Default 1h. Wire: CERTCTL_SESSION_GC_INTERVAL.
	GCInterval time.Duration

	// SameSite: SameSite cookie attribute. Valid values: "Lax"
	// (default) or "Strict". Strict is recommended for high-security
	// environments at the cost of breaking inbound deep-links from
	// external apps. Wire: CERTCTL_SESSION_SAMESITE.
	SameSite string

	// BindIP: when true, the session middleware compares the request's
	// client IP to the session row's recorded IP on every Validate.
	// Mismatch -> 401, audit row, session NOT auto-revoked (user may
	// have legitimate IP change). Default false. Wire:
	// CERTCTL_SESSION_BIND_IP.
	BindIP bool

	// BindUserAgent: when true, the session middleware compares the
	// request's User-Agent to the session row's recorded UA on every
	// Validate. Default false; useful only in tightly-controlled
	// environments. Wire: CERTCTL_SESSION_BIND_USER_AGENT.
	BindUserAgent bool
}

// BreakglassConfig contains the Auth Bundle 2 Phase 7.5 break-glass
// admin tunables. Decision 4: operator-toggleable local-password
// admin for the SSO-broken case. Default-OFF; the entire surface is
// invisible (404 NOT 403) when Enabled=false.
//
// Threat model (load-bearing): enabling break-glass is a deliberate
// bypass of the SSO security boundary. An attacker who phishes the
// password OR finds it in a compromised password manager bypasses
// MFA, OIDC, and every group-claim gate. Recommendation: keep
// CERTCTL_BREAKGLASS_ENABLED=false in steady-state. Enable only
// during SSO-broken incidents. Disable after recovery. WebAuthn
// pairing (v3 per Decision 12) is the load-bearing second factor.
type BreakglassConfig struct {
	// Enabled gates the entire service surface. Default false.
	// Wire: CERTCTL_BREAKGLASS_ENABLED.
	Enabled bool

	// LockoutThreshold is the failure count that trips the lockout.
	// Default 5. Wire: CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD.
	LockoutThreshold int

	// LockoutDuration is how long the account stays locked after the
	// threshold trips. Default 15m.
	// Wire: CERTCTL_BREAKGLASS_LOCKOUT_DURATION.
	LockoutDuration time.Duration

	// LockoutResetInterval is the idle time after last_failure_at
	// before the failure counter resets to 0 on next attempt.
	// Default 1h. Wire: CERTCTL_BREAKGLASS_LOCKOUT_RESET_INTERVAL.
	LockoutResetInterval time.Duration
}

// ParseNamedAPIKeys parses the CERTCTL_API_KEYS_NAMED environment variable.
// Format: "name1:key1,name2:key2:admin,name3:key3"
// The ":admin" suffix is optional; if present, the key has admin privileges.
// Returns a typed []NamedAPIKey so main.go can pass it directly to the
// middleware layer without type assertion gymnastics.
//
// Audit L-004 (CWE-924) — graceful key rotation contract:
//
//	Two entries MAY share the same Name during a rotation overlap window:
//	    CERTCTL_API_KEYS_NAMED="alice:OLDKEY:admin,alice:NEWKEY:admin"
//	When duplicates appear, both keys validate at the auth middleware
//	(NewAuthWithNamedKeys iterates every entry on every request, so the
//	match is by hash regardless of name collisions). Both produce the
//	same UserKey context value (the shared name), which keeps the audit
//	trail and per-user rate-limit bucket (Bundle B M-025) consistent
//	across the rollover.
//
//	The duplicate-name path is restricted: every entry sharing a name
//	MUST carry the same admin flag — mixing admin=true with admin=false
//	under the same identity would let a non-admin caller present the
//	admin-flagged key and bypass the gate (or vice-versa). The contract
//	is "rotate ONE key at a time"; the privilege level stays constant
//	within the overlap window.
//
//	Exact (name,key) duplicates are still rejected — that's a typo,
//	not a rotation. Rotation requires DIFFERENT keys under the same
//	name.
//
//	Once the rollover is complete, the operator removes the OLDKEY
//	entry and restarts. Single-entry steady state resumes.
//
//	See docs/security.md::API key rotation for the full operator runbook.
func ParseNamedAPIKeys(input string) ([]NamedAPIKey, error) {
	if input == "" {
		return nil, nil
	}

	parts := splitComma(input)
	var keys []NamedAPIKey
	// nameToAdmin pins the admin flag for any name we've seen before; it
	// is consulted on subsequent duplicate-name entries to enforce the
	// "matching admin" contract above.
	nameToAdmin := make(map[string]bool)
	// nameSeen records whether we've seen a name at all (used to
	// distinguish first-occurrence from duplicate-occurrence; we need
	// this separate from nameToAdmin because admin=false is a valid
	// recorded state).
	nameSeen := make(map[string]bool)
	// pairSeen rejects exact (name,key) duplicates as typos.
	pairSeen := make(map[string]bool)

	for _, part := range parts {
		part = trimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon: name:key or name:key:admin
		fields := strings.Split(part, ":")
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("invalid named key format: %s (expected name:key or name:key:admin)", part)
		}

		name := trimSpace(fields[0])
		key := trimSpace(fields[1])
		admin := false

		if len(fields) == 3 {
			adminStr := trimSpace(fields[2])
			if adminStr == "admin" {
				admin = true
			} else {
				return nil, fmt.Errorf("invalid admin flag: %s (expected 'admin')", adminStr)
			}
		}

		// Validate name format: alphanumeric, hyphens, underscores
		if !isValidKeyName(name) {
			return nil, fmt.Errorf("invalid key name: %s (must be alphanumeric, hyphens, underscores)", name)
		}

		if key == "" {
			return nil, fmt.Errorf("empty key for name: %s", name)
		}

		// Typo guard: same (name,key) pair twice is never legitimate —
		// rotation requires DIFFERENT keys under the same name.
		pairKey := name + "\x00" + key
		if pairSeen[pairKey] {
			return nil, fmt.Errorf("duplicate (name,key) entry for name %q — rotation requires DIFFERENT keys under the same name", name)
		}
		pairSeen[pairKey] = true

		// Duplicate-name path: allowed iff admin flag matches the prior
		// entry for the same name (L-004 rotation overlap contract).
		if nameSeen[name] {
			priorAdmin := nameToAdmin[name]
			if priorAdmin != admin {
				return nil, fmt.Errorf("duplicate key name %q with mismatched admin flag — rotation overlap requires both entries carry the same privilege level (prior=%v, this=%v)", name, priorAdmin, admin)
			}
		} else {
			nameSeen[name] = true
			nameToAdmin[name] = admin
		}

		keys = append(keys, NamedAPIKey{
			Name:  name,
			Key:   key,
			Admin: admin,
		})
	}

	// Rotation-window observability: emit a one-shot startup INFO log
	// per name with multiple entries so operators can see the active
	// overlap state in logs. (Single-entry steady state stays silent.)
	nameCounts := make(map[string]int)
	for _, k := range keys {
		nameCounts[k.Name]++
	}
	for name, count := range nameCounts {
		if count > 1 {
			slog.Info("api-key rotation window active",
				"name", name,
				"entries", count,
				"see", "docs/security.md::api-key-rotation",
			)
		}
	}

	return keys, nil
}

// isValidKeyName checks if a key name is valid (alphanumeric, hyphens, underscores).
func isValidKeyName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
