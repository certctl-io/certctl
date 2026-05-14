// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"strings"
)

// Phase 9 ARCH-M2 closure Sprint 4 (2026-05-14): extracted from
// config.go. Same complexity shape as Sprint 3 (SCEP). Two structs
// AND five unexported helpers move together:
//
//   ESTConfig                — top-level multi-profile EST config
//                              (Enabled + Profiles slice + legacy
//                              single-issuer flat fields kept for
//                              backward compat — fewer trigger
//                              fields than SCEP because EST has no
//                              per-profile RA pair or challenge
//                              password in this hardening-bundle
//                              phase).
//   ESTProfileConfig          — one EST endpoint's configuration
//                              (PathID + IssuerID + ProfileID +
//                              EnrollmentPassword + MTLS gate +
//                              channel-binding requirement +
//                              allowed-auth-modes + rate-limit +
//                              server-keygen gate). Field surface
//                              spans the full RFC 7030 hardening
//                              bundle's per-phase plans (Phases
//                              2-5).
//
//   loadESTProfilesFromEnv     — reads CERTCTL_EST_PROFILES + expands
//                                each name into an ESTProfileConfig
//                                via the indexed env-var family.
//                                Mirrors loadSCEPProfilesFromEnv
//                                exactly.
//   parseAuthModes             — splits a comma-separated env value
//                                into a normalized []string of
//                                auth-mode tokens (lowercased +
//                                trimmed; empty input → nil).
//                                Exercised by
//                                config_est_profiles_test.go which
//                                is in package `config` so the
//                                unexported callable surface is
//                                preserved by the move.
//   mergeESTLegacyIntoProfiles — backward-compat shim: synthesize
//                                Profiles[0] from the legacy
//                                single-issuer fields when Profiles
//                                is empty AND EST is enabled.
//   validESTPathID             — path-segment validator (ASCII
//                                [a-z0-9-], no leading/trailing
//                                hyphen, empty allowed). Kept as a
//                                separate function from
//                                validSCEPPathID so future
//                                EST-specific path constraints
//                                (e.g. RFC 7030 §3.2.2 reserved
//                                segments) can land without
//                                affecting SCEP.
//   validESTAuthMode           — refuses unknown auth-mode tokens at
//                                startup ("mtls" and "basic" are
//                                the valid set in Phase 1; future
//                                phases may add).
//
// All callers stay in config.go and continue to resolve via
// same-package lookup. Specifically:
//   - Load() calls loadESTProfilesFromEnv() during initial cfg.EST
//     construction.
//   - Load() calls mergeESTLegacyIntoProfiles(&cfg.EST) after the
//     initial profile-load.
//   - loadESTProfilesFromEnv() itself calls parseAuthModes() —
//     intra-helper call that stays inside est.go after the move
//     (one less cross-file edge).
//   - Validate() calls validESTPathID(p.PathID) per-profile.
//   - Validate() calls validESTAuthMode(mode) per auth-mode in
//     each profile's AllowedAuthModes slice.
//   - config_est_profiles_test.go (package `config`) directly tests
//     parseAuthModes — that test file isn't touched by the move
//     because parseAuthModes stays in the same package.
//
// The unexported helpers getEnv / getEnvBool / getEnvInt used by
// loadESTProfilesFromEnv also stay in config.go (shared across every
// config family); same-package resolution makes the calls work
// without any import change.
//
// Public-surface invariant: `go doc internal/config ESTConfig` and
// `go doc internal/config ESTProfileConfig` produce identical output
// before and after this split. Unexported helpers are unaffected by
// `go doc`.

// ESTConfig controls the RFC 7030 Enrollment over Secure Transport server.
// EST RFC 7030 hardening master bundle Phase 1: this type was originally a
// flat single-issuer struct. Real enterprise deployments need to expose
// multiple EST endpoints from one certctl instance — corp-laptop CA, IoT
// CA, WiFi/802.1X CA — each with its own issuer + auth modes + URL path
// (/.well-known/est/<pathID>/). The Profiles slice carries that. Existing
// operators see no behavior change: when Profiles is empty AND the legacy
// single-issuer flat fields below are set, ConfigLoad synthesizes a
// single-element Profiles[0] with PathID="" (which maps to the legacy
// /.well-known/est/ root path).
type ESTConfig struct {
	// Enabled controls whether EST endpoints are available for device enrollment.
	// Default: false (EST disabled). Set to true to enable RFC 7030 endpoints
	// under /.well-known/est/ (cacerts, simpleenroll, simplereenroll, csrattrs).
	Enabled bool

	// IssuerID selects which issuer connector processes EST certificate requests.
	// Default: "iss-local". Legacy single-issuer field; merged into Profiles[0]
	// by mergeESTLegacyIntoProfiles when Profiles is empty.
	IssuerID string

	// ProfileID optionally constrains EST enrollments to a specific certificate profile.
	// Legacy single-issuer field; merged into Profiles[0] when applicable.
	ProfileID string

	// Profiles is the multi-endpoint configuration. Each profile gets its own
	// URL path (/.well-known/est/<PathID>/), its own bound issuer, its own auth
	// modes, and its own per-profile policy knobs (rate limit, server-keygen
	// gate, mTLS bundle, RFC 9266 channel-binding requirement). Population
	// sources, in priority order:
	//
	//   1. Explicit list via CERTCTL_EST_PROFILES (e.g. "corp,iot,wifi").
	//   2. Backward-compat shim: when CERTCTL_EST_PROFILES is unset AND the
	//      legacy flat fields above are populated AND Enabled=true, ConfigLoad
	//      synthesizes a single-element Profiles[0] with PathID="" so
	//      /.well-known/est/ continues to route the same way it did
	//      pre-Phase-1.
	//
	// EST RFC 7030 hardening master bundle Phase 1.
	Profiles []ESTProfileConfig
}

// ESTProfileConfig is one EST endpoint's configuration. Each profile is
// bound to one issuer + one optional certctl CertificateProfile + one set
// of per-profile auth modes (mTLS / HTTP Basic / both). Future phases of
// the hardening bundle wire the additional per-profile fields:
//
//   - Phase 2 reads MTLSEnabled + MTLSClientCATrustBundlePath +
//     ChannelBindingRequired to enable the /.well-known/est-mtls/<PathID>
//     sibling route (mirrors SCEP's /scep-mtls/<PathID> from commit e7a3075).
//   - Phase 3 reads EnrollmentPassword + AllowedAuthModes to enforce HTTP
//     Basic auth on the standard /.well-known/est/<PathID>/ route.
//   - Phase 4 reads RateLimitPerPrincipal24h to apply per-CN+source-IP
//     sliding-window rate limiting (mirrors SCEP/Intune's
//     PerDeviceRateLimiter from internal/scep/intune/rate_limit.go).
//   - Phase 5 reads ServerKeygenEnabled to gate the new /serverkeygen
//     endpoint per RFC 7030 §4.4.
//
// Phase 1 (this commit) lays the FIELD CONTRACTS + per-profile Validate()
// gates so an operator who flips MTLSEnabled=true without supplying the
// bundle path gets a loud refuse-to-start error rather than a silent
// no-op. The actual auth/limit/keygen handlers ship in Phases 2-5.
//
// EST RFC 7030 hardening master bundle Phase 1.
type ESTProfileConfig struct {
	// PathID is the URL segment after /.well-known/est/. Empty string maps
	// to the legacy /.well-known/est/ root for backward compatibility (so
	// existing operators with the flat single-issuer config see no URL
	// change). Non-empty values MUST be a single path-safe slug
	// ([a-z0-9-], no slashes); validated at startup by Config.Validate().
	// Multi-profile deployments typically use short tokens like "corp",
	// "iot", "wifi" — the URL becomes /.well-known/est/corp/cacerts,
	// /.well-known/est/iot/simpleenroll, etc.
	PathID string

	// IssuerID selects which issuer connector this profile's enrollments
	// go through. Must reference a configured issuer. Required (Validate
	// refuses empty IssuerID).
	IssuerID string

	// ProfileID optionally constrains enrollments under this PathID to a
	// specific CertificateProfile. Leave empty to allow the issuer's
	// defaults. When non-empty, profile crypto policy (allowed key
	// algorithms, required EKUs, max TTL) is enforced at enrollment time
	// via service.ValidateCSRAgainstProfile.
	ProfileID string

	// EnrollmentPassword is the per-profile shared secret for HTTP Basic
	// auth on the standard /.well-known/est/<PathID>/ route (Phase 3).
	// Empty value means HTTP Basic auth is NOT required for this profile
	// (mTLS-only or anonymous, depending on AllowedAuthModes). Stored only
	// in process memory; never logged. Constant-time comparison via
	// crypto/subtle.ConstantTimeCompare in the handler.
	EnrollmentPassword string

	// MTLSEnabled gates the sibling /.well-known/est-mtls/<PathID>/ route
	// (Phase 2). When true, the route requires a client cert that chains
	// to one of the certs in MTLSClientCATrustBundlePath. The standard
	// /.well-known/est/<PathID>/ route remains application-layer-auth
	// (HTTP Basic password) so existing clients keep working — mTLS is
	// additive, not replacement.
	//
	// Mirrors SCEP's MTLSEnabled (commit e7a3075). Same defense-in-depth
	// rationale: enterprise procurement teams routinely reject 'shared
	// password authentication' as a checkbox-fail regardless of how
	// strong the password is. This flag wires up a sibling route that
	// adds client-cert auth at the handler layer.
	MTLSEnabled bool

	// MTLSClientCATrustBundlePath is the PEM bundle of CA certs that sign
	// the client (device-bootstrap) certs the operator allows to enroll
	// via the mTLS sibling route. Required when MTLSEnabled is true.
	// Validated at startup by cmd/server/main.go's
	// preflightESTMTLSClientCATrustBundle (Phase 2): file exists, parses
	// as PEM, contains ≥1 cert, none expired.
	MTLSClientCATrustBundlePath string

	// ChannelBindingRequired forces the EST mTLS handler (Phase 2) to
	// require RFC 9266 tls-exporter channel binding in the CSR's CMC
	// id-aa-channelBindings attribute. When true, CSRs without the
	// binding are refused with ErrChannelBindingMissing; mismatched
	// bindings refused with ErrChannelBindingMismatch. Defaults true for
	// new-cert-issuance flows (Phase 2 default), false for re-enrollment
	// where the previous-cert presentation is the trust signal. Operators
	// running clients that don't support RFC 9266 (older libest, etc.)
	// can opt out per-profile.
	//
	// EST RFC 7030 hardening master bundle Phase 0 frozen decision 0.2.
	ChannelBindingRequired bool

	// AllowedAuthModes enumerates which application-layer auth modes
	// this profile accepts. Valid entries: "mtls", "basic". Empty slice
	// means no auth required (the unauthenticated default that EST
	// shipped with at v2.0.66; preserved for backward compat — Validate
	// emits a warning log for empty slices to nudge operators toward
	// explicit opt-in). Phase 2 + 3 read this to enforce per-mode
	// requirements; Phase 1 just validates shape.
	//
	// EST RFC 7030 hardening master bundle Phase 0 frozen decision 0.1.
	AllowedAuthModes []string

	// RateLimitPerPrincipal24h caps enrollments per (CSR.Subject.CN,
	// sourceIP) pair in any rolling 24-hour window. Default 0 (Phase 1
	// preserves the unauthenticated/unlimited default to avoid changing
	// production behavior); Phase 4 will wire this against the extracted
	// internal/ratelimit/SlidingWindowLimiter. Negative values are
	// rejected at Validate time as a config typo.
	//
	// EST RFC 7030 hardening master bundle Phase 1 + Phase 4.
	RateLimitPerPrincipal24h int

	// ServerKeygenEnabled gates the /.well-known/est/<PathID>/serverkeygen
	// endpoint (RFC 7030 §4.4) for this profile. When true, the server
	// generates the keypair on behalf of the client and returns both
	// cert + private key (the latter wrapped in CMS EnvelopedData).
	// Default false. Phase 5 wires the handler; Phase 1 lays the gate
	// + the Validate refusal for ServerKeygenEnabled=true without a
	// CertificateProfile that pins AllowedKeyAlgorithms (the server
	// must know what algorithm to generate).
	//
	// EST RFC 7030 hardening master bundle Phase 5.
	ServerKeygenEnabled bool
}

// loadESTProfilesFromEnv reads the indexed CERTCTL_EST_PROFILES env var
// (e.g. "corp,iot,wifi") and expands each name into an ESTProfileConfig
// populated from CERTCTL_EST_PROFILE_<NAME>_*. Returns nil when the
// CERTCTL_EST_PROFILES env var is unset or empty — in that case the
// legacy-shim path (mergeESTLegacyIntoProfiles, called from Load after
// the initial config build) populates Profiles[0] from the flat fields
// if needed.
//
// PathID for each profile is the lowercased trimmed name from the
// CERTCTL_EST_PROFILES list (e.g. "Corp" -> "corp"). Validation that
// the PathID is path-safe ([a-z0-9-]+) lives in Config.Validate() so
// the loader can stay free of error returns.
//
// Mirrors loadSCEPProfilesFromEnv exactly. EST RFC 7030 hardening Phase 1.
func loadESTProfilesFromEnv() []ESTProfileConfig {
	raw := strings.TrimSpace(os.Getenv("CERTCTL_EST_PROFILES"))
	if raw == "" {
		return nil
	}
	names := strings.Split(raw, ",")
	out := make([]ESTProfileConfig, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		// The env-var key is the upper-cased name (CERTCTL_EST_PROFILE_CORP_*),
		// but the URL path segment is the lower-cased name to match the
		// path-safe slug constraint enforced in Validate.
		envName := strings.ToUpper(n)
		pathID := strings.ToLower(n)
		out = append(out, ESTProfileConfig{
			PathID:                      pathID,
			IssuerID:                    getEnv("CERTCTL_EST_PROFILE_"+envName+"_ISSUER_ID", ""),
			ProfileID:                   getEnv("CERTCTL_EST_PROFILE_"+envName+"_PROFILE_ID", ""),
			EnrollmentPassword:          getEnv("CERTCTL_EST_PROFILE_"+envName+"_ENROLLMENT_PASSWORD", ""),
			MTLSEnabled:                 getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_MTLS_ENABLED", false),
			MTLSClientCATrustBundlePath: getEnv("CERTCTL_EST_PROFILE_"+envName+"_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", ""),
			ChannelBindingRequired:      getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_CHANNEL_BINDING_REQUIRED", false),
			AllowedAuthModes:            parseAuthModes(getEnv("CERTCTL_EST_PROFILE_"+envName+"_ALLOWED_AUTH_MODES", "")),
			RateLimitPerPrincipal24h:    getEnvInt("CERTCTL_EST_PROFILE_"+envName+"_RATE_LIMIT_PER_PRINCIPAL_24H", 0),
			ServerKeygenEnabled:         getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_SERVERKEYGEN_ENABLED", false),
		})
	}
	return out
}

// parseAuthModes splits a comma-separated env value into a normalized
// []string of auth-mode tokens. Empty input returns nil (the
// "unauthenticated default" Phase 1 preserves for back-compat). Tokens
// are lowercased + trimmed; unknown tokens are kept as-is so Validate
// can refuse them with a typed error message naming the offending token.
func parseAuthModes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// mergeESTLegacyIntoProfiles is the EST backward-compat shim. When
// Profiles is empty AND the legacy single-issuer fields are populated
// (Enabled=true is the trigger; IssuerID has a non-empty default so it
// can't be the trigger by itself), synthesise a single-element
// Profiles[0] with PathID="" so /.well-known/est/ dispatches identically
// to the pre-Phase-1 deploy. No-op when Profiles is non-empty (the
// operator explicitly opted into the structured form via
// CERTCTL_EST_PROFILES) or when EST is disabled.
//
// EST's legacy single-issuer config has fewer "trigger" fields than
// SCEP's (no per-profile RA pair, no per-profile challenge password —
// both of those land in Phases 2/3 of the hardening bundle). The shim
// triggers whenever EST is enabled, since the operator clearly intends
// to serve EST. This makes the back-compat behavior identical to v2.0.66
// (single /.well-known/est/ root with the operator's chosen issuer).
//
// EST RFC 7030 hardening Phase 1.
func mergeESTLegacyIntoProfiles(c *ESTConfig) {
	if c == nil || !c.Enabled || len(c.Profiles) > 0 {
		return
	}
	c.Profiles = []ESTProfileConfig{{
		PathID:    "", // empty pathID maps to the legacy /.well-known/est/ root
		IssuerID:  c.IssuerID,
		ProfileID: c.ProfileID,
		// No legacy fields exist for EnrollmentPassword, MTLS*, etc. —
		// those land in Phases 2/3. Operators upgrading from v2.0.66 get
		// the same unauthenticated behavior they had before; opting into
		// auth requires moving to the structured CERTCTL_EST_PROFILES
		// form (which Phase 12 docs as the recommended migration path).
	}}
}

// validESTPathID reports whether s is a valid EST profile path segment.
// Same shape as validSCEPPathID — empty string allowed (legacy root),
// otherwise ASCII lowercase letters / digits / hyphens with no
// leading/trailing hyphen. Kept as a separate function (rather than
// generalizing) so that future EST-specific path constraints (e.g. RFC
// 7030 §3.2.2 reserved path segments) can land here without affecting
// SCEP's validator.
//
// EST RFC 7030 hardening Phase 1.
func validESTPathID(s string) bool {
	if s == "" {
		return true // empty maps to legacy /.well-known/est/ root
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validESTAuthMode reports whether mode is one of the documented EST
// auth modes Phase 2 + Phase 3 will dispatch on. Kept here so Validate
// can refuse unknown modes (typos, future modes the binary doesn't yet
// implement) at startup with a clear error rather than at first-request
// with a confusing 401/403.
//
// EST RFC 7030 hardening Phase 1.
func validESTAuthMode(mode string) bool {
	switch mode {
	case "mtls", "basic":
		return true
	}
	return false
}
