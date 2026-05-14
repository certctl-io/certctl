// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"strings"
	"time"
)

// Phase 9 ARCH-M2 closure Sprint 3 (2026-05-14): extracted from
// config.go. Larger and more complex than Sprints 1+2 because the
// SCEP surface has THREE structs AND three helper functions that
// move together:
//
//   SCEPConfig                — top-level multi-profile config
//                               (Enabled + Profiles slice + the
//                               legacy single-profile flat fields
//                               kept for backward compat).
//   SCEPProfileConfig         — one SCEP endpoint's binding
//                               (PathID + IssuerID + ProfileID +
//                               ChallengePassword + RA cert/key +
//                               mTLS sibling-route gate + per-
//                               profile Intune block).
//   SCEPIntuneProfileConfig   — per-profile Microsoft Intune
//                               Certificate Connector integration
//                               (Enabled, ConnectorCertPath,
//                               Audience, ChallengeValidity,
//                               PerDeviceRateLimit24h,
//                               ClockSkewTolerance).
//
//   loadSCEPProfilesFromEnv     — reads CERTCTL_SCEP_PROFILES +
//                                 expands each name into a
//                                 SCEPProfileConfig via the
//                                 CERTCTL_SCEP_PROFILE_<NAME>_*
//                                 indexed env-var family.
//   mergeSCEPLegacyIntoProfiles — backward-compat shim: when
//                                 Profiles is empty AND legacy flat
//                                 fields are populated, synthesize
//                                 Profiles[0] with PathID="" so
//                                 /scep dispatches as it did
//                                 pre-Phase-1.5.
//   validSCEPPathID             — path-segment validator (ASCII
//                                 [a-z0-9-], no leading/trailing
//                                 hyphen, empty allowed). Called
//                                 from Config.Validate() in
//                                 config.go.
//
// All callers stay in config.go and continue to resolve via
// same-package lookup. Specifically:
//   - Load() calls loadSCEPProfilesFromEnv() during initial cfg.SCEP
//     construction (currently config.go's Load body)
//   - Load() calls mergeSCEPLegacyIntoProfiles(&cfg.SCEP) after the
//     initial profile-load
//   - Validate() calls validSCEPPathID(p.PathID) per-profile
//
// The unexported helpers getEnv / getEnvBool / getEnvInt /
// getEnvDuration used by loadSCEPProfilesFromEnv also stay in
// config.go (shared across every config family); same-package
// resolution makes the calls work without any import change.
//
// Public-surface invariant: `go doc internal/config SCEPConfig`,
// `go doc internal/config SCEPProfileConfig`, and
// `go doc internal/config SCEPIntuneProfileConfig` produce
// identical output before and after this split. Unexported helpers
// are unaffected by `go doc` (which only shows the exported
// surface).

// SCEPConfig controls the RFC 8894 Simple Certificate Enrollment Protocol server.
//
// SCEP RFC 8894 + Intune master bundle Phase 1.5: this type was originally a
// single flat struct with one IssuerID + one RA pair + one challenge password
// (the shape of v2.0.x). Real enterprise deployments need to expose multiple
// SCEP endpoints from one certctl instance — corp-laptop CA, server CA, IoT
// CA — each with its own issuer + RA pair + challenge password + URL path
// (/scep/<pathID>). The Profiles slice carries that. Existing operators see
// no behavior change: when Profiles is empty AND the legacy single-profile
// fields below are set, ConfigLoad synthesizes a single-element Profiles[0]
// with PathID="" (which maps to the legacy /scep root path).
type SCEPConfig struct {
	// Enabled controls whether SCEP endpoints are available for device enrollment.
	// Default: false (SCEP disabled). Set to true to enable SCEP endpoints under /scep/.
	Enabled bool

	// Profiles is the multi-endpoint configuration. Each profile gets its own
	// URL path (/scep/<PathID>), its own RA cert + key, its own challenge
	// password, and its own bound issuer. Population sources, in priority order:
	//
	//   1. Explicit list via CERTCTL_SCEP_PROFILES (e.g. "corp,iot,server").
	//   2. Backward-compat shim: when CERTCTL_SCEP_PROFILES is unset AND the
	//      legacy flat fields below have ChallengePassword OR RACertPath set,
	//      ConfigLoad synthesizes a single-element Profiles[0] with PathID=""
	//      so /scep continues to route the same way it did pre-Phase-1.5.
	//
	// Validate() iterates Profiles and refuses to boot if any profile is
	// malformed (empty ChallengePassword, missing RA pair, invalid PathID).
	// Each profile's ChallengePassword + RA pair are independently mandatory
	// — the profile-load shim never silently borrows from a sibling profile.
	Profiles []SCEPProfileConfig

	// Legacy single-profile fields — preserved for backward compatibility. New
	// operators should populate Profiles directly via the indexed env-var form.
	// These fields are merged into Profiles[0] by ConfigLoad when Profiles is
	// empty AND any of these fields are non-zero.

	// IssuerID selects which issuer connector processes SCEP certificate requests
	// for the legacy single-profile config. Default: "iss-local". Must reference a
	// configured issuer.
	IssuerID string

	// ProfileID optionally constrains SCEP enrollments to a specific certificate profile
	// for the legacy single-profile config. Leave empty to allow SCEP to use any
	// configured issuer's defaults.
	ProfileID string

	// ChallengePassword is the shared secret used to authenticate SCEP enrollment requests.
	// Clients include this in the PKCS#10 CSR challengePassword attribute.
	//
	// REQUIRED when Enabled is true. Config.Validate() below refuses to start the
	// server if SCEP is enabled and this value is empty (H-2, CWE-306): post-M-001
	// under option (D), the /scep endpoint rides the no-auth middleware chain per
	// RFC 8894 §3.2, so the challenge password is the sole application-layer
	// authentication boundary for SCEP enrollment. An empty shared secret would
	// allow any client that can reach /scep to enroll a CSR against the configured
	// issuer. The service-layer PKCSReq path also rejects this configuration
	// defense-in-depth.
	//
	// Legacy single-profile field; merged into Profiles[0].ChallengePassword by
	// ConfigLoad when Profiles is empty.
	ChallengePassword string

	// RACertPath is the path to a PEM-encoded RA (Registration Authority)
	// certificate used by the RFC 8894 SCEP path. SCEP clients encrypt their
	// PKCS#10 CSR to this cert's public key (via the EnvelopedData wrapper, RFC
	// 8894 §3.2.2). The certctl server uses RAKeyPath to decrypt inbound
	// EnvelopedData and to sign outbound CertRep PKIMessage signerInfo (RFC
	// 8894 §3.3.2).
	//
	// Required when Enabled is true; Config.Validate() refuses to start without
	// it. Without an RA pair the new RFC 8894 path silently falls through to
	// the MVP raw-CSR path on every request and the operator's intent is
	// unclear — fail loud at startup instead.
	//
	// Generation: a self-signed RA cert with subject "CN=<your-ca-id>-RA" and
	// the id-kp-emailProtection / id-kp-cmcRA EKU is sufficient. The RA cert
	// SHOULD be the same cert returned by GetCACert (RFC 8894 §3.5.1) so
	// clients encrypt to a key the server can decrypt with. See
	// docs/legacy-est-scep.md for the openssl recipe.
	RACertPath string

	// RAKeyPath is the path to the PEM-encoded private key matching RACertPath.
	// File MUST be mode 0600 (owner read/write only); preflight refuses to load
	// a world-readable RA key as defense-in-depth against credential leak. The
	// server only ever reads this file at startup; rotation requires a restart
	// (per the existing CERTCTL_TLS_CERT_PATH precedent in cmd/server/tls.go).
	//
	// Legacy single-profile field; merged into Profiles[0].RAKeyPath by
	// ConfigLoad when Profiles is empty.
	RAKeyPath string
}

// SCEPProfileConfig is one SCEP endpoint's configuration. Each profile is
// bound to one issuer + one optional certctl CertificateProfile + one RA
// pair + one challenge password (the per-profile Intune trust anchor lands
// here in Phase 8 of the master bundle).
//
// Multi-profile motivation: a real enterprise deployment exposes distinct
// SCEP endpoints to distinct fleets — corp-laptop CA bound to one issuer
// with one challenge password; IoT CA bound to a different issuer with a
// different challenge password — so a single set of credentials can never
// enroll across CA boundaries by accident. Each SCEPProfileConfig drives
// a separate handler + service instance built at server startup.
type SCEPProfileConfig struct {
	// PathID is the URL segment after /scep/. Empty string maps to the legacy
	// /scep root for backward compatibility (so existing operators with the
	// flat single-profile config see no URL change). Non-empty values MUST
	// be a single path-safe slug ([a-z0-9-], no slashes); validated at
	// startup by Config.Validate(). Multi-profile deployments typically use
	// short tokens like "corp", "iot", "server" — the URL becomes
	// /scep/corp, /scep/iot, /scep/server.
	PathID string

	// IssuerID selects which issuer connector this profile's enrollments go
	// through. Must reference a configured issuer.
	IssuerID string

	// ProfileID optionally constrains enrollments under this PathID to a
	// specific CertificateProfile. Leave empty to allow the issuer's defaults.
	ProfileID string

	// ChallengePassword is the per-profile shared secret. Same constant-time
	// compare semantics as the flat field; empty value at validate time fails
	// the boot.
	ChallengePassword string

	// RACertPath / RAKeyPath are the per-profile RA pair used by the RFC 8894
	// EnvelopedData decryption + CertRep signing path. Same preflight semantics
	// as the legacy flat fields (file existence, key mode 0600, cert/key
	// match, expiry, RSA-or-ECDSA alg).
	RACertPath string
	RAKeyPath  string

	// MTLSEnabled gates the sibling `/scep-mtls/<PathID>` route. When true,
	// the route requires a client cert that chains to one of the certs in
	// MTLSClientCATrustBundlePath. The standard `/scep[/<PathID>]` route
	// remains application-layer-auth (challenge password) so existing
	// clients keep working — mTLS is additive, not replacement.
	//
	// SCEP RFC 8894 + Intune master bundle Phase 6.5: enterprise procurement
	// teams routinely reject 'shared password authentication' as a checkbox-
	// fail regardless of how strong the password is. This flag wires up a
	// sibling route that adds client-cert auth at the handler layer AND keeps
	// the challenge password (defense in depth, not replacement). Devices
	// present a bootstrap cert from a trusted CA (e.g. a manufacturing-time
	// cert), then SCEP-enroll for their long-lived cert. Same model Apple's
	// MDM and Cisco's BRSKI use.
	MTLSEnabled bool

	// MTLSClientCATrustBundlePath is the PEM bundle of CA certs that sign
	// the client (device-bootstrap) certs the operator allows to enroll.
	// Required when MTLSEnabled is true. Operators with multiple bootstrap
	// CAs concatenate them. Validated at startup by
	// `cmd/server/main.go::preflightSCEPMTLSTrustBundle` — file exists,
	// parses as PEM, contains ≥1 cert, none expired.
	MTLSClientCATrustBundlePath string

	// Intune is the per-profile Microsoft Intune Certificate Connector
	// integration block. When Enabled is false (default), this profile only
	// honors the static ChallengePassword; when true, requests with an
	// Intune-shaped challenge password (length + dot-count heuristic) are
	// routed to the Intune dynamic-challenge validator.
	//
	// SCEP RFC 8894 + Intune master bundle Phase 8.8: per-profile dispatch
	// is what makes the heterogeneous-fleet story work — an operator
	// running corp-laptops via Intune AND IoT devices via static challenge
	// configures Intune-mode on the corp profile only; the IoT profile's
	// PKCSReq path skips the Intune dispatcher entirely.
	Intune SCEPIntuneProfileConfig
}

// SCEPIntuneProfileConfig is the per-profile Microsoft Intune Certificate
// Connector integration sub-block on SCEPProfileConfig.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.1.
//
// All fields here are populated from CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_*
// env vars (e.g. CERTCTL_SCEP_PROFILE_CORP_INTUNE_ENABLED=true). Per-profile
// overrides means an operator with two Intune-backed profiles (corp + iot,
// say) can pin distinct Connectors + audiences + rate limits per fleet.
type SCEPIntuneProfileConfig struct {
	// Enabled gates the Intune dynamic-challenge validation path. When
	// false (default), this profile honors only the static ChallengePassword.
	// When true, ConnectorCertPath becomes a required boot gate.
	Enabled bool

	// ConnectorCertPath is the filesystem path to a PEM bundle of one or
	// more Microsoft Intune Certificate Connector signing certs. Required
	// when Enabled=true. Reloaded on SIGHUP via the per-profile
	// TrustAnchorHolder wired in cmd/server/main.go.
	ConnectorCertPath string

	// Audience is the expected "aud" claim value in the Intune challenge —
	// typically the public SCEP endpoint URL the Connector is configured to
	// call (e.g. "https://certctl.example.com/scep/corp"). Defaults to
	// empty (audience check disabled) for proxy / load-balancer scenarios
	// where the URL the Connector saw isn't the URL we see; operators
	// who pin a public URL here gain defense-in-depth against challenge
	// re-use across endpoints.
	Audience string

	// ChallengeValidity caps the maximum age of an Intune challenge, on
	// top of the challenge's own iat/exp claims. Default 60 minutes per
	// Microsoft's published Connector defaults — operators may want a
	// stricter cap to reduce the replay-window exposure on a stolen
	// challenge. Zero means "use Connector's exp claim only" (no extra cap).
	ChallengeValidity time.Duration

	// PerDeviceRateLimit24h caps the number of enrollments per
	// (claim.Subject, claim.Issuer) pair in any rolling 24-hour window.
	// Default 3 (covers legitimate first-cert + recovery + post-wipe
	// re-enrollment, blocks bulk-enumeration from a compromised Connector
	// signing key). Zero means "unlimited" (defense-in-depth disabled;
	// not recommended for production).
	PerDeviceRateLimit24h int

	// ClockSkewTolerance widens the iat/exp validation window by
	// ±|tolerance| to absorb modest clock drift between the Microsoft
	// Intune Certificate Connector and the certctl host. Default 60s
	// per master prompt §15 ("known hazards"). Operators on tightly
	// time-synced fleets can set this to zero to enforce strict
	// iat/exp checks; operators on loosely synced fleets (e.g. field
	// devices with no NTP) may raise to 5m. Validate() refuses any
	// tolerance ≥ ChallengeValidity (which would make the per-profile
	// validity cap meaningless). Source env var:
	// CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CLOCK_SKEW_TOLERANCE.
	ClockSkewTolerance time.Duration
}

// loadSCEPProfilesFromEnv reads the indexed CERTCTL_SCEP_PROFILES env var
// (e.g. "corp,iot,server") and expands each name into a SCEPProfileConfig
// populated from CERTCTL_SCEP_PROFILE_<NAME>_*. Returns nil when the
// CERTCTL_SCEP_PROFILES env var is unset or empty — in that case the
// legacy-shim path (mergeSCEPLegacyIntoProfiles, called from Load after the
// initial config build) populates Profiles[0] from the flat fields if needed.
//
// PathID for each profile is the lowercased trimmed name from the
// CERTCTL_SCEP_PROFILES list (e.g. "Corp" -> "corp"). Validation that the
// PathID is path-safe ([a-z0-9-]+) lives in Config.Validate() so the loader
// can stay free of error returns.
func loadSCEPProfilesFromEnv() []SCEPProfileConfig {
	raw := strings.TrimSpace(os.Getenv("CERTCTL_SCEP_PROFILES"))
	if raw == "" {
		return nil
	}
	names := strings.Split(raw, ",")
	out := make([]SCEPProfileConfig, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		// The env-var key is the upper-cased name (CERTCTL_SCEP_PROFILE_CORP_*),
		// but the URL path segment is the lower-cased name to match the
		// path-safe slug constraint enforced in Validate.
		envName := strings.ToUpper(n)
		pathID := strings.ToLower(n)
		out = append(out, SCEPProfileConfig{
			PathID:            pathID,
			IssuerID:          getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_ISSUER_ID", ""),
			ProfileID:         getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_PROFILE_ID", ""),
			ChallengePassword: getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_CHALLENGE_PASSWORD", ""),
			RACertPath:        getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_RA_CERT_PATH", ""),
			RAKeyPath:         getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_RA_KEY_PATH", ""),
			// SCEP RFC 8894 Phase 6.5: opt-in mTLS sibling route.
			MTLSEnabled:                 getEnvBool("CERTCTL_SCEP_PROFILE_"+envName+"_MTLS_ENABLED", false),
			MTLSClientCATrustBundlePath: getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", ""),
			// SCEP RFC 8894 Phase 8.1: per-profile Intune Connector dispatch.
			Intune: SCEPIntuneProfileConfig{
				Enabled:               getEnvBool("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_ENABLED", false),
				ConnectorCertPath:     getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CONNECTOR_CERT_PATH", ""),
				Audience:              getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_AUDIENCE", ""),
				ChallengeValidity:     getEnvDuration("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CHALLENGE_VALIDITY", 60*time.Minute),
				PerDeviceRateLimit24h: getEnvInt("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_PER_DEVICE_RATE_LIMIT_24H", 3),
				ClockSkewTolerance:    getEnvDuration("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CLOCK_SKEW_TOLERANCE", 60*time.Second),
			},
		})
	}
	return out
}

// mergeSCEPLegacyIntoProfiles is the backward-compat shim. When Profiles is
// empty AND any legacy single-profile field is populated, synthesise a
// single-element Profiles[0] with PathID="" so /scep dispatches identically
// to the pre-Phase-1.5 deploy. No-op when Profiles is non-empty (the operator
// explicitly opted into the structured form via CERTCTL_SCEP_PROFILES) or
// when SCEP is disabled.
//
// "Any legacy field populated" means at least one of ChallengePassword,
// RACertPath, RAKeyPath is non-empty. IssuerID has a non-empty default
// ("iss-local") so it can't be the trigger; ProfileID is optional. The
// trigger set matches what the Validate() refuse cares about.
func mergeSCEPLegacyIntoProfiles(c *SCEPConfig) {
	if c == nil || !c.Enabled || len(c.Profiles) > 0 {
		return
	}
	hasLegacy := c.ChallengePassword != "" || c.RACertPath != "" || c.RAKeyPath != ""
	if !hasLegacy {
		return
	}
	c.Profiles = []SCEPProfileConfig{{
		PathID:            "", // empty pathID maps to the legacy /scep root
		IssuerID:          c.IssuerID,
		ProfileID:         c.ProfileID,
		ChallengePassword: c.ChallengePassword,
		RACertPath:        c.RACertPath,
		RAKeyPath:         c.RAKeyPath,
	}}
}

// validSCEPPathID reports whether s is a valid SCEP profile path segment.
// The empty string is allowed (legacy root /scep). Non-empty values must
// be ASCII lowercase letters / digits / hyphens with no leading/trailing
// hyphen — keeps URL-construction trivial at the router layer and avoids
// percent-encoding surprises for SCEP clients that build the URL by string
// concat rather than url.PathEscape.
func validSCEPPathID(s string) bool {
	if s == "" {
		return true // empty maps to legacy /scep root
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
