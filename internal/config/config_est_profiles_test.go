package config

import (
	"strings"
	"testing"
)

// EST RFC 7030 hardening master bundle Phase 1: per-issuer EST profiles.
// These tests pin:
//
//   1. Backward-compat shim: legacy CERTCTL_EST_* flat env vars (just
//      CERTCTL_EST_ENABLED + CERTCTL_EST_ISSUER_ID + CERTCTL_EST_PROFILE_ID)
//      synthesise a single-element Profiles[0] with PathID="" so existing
//      /.well-known/est/ operators see no behavior change.
//   2. Structured form: CERTCTL_EST_PROFILES=corp,iot,wifi expands into
//      per-profile env vars CERTCTL_EST_PROFILE_<NAME>_*.
//   3. PathID validation: only [a-z0-9-] with no leading/trailing hyphen,
//      empty allowed (legacy root). Validate() refuses anything else.
//   4. Per-profile gates: Validate() refuses each profile independently
//      (missing IssuerID, mtls-enabled-no-bundle, channel-binding-without-
//      mtls, basic-auth-no-password, mtls-mode-without-mtls, unknown auth
//      mode, negative rate limit, server-keygen without ProfileID,
//      duplicate PathID).
//
// Note these tests exercise the loader + Validate() in isolation; the
// per-profile preflight + router-registration paths are exercised by the
// router_test (RegisterESTHandlers shape) and the cmd/server/main.go
// startup path (manual via `make docker-up`).

// validBaseConfigForESTProfiles returns a Config that passes Validate
// EXCEPT for the EST fields the test under exercise sets. Mirrors the
// existing validBaseConfigForSCEPProfiles helper shape so the test file
// stays uniform with its siblings.
func validBaseConfigForESTProfiles(t *testing.T) *Config {
	t.Helper()
	return validBaseConfigForSCEPProfiles(t) // identical infra; EST tests just override the EST block
}

// TestESTConfig_LegacyFlatFields_SynthesizeSingleProfile is the
// load-time backward-compat test: an operator with the pre-Phase-1
// flat env vars (no CERTCTL_EST_PROFILES set) must end up with a
// single-element Profiles slice carrying PathID="" so /.well-known/est/
// routes the same way it did before.
func TestESTConfig_LegacyFlatFields_SynthesizeSingleProfile(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_EST_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ISSUER_ID", "iss-legacy-est")
	t.Setenv("CERTCTL_EST_PROFILE_ID", "prof-legacy-est")
	// Required infra envs so Load() doesn't fail on unrelated gates.
	t.Setenv("CERTCTL_DB_URL", "postgres://localhost/certctl?sslmode=disable")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret")
	srv := validServerConfig(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", srv.TLS.CertPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", srv.TLS.KeyPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil (legacy EST flat fields should pass)", err)
	}
	if len(cfg.EST.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1 (legacy shim should synthesize single-element slice)", len(cfg.EST.Profiles))
	}
	got := cfg.EST.Profiles[0]
	if got.PathID != "" {
		t.Errorf("Profiles[0].PathID = %q, want \"\" (empty maps to legacy /.well-known/est/ root)", got.PathID)
	}
	if got.IssuerID != "iss-legacy-est" {
		t.Errorf("Profiles[0].IssuerID = %q, want %q", got.IssuerID, "iss-legacy-est")
	}
	if got.ProfileID != "prof-legacy-est" {
		t.Errorf("Profiles[0].ProfileID = %q, want %q", got.ProfileID, "prof-legacy-est")
	}
	// Forward-looking fields should be at their defaults (Phase 2/3/4/5
	// will set non-zero values via the structured form; the legacy shim
	// preserves the pre-Phase-1 unauthenticated/unlimited defaults so
	// existing operators see no behavior change).
	if got.MTLSEnabled {
		t.Errorf("Profiles[0].MTLSEnabled = true, want false (legacy shim preserves pre-Phase-1 defaults)")
	}
	if got.EnrollmentPassword != "" {
		t.Errorf("Profiles[0].EnrollmentPassword = %q, want empty", got.EnrollmentPassword)
	}
	if len(got.AllowedAuthModes) != 0 {
		t.Errorf("Profiles[0].AllowedAuthModes = %v, want empty (back-compat = no auth)", got.AllowedAuthModes)
	}
	if got.RateLimitPerPrincipal24h != 0 {
		t.Errorf("Profiles[0].RateLimitPerPrincipal24h = %d, want 0 (back-compat = unlimited)", got.RateLimitPerPrincipal24h)
	}
	if got.ServerKeygenEnabled {
		t.Errorf("Profiles[0].ServerKeygenEnabled = true, want false (Phase 5 opt-in)")
	}
}

// TestESTConfig_DisabledNoLegacyShim verifies that when EST is disabled
// the legacy shim is a no-op (Profiles stays empty, no synthesized
// element). Mirrors the SCEP equivalent.
func TestESTConfig_DisabledNoLegacyShim(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_EST_ENABLED", "false")
	t.Setenv("CERTCTL_EST_ISSUER_ID", "iss-still-set")
	t.Setenv("CERTCTL_DB_URL", "postgres://localhost/certctl?sslmode=disable")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret")
	srv := validServerConfig(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", srv.TLS.CertPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", srv.TLS.KeyPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if len(cfg.EST.Profiles) != 0 {
		t.Errorf("len(Profiles) = %d, want 0 (disabled EST should not trigger the shim)", len(cfg.EST.Profiles))
	}
}

// TestESTConfig_MultipleProfiles_LoadFromEnv exercises the structured form:
// CERTCTL_EST_PROFILES=corp,iot,wifi expands into per-profile env vars.
// All forward-looking fields (auth modes, mTLS, rate limit, server-keygen)
// load correctly even though the dispatching handlers are Phase 2-5 work.
func TestESTConfig_MultipleProfiles_LoadFromEnv(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_EST_ENABLED", "true")
	t.Setenv("CERTCTL_EST_PROFILES", "corp,iot,wifi")

	// CORP: mTLS + Basic, channel-binding required, rate-limited, server-keygen on
	t.Setenv("CERTCTL_EST_PROFILE_CORP_ISSUER_ID", "iss-corp-laptop")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_PROFILE_ID", "prof-corp-tls")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_ENROLLMENT_PASSWORD", "corp-secret")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_MTLS_ENABLED", "true")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", "/etc/certctl/est/corp-trust.pem")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_CHANNEL_BINDING_REQUIRED", "true")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_ALLOWED_AUTH_MODES", "mtls,basic")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_RATE_LIMIT_PER_PRINCIPAL_24H", "5")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_SERVERKEYGEN_ENABLED", "true")

	// IOT: Basic only (no mTLS for resource-constrained devices)
	t.Setenv("CERTCTL_EST_PROFILE_IOT_ISSUER_ID", "iss-iot")
	t.Setenv("CERTCTL_EST_PROFILE_IOT_PROFILE_ID", "prof-iot-30d")
	t.Setenv("CERTCTL_EST_PROFILE_IOT_ENROLLMENT_PASSWORD", "iot-bootstrap")
	t.Setenv("CERTCTL_EST_PROFILE_IOT_ALLOWED_AUTH_MODES", "basic")
	t.Setenv("CERTCTL_EST_PROFILE_IOT_RATE_LIMIT_PER_PRINCIPAL_24H", "3")

	// WIFI: mTLS only (802.1X devices have factory bootstrap certs)
	t.Setenv("CERTCTL_EST_PROFILE_WIFI_ISSUER_ID", "iss-wifi-eaptls")
	t.Setenv("CERTCTL_EST_PROFILE_WIFI_MTLS_ENABLED", "true")
	t.Setenv("CERTCTL_EST_PROFILE_WIFI_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", "/etc/certctl/est/wifi-trust.pem")
	t.Setenv("CERTCTL_EST_PROFILE_WIFI_ALLOWED_AUTH_MODES", "mtls")

	// Required infra envs.
	t.Setenv("CERTCTL_DB_URL", "postgres://localhost/certctl?sslmode=disable")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret")
	srv := validServerConfig(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", srv.TLS.CertPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", srv.TLS.KeyPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if len(cfg.EST.Profiles) != 3 {
		t.Fatalf("len(Profiles) = %d, want 3", len(cfg.EST.Profiles))
	}

	type wantProfile struct {
		PathID, IssuerID, ProfileID, EnrollmentPassword, MTLSBundle string
		MTLSEnabled, ChannelBinding, ServerKeygen                   bool
		RateLimit                                                   int
		AuthModes                                                   []string
	}
	wants := map[string]wantProfile{
		"corp": {
			PathID: "corp", IssuerID: "iss-corp-laptop", ProfileID: "prof-corp-tls",
			EnrollmentPassword: "corp-secret", MTLSBundle: "/etc/certctl/est/corp-trust.pem",
			MTLSEnabled: true, ChannelBinding: true, ServerKeygen: true,
			RateLimit: 5, AuthModes: []string{"mtls", "basic"},
		},
		"iot": {
			PathID: "iot", IssuerID: "iss-iot", ProfileID: "prof-iot-30d",
			EnrollmentPassword: "iot-bootstrap",
			RateLimit:          3, AuthModes: []string{"basic"},
		},
		"wifi": {
			PathID: "wifi", IssuerID: "iss-wifi-eaptls",
			MTLSBundle: "/etc/certctl/est/wifi-trust.pem", MTLSEnabled: true,
			AuthModes: []string{"mtls"},
		},
	}
	got := map[string]ESTProfileConfig{}
	for _, p := range cfg.EST.Profiles {
		got[p.PathID] = p
	}
	for name, want := range wants {
		g, ok := got[name]
		if !ok {
			t.Fatalf("missing profile %q in loaded slice", name)
		}
		if g.PathID != want.PathID || g.IssuerID != want.IssuerID || g.ProfileID != want.ProfileID {
			t.Errorf("profile %q identity = (%q,%q,%q), want (%q,%q,%q)",
				name, g.PathID, g.IssuerID, g.ProfileID, want.PathID, want.IssuerID, want.ProfileID)
		}
		if g.EnrollmentPassword != want.EnrollmentPassword {
			t.Errorf("profile %q EnrollmentPassword = %q, want %q", name, g.EnrollmentPassword, want.EnrollmentPassword)
		}
		if g.MTLSEnabled != want.MTLSEnabled || g.MTLSClientCATrustBundlePath != want.MTLSBundle {
			t.Errorf("profile %q mTLS = (%v,%q), want (%v,%q)",
				name, g.MTLSEnabled, g.MTLSClientCATrustBundlePath, want.MTLSEnabled, want.MTLSBundle)
		}
		if g.ChannelBindingRequired != want.ChannelBinding {
			t.Errorf("profile %q ChannelBindingRequired = %v, want %v", name, g.ChannelBindingRequired, want.ChannelBinding)
		}
		if g.ServerKeygenEnabled != want.ServerKeygen {
			t.Errorf("profile %q ServerKeygenEnabled = %v, want %v", name, g.ServerKeygenEnabled, want.ServerKeygen)
		}
		if g.RateLimitPerPrincipal24h != want.RateLimit {
			t.Errorf("profile %q RateLimit = %d, want %d", name, g.RateLimitPerPrincipal24h, want.RateLimit)
		}
		if !equalStringSlices(g.AllowedAuthModes, want.AuthModes) {
			t.Errorf("profile %q AllowedAuthModes = %v, want %v", name, g.AllowedAuthModes, want.AuthModes)
		}
	}
}

// TestESTConfig_StructuredFormBeatsLegacy: when CERTCTL_EST_PROFILES is
// set, the legacy shim is a no-op (the structured form takes precedence).
func TestESTConfig_StructuredFormBeatsLegacy(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_EST_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ISSUER_ID", "iss-flat-ignored")
	t.Setenv("CERTCTL_EST_PROFILES", "corp")
	t.Setenv("CERTCTL_EST_PROFILE_CORP_ISSUER_ID", "iss-from-structured")
	t.Setenv("CERTCTL_DB_URL", "postgres://localhost/certctl?sslmode=disable")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret")
	srv := validServerConfig(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", srv.TLS.CertPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", srv.TLS.KeyPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if len(cfg.EST.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1 (structured form), got = %#v", len(cfg.EST.Profiles), cfg.EST.Profiles)
	}
	if got := cfg.EST.Profiles[0].IssuerID; got != "iss-from-structured" {
		t.Errorf("Profiles[0].IssuerID = %q, want structured value (legacy shim should not have fired)", got)
	}
	if got := cfg.EST.Profiles[0].PathID; got != "corp" {
		t.Errorf("Profiles[0].PathID = %q, want \"corp\"", got)
	}
}

// TestESTConfig_PathIDValidation pins validESTPathID + Validate() refusal
// of malformed PathIDs.
func TestESTConfig_PathIDValidation(t *testing.T) {
	cases := []struct {
		pathID  string
		valid   bool
		comment string
	}{
		{"", true, "empty (legacy root)"},
		{"corp", true, "lowercase letters"},
		{"iot-fleet-2", true, "letters + digits + hyphens"},
		{"a", true, "single char"},
		{"-corp", false, "leading hyphen"},
		{"corp-", false, "trailing hyphen"},
		{"Corp", false, "uppercase"},
		{"corp/iot", false, "slash"},
		{"corp.iot", false, "dot"},
		{"corp_iot", false, "underscore"},
		{"corp iot", false, "space"},
		{"corp%20iot", false, "percent encoding"},
	}
	for _, tc := range cases {
		t.Run(tc.comment, func(t *testing.T) {
			if got := validESTPathID(tc.pathID); got != tc.valid {
				t.Errorf("validESTPathID(%q) = %v, want %v (%s)", tc.pathID, got, tc.valid, tc.comment)
			}
		})
	}
}

// TestESTConfig_DuplicatePathID_Refuses verifies Validate() refuses two
// profiles with the same PathID. This is the load-bearing dispatch
// uniqueness guarantee — without it, the router would silently overwrite
// the first registration.
func TestESTConfig_DuplicatePathID_Refuses(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{PathID: "corp", IssuerID: "iss-a"},
		{PathID: "corp", IssuerID: "iss-b"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for duplicate PathID")
	}
	if !strings.Contains(err.Error(), "duplicates PathID") {
		t.Errorf("Validate() error = %q, want substring \"duplicates PathID\"", err.Error())
	}
}

// TestESTConfig_MissingPerProfileIssuerID verifies Validate() refuses
// a profile with empty IssuerID.
func TestESTConfig_MissingPerProfileIssuerID(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{PathID: "corp", IssuerID: ""},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty IssuerID")
	}
	if !strings.Contains(err.Error(), "empty IssuerID") {
		t.Errorf("Validate() error = %q, want substring \"empty IssuerID\"", err.Error())
	}
}

// TestESTConfig_MTLSEnabledRequiresBundlePath verifies the per-profile
// gate: MTLSEnabled=true without MTLS_CLIENT_CA_TRUST_BUNDLE_PATH = refuse.
func TestESTConfig_MTLSEnabledRequiresBundlePath(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			MTLSEnabled:                 true,
			MTLSClientCATrustBundlePath: "", // missing
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for MTLSEnabled without trust bundle")
	}
	if !strings.Contains(err.Error(), "MTLSEnabled=true") {
		t.Errorf("Validate() error = %q, want substring mentioning MTLSEnabled=true", err.Error())
	}
	if !strings.Contains(err.Error(), "/.well-known/est-mtls/corp/") {
		t.Errorf("Validate() error = %q, should reference the sibling route URL operators see", err.Error())
	}
}

// TestESTConfig_ChannelBindingWithoutMTLS_Refuses verifies the cross-check:
// channel binding only makes sense when mTLS is in use (RFC 9266 binds the
// TLS-presented client cert to the CSR's CMC attribute).
func TestESTConfig_ChannelBindingWithoutMTLS_Refuses(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			MTLSEnabled:            false,
			ChannelBindingRequired: true,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for ChannelBindingRequired without mTLS")
	}
	if !strings.Contains(err.Error(), "ChannelBindingRequired=true but MTLSEnabled=false") {
		t.Errorf("Validate() error = %q, want substring mentioning the cross-check", err.Error())
	}
}

// TestESTConfig_BasicAuthInModesRequiresPassword verifies the cross-check:
// AllowedAuthModes mentions "basic" → EnrollmentPassword MUST be non-empty.
func TestESTConfig_BasicAuthInModesRequiresPassword(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			AllowedAuthModes:   []string{"basic"},
			EnrollmentPassword: "", // missing
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for basic auth without password")
	}
	if !strings.Contains(err.Error(), "ENROLLMENT_PASSWORD is empty") {
		t.Errorf("Validate() error = %q, want substring mentioning empty ENROLLMENT_PASSWORD", err.Error())
	}
}

// TestESTConfig_MTLSAuthModeRequiresMTLSEnabled verifies the cross-check:
// AllowedAuthModes mentions "mtls" → MTLSEnabled MUST be true.
func TestESTConfig_MTLSAuthModeRequiresMTLSEnabled(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			AllowedAuthModes: []string{"mtls"},
			MTLSEnabled:      false,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for mtls auth mode without MTLSEnabled")
	}
	if !strings.Contains(err.Error(), "lists \"mtls\" in AllowedAuthModes but MTLSEnabled=false") {
		t.Errorf("Validate() error = %q, want substring mentioning the cross-check", err.Error())
	}
}

// TestESTConfig_UnknownAuthModeRefused verifies Validate() refuses any
// auth mode that isn't "mtls" or "basic" (typos, future modes the binary
// doesn't yet implement).
func TestESTConfig_UnknownAuthModeRefused(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			AllowedAuthModes: []string{"oauth"}, // not a documented EST auth mode
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for unknown auth mode")
	}
	if !strings.Contains(err.Error(), "unknown AllowedAuthModes entry") {
		t.Errorf("Validate() error = %q, want substring mentioning unknown auth mode", err.Error())
	}
	if !strings.Contains(err.Error(), "oauth") {
		t.Errorf("Validate() error = %q, want to surface the offending mode name", err.Error())
	}
}

// TestESTConfig_NegativeRateLimitRefused verifies Validate() catches the
// config typo of a negative rate limit.
func TestESTConfig_NegativeRateLimitRefused(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "corp", IssuerID: "iss-corp",
			RateLimitPerPrincipal24h: -1,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative rate limit")
	}
	if !strings.Contains(err.Error(), "RATE_LIMIT_PER_PRINCIPAL_24H=-1") {
		t.Errorf("Validate() error = %q, want substring mentioning negative rate limit", err.Error())
	}
}

// TestESTConfig_ServerKeygenRequiresProfileID verifies Validate() refuses
// ServerKeygenEnabled=true without a CertificateProfile to pin
// AllowedKeyAlgorithms (the server has to know what to generate).
func TestESTConfig_ServerKeygenRequiresProfileID(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = true
	cfg.EST.Profiles = []ESTProfileConfig{
		{
			PathID: "iot", IssuerID: "iss-iot",
			ServerKeygenEnabled: true,
			ProfileID:           "", // missing
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for ServerKeygenEnabled without ProfileID")
	}
	if !strings.Contains(err.Error(), "SERVERKEYGEN_ENABLED=true but PROFILE_ID is empty") {
		t.Errorf("Validate() error = %q, want substring mentioning the missing PROFILE_ID", err.Error())
	}
}

// TestESTConfig_DisabledIgnoresProfiles verifies that when EST is disabled,
// no per-profile validation runs (an operator with a half-configured set of
// profiles can still flip the kill-switch off without fixing every one).
func TestESTConfig_DisabledIgnoresProfiles(t *testing.T) {
	cfg := validBaseConfigForESTProfiles(t)
	cfg.EST.Enabled = false
	cfg.EST.Profiles = []ESTProfileConfig{
		{PathID: "BAD-CASE", IssuerID: ""}, // would refuse if EST.Enabled
		{PathID: "corp", IssuerID: ""},     // would refuse if EST.Enabled
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (disabled EST should skip per-profile gates)", err)
	}
}

// TestESTConfig_ParseAuthModes_Normalization pins the parser's behavior
// (lowercasing, trimming, empty-element filtering).
func TestESTConfig_ParseAuthModes_Normalization(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"   ", nil},
		{"mtls", []string{"mtls"}},
		{"MTLS", []string{"mtls"}},
		{"mtls,basic", []string{"mtls", "basic"}},
		{" mtls , basic ", []string{"mtls", "basic"}},
		{"mtls,,basic", []string{"mtls", "basic"}}, // empty element dropped
		{"BASIC", []string{"basic"}},
	}
	for _, tc := range cases {
		got := parseAuthModes(tc.input)
		if !equalStringSlices(got, tc.want) {
			t.Errorf("parseAuthModes(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// equalStringSlices reports whether two []string slices contain the same
// elements in the same order. nil and []string{} are treated as equal.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
