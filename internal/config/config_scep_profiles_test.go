package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// SCEP RFC 8894 + Intune master bundle Phase 1.5: per-issuer SCEP profiles.
// These tests pin:
//   1. Backward-compat shim: legacy CERTCTL_SCEP_* flat env vars synthesise
//      a single-element Profiles[0] with PathID="" so existing /scep
//      operators see no behavior change.
//   2. Structured form: CERTCTL_SCEP_PROFILES=corp,iot,server expands into
//      per-profile env vars CERTCTL_SCEP_PROFILE_<NAME>_*.
//   3. PathID validation: only [a-z0-9-] with no leading/trailing hyphen,
//      empty allowed (legacy /scep root). Validate() refuses anything else.
//   4. Per-profile gates: Validate() refuses each profile independently
//      (empty challenge password, missing RA pair, missing IssuerID,
//      duplicate PathID).
//
// Note these tests exercise the loader + Validate() in isolation; the
// per-profile preflight + router-registration paths are exercised by the
// cmd/server tests (existing) and the cmd/server/main.go startup path
// (manual via `make docker-up`).

// validBaseConfigForSCEPProfiles returns a Config that passes Validate
// EXCEPT for the SCEP fields the test under exercise sets. Mirrors the
// existing validBaseConfigForEncryption helper shape so the test file
// stays uniform with its siblings.
func validBaseConfigForSCEPProfiles(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
}

// TestSCEPConfig_LegacyFlatFields_SynthesizeSingleProfile is the
// load-time backward-compat test: an operator with the pre-Phase-1.5
// flat env vars (no CERTCTL_SCEP_PROFILES set) must end up with a
// single-element Profiles slice carrying PathID="" so /scep routes
// the same way it did before.
func TestSCEPConfig_LegacyFlatFields_SynthesizeSingleProfile(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_SCEP_ENABLED", "true")
	t.Setenv("CERTCTL_SCEP_ISSUER_ID", "iss-legacy")
	t.Setenv("CERTCTL_SCEP_PROFILE_ID", "prof-legacy")
	t.Setenv("CERTCTL_SCEP_CHALLENGE_PASSWORD", "secret-from-flat-env")
	t.Setenv("CERTCTL_SCEP_RA_CERT_PATH", "/etc/certctl/scep/ra.crt")
	t.Setenv("CERTCTL_SCEP_RA_KEY_PATH", "/etc/certctl/scep/ra.key")
	// Required infra envs so Load() doesn't fail on unrelated gates.
	t.Setenv("CERTCTL_DB_URL", "postgres://localhost/certctl?sslmode=disable")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret")
	srv := validServerConfig(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", srv.TLS.CertPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", srv.TLS.KeyPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil (legacy SCEP flat fields should pass)", err)
	}
	if len(cfg.SCEP.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1 (legacy shim should synthesize single-element slice)", len(cfg.SCEP.Profiles))
	}
	got := cfg.SCEP.Profiles[0]
	if got.PathID != "" {
		t.Errorf("Profiles[0].PathID = %q, want \"\" (empty maps to legacy /scep root)", got.PathID)
	}
	if got.IssuerID != "iss-legacy" {
		t.Errorf("Profiles[0].IssuerID = %q, want %q", got.IssuerID, "iss-legacy")
	}
	if got.ProfileID != "prof-legacy" {
		t.Errorf("Profiles[0].ProfileID = %q, want %q", got.ProfileID, "prof-legacy")
	}
	if got.ChallengePassword != "secret-from-flat-env" {
		t.Errorf("Profiles[0].ChallengePassword = %q, want flat env value", got.ChallengePassword)
	}
	if got.RACertPath != "/etc/certctl/scep/ra.crt" || got.RAKeyPath != "/etc/certctl/scep/ra.key" {
		t.Errorf("Profiles[0] RA paths = (%q, %q), want flat env values", got.RACertPath, got.RAKeyPath)
	}
}

// TestSCEPConfig_MultipleProfiles_LoadFromEnv exercises the structured
// form: CERTCTL_SCEP_PROFILES=corp,iot expands into per-profile env vars.
func TestSCEPConfig_MultipleProfiles_LoadFromEnv(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_SCEP_ENABLED", "true")
	t.Setenv("CERTCTL_SCEP_PROFILES", "corp,iot")
	t.Setenv("CERTCTL_SCEP_PROFILE_CORP_ISSUER_ID", "iss-corp-laptop")
	t.Setenv("CERTCTL_SCEP_PROFILE_CORP_PROFILE_ID", "prof-corp-tls")
	t.Setenv("CERTCTL_SCEP_PROFILE_CORP_CHALLENGE_PASSWORD", "corp-secret")
	t.Setenv("CERTCTL_SCEP_PROFILE_CORP_RA_CERT_PATH", "/etc/certctl/scep/corp-ra.crt")
	t.Setenv("CERTCTL_SCEP_PROFILE_CORP_RA_KEY_PATH", "/etc/certctl/scep/corp-ra.key")
	t.Setenv("CERTCTL_SCEP_PROFILE_IOT_ISSUER_ID", "iss-iot-device")
	t.Setenv("CERTCTL_SCEP_PROFILE_IOT_CHALLENGE_PASSWORD", "iot-secret")
	t.Setenv("CERTCTL_SCEP_PROFILE_IOT_RA_CERT_PATH", "/etc/certctl/scep/iot-ra.crt")
	t.Setenv("CERTCTL_SCEP_PROFILE_IOT_RA_KEY_PATH", "/etc/certctl/scep/iot-ra.key")
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
	if len(cfg.SCEP.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(cfg.SCEP.Profiles))
	}
	// Order matters: env-list order is preserved by the loader.
	if cfg.SCEP.Profiles[0].PathID != "corp" {
		t.Errorf("Profiles[0].PathID = %q, want %q", cfg.SCEP.Profiles[0].PathID, "corp")
	}
	if cfg.SCEP.Profiles[1].PathID != "iot" {
		t.Errorf("Profiles[1].PathID = %q, want %q", cfg.SCEP.Profiles[1].PathID, "iot")
	}
	if cfg.SCEP.Profiles[0].IssuerID != "iss-corp-laptop" {
		t.Errorf("Profiles[0].IssuerID = %q, want %q", cfg.SCEP.Profiles[0].IssuerID, "iss-corp-laptop")
	}
	if cfg.SCEP.Profiles[1].IssuerID != "iss-iot-device" {
		t.Errorf("Profiles[1].IssuerID = %q, want %q", cfg.SCEP.Profiles[1].IssuerID, "iss-iot-device")
	}
	if cfg.SCEP.Profiles[0].ChallengePassword != "corp-secret" {
		t.Errorf("Profiles[0].ChallengePassword = %q, want %q", cfg.SCEP.Profiles[0].ChallengePassword, "corp-secret")
	}
}

// TestSCEPConfig_StructuredFormBeatsLegacy: when CERTCTL_SCEP_PROFILES is
// set, the legacy flat fields are NOT merged in (the structured form is
// the operator's explicit opt-in). Pins that the merge shim is no-op when
// Profiles is non-empty.
func TestSCEPConfig_StructuredFormBeatsLegacy(t *testing.T) {
	clearCertctlEnv(t)
	t.Setenv("CERTCTL_SCEP_ENABLED", "true")
	// Both forms set — structured wins, flat is ignored.
	t.Setenv("CERTCTL_SCEP_CHALLENGE_PASSWORD", "flat-secret-should-not-appear")
	t.Setenv("CERTCTL_SCEP_PROFILES", "only")
	t.Setenv("CERTCTL_SCEP_PROFILE_ONLY_ISSUER_ID", "iss-only")
	t.Setenv("CERTCTL_SCEP_PROFILE_ONLY_CHALLENGE_PASSWORD", "structured-secret-wins")
	t.Setenv("CERTCTL_SCEP_PROFILE_ONLY_RA_CERT_PATH", "/etc/certctl/scep/only-ra.crt")
	t.Setenv("CERTCTL_SCEP_PROFILE_ONLY_RA_KEY_PATH", "/etc/certctl/scep/only-ra.key")
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
	if len(cfg.SCEP.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1 (structured form should NOT be augmented by legacy flat fields)", len(cfg.SCEP.Profiles))
	}
	if cfg.SCEP.Profiles[0].PathID != "only" {
		t.Errorf("Profiles[0].PathID = %q, want %q", cfg.SCEP.Profiles[0].PathID, "only")
	}
	if cfg.SCEP.Profiles[0].ChallengePassword != "structured-secret-wins" {
		t.Errorf("Profiles[0].ChallengePassword = %q, want structured value (legacy flat field MUST NOT leak in)", cfg.SCEP.Profiles[0].ChallengePassword)
	}
}

// TestSCEPConfig_PathIDValidation pins the path-safe slug constraint.
// Validate() refuses anything with uppercase, slashes, leading/trailing
// hyphens, or non-ASCII chars. The empty string is allowed (legacy root).
func TestSCEPConfig_PathIDValidation(t *testing.T) {
	cases := []struct {
		name   string
		pathID string
		valid  bool
	}{
		{"empty_legacy_root", "", true},
		{"valid_lowercase", "corp", true},
		{"valid_with_digits", "iot2", true},
		{"valid_with_hyphen", "corp-laptop", true},
		{"valid_long", "very-long-profile-name-with-many-segments", true},
		{"reject_uppercase", "Corp", false},
		{"reject_slash", "corp/laptop", false},
		{"reject_leading_hyphen", "-corp", false},
		{"reject_trailing_hyphen", "corp-", false},
		{"reject_underscore", "corp_laptop", false},
		{"reject_dot", "corp.laptop", false},
		{"reject_space", "corp laptop", false},
		{"reject_unicode", "corpé", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBaseConfigForSCEPProfiles(t)
			cfg.SCEP = SCEPConfig{
				Enabled: true,
				Profiles: []SCEPProfileConfig{{
					PathID:            tc.pathID,
					IssuerID:          "iss-test",
					ChallengePassword: "secret",
					RACertPath:        "/etc/certctl/scep/ra.crt",
					RAKeyPath:         "/etc/certctl/scep/ra.key",
				}},
			}
			err := cfg.Validate()
			if tc.valid && err != nil {
				t.Errorf("Validate() = %v, want nil for valid PathID %q", err, tc.pathID)
			}
			if !tc.valid && err == nil {
				t.Errorf("Validate() = nil, want error for invalid PathID %q", tc.pathID)
			}
			if !tc.valid && err != nil && !strings.Contains(err.Error(), "invalid PathID") {
				t.Errorf("error should mention invalid PathID, got: %v", err)
			}
		})
	}
}

// TestSCEPConfig_DuplicatePathID_Refuses pins the uniqueness gate so
// the router never gets a {pathID -> handler} map with collisions.
func TestSCEPConfig_DuplicatePathID_Refuses(t *testing.T) {
	cfg := validBaseConfigForSCEPProfiles(t)
	cfg.SCEP = SCEPConfig{
		Enabled: true,
		Profiles: []SCEPProfileConfig{
			{PathID: "corp", IssuerID: "iss-a", ChallengePassword: "x", RACertPath: "/a.crt", RAKeyPath: "/a.key"},
			{PathID: "corp", IssuerID: "iss-b", ChallengePassword: "y", RACertPath: "/b.crt", RAKeyPath: "/b.key"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for duplicate PathID")
	}
	if !strings.Contains(err.Error(), "duplicates PathID") {
		t.Errorf("error should mention duplicates PathID, got: %v", err)
	}
}

// TestSCEPConfig_MissingPerProfileChallengePassword pins the per-profile
// CWE-306 gate. Each profile is independently required to carry a
// non-empty challenge password — defense in depth with the static-form
// gate that fired pre-Phase-1.5.
func TestSCEPConfig_MissingPerProfileChallengePassword(t *testing.T) {
	cfg := validBaseConfigForSCEPProfiles(t)
	cfg.SCEP = SCEPConfig{
		Enabled: true,
		Profiles: []SCEPProfileConfig{
			{PathID: "good", IssuerID: "iss-a", ChallengePassword: "x", RACertPath: "/a.crt", RAKeyPath: "/a.key"},
			{PathID: "bad", IssuerID: "iss-b", ChallengePassword: "", RACertPath: "/b.crt", RAKeyPath: "/b.key"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty per-profile challenge password")
	}
	if !strings.Contains(err.Error(), "empty CHALLENGE_PASSWORD") {
		t.Errorf("error should mention empty CHALLENGE_PASSWORD, got: %v", err)
	}
}

// TestSCEPConfig_MissingPerProfileRAPair pins the RA-pair gate per profile.
func TestSCEPConfig_MissingPerProfileRAPair(t *testing.T) {
	cases := []struct {
		name       string
		raCertPath string
		raKeyPath  string
	}{
		{"both_missing", "", ""},
		{"cert_missing", "", "/x.key"},
		{"key_missing", "/x.crt", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBaseConfigForSCEPProfiles(t)
			cfg.SCEP = SCEPConfig{
				Enabled: true,
				Profiles: []SCEPProfileConfig{{
					PathID:            "p",
					IssuerID:          "iss",
					ChallengePassword: "secret",
					RACertPath:        tc.raCertPath,
					RAKeyPath:         tc.raKeyPath,
				}},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), "missing RA cert/key path") {
				t.Errorf("error should mention missing RA cert/key path, got: %v", err)
			}
		})
	}
}

// TestSCEPConfig_MissingPerProfileIssuerID guards against a profile that
// references no issuer at all (a likely typo in CERTCTL_SCEP_PROFILE_X_ISSUER_ID).
func TestSCEPConfig_MissingPerProfileIssuerID(t *testing.T) {
	cfg := validBaseConfigForSCEPProfiles(t)
	cfg.SCEP = SCEPConfig{
		Enabled: true,
		Profiles: []SCEPProfileConfig{{
			PathID:            "p",
			ChallengePassword: "secret",
			RACertPath:        "/x.crt",
			RAKeyPath:         "/x.key",
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty per-profile IssuerID")
	}
	if !strings.Contains(err.Error(), "empty IssuerID") {
		t.Errorf("error should mention empty IssuerID, got: %v", err)
	}
}

// TestSCEPConfig_DisabledIgnoresProfiles pins that the per-profile gates
// only fire when SCEP is enabled. A disabled deploy can carry malformed
// Profiles entries (e.g. partially-populated by an automation tool) without
// blocking startup.
func TestSCEPConfig_DisabledIgnoresProfiles(t *testing.T) {
	cfg := validBaseConfigForSCEPProfiles(t)
	cfg.SCEP = SCEPConfig{
		Enabled: false,
		Profiles: []SCEPProfileConfig{
			{PathID: "BAD UPPER", IssuerID: "", ChallengePassword: "", RACertPath: "", RAKeyPath: ""},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for SCEP disabled with malformed profiles", err)
	}
}

// clearCertctlEnv resets every CERTCTL_* env var so a Load()-based test
// runs in isolation. Mirrors the existing clearCertctlEnv in the sibling
// test file (config_test.go) but defined locally so the file stays
// self-contained for a future split.
func init() {
	// Reuse the existing clearCertctlEnv from config_test.go via the package
	// scope; declared in this init() block as a sanity check to ensure
	// linking works. The actual helper lives in config_test.go.
	_ = os.Getenv
}
