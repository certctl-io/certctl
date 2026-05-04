package intune

// SCEP RFC 8894 + Intune master bundle Phase 7.2 (originally) +
// EST RFC 7030 hardening master bundle Phase 2.1 (extraction).
//
// LoadTrustAnchor + parseTrustAnchorPEM were extracted to
// internal/trustanchor.LoadBundle + parseBundlePEM so the EST mTLS
// sibling route (Phase 2 of the EST hardening bundle), the Intune
// dispatcher, and any future per-profile-trust-bundle caller can share
// the same PEM-bundle loader + SIGHUP-reload semantics. The shim below
// preserves the original public surface so existing intune callers
// (cmd/server/main.go, scep_intune_e2e_test.go, scep_profile_counter_
// isolation_test.go, scep_intune.go service) compile unchanged.
//
// New callers SHOULD import internal/trustanchor directly — the
// trustanchor.Holder + trustanchor.LoadBundle are the modern API.
//
// Note: the legacy intune error messages ("intune: trust anchor cert
// in %q expired ...") are NOT preserved verbatim across the extraction;
// the shared trustanchor package emits "trustanchor: ..." messages
// instead. The operator-facing log line at cmd/server/main.go's
// preflightSCEPIntuneTrustAnchor wraps the error in its own outer
// ("SCEP profile (PathID=...) INTUNE trust anchor load failed: ...")
// so the prefix change is invisible to log-grep runbooks that filter
// on the outer message.

import (
	"crypto/x509"

	"github.com/certctl-io/certctl/internal/trustanchor"
)

// LoadTrustAnchor reads a PEM bundle of one or more Intune Connector
// signing certificates from the configured path. Delegates to the
// shared trustanchor.LoadBundle (extracted in EST RFC 7030 hardening
// Phase 2.1) so the EST mTLS sibling route + the Intune dispatcher
// + any future per-profile trust-bundle caller share the same
// loader semantics (path-empty refusal, expired-cert refusal,
// non-CERTIFICATE-block tolerance).
//
// Preserved here as a wrapper so existing intune callers compile
// unchanged. New callers SHOULD use trustanchor.LoadBundle directly.
func LoadTrustAnchor(path string) ([]*x509.Certificate, error) {
	return trustanchor.LoadBundle(path)
}
