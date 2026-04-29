package intune

// SCEP RFC 8894 + Intune master bundle Phase 8.5 (originally) +
// EST RFC 7030 hardening master bundle Phase 2.1 (extraction).
//
// TrustAnchorHolder + NewTrustAnchorHolder were extracted to
// internal/trustanchor.Holder + trustanchor.New so the EST mTLS sibling
// route (Phase 2 of the EST hardening bundle) and the Intune dispatcher
// can share the same SIGHUP-reloadable PEM bundle primitive. A single
// SIGHUP now rotates: server TLS cert (cmd/server/tls.go), every Intune
// trust anchor (this package's existing wiring), AND every EST mTLS
// per-profile client-CA bundle (the new sibling route) — exactly the
// design contract documented in the trustanchor package doc.
//
// The aliases below preserve every existing intune call site unchanged:
//   - cmd/server/main.go declares `intuneTrustHolders []*intune.TrustAnchorHolder`
//     + invokes `intune.NewTrustAnchorHolder(path, logger)`
//   - internal/service/scep.go's SCEPService struct field
//     `intuneTrust *intune.TrustAnchorHolder` (the type alias keeps this
//     pointer-compatible with the original)
//   - internal/scep/intune/trust_anchor_holder_test.go + the e2e tests
//     that construct a holder via NewTrustAnchorHolder
//
// New callers SHOULD import internal/trustanchor directly — the
// trustanchor.Holder + trustanchor.New are the modern API. The intune
// aliases are preserved indefinitely for back-compat (no deprecation
// timeline; the cost of the two-line shim is trivial).

import (
	"github.com/shankar0123/certctl/internal/trustanchor"
)

// TrustAnchorHolder is the SIGHUP-reloadable wrapper around a per-profile
// Intune Connector trust anchor pool.
//
// Aliased to trustanchor.Holder (extracted in EST RFC 7030 hardening
// Phase 2.1) so the EST mTLS sibling route + the Intune dispatcher share
// the same primitive. Existing callers compile unchanged because Go type
// aliases are pointer-compatible.
type TrustAnchorHolder = trustanchor.Holder

// NewTrustAnchorHolder loads the trust bundle and returns a holder.
// Aliased to trustanchor.New (extracted in EST RFC 7030 hardening
// Phase 2.1). Returns the same fail-loud error LoadTrustAnchor does on
// initial load — the startup gate at cmd/server/main.go is supposed to
// refuse boot when this fails. Subsequent Reload errors are non-fatal
// (logged + old pool retained).
//
// The logger is required (never nil); the caller passes a per-profile
// scoped logger so SIGHUP-reload events show the PathID for triage.
//
// Note: the original intune.NewTrustAnchorHolder set the holder's
// internal log label to "Intune trust anchor"; the extracted
// trustanchor.New defaults to "trust anchor". Existing intune callers
// that need the original label should call .SetLabelForLog("intune
// trust anchor (PathID=…)") on the returned holder. cmd/server/main.go
// does this in the per-profile Intune startup loop.
var NewTrustAnchorHolder = trustanchor.New
