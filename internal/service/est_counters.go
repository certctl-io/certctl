package service

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/certctl-io/certctl/internal/trustanchor"
)

// EST RFC 7030 hardening master bundle Phase 7.1.
//
// estCounterTab is the in-memory equivalent of a Prometheus
// `certctl_est_enrollments_total{status="..."}` metric. We don't take a
// Prometheus dependency here (the project doesn't expose /metrics today;
// that's a separate decision). The admin GUI's "EST Profiles" tab calls
// the GET /api/v1/admin/est/profiles endpoint, which calls
// ESTService.Stats() to render the counter snapshot.
//
// Concurrency: every field is read/written via sync/atomic so the
// service hot path stays lock-free.

// Counter labels — keep in sync with snapshot() + the admin GUI's
// counter-grid renderer. New labels MUST be added in three places:
// constants below, snapshot()'s map, and inc()'s switch.
const (
	estCounterSuccessSimpleEnroll   = "success_simpleenroll"
	estCounterSuccessSimpleReEnroll = "success_simplereenroll"
	estCounterSuccessServerKeygen   = "success_serverkeygen"
	estCounterAuthFailedBasic       = "auth_failed_basic"
	estCounterAuthFailedMTLS        = "auth_failed_mtls"
	estCounterAuthFailedChannelBind = "auth_failed_channel_binding"
	estCounterCSRInvalid            = "csr_invalid"
	estCounterCSRPolicyViolation    = "csr_policy_violation"
	estCounterCSRSignatureMismatch  = "csr_signature_mismatch"
	estCounterRateLimited           = "rate_limited"
	estCounterIssuerError           = "issuer_error"
	estCounterInternalError         = "internal_error"
)

type estCounterTab struct {
	successSimpleEnroll   atomic.Uint64
	successSimpleReEnroll atomic.Uint64
	successServerKeygen   atomic.Uint64
	authFailedBasic       atomic.Uint64
	authFailedMTLS        atomic.Uint64
	authFailedChannelBind atomic.Uint64
	csrInvalid            atomic.Uint64
	csrPolicyViolation    atomic.Uint64
	csrSignatureMismatch  atomic.Uint64
	rateLimited           atomic.Uint64
	issuerError           atomic.Uint64
	internalError         atomic.Uint64
}

// snapshot returns a zero-allocation copy of the current counter values
// keyed by the same label strings inc() accepts.
func (c *estCounterTab) snapshot() map[string]uint64 {
	if c == nil {
		return map[string]uint64{}
	}
	return map[string]uint64{
		estCounterSuccessSimpleEnroll:   c.successSimpleEnroll.Load(),
		estCounterSuccessSimpleReEnroll: c.successSimpleReEnroll.Load(),
		estCounterSuccessServerKeygen:   c.successServerKeygen.Load(),
		estCounterAuthFailedBasic:       c.authFailedBasic.Load(),
		estCounterAuthFailedMTLS:        c.authFailedMTLS.Load(),
		estCounterAuthFailedChannelBind: c.authFailedChannelBind.Load(),
		estCounterCSRInvalid:            c.csrInvalid.Load(),
		estCounterCSRPolicyViolation:    c.csrPolicyViolation.Load(),
		estCounterCSRSignatureMismatch:  c.csrSignatureMismatch.Load(),
		estCounterRateLimited:           c.rateLimited.Load(),
		estCounterIssuerError:           c.issuerError.Load(),
		estCounterInternalError:         c.internalError.Load(),
	}
}

// inc advances the counter matching the given label. Unknown labels
// fall through to internal_error so an enum drift doesn't silently
// lose counts.
func (c *estCounterTab) inc(label string) {
	if c == nil {
		return
	}
	switch label {
	case estCounterSuccessSimpleEnroll:
		c.successSimpleEnroll.Add(1)
	case estCounterSuccessSimpleReEnroll:
		c.successSimpleReEnroll.Add(1)
	case estCounterSuccessServerKeygen:
		c.successServerKeygen.Add(1)
	case estCounterAuthFailedBasic:
		c.authFailedBasic.Add(1)
	case estCounterAuthFailedMTLS:
		c.authFailedMTLS.Add(1)
	case estCounterAuthFailedChannelBind:
		c.authFailedChannelBind.Add(1)
	case estCounterCSRInvalid:
		c.csrInvalid.Add(1)
	case estCounterCSRPolicyViolation:
		c.csrPolicyViolation.Add(1)
	case estCounterCSRSignatureMismatch:
		c.csrSignatureMismatch.Add(1)
	case estCounterRateLimited:
		c.rateLimited.Add(1)
	case estCounterIssuerError:
		c.issuerError.Add(1)
	default:
		c.internalError.Add(1)
	}
}

// ESTStatsSnapshot is the per-profile observability view the admin
// GET endpoint renders. Mirrors IntuneStatsSnapshot's shape so the GUI
// can re-use the same counter-grid component.
//
// EST RFC 7030 hardening master bundle Phase 7.1.
type ESTStatsSnapshot struct {
	PathID          string               `json:"path_id"`
	IssuerID        string               `json:"issuer_id"`
	ProfileID       string               `json:"profile_id,omitempty"`
	Counters        map[string]uint64    `json:"counters"`
	MTLSEnabled     bool                 `json:"mtls_enabled"`
	BasicConfigured bool                 `json:"basic_auth_configured"`
	ServerKeygen    bool                 `json:"server_keygen_enabled"`
	TrustAnchors    []ESTTrustAnchorInfo `json:"trust_anchors,omitempty"`
	TrustAnchorPath string               `json:"trust_anchor_path,omitempty"`
	Now             time.Time            `json:"now"`
}

// ESTTrustAnchorInfo is the per-cert public summary of one trust anchor
// in the holder's pool. Same shape as IntuneTrustAnchorInfo.
type ESTTrustAnchorInfo struct {
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DaysToExpiry int       `json:"days_to_expiry"`
	Expired      bool      `json:"expired"`
}

// Stats returns the per-profile observability snapshot. Safe for
// concurrent callers — every counter access is atomic + the trust-
// anchor walk is a per-snapshot copy.
func (s *ESTService) Stats(now time.Time) ESTStatsSnapshot {
	out := ESTStatsSnapshot{
		PathID:          s.estPathIDForLog,
		IssuerID:        s.issuerID,
		ProfileID:       s.profileID,
		Counters:        s.counters.snapshot(),
		MTLSEnabled:     s.estMTLSConfigured,
		BasicConfigured: s.estBasicConfigured,
		ServerKeygen:    s.estServerKeygenEnabled,
		Now:             now,
	}
	if s.estTrustAnchor != nil {
		out.TrustAnchorPath = s.estTrustAnchor.Path()
		for _, c := range s.estTrustAnchor.Get() {
			daysToExpiry := int(c.NotAfter.Sub(now).Hours() / 24)
			out.TrustAnchors = append(out.TrustAnchors, ESTTrustAnchorInfo{
				Subject:      c.Subject.CommonName,
				NotBefore:    c.NotBefore,
				NotAfter:     c.NotAfter,
				DaysToExpiry: daysToExpiry,
				Expired:      now.After(c.NotAfter),
			})
		}
	}
	return out
}

// ReloadTrust forces a SIGHUP-equivalent reload of the per-profile
// EST mTLS trust anchor pool. Returns nil on success; the configured
// holder error otherwise (typically a parse error from a half-rotated
// bundle file). Mirror of SCEPService.ReloadIntuneTrust.
//
// Returns ErrESTMTLSDisabled when the profile doesn't have an mTLS
// trust anchor configured (admin handler maps to HTTP 409).
//
// Phase 11.3: emits AuditActionESTTrustAnchorReloaded on successful
// reload so operators have a typed grep target for "who rotated the
// trust bundle for which profile + when". The caller-supplied ctx is
// forwarded into RecordEvent so the audit row carries the same
// request-scoped trace identifiers as the rest of the admin pipeline,
// and so the contextcheck linter doesn't flag the admin handler for
// silently dropping its r.Context() at the service boundary.
func (s *ESTService) ReloadTrust(ctx context.Context) error {
	if s.estTrustAnchor == nil {
		return ErrESTMTLSDisabled
	}
	if err := s.estTrustAnchor.Reload(); err != nil {
		return err
	}
	if s.auditService != nil {
		details := map[string]interface{}{
			"path_id":           s.estPathIDForLog,
			"trust_anchor_path": s.estTrustAnchor.Path(),
			"protocol":          "EST",
		}
		_ = s.auditService.RecordEvent(ctx, "est-admin", "system",
			AuditActionESTTrustAnchorReloaded, "trust_anchor", s.estPathIDForLog, details)
	}
	return nil
}

// ErrESTMTLSDisabled signals the admin handler that an EST profile
// doesn't have mTLS configured. Maps to HTTP 409 Conflict.
var ErrESTMTLSDisabled = newESTAdminError("EST profile mTLS not enabled — no trust anchor to reload")

func newESTAdminError(msg string) error { return &estAdminError{msg: msg} }

type estAdminError struct{ msg string }

func (e *estAdminError) Error() string { return e.msg }

// SetESTAdminMetadata records the per-profile observability hints the
// AdminEST handler needs to render the Profiles tab. cmd/server/main.go
// invokes this once at startup with the data already in scope from the
// per-profile loop. Idempotent. Consolidated into one setter so the
// public surface stays narrow + every metadata field moves together.
func (s *ESTService) SetESTAdminMetadata(pathID string, mtlsEnabled, basicConfigured, serverKeygenEnabled bool, trustAnchor *trustanchor.Holder) {
	s.estPathIDForLog = pathID
	s.estMTLSConfigured = mtlsEnabled
	s.estBasicConfigured = basicConfigured
	s.estServerKeygenEnabled = serverKeygenEnabled
	s.estTrustAnchor = trustAnchor
}
