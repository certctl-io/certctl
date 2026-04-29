package service

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/scep/intune"
)

// SCEPService implements the SCEP (RFC 8894) enrollment protocol.
// It delegates certificate operations to an existing IssuerConnector and records
// enrollment events in the audit trail.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.3 + 8.4 + 8.7: per-profile
// Intune dynamic-challenge dispatcher (intuneEnabled+intuneTrust+...);
// audit action `scep_pkcsreq_intune` flows through the existing
// auditService; per-device rate limit + nil-default compliance hook seam.
//
// Lifecycle: a service instance per SCEP profile (Phase 1.5). The Intune
// fields are populated only on profiles where INTUNE_ENABLED=true; on the
// rest they're nil/empty and looksIntuneShaped short-circuits to the
// existing static-challenge path.
type SCEPService struct {
	issuer            IssuerConnector
	issuerID          string
	auditService      *AuditService
	logger            *slog.Logger
	profileID         string // optional: constrain enrollments to a specific profile
	profileRepo       repository.CertificateProfileRepository
	challengePassword string // shared secret for enrollment authentication

	// Intune dispatcher state (Phase 8.3+8.6+8.7). All nil/zero when this
	// profile has INTUNE_ENABLED=false; all populated when true. The
	// dispatcher in PKCSReq + PKCSReqWithEnvelope + RenewalReqWithEnvelope
	// gates on intuneEnabled before consulting any of these.
	intuneEnabled     bool
	intuneTrust       *intune.TrustAnchorHolder // SIGHUP-reloadable trust pool
	intuneAudience    string                    // expected "aud" claim; empty disables the check
	intuneValidity    time.Duration             // optional override on top of the challenge's exp
	intuneClockSkew   time.Duration             // ±tolerance applied to iat/exp; default 60s wired from config
	intuneReplayCache *intune.ReplayCache       // nonce-keyed; catches duplicate submission
	intuneRateLimiter *intune.PerDeviceRateLimiter
	complianceCheck   ComplianceCheck   // V3-Pro plug-in seam; nil-default no-op
	intuneCounters    *intuneCounterTab // per-status atomic counters for the admin endpoint
	pathID            string            // SCEP profile path ID; surfaced by admin endpoints

	// Per-profile metadata surfaced by the new /admin/scep/profiles
	// endpoint. SCEP RFC 8894 + Intune master bundle Phase 9 follow-up
	// (cowork/scep-gui-restructure-prompt.md). All fields are nil/zero
	// when the operator runs without Intune AND without mTLS — we still
	// surface the always-present challenge-password-set + RA cert
	// expiry on the Profiles tab for those.
	raCertSubject       string
	raCertNotBefore     time.Time
	raCertNotAfter      time.Time
	mtlsEnabled         bool
	mtlsTrustBundlePath string
}

// intuneCounterTab is the in-memory equivalent of the
// `certctl_scep_intune_enrollments_total{status="..."}` metric the
// master prompt's Phase 8.4 mentions. We don't take a Prometheus
// dependency here (the project doesn't currently expose /metrics; that's
// a separate decision); operators who want scraping can wrap these with
// a prom.Collector later. For Phase 9 the in-memory counters drive the
// admin GUI's "Intune Monitoring" tab via GET /api/v1/admin/scep/intune/stats.
//
// Concurrency: every field is read/written via sync/atomic so the
// dispatcher's hot path stays lock-free.
type intuneCounterTab struct {
	success         atomic.Uint64
	signatureFailed atomic.Uint64
	expired         atomic.Uint64
	notYetValid     atomic.Uint64
	wrongAudience   atomic.Uint64
	replay          atomic.Uint64
	unknownVersion  atomic.Uint64
	malformed       atomic.Uint64
	rateLimited     atomic.Uint64
	claimMismatch   atomic.Uint64
	complianceErr   atomic.Uint64
}

// snapshot returns a zero-allocation copy of the current counter values
// keyed by the same status labels intuneFailReason emits.
func (c *intuneCounterTab) snapshot() map[string]uint64 {
	if c == nil {
		return map[string]uint64{}
	}
	return map[string]uint64{
		"success":           c.success.Load(),
		"signature_invalid": c.signatureFailed.Load(),
		"expired":           c.expired.Load(),
		"not_yet_valid":     c.notYetValid.Load(),
		"wrong_audience":    c.wrongAudience.Load(),
		"replay":            c.replay.Load(),
		"unknown_version":   c.unknownVersion.Load(),
		"malformed":         c.malformed.Load(),
		"rate_limited":      c.rateLimited.Load(),
		"claim_mismatch":    c.claimMismatch.Load(),
		"compliance_failed": c.complianceErr.Load(),
	}
}

// inc advances the counter that matches the given fail-reason label
// (must be one of the strings intuneFailReason returns). Unknown labels
// fall through to "malformed" so an enum drift doesn't silently lose
// counts.
func (c *intuneCounterTab) inc(label string) {
	if c == nil {
		return
	}
	switch label {
	case "success":
		c.success.Add(1)
	case "signature_invalid":
		c.signatureFailed.Add(1)
	case "expired":
		c.expired.Add(1)
	case "not_yet_valid":
		c.notYetValid.Add(1)
	case "wrong_audience":
		c.wrongAudience.Add(1)
	case "replay":
		c.replay.Add(1)
	case "unknown_version":
		c.unknownVersion.Add(1)
	case "rate_limited":
		c.rateLimited.Add(1)
	case "claim_mismatch":
		c.claimMismatch.Add(1)
	case "compliance_failed":
		c.complianceErr.Add(1)
	default:
		c.malformed.Add(1)
	}
}

// IntuneTrustAnchorInfo is the per-cert public summary of one trust
// anchor in the holder's pool. Matches the shape the admin endpoint
// returns to the GUI.
type IntuneTrustAnchorInfo struct {
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DaysToExpiry int       `json:"days_to_expiry"`
	Expired      bool      `json:"expired"`
}

// IntuneStatsSnapshot is the per-profile observability view the admin
// GET endpoint hands back. SCEPService.IntuneStats() builds one of
// these on demand under no contention with the dispatcher hot path.
type IntuneStatsSnapshot struct {
	PathID             string                  `json:"path_id"`
	IssuerID           string                  `json:"issuer_id"`
	Enabled            bool                    `json:"enabled"`
	TrustAnchorPath    string                  `json:"trust_anchor_path,omitempty"`
	TrustAnchors       []IntuneTrustAnchorInfo `json:"trust_anchors,omitempty"`
	Audience           string                  `json:"audience,omitempty"`
	ChallengeValidity  time.Duration           `json:"challenge_validity_ns,omitempty"`
	ClockSkewTolerance time.Duration           `json:"clock_skew_tolerance_ns,omitempty"`
	RateLimitDisabled  bool                    `json:"rate_limit_disabled"`
	ReplayCacheSize    int                     `json:"replay_cache_size"`
	Counters           map[string]uint64       `json:"counters"`
	GeneratedAt        time.Time               `json:"generated_at"`
}

// SetPathID records the SCEP profile path ID this service instance
// serves. Admin endpoints surface the PathID per row so operators can
// triage which profile a stat or failure belongs to. Empty PathID maps
// to the legacy `/scep` root.
func (s *SCEPService) SetPathID(pathID string) { s.pathID = pathID }

// PathID returns the SCEP profile path ID this service serves. Empty
// for the legacy `/scep` root.
func (s *SCEPService) PathID() string { return s.pathID }

// IssuerID returns the issuer this service binds to. Useful for the
// admin endpoint's per-profile rendering.
func (s *SCEPService) IssuerID() string { return s.issuerID }

// IntuneStats returns the per-profile observability snapshot. Safe for
// concurrent callers; the snapshot is taken under no contention with
// the dispatcher hot path. Returns a zero-value snapshot with
// Enabled=false on profiles that never called SetIntuneIntegration.
//
// SCEP RFC 8894 + Intune master bundle Phase 9.1.
func (s *SCEPService) IntuneStats(now time.Time) IntuneStatsSnapshot {
	out := IntuneStatsSnapshot{
		PathID:      s.pathID,
		IssuerID:    s.issuerID,
		Enabled:     s.intuneEnabled,
		Counters:    s.intuneCounters.snapshot(),
		GeneratedAt: now.UTC(),
	}
	if !s.intuneEnabled {
		return out
	}
	out.Audience = s.intuneAudience
	out.ChallengeValidity = s.intuneValidity
	out.ClockSkewTolerance = s.intuneClockSkew
	if s.intuneRateLimiter != nil {
		out.RateLimitDisabled = s.intuneRateLimiter.Disabled()
	}
	if s.intuneReplayCache != nil {
		out.ReplayCacheSize = s.intuneReplayCache.Len()
	}
	if s.intuneTrust != nil {
		out.TrustAnchorPath = s.intuneTrust.Path()
		certs := s.intuneTrust.Get()
		out.TrustAnchors = make([]IntuneTrustAnchorInfo, 0, len(certs))
		for _, c := range certs {
			info := IntuneTrustAnchorInfo{
				Subject:   c.Subject.CommonName,
				NotBefore: c.NotBefore,
				NotAfter:  c.NotAfter,
				Expired:   now.After(c.NotAfter),
			}
			if !info.Expired {
				info.DaysToExpiry = int(c.NotAfter.Sub(now).Hours() / 24)
			}
			out.TrustAnchors = append(out.TrustAnchors, info)
		}
	}
	return out
}

// ReloadIntuneTrust triggers the same Reload the SIGHUP watcher would
// run. Returns the parse error if the new file is invalid; the OLD
// pool stays in place (TrustAnchorHolder.Reload's documented
// fail-safe). Returns a typed error when this profile has Intune
// disabled so the admin endpoint can surface a 400 / 409.
//
// SCEP RFC 8894 + Intune master bundle Phase 9.2.
func (s *SCEPService) ReloadIntuneTrust() error {
	if !s.intuneEnabled || s.intuneTrust == nil {
		return ErrSCEPProfileIntuneDisabled
	}
	return s.intuneTrust.Reload()
}

// SetRACert records the RA cert metadata the admin Profiles endpoint
// surfaces (subject + NotBefore + NotAfter for the expiry countdown).
// Called from cmd/server/main.go right after loadSCEPRAPair returns the
// leaf cert. Nil-safe — passing nil leaves the fields zero-valued so
// the snapshot's RACertSubject is empty (the GUI then renders
// "RA cert not loaded").
//
// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up.
func (s *SCEPService) SetRACert(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	s.raCertSubject = cert.Subject.CommonName
	s.raCertNotBefore = cert.NotBefore
	s.raCertNotAfter = cert.NotAfter
}

// SetMTLSConfig records this profile's mTLS sibling-route status for
// the admin Profiles endpoint. The trust bundle PATH is surfaced (not
// the bundle contents) so operators can correlate against their own
// secret manager / file system audit. Called from cmd/server/main.go
// in the per-profile loop, parallel to SetIntuneIntegration.
//
// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up.
func (s *SCEPService) SetMTLSConfig(enabled bool, bundlePath string) {
	s.mtlsEnabled = enabled
	s.mtlsTrustBundlePath = bundlePath
}

// SCEPProfileStatsSnapshot is the per-profile observability shape the
// new /admin/scep/profiles endpoint emits. Surfaces every always-
// present per-profile field PLUS an optional Intune sub-block.
// Profiles that don't have Intune enabled get Intune=nil (the GUI
// renders the lean per-profile card without the Intune deep-dive
// button).
//
// Distinct from IntuneStatsSnapshot (which the existing
// /admin/scep/intune/stats endpoint emits) so the existing endpoint's
// JSON shape stays byte-stable for external consumers — backward
// compatibility for the Phase 9 admin contract.
//
// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up
// (cowork/scep-gui-restructure-prompt.md).
type SCEPProfileStatsSnapshot struct {
	// Always-present per-profile fields.
	PathID               string    `json:"path_id"`
	IssuerID             string    `json:"issuer_id"`
	ChallengePasswordSet bool      `json:"challenge_password_set"`
	RACertSubject        string    `json:"ra_cert_subject,omitempty"`
	RACertNotBefore      time.Time `json:"ra_cert_not_before,omitempty"`
	RACertNotAfter       time.Time `json:"ra_cert_not_after,omitempty"`
	RACertDaysToExpiry   int       `json:"ra_cert_days_to_expiry"`
	RACertExpired        bool      `json:"ra_cert_expired"`
	MTLSEnabled          bool      `json:"mtls_enabled"`
	MTLSTrustBundlePath  string    `json:"mtls_trust_bundle_path,omitempty"`
	GeneratedAt          time.Time `json:"generated_at"`

	// Optional Intune sub-block; nil when this profile has Intune
	// disabled. Mirrors the IntuneStatsSnapshot fields minus the
	// always-present per-profile ones (which now live on the parent).
	Intune *IntuneSection `json:"intune,omitempty"`
}

// IntuneSection is the Intune-specific data a per-profile snapshot
// carries when INTUNE_ENABLED=true. Same fields as IntuneStatsSnapshot
// minus the always-present per-profile ones (PathID, IssuerID,
// GeneratedAt) which live on SCEPProfileStatsSnapshot.
type IntuneSection struct {
	TrustAnchorPath    string                  `json:"trust_anchor_path,omitempty"`
	TrustAnchors       []IntuneTrustAnchorInfo `json:"trust_anchors,omitempty"`
	Audience           string                  `json:"audience,omitempty"`
	ChallengeValidity  time.Duration           `json:"challenge_validity_ns,omitempty"`
	ClockSkewTolerance time.Duration           `json:"clock_skew_tolerance_ns,omitempty"`
	RateLimitDisabled  bool                    `json:"rate_limit_disabled"`
	ReplayCacheSize    int                     `json:"replay_cache_size"`
	Counters           map[string]uint64       `json:"counters"`
}

// ProfileStats returns the per-profile observability snapshot in the
// new shape (always-present fields + optional Intune sub-block).
// Safe for concurrent callers; reads only; uses the same atomic
// counter snapshots as IntuneStats.
//
// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up.
func (s *SCEPService) ProfileStats(now time.Time) SCEPProfileStatsSnapshot {
	out := SCEPProfileStatsSnapshot{
		PathID:               s.pathID,
		IssuerID:             s.issuerID,
		ChallengePasswordSet: s.challengePassword != "",
		RACertSubject:        s.raCertSubject,
		RACertNotBefore:      s.raCertNotBefore,
		RACertNotAfter:       s.raCertNotAfter,
		MTLSEnabled:          s.mtlsEnabled,
		MTLSTrustBundlePath:  s.mtlsTrustBundlePath,
		GeneratedAt:          now.UTC(),
	}
	if !s.raCertNotAfter.IsZero() {
		out.RACertExpired = now.After(s.raCertNotAfter)
		if !out.RACertExpired {
			out.RACertDaysToExpiry = int(s.raCertNotAfter.Sub(now).Hours() / 24)
		}
	}
	if !s.intuneEnabled {
		return out
	}
	intuneSection := IntuneSection{
		Audience:           s.intuneAudience,
		ChallengeValidity:  s.intuneValidity,
		ClockSkewTolerance: s.intuneClockSkew,
		Counters:           s.intuneCounters.snapshot(),
	}
	if s.intuneRateLimiter != nil {
		intuneSection.RateLimitDisabled = s.intuneRateLimiter.Disabled()
	}
	if s.intuneReplayCache != nil {
		intuneSection.ReplayCacheSize = s.intuneReplayCache.Len()
	}
	if s.intuneTrust != nil {
		intuneSection.TrustAnchorPath = s.intuneTrust.Path()
		certs := s.intuneTrust.Get()
		intuneSection.TrustAnchors = make([]IntuneTrustAnchorInfo, 0, len(certs))
		for _, c := range certs {
			info := IntuneTrustAnchorInfo{
				Subject:   c.Subject.CommonName,
				NotBefore: c.NotBefore,
				NotAfter:  c.NotAfter,
				Expired:   now.After(c.NotAfter),
			}
			if !info.Expired {
				info.DaysToExpiry = int(c.NotAfter.Sub(now).Hours() / 24)
			}
			intuneSection.TrustAnchors = append(intuneSection.TrustAnchors, info)
		}
	}
	out.Intune = &intuneSection
	return out
}

// ErrSCEPProfileIntuneDisabled is returned by ReloadIntuneTrust when
// invoked on a profile that has Intune turned off. Lets the admin
// handler distinguish "operator targeted the wrong profile" (HTTP 409)
// from "trust anchor file is broken" (HTTP 500 + the underlying
// parse-error string).
var ErrSCEPProfileIntuneDisabled = errors.New("scep profile: intune dispatcher not enabled")

// the once + mu fields keep IntuneStats accessor lookup-stable in case
// future refactors add background mutators of intuneCounters; both are
// currently unused by the runtime path.
var _ = sync.Once{}

// ComplianceCheck is the optional gate that pings Intune's compliance API
// (or any custom policy backend) to confirm the device is in good standing
// before issuing a cert. When nil (the V2-free default), the gate is a
// no-op and enrollments proceed solely on challenge validation +
// claim-binding + replay + per-device rate limit.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.7 — V3-Pro plug-in seam.
//
// V3-Pro plugs in here via a new module that calls Microsoft Graph's
// /deviceManagement/managedDevices/{id}/compliancePolicyStates endpoint
// (or equivalent), wires SetComplianceCheck on the service, and
// short-circuits non-compliant device enrollments with a SCEP CertRep
// FAILURE/badRequest plus a compliance_failed audit event + metric.
//
// Return contract:
//
//   - compliant=true,  err=nil   → proceed with enrollment.
//   - compliant=false, err=nil   → CertRep FAILURE + compliance_failed metric;
//     the reason string flows into the audit event for ops triage.
//   - compliant=*,     err!=nil  → fail-safe (deny) by default; the V3-Pro
//     module is responsible for a more nuanced "permit on API failure"
//     mode if its policy demands one.
//
// Leaving the hook here means the V3-Pro work is plug-in code, not a
// dispatcher refactor. The cost today is one struct field + one setter +
// one nil-guarded call site. Zero behavior change in V2.
type ComplianceCheck func(ctx context.Context, claim *intune.ChallengeClaim) (compliant bool, reason string, err error)

// SetComplianceCheck installs the V3-Pro compliance gate. Idempotent;
// passing nil re-disables the gate (useful for tests + the rare case where
// V3-Pro plugin code wants to drop the gate at runtime). Safe to call
// before or after the service starts serving requests.
func (s *SCEPService) SetComplianceCheck(fn ComplianceCheck) { s.complianceCheck = fn }

// SetIntuneIntegration wires the per-profile Intune dispatcher onto the
// service. Pass enabled=false (with nil/zero values for the rest) to
// explicitly opt this profile out of Intune mode; pass enabled=true with
// a populated trust holder + replay cache + rate limiter to opt in. The
// audience is allowed to be empty (the validator's audience check then
// becomes a no-op, useful for proxy/load-balancer scenarios where the URL
// the Connector saw differs from the URL we see).
//
// Constructor-time injection (rather than NewSCEPService extra params)
// keeps the surface stable for the existing callers + lets the wire-in
// at cmd/server/main.go construct the holder + cache + limiter once and
// share them across profiles cleanly. Profiles where INTUNE_ENABLED=false
// simply never call this method.
func (s *SCEPService) SetIntuneIntegration(
	trust *intune.TrustAnchorHolder,
	audience string,
	validity time.Duration,
	clockSkew time.Duration,
	replayCache *intune.ReplayCache,
	rateLimiter *intune.PerDeviceRateLimiter,
) {
	s.intuneEnabled = true
	s.intuneTrust = trust
	s.intuneAudience = audience
	s.intuneValidity = validity
	s.intuneClockSkew = clockSkew
	s.intuneReplayCache = replayCache
	s.intuneRateLimiter = rateLimiter
	if s.intuneCounters == nil {
		s.intuneCounters = &intuneCounterTab{}
	}
}

// IntuneEnabled reports whether this service instance is wired for Intune
// dynamic-challenge dispatch. Useful for handler-layer gating + admin
// endpoints (Phase 9 GUI surface). Always returns false on profiles where
// SetIntuneIntegration was never called.
func (s *SCEPService) IntuneEnabled() bool { return s.intuneEnabled }

// looksIntuneShaped is the fast pre-check that distinguishes an
// Intune-format challenge from a static challenge password. Intune
// challenges are JWT-like (three base64url segments separated by dots,
// total length > 200 bytes for any reasonable claim payload). Static
// challenges are typically ≤ 64 bytes ASCII.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.3.
//
// The heuristic is allowed to false-positive (the validator catches
// malformed input → ErrChallengeMalformed), but it MUST NOT false-negative
// on real Intune challenges — that would route an Intune challenge to the
// constant-time static compare and reject every enrollment. Hence the
// generous length threshold (real Intune challenges are typically
// >800 bytes; the 200 floor is well below the smallest plausible v1
// payload + signature).
func looksIntuneShaped(s string) bool {
	if len(s) <= 200 {
		return false
	}
	return strings.Count(s, ".") == 2
}

// intuneFailReason maps a typed Intune error to the metric label used in
// `certctl_scep_intune_enrollments_total{status="..."}`. Defaults to
// "malformed" so a previously-unseen error category still surfaces in
// the metric (with a follow-up to add a typed branch here).
func intuneFailReason(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, intune.ErrChallengeSignature):
		return "signature_invalid"
	case errors.Is(err, intune.ErrChallengeExpired):
		return "expired"
	case errors.Is(err, intune.ErrChallengeNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, intune.ErrChallengeWrongAudience):
		return "wrong_audience"
	case errors.Is(err, intune.ErrChallengeReplay):
		return "replay"
	case errors.Is(err, intune.ErrChallengeUnknownVersion):
		return "unknown_version"
	case errors.Is(err, intune.ErrChallengeMalformed):
		return "malformed"
	case errors.Is(err, intune.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, intune.ErrClaimCNMismatch),
		errors.Is(err, intune.ErrClaimSANDNSMismatch),
		errors.Is(err, intune.ErrClaimSANRFC822Mismatch),
		errors.Is(err, intune.ErrClaimSANUPNMismatch):
		return "claim_mismatch"
	default:
		return "malformed"
	}
}

// intuneEnrollOutcome is the envelope the dispatcher hands back to its two
// callers (PKCSReq's MVP path + PKCSReqWithEnvelope/RenewalReqWithEnvelope's
// RFC 8894 path). It carries enough to short-circuit OR continue to the
// existing processEnrollment flow:
//
//   - decided=false → not Intune-shaped (or Intune disabled); fall through
//     to the static-challenge path.
//   - decided=true, err=nil → Intune validation passed; the caller MUST
//     call processEnrollment with auditAction="scep_pkcsreq_intune".
//   - decided=true, err!=nil → Intune validation failed; the caller MUST
//     short-circuit with the typed error (handler maps to FailInfo).
type intuneEnrollOutcome struct {
	decided bool
	claim   *intune.ChallengeClaim
	err     error
}

// dispatchIntuneChallenge runs the full Intune validation pipeline for a
// single PKCSReq invocation: shape check → ValidateChallenge → DeviceMatchesCSR
// → replay-cache CheckAndInsert → per-device rate limit → optional
// compliance check. Each failure leg increments the appropriate metric
// label + emits an audit-friendly Warn log line. Returns an outcome that
// tells the caller whether to short-circuit or continue to enrollment.
//
// Splitting the dispatcher out of PKCSReq* keeps the three call sites
// (PKCSReq, PKCSReqWithEnvelope, RenewalReqWithEnvelope) consistent — every
// path through the Intune mode runs through the same gate sequence so an
// operator gets the same audit shape regardless of which SCEP message
// type the device sent.
//
// Phase 9.1: every typed return path also bumps the per-status atomic
// counter on s.intuneCounters so the admin GUI's stats endpoint reflects
// real enrollment traffic. The success path bumps "success" once when
// the outer caller invokes processEnrollment — see PKCSReq below.
func (s *SCEPService) dispatchIntuneChallenge(ctx context.Context, csrPEM string, challengePassword string, transactionID string) intuneEnrollOutcome {
	if !s.intuneEnabled || !looksIntuneShaped(challengePassword) {
		return intuneEnrollOutcome{decided: false}
	}
	if s.intuneTrust == nil {
		// Defensive: enabled bit was flipped without wiring the trust
		// holder. Treat as a hard failure so the operator sees it
		// instead of silently falling through to the static path.
		s.logger.Error("SCEP enrollment rejected: Intune mode enabled but no trust anchor holder wired",
			"transaction_id", transactionID)
		s.intuneCounters.inc("signature_invalid")
		return intuneEnrollOutcome{decided: true, err: intune.ErrChallengeSignature}
	}

	now := time.Now()
	trust := s.intuneTrust.Get()

	claim, err := intune.ValidateChallenge(challengePassword, intune.ValidateOptions{
		Trust:              trust,
		ExpectedAudience:   s.intuneAudience,
		Now:                now,
		ClockSkewTolerance: s.intuneClockSkew,
	})
	if err != nil {
		s.logger.Warn("SCEP enrollment rejected: Intune challenge validation failed",
			"transaction_id", transactionID, "reason", intuneFailReason(err), "error", err)
		s.intuneCounters.inc(intuneFailReason(err))
		return intuneEnrollOutcome{decided: true, err: err}
	}

	// Defense-in-depth validity cap on top of the challenge's own iat/exp.
	// When intuneValidity is non-zero, the challenge's iat must be within
	// (now - intuneValidity, now]; an old-but-not-yet-expired challenge
	// (per the Connector's exp claim) gets rejected here.
	if s.intuneValidity > 0 && !claim.IssuedAt.IsZero() && now.Sub(claim.IssuedAt) > s.intuneValidity {
		err := fmt.Errorf("%w: iat=%s exceeds operator-configured validity cap %s",
			intune.ErrChallengeExpired, claim.IssuedAt.Format(time.RFC3339), s.intuneValidity)
		s.logger.Warn("SCEP enrollment rejected: Intune challenge older than operator validity cap",
			"transaction_id", transactionID, "error", err)
		s.intuneCounters.inc("expired")
		return intuneEnrollOutcome{decided: true, err: err}
	}

	// Bind claim ↔ CSR before consuming the replay-cache slot. If the CSR
	// doesn't match the claim, we don't want to mark the nonce as seen
	// (the next legitimate retry should still work).
	csr, perr := parseCSRForIntune(csrPEM)
	if perr != nil {
		s.logger.Warn("SCEP enrollment rejected: CSR parse failed during Intune dispatch",
			"transaction_id", transactionID, "error", perr)
		// CSR parse failure surfaces as a "malformed" intune metric label
		// (the wrapping helps the audit log distinguish it from a
		// challenge-malformed failure).
		s.intuneCounters.inc("malformed")
		return intuneEnrollOutcome{decided: true, err: fmt.Errorf("%w: CSR parse: %v", intune.ErrChallengeMalformed, perr)}
	}
	if mErr := claim.DeviceMatchesCSR(csr); mErr != nil {
		s.logger.Warn("SCEP enrollment rejected: Intune claim does not match CSR",
			"transaction_id", transactionID, "error", mErr)
		s.intuneCounters.inc("claim_mismatch")
		return intuneEnrollOutcome{decided: true, err: mErr}
	}

	// Replay protection — runs AFTER claim validation + CSR binding so a
	// failed validation doesn't burn a replay slot on a legitimate retry.
	if s.intuneReplayCache != nil && claim.Nonce != "" {
		if !s.intuneReplayCache.CheckAndInsert(claim.Nonce, now) {
			err := fmt.Errorf("%w: nonce=%q", intune.ErrChallengeReplay, claim.Nonce)
			s.logger.Warn("SCEP enrollment rejected: Intune challenge nonce replay",
				"transaction_id", transactionID, "subject", claim.Subject)
			s.intuneCounters.inc("replay")
			return intuneEnrollOutcome{decided: true, err: err}
		}
	}

	// Per-device rate limit — second line of defense against a compromised
	// Connector signing key issuing many DIFFERENT valid challenges for
	// the same device.
	if s.intuneRateLimiter != nil {
		if rlErr := s.intuneRateLimiter.Allow(claim.Subject, claim.Issuer, now); rlErr != nil {
			s.logger.Warn("SCEP enrollment rejected: Intune per-device rate limit exceeded",
				"transaction_id", transactionID, "subject", claim.Subject, "issuer", claim.Issuer)
			s.intuneCounters.inc("rate_limited")
			return intuneEnrollOutcome{decided: true, err: rlErr}
		}
	}

	// Optional V3-Pro compliance hook (nil-default no-op in V2). Runs LAST
	// so we don't ping the compliance API for requests we'd reject anyway.
	if s.complianceCheck != nil {
		compliant, reason, cerr := s.complianceCheck(ctx, claim)
		if cerr != nil {
			s.logger.Error("Intune compliance check returned error; failing closed",
				"transaction_id", transactionID, "subject", claim.Subject, "error", cerr)
			s.intuneCounters.inc("compliance_failed")
			return intuneEnrollOutcome{decided: true, err: fmt.Errorf("intune compliance check: %w", cerr)}
		}
		if !compliant {
			s.logger.Warn("SCEP enrollment rejected: device non-compliant per Intune compliance check",
				"transaction_id", transactionID, "subject", claim.Subject, "reason", reason)
			s.intuneCounters.inc("compliance_failed")
			return intuneEnrollOutcome{decided: true, err: fmt.Errorf("intune compliance: %s", reason)}
		}
	}

	// Success leg — increment the success counter so the admin GUI's
	// stats endpoint reflects every legitimate enrollment. The actual
	// processEnrollment call is made by the caller (PKCSReq* /
	// RenewalReqWithEnvelope); we credit success here so a downstream
	// processEnrollment failure (issuer connector outage, etc.) doesn't
	// double-count — that's a separate non-Intune metric.
	s.intuneCounters.inc("success")
	return intuneEnrollOutcome{decided: true, claim: claim}
}

// parseCSRForIntune is a thin wrapper around encoding/pem + x509 that the
// dispatcher uses for the claim ↔ CSR binding check. Kept private + named
// for grepability so a future refactor can swap the parse strategy without
// touching the dispatcher.
func parseCSRForIntune(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

// NewSCEPService creates a new SCEPService for the given issuer connector.
func NewSCEPService(issuerID string, issuer IssuerConnector, auditService *AuditService, logger *slog.Logger, challengePassword string) *SCEPService {
	return &SCEPService{
		issuer:            issuer,
		issuerID:          issuerID,
		auditService:      auditService,
		logger:            logger,
		challengePassword: challengePassword,
	}
}

// SetProfileID constrains SCEP enrollments to a specific certificate profile.
func (s *SCEPService) SetProfileID(profileID string) {
	s.profileID = profileID
}

// SetProfileRepo sets the profile repository for crypto policy enforcement during enrollment.
func (s *SCEPService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// GetCACaps returns the capabilities of this SCEP server.
// RFC 8894 Section 3.5.2: GetCACaps returns a list of capabilities, one per line.
//
// SCEP RFC 8894 + Intune master bundle Phase 5.1: extended from the
// initial value (POSTPKIOperation+SHA-256+AES+SCEPStandard) to additionally
// advertise SHA-512 (now-implemented modern digest alternative) and Renewal
// (the messageType-17 dispatch from Phase 4). ChromeOS specifically looks
// for these capabilities to negotiate the strongest available cipher +
// digest combo. Order is by historical convention; clients walk the list
// linearly.
func (s *SCEPService) GetCACaps(ctx context.Context) string {
	return "POSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\nRenewal\n"
}

// GetCACert returns the PEM-encoded CA certificate chain for this SCEP server.
// RFC 8894 Section 3.5.1: GetCACert distributes the CA certificate(s).
func (s *SCEPService) GetCACert(ctx context.Context) (string, error) {
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates from issuer %s: %w", s.issuerID, err)
	}
	if caPEM == "" {
		return "", fmt.Errorf("issuer %s does not provide CA certificates for SCEP", s.issuerID)
	}
	return caPEM, nil
}

// PKCSReq processes a SCEP enrollment request.
// RFC 8894 Section 3.3.1: PKCSReq contains a PKCS#10 CSR for certificate enrollment.
// The CSR PEM and challenge password are extracted by the handler from the PKCS#7 envelope.
//
// H-2 fix (CWE-306): the previous implementation skipped the shared-secret
// check entirely when s.challengePassword was empty, meaning any unauthenticated
// client that could reach /scep could enroll a CSR against the configured
// issuer. Reject that configuration defense-in-depth even though main() already
// refuses to start in the same state (see preflightSCEPChallengePassword). The
// non-empty branch now uses crypto/subtle.ConstantTimeCompare to avoid leaking
// the shared secret through a response-time side channel.
func (s *SCEPService) PKCSReq(ctx context.Context, csrPEM string, challengePassword string, transactionID string) (*domain.SCEPEnrollResult, error) {
	// SCEP RFC 8894 + Intune master bundle Phase 8.3: try the Intune
	// dispatcher first. When it returns decided=true the service has
	// already made the call (success or typed failure); when decided=false
	// we fall through to the existing static-challenge path. The
	// dispatcher gates internally on intuneEnabled + looksIntuneShaped,
	// so this is a free no-op for profiles where Intune is disabled.
	if outcome := s.dispatchIntuneChallenge(ctx, csrPEM, challengePassword, transactionID); outcome.decided {
		if outcome.err != nil {
			return nil, fmt.Errorf("intune challenge: %w", outcome.err)
		}
		return s.processEnrollment(ctx, csrPEM, transactionID, "scep_pkcsreq_intune")
	}

	// Defense-in-depth: refuse any enrollment when no shared secret is
	// configured. The server-level pre-flight check in cmd/server/main.go
	// normally prevents the service from being constructed in this state, but
	// this branch also protects future call sites (tests, library reuse, a
	// future REST-over-HTTPS wrapper) from silently accepting unauthenticated
	// CSRs.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP enrollment rejected: server has no challenge password configured",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("SCEP challenge password not configured on server")
	}
	// Constant-time compare avoids leaking the configured secret through
	// response-time variance. ConstantTimeCompare returns 1 only when both
	// slices have equal length AND equal content; a mismatched-length input
	// still takes the same path as a content mismatch.
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP enrollment rejected: invalid challenge password",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("invalid challenge password")
	}

	return s.processEnrollment(ctx, csrPEM, transactionID, "scep_pkcsreq")
}

// processEnrollment handles the common enrollment logic.
func (s *SCEPService) processEnrollment(ctx context.Context, csrPEM string, transactionID string, auditAction string) (*domain.SCEPEnrollResult, error) {
	// Parse the CSR to extract CN and SANs
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	commonName := csr.Subject.CommonName
	if commonName == "" {
		return nil, fmt.Errorf("CSR must include a Common Name")
	}

	// Collect SANs
	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range csr.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	// Validate CSR key algorithm/size against profile (crypto policy enforcement)
	var profile *domain.CertificateProfile
	var ekus []string
	if s.profileID != "" && s.profileRepo != nil {
		if p, profileErr := s.profileRepo.Get(ctx, s.profileID); profileErr == nil && p != nil {
			profile = p
			ekus = profile.AllowedEKUs
		}
	}
	if _, csrErr := ValidateCSRAgainstProfile(csrPEM, profile); csrErr != nil {
		s.logger.Error("SCEP enrollment rejected: crypto policy violation",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", csrErr)
		return nil, fmt.Errorf("SCEP enrollment rejected: %w", csrErr)
	}

	s.logger.Info("SCEP enrollment request",
		"action", auditAction,
		"common_name", commonName,
		"sans", strings.Join(sans, ","),
		"transaction_id", transactionID,
		"issuer", s.issuerID)

	// Resolve MaxTTL + must-staple from profile.
	// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: thread
	// profile.MustStaple through to the issuer so the local issuer can
	// add the RFC 7633 id-pe-tlsfeature extension. Without this read the
	// CertificateProfile.MustStaple field would be a stored-but-ignored
	// "lying field" that operators set without behavior change.
	var (
		maxTTLSeconds int
		mustStaple    bool
	)
	if profile != nil {
		maxTTLSeconds = profile.MaxTTLSeconds
		mustStaple = profile.MustStaple
	}

	// Issue the certificate via the configured issuer connector
	// SCEP enrollments use profile EKUs if available, otherwise default (serverAuth + clientAuth fallback)
	result, err := s.issuer.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
	if err != nil {
		s.logger.Error("SCEP enrollment failed",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", err)
		return nil, fmt.Errorf("certificate issuance failed: %w", err)
	}

	// Audit the enrollment
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name":    commonName,
			"sans":           sans,
			"issuer_id":      s.issuerID,
			"serial":         result.Serial,
			"transaction_id": transactionID,
			"protocol":       "SCEP",
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "scep-client", "system", auditAction, "certificate", result.Serial, details)
	}

	s.logger.Info("SCEP enrollment successful",
		"action", auditAction,
		"common_name", commonName,
		"serial", result.Serial,
		"transaction_id", transactionID,
		"not_after", result.NotAfter)

	return &domain.SCEPEnrollResult{
		CertPEM:  result.CertPEM,
		ChainPEM: result.ChainPEM,
	}, nil
}

// PKCSReqWithEnvelope processes a SCEP PKCSReq from the RFC 8894 path
// (where the handler successfully parsed an EnvelopedData + signerInfo
// instead of the MVP raw-CSR path).
//
// SCEP RFC 8894 + Intune master bundle Phase 2.4.
//
// Returns *SCEPResponseEnvelope (not error + *SCEPEnrollResult) because
// RFC 8894 mandates a CertRep PKIMessage on every PKIOperation request,
// even failure cases — the handler shouldn't have to translate Go errors
// into SCEP failInfo codes; the service does that mapping.
//
// Service-side error → failInfo mapping (from the prompt's exact table):
//
//	Invalid challenge password    → caller returns HTTP 403, NOT a PKIMessage
//	                                (RFC 8894 §3.3.1 silent on this; matches MVP precedent)
//	CSR parse failure             → BadRequest (2)
//	CSR signature invalid         → BadMessageCheck (1)
//	Crypto policy violation       → BadAlg (0)
//	Issuer connector failure      → BadRequest (2)
//	Audit-log write failure       → log + continue with success (best-effort)
//
// The challenge-password failure case returns nil to signal "let the caller
// translate to 403"; every other failure mode returns a populated envelope
// with FailInfo set so the handler can build a CertRep with pkiStatus=2.
func (s *SCEPService) PKCSReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	resp := &domain.SCEPResponseEnvelope{
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}

	// SCEP RFC 8894 + Intune master bundle Phase 8.3: same dispatcher as
	// PKCSReq, applied to the RFC 8894 path. The dispatcher runs AFTER the
	// EnvelopedData decryption + POPO verification (handler-side, before
	// the service is invoked) but BEFORE the static-challenge fallback. On
	// Intune-validation failure the response envelope carries a typed
	// FailInfo so the CertRep wire shape is preserved (RFC 8894 §3.3).
	if outcome := s.dispatchIntuneChallenge(ctx, csrPEM, challengePassword, envelope.TransactionID); outcome.decided {
		if outcome.err != nil {
			resp.Status = domain.SCEPStatusFailure
			resp.FailInfo = mapIntuneErrorToFailInfo(outcome.err)
			return resp
		}
		result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_pkcsreq_intune")
		if err != nil {
			resp.Status = domain.SCEPStatusFailure
			resp.FailInfo = mapServiceErrorToFailInfo(err)
			return resp
		}
		resp.Status = domain.SCEPStatusSuccess
		resp.Result = result
		return resp
	}

	// Defense-in-depth: refuse any enrollment when no shared secret is
	// configured. Mirrors PKCSReq's gate. Returning nil signals 'let the
	// caller translate to HTTP 403' — the existing PKCSReq path returns
	// an error string the handler matched on, but PKCSReqWithEnvelope
	// returns *SCEPResponseEnvelope so we use a nil sentinel.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP enrollment rejected: server has no challenge password configured (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP enrollment rejected: invalid challenge password (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}

	// Reuse the existing processEnrollment for the actual issuance work.
	// Errors mapped to SCEP failInfo per the table above.
	result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_pkcsreq")
	if err != nil {
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = mapServiceErrorToFailInfo(err)
		return resp
	}
	resp.Status = domain.SCEPStatusSuccess
	resp.Result = result
	return resp
}

// mapIntuneErrorToFailInfo maps a typed Intune-validation error to the
// SCEP failInfo code RFC 8894 §3.2.1.4.5 enumerates. Mapping rationale:
//
//   - Signature / replay / wrong-audience / expired / not-yet-valid →
//     BadMessageCheck (the request didn't pass integrity / freshness
//     checks; same wire shape as a tampered EnvelopedData).
//   - Claim mismatches (CN / SAN-DNS / SAN-RFC822 / SAN-UPN) → BadRequest
//     (the request was well-formed and signed but the asserted identity
//     doesn't match what the device actually requested).
//   - Rate-limited / unknown-version → BadRequest (no better wire-level
//     code; the audit log carries the exact reason).
//   - Malformed → BadRequest.
//   - Compliance failure → BadRequest (V3-Pro can swap to a more
//     specific code if it cares).
func mapIntuneErrorToFailInfo(err error) domain.SCEPFailInfo {
	if err == nil {
		return domain.SCEPFailBadRequest
	}
	switch {
	case errors.Is(err, intune.ErrChallengeSignature),
		errors.Is(err, intune.ErrChallengeExpired),
		errors.Is(err, intune.ErrChallengeNotYetValid),
		errors.Is(err, intune.ErrChallengeWrongAudience),
		errors.Is(err, intune.ErrChallengeReplay):
		return domain.SCEPFailBadMessageCheck
	case errors.Is(err, intune.ErrClaimCNMismatch),
		errors.Is(err, intune.ErrClaimSANDNSMismatch),
		errors.Is(err, intune.ErrClaimSANRFC822Mismatch),
		errors.Is(err, intune.ErrClaimSANUPNMismatch):
		return domain.SCEPFailBadRequest
	default:
		return domain.SCEPFailBadRequest
	}
}

// mapServiceErrorToFailInfo translates a service-layer error into the
// SCEP failInfo code RFC 8894 §3.2.1.4.5 enumerates. The mapping mirrors
// the table in PKCSReqWithEnvelope's docblock; defaults to BadRequest
// when the error doesn't match any specific category.
func mapServiceErrorToFailInfo(err error) domain.SCEPFailInfo {
	if err == nil {
		return domain.SCEPFailBadRequest
	}
	msg := err.Error()
	switch {
	case containsAnyOf(msg, "invalid CSR PEM", "failed to parse CSR"):
		return domain.SCEPFailBadRequest
	case containsAnyOf(msg, "CSR signature verification failed"):
		return domain.SCEPFailBadMessageCheck
	case containsAnyOf(msg, "key algorithm", "key size", "algorithm not allowed", "crypto policy"):
		return domain.SCEPFailBadAlg
	default:
		return domain.SCEPFailBadRequest
	}
}

func containsAnyOf(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// RenewalReqWithEnvelope processes a SCEP RenewalReq from the RFC 8894 path.
// RFC 8894 §3.3.1.2 — re-enrollment with an existing valid cert. Distinct
// from PKCSReq because the signerInfo is signed by the EXISTING cert
// (proving possession), not by a transient self-signed device key.
//
// SCEP RFC 8894 + Intune master bundle Phase 4.2.
//
// Functionally identical to PKCSReqWithEnvelope but with two differences:
//
//  1. Audit action is `scep_renewalreq` (vs `scep_pkcsreq`) — operators
//     can grep the audit log to distinguish initial enrollments from
//     renewals.
//
//  2. The signing cert presented as POPO MUST chain to the issuer's CA
//     (the cert was previously issued by THIS issuer, not a self-signed
//     throwaway). Verified against the issuer's GetCACertPEM chain via
//     x509.Certificate.Verify. A signing cert that doesn't chain is
//     mapped to BadMessageCheck per the same RFC 8894 §3.3.2.2 semantics
//     as an EnvelopedData decrypt failure (integrity-check failure).
//
// Returns *SCEPResponseEnvelope (same contract as PKCSReqWithEnvelope);
// nil signals 'invalid challenge password' for HTTP 403 translation.
func (s *SCEPService) RenewalReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	resp := &domain.SCEPResponseEnvelope{
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}

	// SCEP RFC 8894 + Intune master bundle Phase 8.3: Intune dispatcher
	// applies to RenewalReq too. The chain-validation gate further down
	// stays in place — Intune-managed devices still need to present a
	// previously-issued cert as POPO when re-enrolling. The Intune
	// validator covers "is this a legitimate Intune challenge?" and the
	// chain check covers "did this device hold a prior cert from this
	// issuer?" — both must pass.
	if outcome := s.dispatchIntuneChallenge(ctx, csrPEM, challengePassword, envelope.TransactionID); outcome.decided {
		if outcome.err != nil {
			resp.Status = domain.SCEPStatusFailure
			resp.FailInfo = mapIntuneErrorToFailInfo(outcome.err)
			return resp
		}
		// Chain-of-trust check still applies on renewal even via Intune.
		if err := s.verifyRenewalSignerCertChain(ctx, envelope.SignerCert); err != nil {
			s.logger.Warn("SCEP renewal rejected: signer cert chain invalid (Intune path)",
				"transaction_id", envelope.TransactionID, "error", err.Error())
			resp.Status = domain.SCEPStatusFailure
			resp.FailInfo = domain.SCEPFailBadMessageCheck
			return resp
		}
		result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_renewalreq_intune")
		if err != nil {
			resp.Status = domain.SCEPStatusFailure
			resp.FailInfo = mapServiceErrorToFailInfo(err)
			return resp
		}
		resp.Status = domain.SCEPStatusSuccess
		resp.Result = result
		return resp
	}

	// Same challenge-password gate as PKCSReqWithEnvelope. Defense in depth
	// even though the RenewalReq path additionally verifies the signing
	// cert chain — a stolen/leaked challenge password combined with a
	// previously-issued cert (e.g. from a compromised device) would still
	// allow renewal otherwise. The two checks are independent.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP renewal rejected: server has no challenge password configured (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP renewal rejected: invalid challenge password (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}

	// Verify the signing cert chains to the issuer's CA. Without this gate
	// any self-signed cert with a valid challenge password could trigger a
	// renewal — defeating the 'proof of prior issuance' contract RenewalReq
	// is supposed to provide.
	if err := s.verifyRenewalSignerCertChain(ctx, envelope.SignerCert); err != nil {
		s.logger.Warn("SCEP renewal rejected: signer cert chain invalid",
			"transaction_id", envelope.TransactionID,
			"error", err.Error(),
		)
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = domain.SCEPFailBadMessageCheck
		return resp
	}

	// Reuse the existing processEnrollment for the actual issuance work
	// — RenewalReq is functionally a re-issuance with a different audit
	// action and chain-validation precondition.
	result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_renewalreq")
	if err != nil {
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = mapServiceErrorToFailInfo(err)
		return resp
	}
	resp.Status = domain.SCEPStatusSuccess
	resp.Result = result
	return resp
}

// verifyRenewalSignerCertChain confirms the device's signing cert (the cert
// presented as POPO in the SignerInfo) was previously issued by the
// configured issuer. Used by RenewalReqWithEnvelope to enforce the 'must
// have a previously-issued cert' contract RFC 8894 §3.3.1.2 implies.
//
// A self-signed throwaway cert (initial-enrollment shape) fails this check
// — that's an indicator the client meant to send PKCSReq, not RenewalReq.
// Operators see the audit-log entry; the client sees BadMessageCheck.
func (s *SCEPService) verifyRenewalSignerCertChain(ctx context.Context, signerCertDER []byte) error {
	if len(signerCertDER) == 0 {
		return fmt.Errorf("signer cert is empty (no POPO cert in SignerInfo)")
	}
	signerCert, err := x509.ParseCertificate(signerCertDER)
	if err != nil {
		return fmt.Errorf("parse signer cert: %w", err)
	}

	// Pull the issuer's CA chain via the existing IssuerConnector
	// surface. Failure here is a deploy bug (the issuer connector lost
	// its CA cert mid-flight) rather than a client error — surface as
	// the same generic failure to avoid leaking server state.
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return fmt.Errorf("get CA cert PEM: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return fmt.Errorf("CA cert PEM contains no parseable certs")
	}
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := signerCert.Verify(opts); err != nil {
		return fmt.Errorf("signer cert chain validation failed: %w", err)
	}
	return nil
}

// GetCertInitialWithEnvelope handles SCEP polling requests. RFC 8894 §3.3.3
// — the client polls when the prior PKCSReq returned Status=Pending.
//
// SCEP RFC 8894 + Intune master bundle Phase 4.3.
//
// v1 of this bundle returns FAILURE+badCertID for all GetCertInitial
// requests since deferred-issuance isn't supported (every PKCSReq either
// succeeds or fails synchronously — no Pending state in the existing
// service-layer issuance pipeline). The wiring stays in place for a
// future enhancement (e.g. 'queue for manual approval' workflows).
func (s *SCEPService) GetCertInitialWithEnvelope(_ context.Context, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	s.logger.Info("SCEP GetCertInitial received — deferred-issuance not supported in v1, returning badCertID",
		"transaction_id", envelope.TransactionID)
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusFailure,
		FailInfo:       domain.SCEPFailBadCertID,
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}
}
