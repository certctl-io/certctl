package service

import (
	"sync"
	"sync/atomic"
)

// Phase 10 of the deploy-hardening I master bundle — per-target-type
// deploy counters. Mirrors the OCSPCounters / ESTCounters / SCEPCounters
// pattern: sync/atomic primitives keep the hot path lock-free, and a
// snapshot accessor produces a stable per-(target_type, label) map for
// the Prometheus exposer.
//
// Per frozen decision 0.9 (deploy-hardening I), the metric-naming
// convention is `certctl_deploy_<area>_total` — the exposer
// converts the snapshot into the labeled metrics:
//
//   - certctl_deploy_attempts_total{target_type, result}
//   - certctl_deploy_validate_failures_total{target_type, reason}
//   - certctl_deploy_reload_failures_total{target_type}
//   - certctl_deploy_post_verify_failures_total{target_type, reason}
//   - certctl_deploy_rollback_total{target_type, outcome}
//   - certctl_deploy_idempotent_skip_total{target_type}
//
// The Phase 10 exposer enumerates the (target_type, sub-label) tuples
// to defend against drift — adding a new target type or sub-label
// here without also adding it to the exposer would be a "silent
// counter" bug.

// DeployCounters is the shared counter table for deployment job
// processing. A single instance lives on the agent (cmd/agent/main.go)
// and ticks every deploy through its lifecycle. The agent's HTTP
// counter-snapshot endpoint then bridges this to the server's
// Prometheus exposer for centralized scraping.
//
// All Inc* methods are safe for concurrent callers (atomic.Uint64
// hot path; sync.Map for the per-target-type bucket lookup).
type DeployCounters struct {
	// buckets maps target_type ("nginx", "apache", ...) to a
	// per-target deployBucket holding all sub-counters.
	buckets sync.Map // map[string]*deployBucket
}

type deployBucket struct {
	attemptsSuccess  atomic.Uint64
	attemptsFailure  atomic.Uint64
	validateFailures atomic.Uint64
	reloadFailures   atomic.Uint64
	postVerifyFails  atomic.Uint64
	rollbackRestored atomic.Uint64
	rollbackAlsoFail atomic.Uint64
	idempotentSkips  atomic.Uint64
}

// NewDeployCounters constructs a zero-value counter table. The
// caller holds it for the agent's lifetime; counters are never
// reset.
func NewDeployCounters() *DeployCounters {
	return &DeployCounters{}
}

// bucket returns (creating if needed) the per-target-type counter
// bucket. Lock-free fast path when the bucket exists.
func (c *DeployCounters) bucket(targetType string) *deployBucket {
	if v, ok := c.buckets.Load(targetType); ok {
		return v.(*deployBucket)
	}
	v, _ := c.buckets.LoadOrStore(targetType, &deployBucket{})
	return v.(*deployBucket)
}

// IncAttemptSuccess ticks the success leg of the attempts counter.
func (c *DeployCounters) IncAttemptSuccess(targetType string) {
	c.bucket(targetType).attemptsSuccess.Add(1)
}

// IncAttemptFailure ticks the failure leg of the attempts counter.
// Failure includes any of: validate-fail, reload-fail (after
// rollback), post-verify-fail (after rollback), rollback-fail,
// connector-init-fail, etc.
func (c *DeployCounters) IncAttemptFailure(targetType string) {
	c.bucket(targetType).attemptsFailure.Add(1)
}

// IncValidateFailure ticks when the connector's PreCommit
// (validate-with-the-target) returns an error.
func (c *DeployCounters) IncValidateFailure(targetType string) {
	c.bucket(targetType).validateFailures.Add(1)
}

// IncReloadFailure ticks when the connector's PostCommit (reload)
// returns an error and rollback is invoked.
func (c *DeployCounters) IncReloadFailure(targetType string) {
	c.bucket(targetType).reloadFailures.Add(1)
}

// IncPostVerifyFailure ticks when the post-deploy TLS handshake
// fails (SHA-256 mismatch, dial timeout, handshake fail).
func (c *DeployCounters) IncPostVerifyFailure(targetType string) {
	c.bucket(targetType).postVerifyFails.Add(1)
}

// IncRollbackRestored ticks when a rollback successfully restored
// the previous bytes.
func (c *DeployCounters) IncRollbackRestored(targetType string) {
	c.bucket(targetType).rollbackRestored.Add(1)
}

// IncRollbackAlsoFailed ticks the operator-actionable escalation:
// the deploy failed AND the rollback also failed. Operators alert
// on this.
func (c *DeployCounters) IncRollbackAlsoFailed(targetType string) {
	c.bucket(targetType).rollbackAlsoFail.Add(1)
}

// IncIdempotentSkip ticks when an Apply was a SHA-256-match no-op.
// Operator-visible signal of agent-restart retry storms (which
// otherwise hammer targets with no-op reloads).
func (c *DeployCounters) IncIdempotentSkip(targetType string) {
	c.bucket(targetType).idempotentSkips.Add(1)
}

// DeploySnapshot is the per-(target_type, label) snapshot returned
// to the Prometheus exposer.
type DeploySnapshot struct {
	TargetType       string
	AttemptsSuccess  uint64
	AttemptsFailure  uint64
	ValidateFailures uint64
	ReloadFailures   uint64
	PostVerifyFails  uint64
	RollbackRestored uint64
	RollbackAlsoFail uint64
	IdempotentSkips  uint64
}

// Snapshot returns one DeploySnapshot per known target type.
// Map iteration on sync.Map is unordered; the exposer handles the
// sort to produce stable Prometheus output.
func (c *DeployCounters) Snapshot() []DeploySnapshot {
	var out []DeploySnapshot
	c.buckets.Range(func(k, v any) bool {
		b := v.(*deployBucket)
		out = append(out, DeploySnapshot{
			TargetType:       k.(string),
			AttemptsSuccess:  b.attemptsSuccess.Load(),
			AttemptsFailure:  b.attemptsFailure.Load(),
			ValidateFailures: b.validateFailures.Load(),
			ReloadFailures:   b.reloadFailures.Load(),
			PostVerifyFails:  b.postVerifyFails.Load(),
			RollbackRestored: b.rollbackRestored.Load(),
			RollbackAlsoFail: b.rollbackAlsoFail.Load(),
			IdempotentSkips:  b.idempotentSkips.Load(),
		})
		return true
	})
	return out
}
