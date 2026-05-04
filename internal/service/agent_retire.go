package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// I-004 coverage-gap closure: the agent retirement surface.
//
// Before 000015, DELETE /api/v1/agents/{id} hard-deleted the agents row and
// the deployment_targets.agent_id FK CASCADE cleaned up downstream rows with
// no preflight, no archival, and no knowledge of in-flight jobs. Any cert
// still rotating through one of those targets would observe half-migrated
// state. I-004 closes that gap with a preflight + soft-retire + optional
// forced-cascade contract; the symbols in this file are the service-layer
// surface that the handler and operator UI bind against.

// ErrAgentIsSentinel is returned when an operator tries to retire one of the
// four reserved sentinel agent IDs (server-scanner, cloud-aws-sm,
// cloud-azure-kv, cloud-gcp-sm). These rows back the network scanner and the
// three cloud secret-manager discovery sources; retiring any of them orphans
// its subsystem. The guard fires unconditionally — force=true does not bypass
// it, because a sentinel is a structural invariant of the deployment, not
// a piece of fleet state the operator owns. Handler maps this to HTTP 403.
var ErrAgentIsSentinel = errors.New("agent is a reserved sentinel and cannot be retired")

// ErrBlockedByDependencies is returned by RetireAgent when at least one of
// (active targets, active certificates, pending jobs) referencing the agent
// is non-zero and force=false. The caller always receives it wrapped in
// a *BlockedByDependenciesError (see below), so handlers doing errors.As
// can surface the per-bucket counts in the 409 body for operator
// troubleshooting. Tests use errors.Is; handlers use errors.As.
var ErrBlockedByDependencies = errors.New("agent has active downstream dependencies")

// ErrForceReasonRequired is returned when force=true is supplied without a
// non-empty reason. The force escape hatch is deliberately chatty: operators
// pulling the emergency cord must leave an auditable breadcrumb explaining
// why a cascade was justified. Handler maps this to HTTP 400 so the operator
// retries with --reason rather than silently skipping the guard. Checked
// before any DB mutation to keep the no-reason path transactionally clean.
var ErrForceReasonRequired = errors.New("force=true requires a non-empty reason")

// ErrAgentRetired is returned by Heartbeat (and any future agent-authenticated
// call site) when a retired agent is still polling. The handler layer maps
// this to HTTP 410 Gone so the cmd/agent sendHeartbeat loop can detect it
// deterministically and shut down the agent process, rather than looping
// forever on a soft-retired identity. IsRetired() on the domain model is
// the single source of truth; the sentinel exists so service and handler
// callers can errors.Is against one symbol.
var ErrAgentRetired = errors.New("agent has been retired")

// BlockedByDependenciesError wraps ErrBlockedByDependencies and carries the
// per-bucket dependency snapshot the preflight pass captured. The embedded
// AgentDependencyCounts is the same struct the repo returns from the three
// CountActive* calls, so the handler can marshal it directly into the 409
// body without reshaping fields. Unwrap() satisfies errors.Is against the
// sentinel; Error() includes the counts so logs are diagnostic on their own.
type BlockedByDependenciesError struct {
	Counts domain.AgentDependencyCounts
}

// Error formats the wrapped error with the per-bucket counts. Kept short so
// it reads cleanly in slog output.
func (e *BlockedByDependenciesError) Error() string {
	return fmt.Sprintf(
		"%s (active_targets=%d, active_certificates=%d, pending_jobs=%d)",
		ErrBlockedByDependencies.Error(),
		e.Counts.ActiveTargets,
		e.Counts.ActiveCertificates,
		e.Counts.PendingJobs,
	)
}

// Unwrap lets errors.Is(err, ErrBlockedByDependencies) match the wrapped
// struct — the test contract (agent_retire_test.go:167) depends on it.
func (e *BlockedByDependenciesError) Unwrap() error { return ErrBlockedByDependencies }

// AgentRetirementResult is the outcome surface the handler returns to the
// operator. It discriminates the three happy paths the endpoint can take —
// idempotent no-op (AlreadyRetired), clean soft-retire (Cascade=false), and
// forced cascade (Cascade=true) — and always carries the retired_at timestamp
// and the dependency-count snapshot so the 200/204 response body can echo
// what was (or would have been) affected.
//
//	AlreadyRetired=true          → agent was already retired; no new audit
//	                               event was emitted; RetiredAt is the
//	                               original stamp, not the current time.
//	Cascade=false                → clean soft-retire; Counts is all zeros.
//	Cascade=true                 → force=true retired agent + downstream
//	                               targets; Counts is the PRE-cascade
//	                               snapshot (so the operator sees what
//	                               they just retired).
type AgentRetirementResult struct {
	AlreadyRetired bool
	Cascade        bool
	RetiredAt      time.Time
	Counts         domain.AgentDependencyCounts
}

// RetireAgent implements the I-004 retirement contract. Ordering matters —
// every guard fires before the one that would mutate state, so a rejected
// retire leaves zero trace (no audit event, no partial DB write):
//
//  1. Sentinel check (unconditional; force does not bypass).
//  2. Fetch agent (404 surfaces as-is from the repo).
//  3. Already-retired idempotency: return AlreadyRetired=true with NO new
//     audit event — the original retire already recorded one.
//  4. Preflight count pass via the three CountActive* repo methods.
//  5. Force-reason guard: force=true with empty reason is rejected here,
//     after the counts are known but before any mutation.
//  6. Default no-force path: any non-zero count returns
//     *BlockedByDependenciesError with counts attached.
//  7. Mutation: SoftRetire (no cascade) or RetireAgentWithCascade, with
//     a single retiredAt timestamp pinned BEFORE the repo call so the
//     audit event and the DB row agree to the nanosecond.
//  8. Audit: agent_retired always; agent_retirement_cascaded additionally
//     on the force=true cascade path.
//
// Actor comes from the handler's resolveActor (API key → user, agent key →
// agent-<id>, unauthenticated → "anonymous"); the service does not second-
// guess it. Audit emission is best-effort: a failed RecordEvent logs a
// warning but does not fail the overall retirement, consistent with how
// the rest of the codebase treats audit as an observability concern
// rather than a correctness barrier.
func (s *AgentService) RetireAgent(ctx context.Context, id string, actor string, force bool, reason string) (*AgentRetirementResult, error) {
	// Step 1 — reserved-sentinel guard. Applies even under force=true.
	if domain.IsSentinelAgent(id) {
		return nil, ErrAgentIsSentinel
	}

	// Step 2 — existence check. Missing agent surfaces the repo's not-found
	// error verbatim so the handler can map it to 404 via its existing
	// detection path (the handler layer already has "not found" mapping
	// logic inherited from the pre-I-004 Delete endpoint).
	agent, err := s.agentRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Step 3 — idempotency. A retired agent returns AlreadyRetired=true
	// WITHOUT emitting a fresh audit event. Handler maps this to HTTP 204.
	// Guarding here (before preflight) means a re-retire of an agent that
	// now has zero deps doesn't spuriously "succeed again" and double-log.
	if agent.IsRetired() {
		return &AgentRetirementResult{
			AlreadyRetired: true,
			RetiredAt:      *agent.RetiredAt,
		}, nil
	}

	// Step 4 — preflight counts. All three run even when force=true: we
	// need them to populate AgentRetirementResult.Counts (the pre-cascade
	// snapshot). A repo failure here aborts the whole operation — partial
	// preflight is worse than no preflight.
	counts, err := s.collectAgentDependencyCounts(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to collect agent dependency counts: %w", err)
	}

	// Step 5 — force-reason guard. Positioned AFTER preflight so operators
	// who forgot --reason still see accurate counts when they retry. The
	// empty-reason rejection fires before any mutation, so the rejected
	// attempt leaves no audit noise.
	if force && reason == "" {
		return nil, ErrForceReasonRequired
	}

	// Step 6 — default path: block on any non-zero bucket. Wrapping the
	// sentinel in *BlockedByDependenciesError lets the handler use errors.As
	// to surface counts in the 409 body while tests use errors.Is against
	// the sentinel. Both callers are satisfied by the single Unwrap chain.
	if !force && counts.HasDependencies() {
		return nil, &BlockedByDependenciesError{Counts: counts}
	}

	// Step 7 — mutation. Pin retiredAt once so the audit event, the agent
	// row, and (on cascade) every deployment_targets row share the same
	// timestamp. Callers querying "what happened at T?" can correlate
	// retirement rows across tables without clock-skew tie-breaking.
	retiredAt := time.Now()
	cascade := force && counts.HasDependencies()

	if cascade {
		if err := s.agentRepo.RetireAgentWithCascade(ctx, id, retiredAt, reason); err != nil {
			return nil, fmt.Errorf("failed to retire agent with cascade: %w", err)
		}
	} else {
		if err := s.agentRepo.SoftRetire(ctx, id, retiredAt, reason); err != nil {
			return nil, fmt.Errorf("failed to soft-retire agent: %w", err)
		}
	}

	// Step 8 — audit. Two events on the cascade path so forensics can
	// distinguish "agent was retired" (agent_retired) from "downstream
	// targets were flipped" (agent_retirement_cascaded). Details on the
	// cascaded event carry the pre-cascade counts so a reviewer looking
	// only at the audit log knows how much state was affected. Emission
	// is best-effort — audit is observability, not a correctness barrier.
	actorType := s.resolveActorType(actor)
	details := map[string]interface{}{
		"actor":               actor,
		"reason":              reason,
		"force":               force,
		"active_targets":      counts.ActiveTargets,
		"active_certificates": counts.ActiveCertificates,
		"pending_jobs":        counts.PendingJobs,
	}
	if err := s.auditService.RecordEvent(ctx, actor, actorType,
		"agent_retired", "agent", id, details); err != nil {
		slog.Error("failed to record agent_retired audit event", "agent_id", id, "error", err)
	}
	if cascade {
		cascadeDetails := map[string]interface{}{
			"actor":               actor,
			"reason":              reason,
			"active_targets":      counts.ActiveTargets,
			"active_certificates": counts.ActiveCertificates,
			"pending_jobs":        counts.PendingJobs,
		}
		if err := s.auditService.RecordEvent(ctx, actor, actorType,
			"agent_retirement_cascaded", "agent", id, cascadeDetails); err != nil {
			slog.Error("failed to record agent_retirement_cascaded audit event", "agent_id", id, "error", err)
		}
	}

	return &AgentRetirementResult{
		AlreadyRetired: false,
		Cascade:        cascade,
		RetiredAt:      retiredAt,
		Counts:         counts,
	}, nil
}

// ListRetiredAgents returns the paginated list of retired agents in
// retired_at DESC order. This is the companion to ListAgents — which
// hides retired rows — so the operator UI can render a dedicated
// "Retired" tab without leaking retired rows into every other listing.
// Pagination defaults (page<1→1, perPage<1→50) are applied here as
// well as in the repo, so callers can pass 0s when they want defaults.
//
// Return shape harmonizes with handler.AgentService: a value slice
// (not pointer slice) and int64 total. The repo returns []*domain.Agent;
// this method dereferences into a value slice so the handler's
// PagedResponse marshals straight objects and so the compile-time
// interface assertion in agent_retire_handler_test.go:387 is satisfied.
// Nil repo entries are skipped defensively — the repo should never
// return them, but the handler contract is more important than the
// repo's (pointer-slice) convenience.
func (s *AgentService) ListRetiredAgents(ctx context.Context, page, perPage int) ([]domain.Agent, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	agents, total, err := s.agentRepo.ListRetired(ctx, page, perPage)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list retired agents: %w", err)
	}
	out := make([]domain.Agent, 0, len(agents))
	for _, a := range agents {
		if a == nil {
			continue
		}
		out = append(out, *a)
	}
	return out, int64(total), nil
}

// collectAgentDependencyCounts runs the three preflight COUNT queries in
// sequence and bundles the result. Sequential (not parallel) because the
// queries are cheap (<1ms each on the indexed columns added in 000015) and
// sequential keeps error handling simple. Any repo error short-circuits
// — we prefer to refuse the retire than make a half-informed decision.
func (s *AgentService) collectAgentDependencyCounts(ctx context.Context, id string) (domain.AgentDependencyCounts, error) {
	var counts domain.AgentDependencyCounts

	targets, err := s.agentRepo.CountActiveTargets(ctx, id)
	if err != nil {
		return counts, fmt.Errorf("count active targets: %w", err)
	}
	counts.ActiveTargets = targets

	certs, err := s.agentRepo.CountActiveCertificates(ctx, id)
	if err != nil {
		return counts, fmt.Errorf("count active certificates: %w", err)
	}
	counts.ActiveCertificates = certs

	jobs, err := s.agentRepo.CountPendingJobs(ctx, id)
	if err != nil {
		return counts, fmt.Errorf("count pending jobs: %w", err)
	}
	counts.PendingJobs = jobs

	return counts, nil
}

// resolveActorType maps an opaque actor string into the typed ActorType
// used by the audit schema. Matches the conventions the rest of the
// service layer uses: "system" → System, anything that looks like an
// agent identity → Agent, everything else → User.
func (s *AgentService) resolveActorType(actor string) domain.ActorType {
	switch {
	case actor == "system":
		return domain.ActorTypeSystem
	case len(actor) > 6 && actor[:6] == "agent-":
		return domain.ActorTypeAgent
	default:
		return domain.ActorTypeUser
	}
}
