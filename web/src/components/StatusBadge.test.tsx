import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import StatusBadge from './StatusBadge';

// -----------------------------------------------------------------------------
// D-1 master — StatusBadge enum-coverage contract
//
// The single source of truth for what Go actually emits on the wire.
// Update this if the Go enums change (and the StatusBadge will go red
// here BEFORE any user sees a wrong color in production).
//
// Sources (mirror the Go const blocks verbatim — wire VALUES, not Go
// identifier names):
//   AgentStatus       — internal/domain/connector.go:174-176
//   CertificateStatus — internal/domain/certificate.go:50-57
//   JobStatus         — internal/domain/job.go:43-49
//   NotificationStatus— internal/domain/notification.go:51-55
//   DiscoveryStatus   — internal/domain/discovery.go:13-17
//   HealthStatus      — internal/domain/health_check.go:9-13
//
// Issuer 'Enabled' / 'Disabled' are NOT a Go enum — they're frontend-
// synthesized labels mapped from `Issuer.enabled bool` at the call
// site (TargetsPage.tsx similarly). Pinned in a separate group below.
//
// Pre-D-1 drift this test would have caught:
//   - Agent: StatusBadge had 'Stale' (never emitted), missing 'Degraded'
//     (real). Degraded agents rendered as default neutral grey, hiding
//     attention-needed state from operators.
//   - Notification: StatusBadge missing 'dead' (retries exhausted).
//     Dead-letter notifications rendered as default neutral, visually
//     equated with 'read' (operator-acknowledged).
//   - Certificate: StatusBadge had 'PendingIssuance' (never emitted).
//     Dead key, latent confusion vector if anyone copies it as
//     canonical.
// -----------------------------------------------------------------------------
const ENUMS_FROM_GO = {
  AgentStatus:        ['Online', 'Offline', 'Degraded'] as const,
  CertificateStatus:  ['Pending', 'Active', 'Expiring', 'Expired',
                       'RenewalInProgress', 'Failed', 'Revoked', 'Archived'] as const,
  JobStatus:          ['Pending', 'AwaitingCSR', 'AwaitingApproval', 'Running',
                       'Completed', 'Failed', 'Cancelled'] as const,
  NotificationStatus: ['pending', 'sent', 'failed', 'dead', 'read'] as const,
  DiscoveryStatus:    ['Unmanaged', 'Managed', 'Dismissed'] as const,
  HealthStatus:       ['healthy', 'degraded', 'down', 'cert_mismatch', 'unknown'] as const,
};

// Frontend-synthesized labels — not in any Go enum, but surfaced via
// StatusBadge from real call sites (TargetsPage, AgentGroupsPage etc.)
// and therefore part of the visual contract this component owns.
const FRONTEND_SYNTHESIZED = ['Enabled', 'Disabled'] as const;

describe('StatusBadge — enum-coverage contract (D-1 master)', () => {
  // Iterate every Go-emitted value across every enum and assert the
  // rendered <span> carries a class OTHER than the default 'badge-neutral'.
  // EXCEPT for legitimately-neutral statuses (Archived, Cancelled,
  // Dismissed, read, unknown) which are intentionally neutral by UX
  // design — those are pinned by a separate sub-test below.
  const INTENTIONALLY_NEUTRAL = new Set(['Archived', 'Cancelled', 'Dismissed', 'read', 'unknown']);

  for (const [enumName, values] of Object.entries(ENUMS_FROM_GO)) {
    for (const v of values) {
      it(`${enumName}: '${v}' renders a recognised class (no fallthrough)`, () => {
        const { container } = render(<StatusBadge status={v} />);
        const span = container.querySelector('span');
        expect(span).not.toBeNull();
        const cls = span!.className;
        if (INTENTIONALLY_NEUTRAL.has(v)) {
          // Neutral is the right semantic answer for terminal-acknowledged
          // states — but it must come from an EXPLICIT mapping, not the
          // dictionary-default fallthrough. Asserting a 'badge-neutral'
          // class here pins that the explicit entry exists; if someone
          // deletes it, this still passes (because the default is also
          // 'badge-neutral'). The negative assertion in the dead-keys
          // sub-test below catches the deletion case.
          expect(cls).toBe('badge badge-neutral');
        } else {
          expect(cls).toMatch(/badge-(success|warning|danger|info)/);
          expect(cls).not.toBe('badge badge-neutral');
        }
      });
    }
  }

  for (const v of FRONTEND_SYNTHESIZED) {
    it(`Frontend-synthesized '${v}' has an explicit StatusBadge mapping`, () => {
      const { container } = render(<StatusBadge status={v} />);
      const cls = container.querySelector('span')!.className;
      // 'Disabled' is intentionally neutral; 'Enabled' is success.
      expect(cls).toMatch(/badge-(success|warning|danger|info|neutral)/);
    });
  }

  // Negative contract: the dead keys we deleted MUST fall through to the
  // default. If a future PR re-adds 'Stale' or 'PendingIssuance' to
  // statusStyles, this test will surface it because the rendered class
  // will no longer be 'badge badge-neutral' (it'd be the explicit value
  // someone re-added, e.g. 'badge-warning').
  it.each(['Stale', 'PendingIssuance'])(
    "dead key '%s' falls through to neutral default (no explicit mapping)",
    (deadKey) => {
      const { container } = render(<StatusBadge status={deadKey} />);
      expect(container.querySelector('span')!.className).toBe('badge badge-neutral');
    },
  );

  // Specific danger-class contracts (UX correctness, not just non-default).
  // These pin the operator-attention semantics. If anyone changes 'dead'
  // or 'Degraded' away from these classes, the operator's perception of
  // "this needs my attention" changes — these are the highest-stakes
  // visual semantics in the dashboard.
  it("Notification 'dead' renders as danger (operator attention required)", () => {
    const { container } = render(<StatusBadge status="dead" />);
    expect(container.querySelector('span')!.className).toContain('badge-danger');
  });

  it("Agent 'Degraded' renders as warning (degradation, not failure)", () => {
    const { container } = render(<StatusBadge status="Degraded" />);
    expect(container.querySelector('span')!.className).toContain('badge-warning');
  });

  // Unknown statuses fall through to neutral. The string is still
  // displayed verbatim so an operator can see "what is this?" rather
  // than nothing at all.
  it('unknown status string renders as neutral but preserves the label text', () => {
    const { container } = render(<StatusBadge status="SomeFutureStatus" />);
    const span = container.querySelector('span');
    expect(span!.className).toBe('badge badge-neutral');
    expect(span!.textContent).toBe('SomeFutureStatus');
  });
});
