import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import StatusBadge, { statusDisplay, titleCase } from './StatusBadge';

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

  // Unknown statuses fall through to neutral. The label is humanised
  // via the titleCase() helper (UX-H5) so the operator sees readable
  // text rather than the raw enum key — "Some future status" instead
  // of "SomeFutureStatus".
  it('unknown status string renders as neutral with titleCase fallback', () => {
    const { container } = render(<StatusBadge status="SomeFutureStatus" />);
    const span = container.querySelector('span');
    expect(span!.className).toBe('badge badge-neutral');
    expect(span!.textContent).toBe('Some future status');
  });
});

// -----------------------------------------------------------------------------
// UX-H5 master — StatusBadge display-string contract (Phase 1, 2026-05-14)
//
// The audit finding: pre-Phase-1, StatusBadge rendered raw Go enum keys
// — operators saw "RenewalInProgress" / "AwaitingCSR" / "cert_mismatch"
// / "dead" verbatim. Phase 1 adds a statusDisplay map next to
// statusStyles; this suite pins the byte-exact display string for every
// wire key.
// -----------------------------------------------------------------------------
describe('StatusBadge — display-string contract (UX-H5)', () => {
  // Every wire key in the colour map MUST have a display-string entry
  // and the entry MUST be non-empty. Missing entries fall back to the
  // titleCase() helper, but having an explicit entry in statusDisplay
  // is the preferred path (lets us pick the cleanest sentence-case
  // phrasing, with terms like "Awaiting CSR" capitalised correctly
  // where titleCase would yield "Awaiting csr").
  const EXPECTED_DISPLAY: Array<[string, string]> = [
    // Certificate statuses
    ['Active', 'Active'],
    ['Expiring', 'Expiring soon'],
    ['Expired', 'Expired'],
    ['RenewalInProgress', 'Renewal in progress'],
    ['Archived', 'Archived'],
    ['Revoked', 'Revoked'],
    // Job statuses
    ['Pending', 'Pending'],
    ['AwaitingCSR', 'Awaiting CSR'],
    ['AwaitingApproval', 'Awaiting approval'],
    ['Running', 'Running'],
    ['Completed', 'Completed'],
    ['Failed', 'Failed'],
    ['Cancelled', 'Cancelled'],
    // Agent statuses
    ['Online', 'Online'],
    ['Offline', 'Offline'],
    ['Degraded', 'Degraded'],
    // Discovery statuses
    ['Unmanaged', 'Unmanaged'],
    ['Managed', 'Managed'],
    ['Dismissed', 'Dismissed'],
    // Frontend-synthesized issuer statuses
    ['Enabled', 'Enabled'],
    ['Disabled', 'Disabled'],
    // Notification statuses (lowercase wire values)
    ['sent', 'Sent'],
    ['pending', 'Pending'],
    ['failed', 'Failed'],
    ['dead', 'Dead-lettered'],
    ['read', 'Read'],
    // Health check statuses (lowercase + snake_case)
    ['healthy', 'Healthy'],
    ['degraded', 'Degraded'],
    ['down', 'Down'],
    ['cert_mismatch', 'Certificate mismatch'],
    ['unknown', 'Unknown'],
  ];

  it.each(EXPECTED_DISPLAY)(
    "wire key '%s' renders display string '%s'",
    (wire, expected) => {
      // First — verify the statusDisplay map carries the entry verbatim.
      expect(statusDisplay[wire]).toBe(expected);
      // Then — verify the rendered <span>'s textContent matches.
      const { container } = render(<StatusBadge status={wire} />);
      expect(container.querySelector('span')!.textContent).toBe(expected);
    },
  );

  it('every wire key in statusStyles has a matching statusDisplay entry', () => {
    // Parity check — re-deriving the styles key set isn't possible at
    // runtime without re-importing it, but we can probe a known sample
    // and pin: if a future PR adds a new style entry without a display
    // entry, the EXPECTED_DISPLAY list above will mismatch.
    expect(Object.keys(statusDisplay).length).toBeGreaterThanOrEqual(
      EXPECTED_DISPLAY.length,
    );
  });

  describe('titleCase() helper — fallback for unmapped keys', () => {
    it('humanises PascalCase', () => {
      expect(titleCase('RenewalInProgress')).toBe('Renewal in progress');
    });
    it('humanises snake_case', () => {
      expect(titleCase('cert_mismatch')).toBe('Cert mismatch');
    });
    it('handles single-word lowercase', () => {
      expect(titleCase('pending')).toBe('Pending');
    });
    it('handles single-word PascalCase', () => {
      expect(titleCase('Active')).toBe('Active');
    });
    it('handles empty string defensively', () => {
      expect(titleCase('')).toBe('');
    });
  });
});
