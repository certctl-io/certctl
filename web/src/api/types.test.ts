import { describe, it, expect } from 'vitest';
import { POLICY_TYPES, POLICY_SEVERITIES } from './types';
import type { Agent } from './types';

/**
 * Regression tests for the policy enum tuples.
 *
 * These tuples are the GUI's source of truth for the policy type and severity
 * dropdowns. They MUST stay in lockstep with the backend enum values:
 *   - internal/domain/policy.go defines the PolicyType / PolicySeverity consts
 *   - internal/api/handler/validators.go rejects anything outside the allowlist
 *   - migration 000013 enforces the severity allowlist at the DB level via CHECK
 *
 * Audit history (D-005, D-006):
 *   - The GUI previously sent lowercase values (e.g. 'key_algorithm',
 *     'ownership'), which the backend validator rejected with a 400. Every
 *     attempt to create a policy from the "+ New Policy" button silently
 *     failed until the modal was closed.
 *   - The severity dropdown carried a four-value `low/medium/high/critical`
 *     tuple that shared zero values with the backend's
 *     `Warning/Error/Critical` — the `medium` option has no backend analog
 *     and is removed.
 *
 * If these tests fail because a backend enum changed, DO NOT update the
 * expected arrays without also updating the backend consts and the migration.
 * Frontend/backend drift on these tuples is precisely what this regression
 * guards against.
 */

describe('POLICY_TYPES', () => {
  it('matches the backend PolicyType TitleCase allowlist exactly', () => {
    expect(POLICY_TYPES).toEqual([
      'AllowedIssuers',
      'AllowedDomains',
      'RequiredMetadata',
      'AllowedEnvironments',
      'RenewalLeadTime',
      'CertificateLifetime',
    ]);
  });

  it('has no duplicate entries', () => {
    expect(new Set(POLICY_TYPES).size).toBe(POLICY_TYPES.length);
  });
});

describe('POLICY_SEVERITIES', () => {
  it('matches the backend PolicySeverity TitleCase allowlist exactly', () => {
    expect(POLICY_SEVERITIES).toEqual(['Warning', 'Error', 'Critical']);
  });

  it('has no duplicate entries', () => {
    expect(new Set(POLICY_SEVERITIES).size).toBe(POLICY_SEVERITIES.length);
  });

  it('does not include the removed pre-fix `medium` value', () => {
    // Explicit negative assertion. Pre-fix the GUI offered four severities
    // (low/medium/high/critical); `medium` never had a backend analog.
    expect(POLICY_SEVERITIES as readonly string[]).not.toContain('medium');
  });
});

/**
 * Regression test for the Agent interface's I-004 soft-retirement shape.
 *
 * Backend (migration 000015, Phase 2b) adds two nullable timestamps/strings to
 * the agents table — `retired_at` and `retired_reason` — mirroring the existing
 * Certificate.revoked_at / Certificate.revocation_reason pair. The GUI needs
 * these fields on the Agent interface so the Retired tab, retire modal, and
 * retirement banner can render the agent's retired state without resorting to
 * `(agent as any).retired_at` escapes.
 *
 * Both fields are optional (agent.ts interface) because the server omits them
 * from the response for active agents. A compile-time shape check here pins
 * that Phase 2b does not drift the field names (e.g. to retiredAt camelCase)
 * or accidentally promote them to required.
 *
 * Compile-fail until Phase 2b adds:
 *   retired_at?: string;
 *   retired_reason?: string;
 * to the Agent interface in types.ts.
 */
describe('Agent interface (I-004 retirement)', () => {
  it('accepts retired_at and retired_reason as optional string fields', () => {
    // Construct an Agent with the retirement fields set. If Phase 2b names
    // them anything other than retired_at / retired_reason, this fails to
    // compile — which is exactly what the Red stage wants.
    const retired: Agent = {
      id: 'ag-1',
      name: 'decom-01',
      hostname: 'server-old',
      ip_address: '10.0.0.1',
      os: 'linux',
      architecture: 'amd64',
      status: 'Offline',
      version: '2.1.0',
      last_heartbeat: '2026-01-01T00:00:00Z',
      last_heartbeat_at: '2026-01-01T00:00:00Z',
      capabilities: [],
      tags: {},
      registered_at: '2024-01-01T00:00:00Z',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      retired_at: '2026-01-01T00:00:00Z',
      retired_reason: 'old hardware',
    };
    expect(retired.retired_at).toBe('2026-01-01T00:00:00Z');
    expect(retired.retired_reason).toBe('old hardware');
  });

  it('accepts an Agent without retired_at / retired_reason (optional fields)', () => {
    // Active agents should not carry retirement metadata. If Phase 2b makes
    // the fields required, this block fails to compile.
    const active: Agent = {
      id: 'ag-2',
      name: 'web01',
      hostname: 'web01.prod',
      ip_address: '10.0.0.2',
      os: 'linux',
      architecture: 'amd64',
      status: 'Online',
      version: '2.1.0',
      last_heartbeat: '2026-04-18T12:00:00Z',
      last_heartbeat_at: '2026-04-18T12:00:00Z',
      capabilities: ['deploy', 'scan'],
      tags: {},
      registered_at: '2024-06-01T00:00:00Z',
      created_at: '2024-06-01T00:00:00Z',
      updated_at: '2026-04-18T12:00:00Z',
    };
    expect(active.retired_at).toBeUndefined();
    expect(active.retired_reason).toBeUndefined();
  });
});
