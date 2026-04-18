import { describe, it, expect } from 'vitest';
import { POLICY_TYPES, POLICY_SEVERITIES } from './types';

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
