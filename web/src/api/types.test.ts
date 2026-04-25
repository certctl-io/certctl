import { describe, it, expect } from 'vitest';
import { POLICY_TYPES, POLICY_SEVERITIES } from './types';
import type {
  Agent,
  Certificate,
  CertificateVersion,
  DiscoveredCertificate,
  Issuer,
  Notification,
  Target,
} from './types';

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
    // D-2 (master): the post-D-2 Agent shape no longer carries
    // last_heartbeat / capabilities / tags / created_at / updated_at —
    // those were TS phantoms the Go-side struct never emitted.
    const retired: Agent = {
      id: 'ag-1',
      name: 'decom-01',
      hostname: 'server-old',
      ip_address: '10.0.0.1',
      os: 'linux',
      architecture: 'amd64',
      status: 'Offline',
      version: '2.1.0',
      last_heartbeat_at: '2026-01-01T00:00:00Z',
      registered_at: '2024-01-01T00:00:00Z',
      retired_at: '2026-01-01T00:00:00Z',
      retired_reason: 'old hardware',
    };
    expect(retired.retired_at).toBe('2026-01-01T00:00:00Z');
    expect(retired.retired_reason).toBe('old hardware');
  });

  it('accepts an Agent without retired_at / retired_reason (optional fields)', () => {
    // Active agents should not carry retirement metadata. If Phase 2b makes
    // the fields required, this block fails to compile.
    // D-2 (master): post-D-2 Agent shape (see sibling describe block).
    const active: Agent = {
      id: 'ag-2',
      name: 'web01',
      hostname: 'web01.prod',
      ip_address: '10.0.0.2',
      os: 'linux',
      architecture: 'amd64',
      status: 'Online',
      version: '2.1.0',
      last_heartbeat_at: '2026-04-18T12:00:00Z',
      registered_at: '2024-06-01T00:00:00Z',
    };
    expect(active.retired_at).toBeUndefined();
    expect(active.retired_reason).toBeUndefined();
  });
});

/**
 * D-5 (cat-f-ae0d06b6588f, master): Certificate TS phantom-fields trim.
 *
 * Pre-D-5 the Certificate interface declared `serial_number`,
 * `fingerprint_sha256`, `key_algorithm`, `key_size`, and `issued_at` as
 * optional. These fields were never emitted by Go's `ManagedCertificate`
 * (internal/domain/certificate.go) — they live on `CertificateVersion`,
 * which is the per-issuance record fetched from
 * /api/v1/certificates/{id}/versions. The optional declarations made
 * `cert.serial_number` always-undefined on list responses, and downstream
 * consumers (CertificateDetailPage's Key Algorithm / Key Size rows in
 * particular) silently rendered '—' for every cert despite the data
 * being available a single fetch away.
 *
 * Post-D-5 the TS type makes the missing-data case explicit: a
 * `cert.serial_number` access becomes a TS compile error, forcing every
 * consumer to acknowledge the version-fallback pattern. This regression
 * test pins the trim — if a future PR re-adds any of the five phantom
 * fields to Certificate (e.g. via merge conflict, copy-paste, or a
 * codegen run that regenerates from a stale OpenAPI spec), the
 * compile-fail block here will surface it.
 */
describe('Certificate interface (D-5 phantom-fields trim)', () => {
  it('does NOT declare per-issuance fields — those live on CertificateVersion', () => {
    // Construct a fully-populated Certificate. If a future PR re-adds
    // any of the five phantom fields (serial_number, fingerprint_sha256,
    // key_algorithm, key_size, issued_at) to the interface, every
    // omission in this literal becomes "missing required field" and
    // the test fails to compile. Conversely, attempting to set any of
    // the five fields on the literal is a TS error today (excess
    // property), so the negative-assertion block below also fails to
    // compile if someone re-adds them as optional.
    const cert: Certificate = {
      id: 'mc-test',
      name: 'test',
      common_name: 'test.example.com',
      sans: [],
      status: 'Active',
      environment: 'production',
      issuer_id: 'iss-test',
      owner_id: 'o-test',
      team_id: 't-test',
      renewal_policy_id: 'rp-default',
      certificate_profile_id: 'cp-default',
      expires_at: '2027-01-01T00:00:00Z',
      tags: {},
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    };
    expect(cert.id).toBe('mc-test');

    // Excess-property check: each of these MUST be a TS error if
    // uncommented. Keep them in the test as documentation of what's
    // intentionally absent. (We can't directly assert "type does not
    // have property X" without a type-level helper, but the literal
    // construction above plus tsc --noEmit in CI is the binding check.)
    //
    // const broken: Certificate = { ...cert, serial_number: '01:02' }; // ❌ TS2353
    // const broken2: Certificate = { ...cert, key_algorithm: 'EC' };   // ❌ TS2353
    // const broken3: Certificate = { ...cert, key_size: 256 };         // ❌ TS2353
    // const broken4: Certificate = { ...cert, fingerprint_sha256: '' };// ❌ TS2353
    // const broken5: Certificate = { ...cert, issued_at: '...' };      // ❌ TS2353
  });

  it('CertificateVersion still carries the per-issuance fields', () => {
    // The other half of the contract: the trimmed fields didn't go to
    // /dev/null — they live (and have always lived) on CertificateVersion.
    // If a refactor removes them from CertificateVersion too, the
    // CertificateDetailPage fallback path breaks. Pin both halves.
    const v: CertificateVersion = {
      id: 'mcv-test',
      certificate_id: 'mc-test',
      serial_number: '01:02:03',
      fingerprint_sha256: 'a'.repeat(64),
      pem_chain: '-----BEGIN CERTIFICATE-----\n...',
      csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\n...',
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2027-01-01T00:00:00Z',
      key_algorithm: 'ECDSA',
      key_size: 256,
      created_at: '2026-01-01T00:00:00Z',
    };
    expect(v.serial_number).toBe('01:02:03');
    expect(v.key_algorithm).toBe('ECDSA');
    expect(v.key_size).toBe(256);
  });
});

/**
 * D-2 (diff-05x06-7cdf4e78ae24, master): Agent TS phantom-fields trim.
 *
 * Pre-D-2 the `Agent` interface declared five fields that the Go-side
 * struct (`internal/domain/connector.go::Agent`) does NOT emit on the
 * wire: `last_heartbeat`, `capabilities`, `tags`, `created_at`,
 * `updated_at`. Two of them had real consumers (`AgentDetailPage.tsx`
 * read `agent.capabilities` and `agent.tags`) — both always rendered the
 * empty-state branch because the runtime values were always `undefined`.
 *
 * Post-D-2 a `agent.capabilities` access is a TS compile error, forcing
 * every consumer to acknowledge the field is not part of the Agent
 * contract. The Go-side struct emits exactly: id, name, hostname, status,
 * last_heartbeat_at (note the `_at` suffix — this is the real heartbeat
 * field and stays), registered_at, os, architecture, ip_address, version,
 * retired_at?, retired_reason?.
 */
describe('Agent interface (D-2 phantom-fields trim)', () => {
  it('does NOT declare last_heartbeat / capabilities / tags / created_at / updated_at', () => {
    // Construct an Agent with ONLY the post-D-2 field set. If a future
    // PR re-adds any of the five trimmed fields, the excess-property
    // comments below become live TS errors when uncommented (and the
    // CI guardrail in .github/workflows/ci.yml fires regardless).
    const a: Agent = {
      id: 'ag-test',
      name: 'web-01',
      hostname: 'web-01.prod',
      status: 'Online',
      last_heartbeat_at: '2026-04-25T12:00:00Z',
      registered_at: '2024-06-01T00:00:00Z',
      os: 'linux',
      architecture: 'amd64',
      ip_address: '10.0.0.1',
      version: '2.1.0',
    };
    expect(a.id).toBe('ag-test');
    expect(a.last_heartbeat_at).toBe('2026-04-25T12:00:00Z');

    // Excess-property check (each MUST be a TS error if uncommented):
    // const broken1: Agent = { ...a, last_heartbeat: '2026-...' }; // ❌ TS2353
    // const broken2: Agent = { ...a, capabilities: ['deploy'] };   // ❌ TS2353
    // const broken3: Agent = { ...a, tags: { env: 'prod' } };      // ❌ TS2353
    // const broken4: Agent = { ...a, created_at: '...' };          // ❌ TS2353
    // const broken5: Agent = { ...a, updated_at: '...' };          // ❌ TS2353
  });

  it('keeps last_heartbeat_at (the real Go-emitted heartbeat field)', () => {
    // Negative-prevention guard: the awk-windowed CI grep for the trimmed
    // `last_heartbeat` field must NOT trip on the legitimate
    // `last_heartbeat_at`. This test pins that the legitimate field stays.
    const a: Agent = {
      id: 'ag-2',
      name: 'web-02',
      hostname: 'web-02.prod',
      status: 'Offline',
      registered_at: '2024-06-01T00:00:00Z',
      os: 'linux',
      architecture: 'amd64',
      ip_address: '10.0.0.2',
      version: '2.1.0',
    };
    expect(a.last_heartbeat_at).toBeUndefined();
  });
});

/**
 * D-2 (diff-05x06-2044a46f4dd0, master): Target retirement-fields ADD.
 *
 * Pre-D-2 the Go-side `DeploymentTarget` struct
 * (`internal/domain/connector.go:24`) emitted `retired_at` and
 * `retired_reason` (I-004 soft-retirement, mirroring the Agent
 * treatment), but the TS `Target` interface did not declare them.
 * Consumers wanting to surface the retired state in the GUI had to
 * use `(target as any).retired_at` escapes that lost type-checking.
 *
 * Post-D-2 the TS interface declares both as optional nullable strings,
 * mirroring the existing Agent retirement-fields shape.
 */
describe('Target interface (D-2 retirement fields)', () => {
  it('accepts retired_at and retired_reason as optional nullable strings', () => {
    const retired: Target = {
      id: 't-decom-01',
      name: 'old-iis-server',
      type: 'iis',
      agent_id: 'ag-old',
      config: {},
      enabled: false,
      created_at: '2024-01-01T00:00:00Z',
      retired_at: '2026-03-01T00:00:00Z',
      retired_reason: 'replaced by new iis-server',
    };
    expect(retired.retired_at).toBe('2026-03-01T00:00:00Z');
    expect(retired.retired_reason).toBe('replaced by new iis-server');
  });

  it('accepts a Target without the retirement fields (active row)', () => {
    const active: Target = {
      id: 't-1',
      name: 'iis-server',
      type: 'iis',
      agent_id: 'ag-1',
      config: {},
      enabled: true,
      created_at: '2024-01-01T00:00:00Z',
    };
    expect(active.retired_at).toBeUndefined();
    expect(active.retired_reason).toBeUndefined();
  });
});

/**
 * D-2 (diff-05x06-85ab6b98a2f7, master): DiscoveredCertificate pem_data ADD.
 *
 * Pre-D-2 the Go-side `DiscoveredCertificate` struct
 * (`internal/domain/discovery.go::DiscoveredCertificate.PEMData`) emitted
 * `pem_data` (omitempty — populated by repo SELECT, agent ingestion at
 * cmd/agent/main.go:1021, and connector scans at
 * internal/connector/discovery/azurekv/azurekv.go:234), but the TS
 * `DiscoveredCertificate` interface did not declare it. Consumers wanting
 * to inspect or download the raw PEM had to use `(d as any).pem_data`.
 *
 * Post-D-2 the TS interface declares it as `pem_data?: string`, optional
 * because the Go side uses `omitempty` (empty string → not emitted).
 *
 * Performance note (deferred follow-up): the LIST endpoint also loads
 * pem_data via the same repo SELECT; for large discovered-cert tables
 * this can ship kilobytes per row. Optimising the list response to omit
 * pem_data is a separate backend change.
 */
describe('DiscoveredCertificate interface (D-2 pem_data ADD)', () => {
  it('accepts pem_data as an optional string', () => {
    const d: DiscoveredCertificate = {
      id: 'dc-1',
      fingerprint_sha256: 'a'.repeat(64),
      common_name: 'discovered.example.com',
      sans: [],
      serial_number: '01:02:03',
      issuer_dn: 'CN=Test CA',
      subject_dn: 'CN=discovered.example.com',
      key_algorithm: 'ECDSA',
      key_size: 256,
      is_ca: false,
      source_path: '/etc/ssl/certs/disc.pem',
      source_format: 'pem',
      agent_id: 'ag-1',
      status: 'Unmanaged',
      first_seen_at: '2026-04-25T12:00:00Z',
      last_seen_at: '2026-04-25T12:00:00Z',
      created_at: '2026-04-25T12:00:00Z',
      updated_at: '2026-04-25T12:00:00Z',
      pem_data: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n',
    };
    expect(d.pem_data).toContain('BEGIN CERTIFICATE');
  });

  it('accepts a DiscoveredCertificate without pem_data (list-response shape)', () => {
    const d: DiscoveredCertificate = {
      id: 'dc-2',
      fingerprint_sha256: 'b'.repeat(64),
      common_name: 'list.example.com',
      sans: [],
      serial_number: '04:05:06',
      issuer_dn: 'CN=Test CA',
      subject_dn: 'CN=list.example.com',
      key_algorithm: 'ECDSA',
      key_size: 256,
      is_ca: false,
      source_path: '/etc/ssl/certs/list.pem',
      source_format: 'pem',
      agent_id: 'ag-1',
      status: 'Unmanaged',
      first_seen_at: '2026-04-25T12:00:00Z',
      last_seen_at: '2026-04-25T12:00:00Z',
      created_at: '2026-04-25T12:00:00Z',
      updated_at: '2026-04-25T12:00:00Z',
    };
    expect(d.pem_data).toBeUndefined();
  });
});

/**
 * D-2 (diff-05x06-97fab8783a5c, master): Issuer status phantom trim.
 *
 * Pre-D-2 the TS `Issuer` interface declared a required `status: string`
 * field that the Go-side struct (`internal/domain/connector.go::Issuer`)
 * never emitted — the Go struct has only `Enabled bool`. The TS interface
 * comment claimed "Backend returns enabled boolean; status is derived
 * from this" but no derivation logic existed: `IssuersPage.tsx::~line 23`
 * read `issuer.status || 'Unknown'` and always rendered 'Unknown'.
 *
 * Post-D-2 the `status` field is removed; the consumer now derives the
 * displayed status from `enabled` at render time.
 */
describe('Issuer interface (D-2 status phantom trim)', () => {
  it('does NOT declare a phantom `status` field — derive from `enabled`', () => {
    // Construct a fully-populated Issuer with the post-D-2 shape.
    // If `status` is re-added, this construction fails with "missing
    // required" (TS2741) when status is required, or the excess-property
    // comment below trips when it's added back as optional.
    const i: Issuer = {
      id: 'iss-test',
      name: 'Test ACME',
      type: 'acme',
      config: {},
      enabled: true,
      created_at: '2026-01-01T00:00:00Z',
    };
    expect(i.id).toBe('iss-test');
    expect(i.enabled).toBe(true);

    // Excess-property check:
    // const broken: Issuer = { ...i, status: 'Active' }; // ❌ TS2353
  });
});

/**
 * D-2 (diff-05x06-caba9eb3620e, master): Notification subject phantom trim.
 *
 * Pre-D-2 the TS `Notification` interface declared `subject?: string` —
 * the field was acknowledged in the existing comment as "a historical
 * frontend-only field the backend never emits" but kept on the interface
 * "so legacy fixtures and the pendingNotif test mock still type
 * correctly." Real consumer at `NotificationsPage.tsx::~line 241` had
 * `{n.message || n.subject}` as a fallback that always fell through to
 * `n.message` (since `n.subject` was always undefined).
 *
 * Post-D-2 the field is removed; the consumer drops the dead fallback
 * and the test fixtures drop the dead `subject:` initializer.
 */
describe('Notification interface (D-2 subject phantom trim)', () => {
  it('does NOT declare the phantom `subject` field', () => {
    const n: Notification = {
      id: 'no-test',
      type: 'CertificateExpiring',
      channel: 'email',
      recipient: 'ops@example.com',
      message: 'Certificate api.example.com expires in 14 days',
      status: 'pending',
      created_at: '2026-04-25T12:00:00Z',
    };
    expect(n.id).toBe('no-test');
    expect(n.message).toContain('14 days');

    // Excess-property check:
    // const broken: Notification = { ...n, subject: 'Cert expiring' }; // ❌ TS2353
  });
});
