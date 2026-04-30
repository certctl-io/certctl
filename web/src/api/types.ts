// D-5 (cat-f-ae0d06b6588f, master): the five per-issuance fields
// (serial_number, fingerprint_sha256, key_algorithm, key_size,
// issued_at) USED to live here as optional. They were never emitted
// by Go's `ManagedCertificate` (internal/domain/certificate.go) — they
// live on `CertificateVersion` (per-issuance evidence) and are fetched
// via getCertificateVersions(id). Render-site consumers (notably
// CertificateDetailPage) use `latestVersion?.field` as the canonical
// access path. Pre-D-5 the optional declaration silently returned
// `undefined` on every list response, so consumers who didn't know
// about the version-fallback pattern rendered '—' for every cert; now
// the missing-data case is explicit at the type level (a `cert.X`
// access for one of these fields is a TS compile error).
export interface Certificate {
  id: string;
  name: string;
  common_name: string;
  sans: string[];
  status: string;
  environment: string;
  issuer_id: string;
  owner_id: string;
  team_id: string;
  renewal_policy_id: string;
  certificate_profile_id: string;
  expires_at: string;
  revoked_at?: string;
  revocation_reason?: string;
  target_ids?: string[];
  tags: Record<string, string>;
  last_renewal_at?: string;
  last_deployment_at?: string;
  created_at: string;
  updated_at: string;
}

export const REVOCATION_REASONS = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'keyCompromise', label: 'Key Compromise' },
  { value: 'caCompromise', label: 'CA Compromise' },
  { value: 'affiliationChanged', label: 'Affiliation Changed' },
  { value: 'superseded', label: 'Superseded' },
  { value: 'cessationOfOperation', label: 'Cessation of Operation' },
  { value: 'certificateHold', label: 'Certificate Hold' },
  { value: 'privilegeWithdrawn', label: 'Privilege Withdrawn' },
] as const;

export interface CertificateVersion {
  id: string;
  certificate_id: string;
  serial_number: string;
  fingerprint_sha256: string;
  pem_chain: string;
  csr_pem: string;
  not_before: string;
  not_after: string;
  key_algorithm?: string;
  key_size?: number;
  created_at: string;
}

// G-2 (P1): `api_key_hash` is intentionally absent from this interface.
// The server-side struct (internal/domain/connector.go::Agent) carries
// the field for the auth-lookup path but redacts it via a custom
// MarshalJSON so it never reaches the JSON wire. Adding `api_key_hash`
// here would not magically populate it on the wire — and would mislead
// future contributors into thinking the field is part of the public
// API contract. See docs/architecture.md ER-diagram note and
// coverage-gap-audit-2026-04-24-v5/unified-audit.md cat-s5-apikey_leak
// for the closure rationale.
//
// D-2 (diff-05x06-7cdf4e78ae24, master): pre-D-2 this interface declared
// five fields the Go-side struct (internal/domain/connector.go::Agent)
// does NOT emit on the wire: `last_heartbeat` (the real field is
// `last_heartbeat_at`; the bare-name was a sibling typo never rejected
// at compile time), `capabilities`, `tags`, `created_at`, `updated_at`.
// Two of them had real consumers (AgentDetailPage rendered
// `agent.capabilities` and `agent.tags`) — both always rendered the
// empty-state branch because the runtime values were always undefined.
// Post-D-2 the interface field set matches the Go-emitted JSON exactly:
// id, name, hostname, status, last_heartbeat_at, registered_at, os,
// architecture, ip_address, version, retired_at?, retired_reason?. A
// `agent.capabilities` access is now a TS compile error. The CI guardrail
// in .github/workflows/ci.yml (`Forbidden StatusBadge dead-key + TS
// phantom-field regression guard (D-1 + D-2)`) blocks reintroduction of
// the trimmed field names while explicitly excluding `last_heartbeat_at`
// from the `last_heartbeat` regex.
export interface Agent {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  os: string;
  architecture: string;
  status: string;
  version: string;
  last_heartbeat_at?: string;
  registered_at: string;
  // I-004: soft-retirement fields. When retired_at is non-null, the agent is
  // tombstoned — it will never heartbeat again and cascaded targets have been
  // retired alongside it. The retired tab on AgentsPage uses these to show the
  // when/why. The server filters retired rows from the default /api/v1/agents
  // listing; they appear only via GET /api/v1/agents/retired.
  retired_at?: string | null;
  retired_reason?: string | null;
}

// I-004: dependency counts returned by the retire handler in both the 200
// success-with-cascade body and the 409 blocked_by_dependencies body. The
// operator UI uses these to show "this agent has N targets, M certs, K jobs
// depending on it" in the confirm-retire dialog.
export interface AgentDependencyCounts {
  active_targets: number;
  active_certificates: number;
  pending_jobs: number;
}

// I-004: success shape for DELETE /api/v1/agents/{id}. already_retired is
// always false for 200 responses; 204 responses carry no body (the retire was
// idempotent — the agent was already retired). The frontend distinguishes by
// HTTP status, not by this field.
export interface RetireAgentResponse {
  retired_at: string;
  already_retired: boolean;
  cascade: boolean;
  counts: AgentDependencyCounts;
}

// I-004: shape returned with HTTP 409 when a retire is blocked by active
// downstream dependencies. Keep in lockstep with the handler's inline struct
// in internal/api/handler/agents.go (search "blocked_by_dependencies").
export interface BlockedByDependenciesResponse {
  error: 'blocked_by_dependencies';
  message: string;
  counts: AgentDependencyCounts;
}

export interface Job {
  id: string;
  certificate_id: string;
  type: string;
  target_id?: string;
  agent_id?: string;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error?: string;
  scheduled_at: string;
  started_at: string;
  completed_at: string;
  created_at: string;
  verification_status?: string;
  verified_at?: string;
  verification_fingerprint?: string;
  verification_error?: string;
}

/**
 * Notification mirrors internal/domain/notification.go#NotificationEvent.
 *
 * I-005 (Notification Retry + Dead-letter Queue) widens the shape with three
 * audit fields:
 *
 *   - retry_count   — number of delivery attempts already consumed (0..5). The
 *                     5-cap is enforced server-side by NotificationsMaxAttempts.
 *   - next_retry_at — RFC3339 timestamp the retry sweep will next consider this
 *                     notification. Null for sent/dead/read and between sweeps
 *                     for pending rows; the sweep populates it on each failure
 *                     using min(2^retry_count * 1m, 1h).
 *   - last_error    — most recent transient delivery failure. Preserved across
 *                     requeue so Dead letter triage shows *why* the row died
 *                     without chasing server logs.
 *
 * `sent_at` and `error` are the pre-I-005 audit fields on the backend struct.
 *
 * D-2 (diff-05x06-caba9eb3620e, master): pre-D-2 this interface carried a
 * phantom `subject?: string` field documented as "kept optional so legacy
 * fixtures and the pendingNotif test mock still type correctly without
 * forcing a rewrite of every existing consumer." The Go-side struct
 * (`internal/domain/notification.go::NotificationEvent`) never emitted it,
 * so `n.subject` was always `undefined` at runtime. The one real consumer
 * (NotificationsPage rendering `{n.message || n.subject}`) always fell
 * through to `n.message`. Post-D-2 the field is removed; the consumer
 * drops the dead `|| n.subject` fallback and the test fixtures drop the
 * dead `subject:` initializer. The CI guardrail blocks reintroduction.
 *
 * Status values follow the backend NotificationStatus constants:
 *   pending · sent · failed · dead · read
 * The existing list view tolerates the legacy title-cased "Pending" alias at
 * render time (NotificationRow) so upgraded clients talking to older servers
 * don't regress — see `isUnread` logic in NotificationsPage.tsx.
 */
export interface Notification {
  id: string;
  type: string;
  channel: string;
  recipient: string;
  message: string;
  status: string;
  certificate_id?: string;
  sent_at?: string | null;
  error?: string | null;
  retry_count?: number;
  next_retry_at?: string | null;
  last_error?: string | null;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  actor: string;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  timestamp: string;
}

/**
 * Policy rule type enum — pinned to the backend's TitleCase constants in
 * internal/domain/policy.go. Historical note (D-005): the GUI previously sent
 * lowercase values (`ownership`, `environment`, etc.) that the handler's
 * ValidatePolicyType rejected with a 400. These tuples are the canonical
 * source of truth for the dropdown options; the regression test in
 * types.test.ts pins them so future drift is caught at CI time.
 */
export const POLICY_TYPES = [
  'AllowedIssuers',
  'AllowedDomains',
  'RequiredMetadata',
  'AllowedEnvironments',
  'RenewalLeadTime',
  'CertificateLifetime',
] as const;
export type PolicyType = (typeof POLICY_TYPES)[number];

/**
 * Policy severity enum — pinned to the backend's PolicySeverity constants.
 * The backend CHECK constraint on policy_rules.severity enforces the same
 * allowlist (migration 000013). The 4-value `medium` option that used to
 * appear in the GUI was never a valid backend value and has been removed.
 */
export const POLICY_SEVERITIES = ['Warning', 'Error', 'Critical'] as const;
export type PolicySeverity = (typeof POLICY_SEVERITIES)[number];

export interface PolicyRule {
  id: string;
  name: string;
  type: PolicyType;
  severity: PolicySeverity;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyViolation {
  id: string;
  rule_id: string;
  certificate_id: string;
  severity: PolicySeverity;
  message: string;
  created_at: string;
}

/**
 * G-1: RenewalPolicy is the lifecycle policy attached to managed certificates
 * via `managed_certificates.renewal_policy_id` (FK ON DELETE RESTRICT → `rp-*`
 * IDs in the `renewal_policies` table). Distinct from `PolicyRule` above, which
 * models compliance rules in the `policy_rules` table with `pol-*` IDs. The
 * OnboardingWizard + CertificatesPage + CertificateDetailPage dropdowns populate
 * `renewal_policy_id` from this interface — previously they mis-populated it
 * from `getPolicies()` which returned `pol-*` IDs and produced FK violations on
 * certificate insert/update.
 *
 * JSON tags mirror internal/domain/renewal_policy.go.
 */
export interface RenewalPolicy {
  id: string;
  name: string;
  renewal_window_days: number;
  auto_renew: boolean;
  max_retries: number;
  retry_interval_seconds: number;
  alert_thresholds_days: number[];
  certificate_profile_id?: string | null;
  created_at: string;
  updated_at: string;
}

// D-2 (diff-05x06-97fab8783a5c, master): pre-D-2 this interface declared
// a required `status: string` field that the Go-side struct
// (`internal/domain/connector.go::Issuer`) never emitted — the Go struct
// has only `Enabled bool`. The TS comment claimed "status is derived from
// this" but no derivation ever existed: `IssuersPage.tsx` read
// `issuer.status || 'Unknown'` and always rendered 'Unknown'. Post-D-2
// the phantom is removed; render sites derive the displayed status from
// `enabled` (and optionally `test_status`) at the call site. The CI
// guardrail in .github/workflows/ci.yml blocks reintroduction.
export interface Issuer {
  id: string;
  name: string;
  type: string;
  config: Record<string, unknown>;
  /** Backend returns enabled boolean; render sites derive status labels from this */
  enabled: boolean;
  /** Timestamp of last connection test */
  last_tested_at?: string;
  /** Result of last connection test: "untested", "success", or "failed" */
  test_status?: string;
  /** Config source: "database" (GUI-created) or "env" (env var seeded) */
  source?: string;
  created_at: string;
  updated_at?: string;
}

// D-2 (diff-05x06-2044a46f4dd0, master): pre-D-2 this interface lacked
// `retired_at` and `retired_reason` even though the Go-side struct
// (`internal/domain/connector.go::DeploymentTarget`) emits both as part
// of the I-004 soft-retirement model. Consumers wanting to surface the
// retired state had to escape via `(target as any).retired_at`. Post-D-2
// the TS interface declares both as optional nullable strings, mirroring
// the Agent retirement-fields shape (an Agent retire cascades to all
// associated Targets per service.RetireAgent → repository.RetireTarget).
export interface Target {
  id: string;
  name: string;
  type: string;
  agent_id: string;
  config: Record<string, unknown>;
  enabled: boolean;
  last_tested_at?: string;
  test_status?: string;
  source?: string;
  retired_at?: string | null;
  retired_reason?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface KeyAlgorithmRule {
  algorithm: string;
  min_size: number;
}

export interface CertificateProfile {
  id: string;
  name: string;
  description: string;
  allowed_key_algorithms: KeyAlgorithmRule[];
  max_ttl_seconds: number;
  allowed_ekus: string[];
  required_san_patterns: string[];
  spiffe_uri_pattern: string;
  allow_short_lived: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface Owner {
  id: string;
  name: string;
  email: string;
  team_id: string;
  created_at: string;
  updated_at: string;
}

export interface Team {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface AgentGroup {
  id: string;
  name: string;
  description: string;
  match_os: string;
  match_architecture: string;
  match_ip_cidr: string;
  match_version: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AgentGroupMembership {
  agent_group_id: string;
  agent_id: string;
  membership_type: string;
  created_at: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}

// Stats types
export interface DashboardSummary {
  total_certificates: number;
  expiring_certificates: number;
  expired_certificates: number;
  revoked_certificates: number;
  active_agents: number;
  offline_agents: number;
  total_agents: number;
  pending_jobs: number;
  failed_jobs: number;
  complete_jobs: number;
  completed_at: string;
}

export interface CertificateStatusCount {
  status: string;
  count: number;
}

export interface ExpirationBucket {
  date: string;
  count: number;
}

export interface JobTrendDataPoint {
  date: string;
  completed_count: number;
  failed_count: number;
  success_rate: number;
}

export interface IssuanceRateDataPoint {
  date: string;
  issued_count: number;
}

// Discovery types
//
// D-2 (diff-05x06-85ab6b98a2f7, master): pre-D-2 this interface lacked
// `pem_data` even though the Go-side struct
// (`internal/domain/discovery.go::DiscoveredCertificate.PEMData`,
// json:"pem_data,omitempty") emits it on the wire. The field is
// populated by the agent's filesystem scanner
// (cmd/agent/main.go::buildDiscoveryReport), the cloud-secret-manager
// connectors (e.g. internal/connector/discovery/azurekv/azurekv.go), and
// the repo SELECT that materialises the row from PostgreSQL. Post-D-2
// the TS interface declares `pem_data?: string`, optional because the
// Go side uses `omitempty` (empty string → not emitted). Performance
// follow-up: the LIST endpoint loads pem_data via the same repo SELECT;
// a future change should gate emission on the per-id detail path only.
export interface DiscoveredCertificate {
  id: string;
  fingerprint_sha256: string;
  common_name: string;
  sans: string[];
  serial_number: string;
  issuer_dn: string;
  subject_dn: string;
  not_before?: string;
  not_after?: string;
  key_algorithm: string;
  key_size: number;
  is_ca: boolean;
  pem_data?: string;
  source_path: string;
  source_format: string;
  agent_id: string;
  discovery_scan_id?: string;
  managed_certificate_id?: string;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  dismissed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveryScan {
  id: string;
  agent_id: string;
  directories: string[];
  certificates_found: number;
  certificates_new: number;
  errors_count: number;
  scan_duration_ms: number;
  started_at: string;
  completed_at?: string;
}

export interface DiscoverySummary {
  Unmanaged: number;
  Managed: number;
  Dismissed: number;
}

// Network scan types
export interface NetworkScanTarget {
  id: string;
  name: string;
  cidrs: string[];
  ports: number[];
  enabled: boolean;
  scan_interval_hours: number;
  timeout_ms: number;
  last_scan_at?: string;
  last_scan_duration_ms?: number;
  last_scan_certs_found?: number;
  created_at: string;
  updated_at: string;
}

export interface MetricsResponse {
  gauge: {
    certificate_total: number;
    certificate_active: number;
    certificate_expiring_soon: number;
    certificate_expired: number;
    certificate_revoked: number;
    agent_total: number;
    agent_online: number;
    job_pending: number;
  };
  counter: {
    job_completed_total: number;
    job_failed_total: number;
  };
  uptime: {
    uptime_seconds: number;
    server_started: string;
    measured_at: string;
  };
}

// Health check types (M48)
export interface EndpointHealthCheck {
  id: string;
  endpoint: string;
  certificate_id?: string;
  network_scan_target_id?: string;
  expected_fingerprint: string;
  observed_fingerprint: string;
  status: string;
  consecutive_failures: number;
  response_time_ms: number;
  tls_version: string;
  cipher_suite: string;
  cert_subject: string;
  cert_issuer: string;
  cert_expiry?: string;
  last_checked_at?: string;
  last_success_at?: string;
  last_failure_at?: string;
  last_transition_at?: string;
  failure_reason: string;
  degraded_threshold: number;
  down_threshold: number;
  check_interval_seconds: number;
  enabled: boolean;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  created_at: string;
  updated_at: string;
}

export interface HealthHistoryEntry {
  id: string;
  health_check_id: string;
  status: string;
  response_time_ms: number;
  fingerprint: string;
  failure_reason: string;
  checked_at: string;
}

export interface HealthCheckSummary {
  healthy: number;
  degraded: number;
  down: number;
  cert_mismatch: number;
  unknown: number;
  total: number;
}

// CRL/OCSP-Responder Phase 5: admin observability endpoint payload mirror.
//
// Backend type lives at internal/api/handler/admin_crl_cache.go::CRLCacheRow /
// CRLCacheEvt and is gated behind middleware.IsAdmin (M-008 admin-gated handler
// allowlist). The GUI surfaces a per-issuer cache-age badge on the
// CertificateDetailPage Revocation Endpoints panel — only visible to admin
// callers. Non-admin callers get HTTP 403 from the server; the GUI suppresses
// the fetch entirely (and the badge) when useAuth().admin is false.
//
// Optional fields stay optional here because the server omits them when the
// cache row is absent (issuer never had a CRL generated yet) — the panel
// renders a "Not yet generated" pill in that case.
export interface CRLCacheEvent {
  started_at: string;
  duration_ms: number;
  succeeded: boolean;
  crl_number: number;
  revoked_count: number;
  error?: string;
}

export interface CRLCacheRow {
  issuer_id: string;
  cache_present: boolean;
  crl_number?: number;
  this_update?: string;
  next_update?: string;
  generated_at?: string;
  generation_duration_ms?: number;
  revoked_count?: number;
  is_stale?: boolean;
  recent_events?: CRLCacheEvent[];
}

export interface CRLCacheResponse {
  cache_rows: CRLCacheRow[];
  row_count: number;
  generated_at: string;
}

// SCEP RFC 8894 + Intune master bundle Phase 9.2: admin observability
// payload mirror for the per-profile Intune dispatcher.
//
// Backend types live at internal/service/scep.go (IntuneStatsSnapshot +
// IntuneTrustAnchorInfo) and the handler glue in
// internal/api/handler/admin_scep_intune.go. Both endpoints are admin-
// gated (M-008 pin in m008_admin_gate_test.go) — the GUI hides the
// SCEP Intune surface entirely (rather than letting it 403 noisily) by
// gating the React-Query enabled flag on useAuth().admin at the call site.
export interface IntuneTrustAnchorInfo {
  subject: string;
  not_before: string;
  not_after: string;
  days_to_expiry: number;
  expired: boolean;
}

// IntuneStatsSnapshot — one row per configured SCEP profile. Profiles
// where Intune is disabled appear with enabled=false; the remaining
// fields stay zero/empty so the GUI can render a "Not enabled" pill.
export interface IntuneStatsSnapshot {
  path_id: string;
  issuer_id: string;
  enabled: boolean;
  trust_anchor_path?: string;
  trust_anchors?: IntuneTrustAnchorInfo[];
  audience?: string;
  challenge_validity_ns?: number;
  // Master prompt §15 hazard closure (2026-04-29): per-profile
  // ±tolerance on iat/exp checks. Default 60s wired from
  // CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CLOCK_SKEW_TOLERANCE.
  clock_skew_tolerance_ns?: number;
  rate_limit_disabled: boolean;
  replay_cache_size: number;
  // Counter labels match intuneFailReason() in the backend dispatcher:
  // success / signature_invalid / expired / not_yet_valid / wrong_audience /
  // replay / unknown_version / malformed / rate_limited / claim_mismatch /
  // compliance_failed.
  counters: Record<string, number>;
  generated_at: string;
}

export interface IntuneStatsResponse {
  profiles: IntuneStatsSnapshot[];
  profile_count: number;
  generated_at: string;
}

export interface IntuneReloadTrustResponse {
  reloaded: boolean;
  path_id: string;
  reloaded_at: string;
}

// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up
// (cowork/scep-gui-restructure-prompt.md): per-profile SCEP admin
// snapshot. Backs the new /api/v1/admin/scep/profiles endpoint and
// the Profiles tab on the SCEP Administration page.
//
// Distinct from IntuneStatsSnapshot (which mirrors the existing
// /admin/scep/intune/stats endpoint) so the existing endpoint's JSON
// shape stays byte-stable for external consumers — backward-compat
// for the Phase 9 admin contract. The Profiles endpoint nests Intune
// data under a single optional `intune` field; the legacy Intune
// endpoint keeps the flat shape.
export interface IntuneSection {
  trust_anchor_path?: string;
  trust_anchors?: IntuneTrustAnchorInfo[];
  audience?: string;
  challenge_validity_ns?: number;
  // Master prompt §15 hazard closure (2026-04-29): per-profile
  // ±tolerance on iat/exp checks. Default 60s.
  clock_skew_tolerance_ns?: number;
  rate_limit_disabled: boolean;
  replay_cache_size: number;
  counters: Record<string, number>;
}

export interface SCEPProfileStatsSnapshot {
  path_id: string;
  issuer_id: string;
  challenge_password_set: boolean;
  ra_cert_subject?: string;
  ra_cert_not_before?: string;
  ra_cert_not_after?: string;
  ra_cert_days_to_expiry: number;
  ra_cert_expired: boolean;
  mtls_enabled: boolean;
  mtls_trust_bundle_path?: string;
  generated_at: string;
  // nil/undefined when Intune is disabled on this profile.
  intune?: IntuneSection;
}

export interface SCEPProfilesResponse {
  profiles: SCEPProfileStatsSnapshot[];
  profile_count: number;
  generated_at: string;
}

// EST RFC 7030 hardening master bundle Phase 7.1 / 8 GUI:
// per-profile snapshot returned by GET /api/v1/admin/est/profiles. Mirrors
// the Go-side service.ESTStatsSnapshot 1:1.
export interface ESTTrustAnchorInfo {
  subject: string;
  not_before: string;
  not_after: string;
  days_to_expiry: number;
  expired: boolean;
}

export interface ESTStatsSnapshot {
  path_id: string;
  issuer_id: string;
  profile_id?: string;
  // 12 named labels — see service/est_counters.go.
  counters: Record<string, number>;
  mtls_enabled: boolean;
  basic_auth_configured: boolean;
  server_keygen_enabled: boolean;
  trust_anchors?: ESTTrustAnchorInfo[];
  trust_anchor_path?: string;
  now: string;
}

export interface ESTProfilesResponse {
  profiles: ESTStatsSnapshot[];
  profile_count: number;
  generated_at: string;
}

export interface ESTReloadTrustResponse {
  reloaded: boolean;
  path_id: string;
  reloaded_at: string;
}

// SCEP RFC 8894 + Intune master bundle Phase 11.5 — SCEP probe.
//
// Backs the SCEP Probe section on the Network Scan page. The probe
// issues GetCACaps + GetCACert against an operator-supplied SCEP
// server URL and returns capability + posture metadata. Used for
// pre-migration assessment + compliance posture audits. Persisted
// to scep_probe_results (migration 000021) so the GUI can render
// recent probe history.
export interface SCEPProbeResult {
  id: string;
  target_url: string;
  reachable: boolean;
  advertised_caps: string[];
  supports_rfc8894: boolean;
  supports_aes: boolean;
  supports_post_operation: boolean;
  supports_renewal: boolean;
  supports_sha256: boolean;
  supports_sha512: boolean;
  ca_cert_subject?: string;
  ca_cert_issuer?: string;
  ca_cert_not_before?: string;
  ca_cert_not_after?: string;
  ca_cert_expired: boolean;
  ca_cert_days_to_expiry: number;
  ca_cert_algorithm?: string;
  ca_cert_chain_length: number;
  probed_at: string;
  probe_duration_ms: number;
  error?: string;
  created_at?: string;
}

export interface SCEPProbesResponse {
  probes: SCEPProbeResult[];
  probe_count: number;
}
