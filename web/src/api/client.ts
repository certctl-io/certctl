import type { Certificate, CertificateVersion, Agent, Job, Notification, AuditEvent, PolicyRule, PolicyViolation, Issuer, Target, CertificateProfile, Owner, Team, AgentGroup, PaginatedResponse, DashboardSummary, CertificateStatusCount, ExpirationBucket, JobTrendDataPoint, IssuanceRateDataPoint, MetricsResponse, DiscoveredCertificate, DiscoveryScan, DiscoverySummary, NetworkScanTarget, EndpointHealthCheck, HealthHistoryEntry, HealthCheckSummary, AgentDependencyCounts, RetireAgentResponse, BlockedByDependenciesResponse } from './types';

const BASE = '/api/v1';

// API key stored in memory (not localStorage for security)
let apiKey: string | null = null;

export function setApiKey(key: string | null) {
  apiKey = key;
}

export function getApiKey(): string | null {
  return apiKey;
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }
  return headers;
}

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { ...authHeaders(), ...init?.headers },
    ...init,
  });
  if (res.status === 401) {
    // Trigger re-auth
    const event = new CustomEvent('certctl:auth-required');
    window.dispatchEvent(event);
    throw new Error('Authentication required');
  }
  if (!res.ok) {
    let errorMsg = res.statusText;
    try {
      const body = await res.json();
      errorMsg = body.message || body.error || errorMsg;
    } catch {
      // Response body is not JSON, use status text
    }
    throw new Error(errorMsg || `HTTP ${res.status}`);
  }
  if (res.status === 204) return {} as T;
  return res.json();
}

// Auth
export const getAuthInfo = () =>
  fetch(`${BASE}/auth/info`, { headers: { 'Content-Type': 'application/json' } })
    .then(r => r.json() as Promise<{ auth_type: string; required: boolean }>);

// AuthCheckResponse mirrors the /auth/check handler payload. Post-M-003 it
// surfaces `user` (named-key identity) and `admin` (named-key admin flag) so
// the GUI can gate admin-only affordances. When CERTCTL_AUTH_TYPE=none the
// backend returns {user: "", admin: false}.
export interface AuthCheckResponse {
  status: string;
  user: string;
  admin: boolean;
}

export const checkAuth = (key: string) =>
  fetch(`${BASE}/auth/check`, {
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
  }).then(r => {
    if (!r.ok) throw new Error('Invalid API key');
    return r.json() as Promise<AuthCheckResponse>;
  });

// Certificates
export const getCertificates = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Certificate>>(`${BASE}/certificates?${qs}`);
};

export const getCertificate = (id: string) =>
  fetchJSON<Certificate>(`${BASE}/certificates/${id}`);

export const getCertificateVersions = (id: string) =>
  fetchJSON<PaginatedResponse<CertificateVersion>>(`${BASE}/certificates/${id}/versions`);

export const createCertificate = (data: Partial<Certificate>) =>
  fetchJSON<Certificate>(`${BASE}/certificates`, { method: 'POST', body: JSON.stringify(data) });

export const triggerRenewal = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/certificates/${id}/renew`, { method: 'POST' });

export const updateCertificate = (id: string, data: Partial<Certificate>) =>
  fetchJSON<Certificate>(`${BASE}/certificates/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const archiveCertificate = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/certificates/${id}`, { method: 'DELETE' });

export const triggerDeployment = (id: string, targetId: string) =>
  fetchJSON<{ message: string }>(`${BASE}/certificates/${id}/deploy`, {
    method: 'POST',
    body: JSON.stringify({ target_id: targetId }),
  });

export const revokeCertificate = (id: string, reason: string) =>
  fetchJSON<{ status: string }>(`${BASE}/certificates/${id}/revoke`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });

export interface BulkRevokeCriteria {
  reason: string;
  profile_id?: string;
  owner_id?: string;
  agent_id?: string;
  issuer_id?: string;
  team_id?: string;
  certificate_ids?: string[];
}

export interface BulkRevokeResult {
  total_matched: number;
  total_revoked: number;
  total_skipped: number;
  total_failed: number;
  errors?: { certificate_id: string; error: string }[];
}

export const bulkRevokeCertificates = (criteria: BulkRevokeCriteria) =>
  fetchJSON<BulkRevokeResult>(`${BASE}/certificates/bulk-revoke`, {
    method: 'POST',
    body: JSON.stringify(criteria),
  });

// Certificate Export
export const exportCertificatePEM = (id: string) =>
  fetchJSON<{ cert_pem: string; chain_pem: string; full_pem: string }>(`${BASE}/certificates/${id}/export/pem`);

export const downloadCertificatePEM = (id: string) => {
  const headers: Record<string, string> = {};
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  return fetch(`${BASE}/certificates/${id}/export/pem?download=true`, { headers })
    .then(r => {
      if (!r.ok) throw new Error('Export failed');
      return r.blob();
    });
};

export const exportCertificatePKCS12 = (id: string, password: string = '') => {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  return fetch(`${BASE}/certificates/${id}/export/pkcs12`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ password }),
  }).then(r => {
    if (!r.ok) throw new Error('Export failed');
    return r.blob();
  });
};

// Certificate Deployments
export const getCertificateDeployments = (id: string, params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Job>>(`${BASE}/certificates/${id}/deployments?${qs}`);
};

// OCSP (RFC 6960) — served unauthenticated under /.well-known/pki/ per RFC 8615
// (M-006 relocation). The legacy JSON CRL endpoint (`GET /api/v1/crl`) was
// removed entirely; relying parties fetch the DER-encoded CRL directly from
// `/.well-known/pki/crl/{issuer_id}` (no GUI wrapper — binary download only).
export const getOCSPStatus = (issuerId: string, serial: string) => {
  // No Authorization header — the OCSP responder is intentionally unauthenticated
  // so relying parties without certctl API keys can check revocation status.
  return fetch(`/.well-known/pki/ocsp/${issuerId}/${serial}`)
    .then(r => {
      if (!r.ok) throw new Error(`OCSP request failed: ${r.status}`);
      return r.arrayBuffer();
    });
};

// Agents
export const getAgents = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Agent>>(`${BASE}/agents?${qs}`);
};

export const getAgent = (id: string) =>
  fetchJSON<Agent>(`${BASE}/agents/${id}`);

export const registerAgent = (data: Partial<Agent>) =>
  fetchJSON<Agent>(`${BASE}/agents`, { method: 'POST', body: JSON.stringify(data) });

// I-004: typed error thrown by retireAgent when the server returns HTTP 409 with
// {error: "blocked_by_dependencies", ...}. Callers that want to show the
// dependency-counts dialog should `catch (e)` and check `e instanceof
// BlockedByDependenciesError` — the counts field is the same shape the
// backend handler returns from its inline struct in
// internal/api/handler/agents.go. Generic network / 5xx failures still throw
// plain Error so existing error-boundary code is unaffected.
export class BlockedByDependenciesError extends Error {
  readonly counts: AgentDependencyCounts;
  constructor(message: string, counts: AgentDependencyCounts) {
    super(message);
    this.name = 'BlockedByDependenciesError';
    this.counts = counts;
  }
}

// I-004: retire an agent via DELETE /api/v1/agents/{id}. Three distinct
// success paths the UI needs to distinguish:
//   * 200 — fresh retire; body has retired_at, already_retired=false, cascade
//     flag, counts of what was cascaded.
//   * 204 — idempotent re-retire; the row was already retired. No body. We
//     synthesize a RetireAgentResponse with already_retired=true and zero
//     counts so the caller can keep a single return type.
//   * 409 — blocked_by_dependencies; thrown as BlockedByDependenciesError so
//     the caller can surface the active_targets/active_certificates/pending_jobs
//     counts in a confirmation dialog and offer force=true.
// Anything else bubbles up via the standard fetchJSON error path.
export const retireAgent = async (
  id: string,
  opts: { force?: boolean; reason?: string } = {},
): Promise<RetireAgentResponse> => {
  const qs = new URLSearchParams();
  if (opts.force) qs.set('force', 'true');
  if (opts.reason) qs.set('reason', opts.reason);
  const url = qs.toString()
    ? `${BASE}/agents/${id}?${qs.toString()}`
    : `${BASE}/agents/${id}`;

  const res = await fetch(url, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('certctl:auth-required'));
    throw new Error('Authentication required');
  }

  // 204 No Content — idempotent re-retire. Synthesize a response so callers
  // get a uniform shape; already_retired=true tells them the agent was
  // already in the retired state before this call.
  if (res.status === 204) {
    return {
      retired_at: '',
      already_retired: true,
      cascade: false,
      counts: { active_targets: 0, active_certificates: 0, pending_jobs: 0 },
    };
  }

  if (res.status === 409) {
    // Body is always JSON for 409 per the handler contract.
    const body = (await res.json()) as BlockedByDependenciesResponse;
    throw new BlockedByDependenciesError(
      body.message || 'agent has active dependencies',
      body.counts,
    );
  }

  if (!res.ok) {
    let errorMsg = res.statusText;
    try {
      const body = await res.json();
      errorMsg = body.message || body.error || errorMsg;
    } catch {
      // not JSON
    }
    throw new Error(errorMsg || `HTTP ${res.status}`);
  }

  return (await res.json()) as RetireAgentResponse;
};

// I-004: list retired agents via GET /api/v1/agents/retired. Kept separate
// from getAgents (which hits the default active-only listing) so the retired
// tab on AgentsPage can page independently. per_page is capped server-side at
// 500 (see handler ListRetiredAgents).
export const listRetiredAgents = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Agent>>(`${BASE}/agents/retired?${qs}`);
};

// Jobs
export const getJobs = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Job>>(`${BASE}/jobs?${qs}`);
};

export const cancelJob = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/jobs/${id}/cancel`, { method: 'POST' });

// Notifications
export const getNotifications = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Notification>>(`${BASE}/notifications?${qs}`);
};

export const getNotification = (id: string) =>
  fetchJSON<Notification>(`${BASE}/notifications/${id}`);

export const markNotificationRead = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/notifications/${id}/read`, { method: 'POST' });

/**
 * I-005: requeue a dead notification back to the retry queue. Flips status
 * 'dead' → 'pending' and clears next_retry_at so the retry sweep picks it up
 * on its next tick (default 2 minutes, CERTCTL_NOTIFICATION_RETRY_INTERVAL).
 * Used by the Dead letter tab's "Requeue" button after an operator fixes the
 * underlying delivery failure (SMTP config, webhook endpoint, etc.). The
 * handler returns a StatusResponse ({ status: "requeued" }) — the frontend
 * only needs to know the call succeeded so the mutation can invalidate the
 * notifications query.
 */
export const requeueNotification = (id: string) =>
  fetchJSON<{ status: string }>(`${BASE}/notifications/${id}/requeue`, { method: 'POST' });

// Audit
export const getAuditEvents = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '200', ...params }).toString();
  return fetchJSON<PaginatedResponse<AuditEvent>>(`${BASE}/audit?${qs}`);
};

export const getAuditEvent = (id: string) =>
  fetchJSON<AuditEvent>(`${BASE}/audit/${id}`);

// Policies
export const getPolicies = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<PolicyRule>>(`${BASE}/policies?${qs}`);
};

export const createPolicy = (data: Partial<PolicyRule>) =>
  fetchJSON<PolicyRule>(`${BASE}/policies`, { method: 'POST', body: JSON.stringify(data) });

export const updatePolicy = (id: string, data: Partial<PolicyRule>) =>
  fetchJSON<PolicyRule>(`${BASE}/policies/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const getPolicy = (id: string) =>
  fetchJSON<PolicyRule>(`${BASE}/policies/${id}`);

export const deletePolicy = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/policies/${id}`, { method: 'DELETE' });

export const getPolicyViolations = (id: string) =>
  fetchJSON<PaginatedResponse<PolicyViolation>>(`${BASE}/policies/${id}/violations`);

// Issuers
export const getIssuers = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Issuer>>(`${BASE}/issuers?${qs}`);
};

export const createIssuer = (data: Partial<Issuer>) =>
  fetchJSON<Issuer>(`${BASE}/issuers`, { method: 'POST', body: JSON.stringify(data) });

export const testIssuerConnection = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/issuers/${id}/test`, { method: 'POST' });

export const updateIssuer = (id: string, data: Partial<Issuer>) =>
  fetchJSON<Issuer>(`${BASE}/issuers/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteIssuer = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/issuers/${id}`, { method: 'DELETE' });

// Targets
export const getTargets = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Target>>(`${BASE}/targets?${qs}`);
};

export const createTarget = (data: Partial<Target>) =>
  fetchJSON<Target>(`${BASE}/targets`, { method: 'POST', body: JSON.stringify(data) });

export const updateTarget = (id: string, data: Partial<Target>) =>
  fetchJSON<Target>(`${BASE}/targets/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteTarget = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/targets/${id}`, { method: 'DELETE' });

export const testTargetConnection = (id: string) =>
  fetchJSON<{ status: string; message: string }>(`${BASE}/targets/${id}/test`, { method: 'POST' });

// Profiles
export const getProfiles = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<CertificateProfile>>(`${BASE}/profiles?${qs}`);
};

export const getProfile = (id: string) =>
  fetchJSON<CertificateProfile>(`${BASE}/profiles/${id}`);

export const createProfile = (data: Partial<CertificateProfile>) =>
  fetchJSON<CertificateProfile>(`${BASE}/profiles`, { method: 'POST', body: JSON.stringify(data) });

export const updateProfile = (id: string, data: Partial<CertificateProfile>) =>
  fetchJSON<CertificateProfile>(`${BASE}/profiles/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteProfile = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/profiles/${id}`, { method: 'DELETE' });

// Owners
export const getOwners = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Owner>>(`${BASE}/owners?${qs}`);
};

export const getOwner = (id: string) =>
  fetchJSON<Owner>(`${BASE}/owners/${id}`);

export const createOwner = (data: Partial<Owner>) =>
  fetchJSON<Owner>(`${BASE}/owners`, { method: 'POST', body: JSON.stringify(data) });

export const updateOwner = (id: string, data: Partial<Owner>) =>
  fetchJSON<Owner>(`${BASE}/owners/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteOwner = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/owners/${id}`, { method: 'DELETE' });

// Teams
export const getTeams = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Team>>(`${BASE}/teams?${qs}`);
};

export const getTeam = (id: string) =>
  fetchJSON<Team>(`${BASE}/teams/${id}`);

export const createTeam = (data: Partial<Team>) =>
  fetchJSON<Team>(`${BASE}/teams`, { method: 'POST', body: JSON.stringify(data) });

export const updateTeam = (id: string, data: Partial<Team>) =>
  fetchJSON<Team>(`${BASE}/teams/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteTeam = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/teams/${id}`, { method: 'DELETE' });

// Agent Groups
export const getAgentGroups = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<AgentGroup>>(`${BASE}/agent-groups?${qs}`);
};

export const getAgentGroup = (id: string) =>
  fetchJSON<AgentGroup>(`${BASE}/agent-groups/${id}`);

export const createAgentGroup = (data: Partial<AgentGroup>) =>
  fetchJSON<AgentGroup>(`${BASE}/agent-groups`, { method: 'POST', body: JSON.stringify(data) });

export const updateAgentGroup = (id: string, data: Partial<AgentGroup>) =>
  fetchJSON<AgentGroup>(`${BASE}/agent-groups/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteAgentGroup = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/agent-groups/${id}`, { method: 'DELETE' });

export const getAgentGroupMembers = (id: string) =>
  fetchJSON<PaginatedResponse<Agent>>(`${BASE}/agent-groups/${id}/members`);

// Renewal Approvals
export const approveRenewal = (jobId: string) =>
  fetchJSON<{ message: string }>(`${BASE}/jobs/${jobId}/approve`, { method: 'POST' });

export const rejectRenewal = (jobId: string, reason: string) =>
  fetchJSON<{ message: string }>(`${BASE}/jobs/${jobId}/reject`, { method: 'POST', body: JSON.stringify({ reason }) });

// Discovery
export const getDiscoveredCertificates = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<DiscoveredCertificate>>(`${BASE}/discovered-certificates?${qs}`);
};

export const getDiscoveredCertificate = (id: string) =>
  fetchJSON<DiscoveredCertificate>(`${BASE}/discovered-certificates/${id}`);

export const claimDiscoveredCertificate = (id: string, managedCertificateId: string) =>
  fetchJSON<{ message: string }>(`${BASE}/discovered-certificates/${id}/claim`, {
    method: 'POST',
    body: JSON.stringify({ managed_certificate_id: managedCertificateId }),
  });

export const dismissDiscoveredCertificate = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/discovered-certificates/${id}/dismiss`, { method: 'POST' });

export const getDiscoveryScans = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<DiscoveryScan>>(`${BASE}/discovery-scans?${qs}`);
};

export const getDiscoverySummary = () =>
  fetchJSON<DiscoverySummary>(`${BASE}/discovery-summary`);

// Network Scan Targets
export const getNetworkScanTargets = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<NetworkScanTarget>>(`${BASE}/network-scan-targets?${qs}`);
};

export const getNetworkScanTarget = (id: string) =>
  fetchJSON<NetworkScanTarget>(`${BASE}/network-scan-targets/${id}`);

export const createNetworkScanTarget = (data: Partial<NetworkScanTarget>) =>
  fetchJSON<NetworkScanTarget>(`${BASE}/network-scan-targets`, { method: 'POST', body: JSON.stringify(data) });

export const updateNetworkScanTarget = (id: string, data: Partial<NetworkScanTarget>) =>
  fetchJSON<NetworkScanTarget>(`${BASE}/network-scan-targets/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteNetworkScanTarget = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/network-scan-targets/${id}`, { method: 'DELETE' });

export const triggerNetworkScan = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/network-scan-targets/${id}/scan`, { method: 'POST' });

// Stats
export const getDashboardSummary = () =>
  fetchJSON<DashboardSummary>(`${BASE}/stats/summary`);

export const getCertificatesByStatus = () =>
  fetchJSON<CertificateStatusCount[]>(`${BASE}/stats/certificates-by-status`);

export const getExpirationTimeline = (days = 30) =>
  fetchJSON<ExpirationBucket[]>(`${BASE}/stats/expiration-timeline?days=${days}`);

export const getJobTrends = (days = 30) =>
  fetchJSON<JobTrendDataPoint[]>(`${BASE}/stats/job-trends?days=${days}`);

export const getIssuanceRate = (days = 30) =>
  fetchJSON<IssuanceRateDataPoint[]>(`${BASE}/stats/issuance-rate?days=${days}`);

export const getMetrics = () =>
  fetchJSON<MetricsResponse>(`${BASE}/metrics`);

// Digest
export const previewDigest = () => {
  const headers: Record<string, string> = {};
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  return fetch(`${BASE}/digest/preview`, { headers })
    .then(r => {
      if (!r.ok) throw new Error(`Digest preview failed: ${r.status}`);
      return r.text();
    });
};

export const sendDigest = () =>
  fetchJSON<{ message: string }>(`${BASE}/digest/send`, { method: 'POST' });

// Jobs (single)
export const getJob = (id: string) =>
  fetchJSON<Job>(`${BASE}/jobs/${id}`);

// Job Verification
export const getJobVerification = (id: string) =>
  fetchJSON<{ job_id: string; target_id: string; verified: boolean; actual_fingerprint: string; expected_fingerprint: string; verified_at: string; error?: string }>(`${BASE}/jobs/${id}/verification`);

// Issuers (single)
export const getIssuer = (id: string) =>
  fetchJSON<Issuer>(`${BASE}/issuers/${id}`);

// Targets (single)
export const getTarget = (id: string) =>
  fetchJSON<Target>(`${BASE}/targets/${id}`);

// Prometheus metrics (text format)
export const getPrometheusMetrics = () => {
  const headers: Record<string, string> = {};
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  return fetch(`${BASE}/metrics/prometheus`, { headers })
    .then(r => {
      if (!r.ok) throw new Error(`Prometheus metrics failed: ${r.status}`);
      return r.text();
    });
};

// Health
export const getHealth = () => fetchJSON<{ status: string }>('/health');

// Health checks (M48)
export const listHealthChecks = (params?: { status?: string; certificate_id?: string; enabled?: string; page?: number; per_page?: number }): Promise<PaginatedResponse<EndpointHealthCheck>> => {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.certificate_id) query.set('certificate_id', params.certificate_id);
  if (params?.enabled) query.set('enabled', params.enabled);
  if (params?.page) query.set('page', String(params.page));
  if (params?.per_page) query.set('per_page', String(params.per_page));
  const qs = query.toString();
  return fetchJSON<PaginatedResponse<EndpointHealthCheck>>(`${BASE}/health-checks${qs ? '?' + qs : ''}`);
};

export const getHealthCheck = (id: string) =>
  fetchJSON<EndpointHealthCheck>(`${BASE}/health-checks/${id}`);

export const createHealthCheck = (data: Partial<EndpointHealthCheck>) =>
  fetchJSON<EndpointHealthCheck>(`${BASE}/health-checks`, { method: 'POST', body: JSON.stringify(data) });

export const updateHealthCheck = (id: string, data: Partial<EndpointHealthCheck>) =>
  fetchJSON<EndpointHealthCheck>(`${BASE}/health-checks/${id}`, { method: 'PUT', body: JSON.stringify(data) });

export const deleteHealthCheck = (id: string) =>
  fetchJSON<void>(`${BASE}/health-checks/${id}`, { method: 'DELETE' });

export const getHealthCheckHistory = (id: string, limit?: number) => {
  const query = limit ? `?limit=${limit}` : '';
  return fetchJSON<HealthHistoryEntry[]>(`${BASE}/health-checks/${id}/history${query}`);
};

export const acknowledgeHealthCheck = (id: string) =>
  fetchJSON<void>(`${BASE}/health-checks/${id}/acknowledge`, { method: 'POST', body: JSON.stringify({}) });

export const getHealthCheckSummary = () =>
  fetchJSON<HealthCheckSummary>(`${BASE}/health-checks/summary`);
