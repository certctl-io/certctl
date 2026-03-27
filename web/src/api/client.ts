import type { Certificate, CertificateVersion, Agent, Job, Notification, AuditEvent, PolicyRule, PolicyViolation, Issuer, Target, CertificateProfile, Owner, Team, AgentGroup, PaginatedResponse, DashboardSummary, CertificateStatusCount, ExpirationBucket, JobTrendDataPoint, IssuanceRateDataPoint, MetricsResponse, DiscoveredCertificate, DiscoveryScan, DiscoverySummary, NetworkScanTarget } from './types';

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

export const checkAuth = (key: string) =>
  fetch(`${BASE}/auth/check`, {
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
  }).then(r => {
    if (!r.ok) throw new Error('Invalid API key');
    return r.json() as Promise<{ status: string }>;
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

// Agents
export const getAgents = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Agent>>(`${BASE}/agents?${qs}`);
};

export const getAgent = (id: string) =>
  fetchJSON<Agent>(`${BASE}/agents/${id}`);

export const registerAgent = (data: Partial<Agent>) =>
  fetchJSON<Agent>(`${BASE}/agents`, { method: 'POST', body: JSON.stringify(data) });

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

export const markNotificationRead = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/notifications/${id}/read`, { method: 'POST' });

// Audit
export const getAuditEvents = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<AuditEvent>>(`${BASE}/audit?${qs}`);
};

// Policies
export const getPolicies = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<PolicyRule>>(`${BASE}/policies?${qs}`);
};

export const createPolicy = (data: Partial<PolicyRule>) =>
  fetchJSON<PolicyRule>(`${BASE}/policies`, { method: 'POST', body: JSON.stringify(data) });

export const updatePolicy = (id: string, data: Partial<PolicyRule>) =>
  fetchJSON<PolicyRule>(`${BASE}/policies/${id}`, { method: 'PUT', body: JSON.stringify(data) });

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

export const deleteIssuer = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/issuers/${id}`, { method: 'DELETE' });

// Targets
export const getTargets = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ page: '1', per_page: '50', ...params }).toString();
  return fetchJSON<PaginatedResponse<Target>>(`${BASE}/targets?${qs}`);
};

export const createTarget = (data: Partial<Target>) =>
  fetchJSON<Target>(`${BASE}/targets`, { method: 'POST', body: JSON.stringify(data) });

export const deleteTarget = (id: string) =>
  fetchJSON<{ message: string }>(`${BASE}/targets/${id}`, { method: 'DELETE' });

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

// Health
export const getHealth = () => fetchJSON<{ status: string }>('/health');
