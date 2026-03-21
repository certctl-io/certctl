import type { Certificate, CertificateVersion, Agent, Job, Notification, AuditEvent, PolicyRule, PolicyViolation, Issuer, Target, CertificateProfile, PaginatedResponse } from './types';

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

// Health
export const getHealth = () => fetchJSON<{ status: string }>('/health');
