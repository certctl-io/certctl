import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  setApiKey,
  getApiKey,
  getCertificates,
  getCertificate,
  getCertificateVersions,
  createCertificate,
  triggerRenewal,
  triggerDeployment,
  updateCertificate,
  archiveCertificate,
  getAgents,
  getAgent,
  registerAgent,
  getJobs,
  cancelJob,
  getNotifications,
  markNotificationRead,
  getAuditEvents,
  getPolicies,
  updatePolicy,
  deletePolicy,
  getIssuers,
  testIssuerConnection,
  deleteIssuer,
  getTargets,
  createTarget,
  deleteTarget,
  getHealth,
} from './client';

// Mock global fetch
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    statusText: 'OK',
  } as Response);
}

function mockErrorResponse(status: number, body: { message?: string; error?: string } = {}) {
  return Promise.resolve({
    ok: false,
    status,
    json: () => Promise.resolve(body),
    statusText: 'Error',
  } as Response);
}

describe('API Client', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    setApiKey(null);
  });

  // ─── Auth ───────────────────────────────────────────

  describe('API Key management', () => {
    it('stores and retrieves API key', () => {
      expect(getApiKey()).toBeNull();
      setApiKey('test-key-123');
      expect(getApiKey()).toBe('test-key-123');
    });

    it('clears API key', () => {
      setApiKey('test-key');
      setApiKey(null);
      expect(getApiKey()).toBeNull();
    });
  });

  describe('Auth headers', () => {
    it('sends Authorization header when API key is set', async () => {
      setApiKey('my-secret-key');
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));

      await getCertificates();

      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer my-secret-key');
      expect(init.headers['Content-Type']).toBe('application/json');
    });

    it('omits Authorization header when no API key', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));

      await getCertificates();

      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers['Authorization']).toBeUndefined();
      expect(init.headers['Content-Type']).toBe('application/json');
    });

    it('dispatches auth-required event on 401', async () => {
      const listener = vi.fn();
      window.addEventListener('certctl:auth-required', listener);
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));

      await expect(getCertificates()).rejects.toThrow('Authentication required');
      expect(listener).toHaveBeenCalled();

      window.removeEventListener('certctl:auth-required', listener);
    });
  });

  // ─── Error handling ─────────────────────────────────

  describe('Error handling', () => {
    it('throws with server error message', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(400, { message: 'Invalid request' }));
      await expect(getCertificates()).rejects.toThrow('Invalid request');
    });

    it('throws with error field from response', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(500, { error: 'Internal error' }));
      await expect(getCertificates()).rejects.toThrow('Internal error');
    });

    it('falls back to HTTP status text', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: false,
          status: 503,
          json: () => Promise.reject(new Error('not json')),
          statusText: 'Service Unavailable',
        } as Response),
      );
      await expect(getCertificates()).rejects.toThrow('Service Unavailable');
    });
  });

  // ─── Certificates ───────────────────────────────────

  describe('Certificates', () => {
    it('getCertificates sends GET with default pagination', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getCertificates();
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/certificates?page=1&per_page=50',
        expect.objectContaining({ headers: expect.any(Object) }),
      );
    });

    it('getCertificates passes filter params', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getCertificates({ status: 'Active', environment: 'production' });
      const url = mockFetch.mock.calls[0][0] as string;
      expect(url).toContain('status=Active');
      expect(url).toContain('environment=production');
    });

    it('getCertificate fetches single cert by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'mc-test', common_name: 'test.com' }));
      const cert = await getCertificate('mc-test');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/certificates/mc-test');
      expect(cert.id).toBe('mc-test');
    });

    it('getCertificateVersions fetches versions', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getCertificateVersions('mc-test');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/certificates/mc-test/versions');
    });

    it('createCertificate sends POST with body', async () => {
      const certData = { common_name: 'new.example.com', issuer_id: 'iss-local' };
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'mc-new', ...certData }));
      await createCertificate(certData);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual(certData);
    });

    it('updateCertificate sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'mc-test', status: 'Active' }));
      await updateCertificate('mc-test', { status: 'Active' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-test');
      expect(init.method).toBe('PUT');
    });

    it('archiveCertificate sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'archived' }));
      await archiveCertificate('mc-test');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-test');
      expect(init.method).toBe('DELETE');
    });

    it('triggerRenewal sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'renewal triggered' }));
      await triggerRenewal('mc-test');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-test/renew');
      expect(init.method).toBe('POST');
    });

    it('triggerDeployment sends POST with target_id', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deployment triggered' }));
      await triggerDeployment('mc-test', 't-nginx');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-test/deploy');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ target_id: 't-nginx' });
    });
  });

  // ─── Agents ─────────────────────────────────────────

  describe('Agents', () => {
    it('getAgents sends GET with pagination', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getAgents();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/agents?page=1&per_page=50');
    });

    it('getAgent fetches by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'a-web01', name: 'web01' }));
      const agent = await getAgent('a-web01');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/agents/a-web01');
      expect(agent.id).toBe('a-web01');
    });

    it('registerAgent sends POST', async () => {
      const agentData = { name: 'new-agent', hostname: 'host01' };
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'a-new', ...agentData }));
      await registerAgent(agentData);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/agents');
      expect(init.method).toBe('POST');
    });
  });

  // ─── Jobs ───────────────────────────────────────────

  describe('Jobs', () => {
    it('getJobs sends GET with filters', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getJobs({ status: 'Pending', type: 'Renewal' });
      const url = mockFetch.mock.calls[0][0] as string;
      expect(url).toContain('status=Pending');
      expect(url).toContain('type=Renewal');
    });

    it('cancelJob sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'cancelled' }));
      await cancelJob('job-123');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/jobs/job-123/cancel');
      expect(init.method).toBe('POST');
    });
  });

  // ─── Notifications ──────────────────────────────────

  describe('Notifications', () => {
    it('getNotifications sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getNotifications();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/notifications');
    });

    it('markNotificationRead sends POST with auth headers', async () => {
      setApiKey('test-key');
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'marked as read' }));
      await markNotificationRead('notif-123');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/notifications/notif-123/read');
      expect(init.method).toBe('POST');
      expect(init.headers['Authorization']).toBe('Bearer test-key');
    });
  });

  // ─── Policies ───────────────────────────────────────

  describe('Policies', () => {
    it('getPolicies sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getPolicies();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/policies');
    });

    it('updatePolicy sends PUT with partial data', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'pol-1', enabled: false }));
      await updatePolicy('pol-1', { enabled: false });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/policies/pol-1');
      expect(init.method).toBe('PUT');
      expect(JSON.parse(init.body)).toEqual({ enabled: false });
    });

    it('deletePolicy sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deletePolicy('pol-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/policies/pol-1');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Issuers ────────────────────────────────────────

  describe('Issuers', () => {
    it('getIssuers sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getIssuers();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/issuers');
    });

    it('testIssuerConnection sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'ok' }));
      await testIssuerConnection('iss-local');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers/iss-local/test');
      expect(init.method).toBe('POST');
    });

    it('deleteIssuer sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteIssuer('iss-local');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers/iss-local');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Targets ────────────────────────────────────────

  describe('Targets', () => {
    it('getTargets sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getTargets();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/targets');
    });

    it('createTarget sends POST', async () => {
      const targetData = { name: 'nginx-01', type: 'nginx', hostname: 'web01.example.com' };
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-new', ...targetData }));
      await createTarget(targetData);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/targets');
      expect(init.method).toBe('POST');
    });

    it('deleteTarget sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteTarget('t-nginx');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/targets/t-nginx');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Audit ──────────────────────────────────────────

  describe('Audit', () => {
    it('getAuditEvents sends GET with filters', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getAuditEvents({ resource_type: 'certificate' });
      const url = mockFetch.mock.calls[0][0] as string;
      expect(url).toContain('resource_type=certificate');
    });
  });

  // ─── Health ─────────────────────────────────────────

  describe('Health', () => {
    it('getHealth calls /health endpoint', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ status: 'ok' }));
      const result = await getHealth();
      expect(mockFetch.mock.calls[0][0]).toBe('/health');
      expect(result.status).toBe('ok');
    });
  });
});
