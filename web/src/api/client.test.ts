import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  setApiKey,
  getApiKey,
  checkAuth,
  getCertificates,
  getCertificate,
  getCertificateVersions,
  createCertificate,
  triggerRenewal,
  triggerDeployment,
  updateCertificate,
  archiveCertificate,
  revokeCertificate,
  bulkRevokeCertificates,
  downloadCertificatePEM,
  exportCertificatePKCS12,
  getAgents,
  getAgent,
  registerAgent,
  retireAgent,
  listRetiredAgents,
  getJobs,
  cancelJob,
  approveRenewal,
  rejectRenewal,
  getNotifications,
  markNotificationRead,
  getAuditEvents,
  getPolicies,
  createPolicy,
  updatePolicy,
  deletePolicy,
  getPolicyViolations,
  getRenewalPolicies,
  createRenewalPolicy,
  updateRenewalPolicy,
  deleteRenewalPolicy,
  getIssuers,
  createIssuer,
  testIssuerConnection,
  deleteIssuer,
  getTargets,
  createTarget,
  deleteTarget,
  testTargetConnection,
  getProfiles,
  getProfile,
  createProfile,
  updateProfile,
  deleteProfile,
  getOwners,
  getOwner,
  createOwner,
  updateOwner,
  deleteOwner,
  getTeams,
  getTeam,
  createTeam,
  updateTeam,
  deleteTeam,
  getAgentGroups,
  getAgentGroup,
  createAgentGroup,
  updateAgentGroup,
  deleteAgentGroup,
  getAgentGroupMembers,
  getHealth,
  getDashboardSummary,
  getCertificatesByStatus,
  getExpirationTimeline,
  getJobTrends,
  getIssuanceRate,
  getMetrics,
  getDiscoveredCertificates,
  getDiscoveredCertificate,
  claimDiscoveredCertificate,
  dismissDiscoveredCertificate,
  getDiscoveryScans,
  getDiscoverySummary,
  getNetworkScanTargets,
  getNetworkScanTarget,
  createNetworkScanTarget,
  updateNetworkScanTarget,
  deleteNetworkScanTarget,
  triggerNetworkScan,
  previewDigest,
  sendDigest,
  getJob,
  getJobVerification,
  getIssuer,
  getTarget,
  getPrometheusMetrics,
  getCertificateDeployments,
  getOCSPStatus,
  updateIssuer,
  updateTarget,
  getPolicy,
  listHealthChecks,
  getHealthCheck,
  createHealthCheck,
  updateHealthCheck,
  deleteHealthCheck,
  getHealthCheckHistory,
  acknowledgeHealthCheck,
  getHealthCheckSummary,
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

  // ─── checkAuth (M-003: surfaces user + admin) ──────

  describe('checkAuth', () => {
    // Post-M-003 /auth/check returns {status, user, admin}. The admin flag drives
    // GUI gating of admin-only affordances (bulk revoke, etc.). Authoritative
    // enforcement lives server-side — this test only pins the contract the
    // AuthProvider depends on.
    it('returns {status, user, admin} shape and sends Bearer token', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({ status: 'authenticated', user: 'ops-admin', admin: true }),
      );

      const resp = await checkAuth('test-api-key');

      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/auth/check');
      expect(init.headers['Authorization']).toBe('Bearer test-api-key');
      expect(init.headers['Content-Type']).toBe('application/json');
      expect(resp.status).toBe('authenticated');
      expect(resp.user).toBe('ops-admin');
      expect(resp.admin).toBe(true);
    });

    it('returns admin=false for non-admin callers', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({ status: 'authenticated', user: 'alice', admin: false }),
      );

      const resp = await checkAuth('alice-key');

      expect(resp.user).toBe('alice');
      expect(resp.admin).toBe(false);
    });

    it('throws on invalid API key', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(checkAuth('bad-key')).rejects.toThrow('Invalid API key');
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

    // C-001 scope-expansion regression: the OnboardingWizard CertificateStep
    // and the CertificatesPage CreateCertificateModal must both ship the full
    // six-field required payload (name, common_name, renewal_policy_id,
    // issuer_id, owner_id, team_id) — the handler's ValidateRequired contract
    // rejects anything less with HTTP 400. This test pins the wire shape so
    // that accidentally dropping a field from either UI surface fails CI
    // rather than only surfacing as a 400 at runtime.
    it('createCertificate accepts and transmits all six required fields', async () => {
      const wizardPayload = {
        name: 'API Production Cert',
        common_name: 'api.example.com',
        sans: ['www.example.com'],
        issuer_id: 'iss-local',
        owner_id: 'o-alice',
        team_id: 't-platform',
        renewal_policy_id: 'rp-standard',
        environment: 'production',
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'mc-new', ...wizardPayload }));
      await createCertificate(wizardPayload);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      // Assert every required field is present and intact
      expect(body.name).toBe('API Production Cert');
      expect(body.common_name).toBe('api.example.com');
      expect(body.issuer_id).toBe('iss-local');
      expect(body.owner_id).toBe('o-alice');
      expect(body.team_id).toBe('t-platform');
      expect(body.renewal_policy_id).toBe('rp-standard');
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

    it('revokeCertificate sends POST with reason', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ status: 'revoked' }));
      await revokeCertificate('mc-test', 'keyCompromise');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-test/revoke');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ reason: 'keyCompromise' });
    });

    it('bulkRevokeCertificates sends POST with criteria', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ total_matched: 3, total_revoked: 2, total_skipped: 1, total_failed: 0 }));
      await bulkRevokeCertificates({ reason: 'keyCompromise', profile_id: 'prof-tls', certificate_ids: ['mc-1', 'mc-2'] });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/bulk-revoke');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ reason: 'keyCompromise', profile_id: 'prof-tls', certificate_ids: ['mc-1', 'mc-2'] });
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

  // ─── Agent Retirement (I-004) ───────────────────────
  //
  // These tests pin the GUI's retirement contract against what the backend
  // will add in Phase 2b: soft-retire via DELETE, force-cascade via
  // ?force=true&reason=..., idempotent 204 on already-retired, 409 blocked
  // payload with counts, and a GET /agents/retired listing surface.
  //
  // All compile-fail until client.ts exports retireAgent + listRetiredAgents
  // — the shape of those exports is pinned here rather than assumed.
  describe('Agent Retirement (I-004)', () => {
    it('retireAgent sends DELETE without query when no force/reason', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({
          retired_at: '2026-04-18T12:00:00Z',
          already_retired: false,
          cascade: false,
        }),
      );
      await retireAgent('ag-1');
      const [url, init] = mockFetch.mock.calls[0];
      // Default soft-retire: bare path, no stray ? suffix.
      expect(url).toBe('/api/v1/agents/ag-1');
      expect(init.method).toBe('DELETE');
    });

    it('retireAgent propagates force+reason as URL query parameters', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({
          retired_at: '2026-04-18T12:00:00Z',
          already_retired: false,
          cascade: true,
          counts: { active_targets: 3, active_certificates: 7, pending_jobs: 2 },
        }),
      );
      await retireAgent('ag-1', { force: true, reason: 'decommissioning rack 7' });
      const [url, init] = mockFetch.mock.calls[0];
      // URLSearchParams encodes space as "+"; "decommissioning rack 7" → "decommissioning+rack+7"
      expect(url).toBe(
        '/api/v1/agents/ag-1?force=true&reason=decommissioning+rack+7',
      );
      expect(init.method).toBe('DELETE');
    });

    it('retireAgent omits force=false even when reason is supplied', async () => {
      // Client-side guard: the server's 400 ErrForceReasonRequired is the
      // fallback; the GUI should never silently promote reason-without-force
      // into a force call. Pins that reason-only still hits the soft path.
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({
          retired_at: '2026-04-18T12:00:00Z',
          already_retired: false,
          cascade: false,
        }),
      );
      await retireAgent('ag-1', { reason: 'routine decommission' });
      const [url] = mockFetch.mock.calls[0];
      // force defaults to false → query carries reason only.
      expect(url).toBe('/api/v1/agents/ag-1?reason=routine+decommission');
    });

    it('retireAgent surfaces the 409 dependency error message to the caller', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(409, {
          message: 'agent has 3 active targets, 7 active certificates, 2 pending jobs',
        }),
      );
      await expect(retireAgent('ag-1')).rejects.toThrow(
        /active targets|active certificates|pending jobs/,
      );
    });

    it('retireAgent treats 204 (already-retired) as success with empty body', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 204,
          json: () => Promise.reject(new Error('204 has no body')),
          statusText: 'No Content',
        } as Response),
      );
      // fetchJSON normalises 204 to {} — caller must not crash.
      const result = await retireAgent('ag-1');
      expect(result).toBeDefined();
    });

    it('listRetiredAgents sends GET /agents/retired with default pagination', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }),
      );
      await listRetiredAgents();
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/agents/retired?page=1&per_page=50');
      // Default is GET — no explicit method means fetchJSON falls through.
      expect(init.method ?? 'GET').toBe('GET');
    });

    it('listRetiredAgents forwards page/per_page overrides', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({ data: [], total: 0, page: 2, per_page: 100 }),
      );
      await listRetiredAgents({ page: '2', per_page: '100' });
      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('page=2');
      expect(url).toContain('per_page=100');
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

  // ─── Renewal Policies (G-1) ─────────────────────────
  // Distinct from compliance Policies above. Populates the
  // `renewal_policy_id` dropdown on OnboardingWizard + CertificatesPage +
  // CertificateDetailPage.InlinePolicyEditor.  Hits `/api/v1/renewal-policies`.

  describe('RenewalPolicies', () => {
    it('getRenewalPolicies sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getRenewalPolicies();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/renewal-policies');
    });

    it('createRenewalPolicy sends POST with body', async () => {
      mockFetch.mockReturnValueOnce(
        mockJsonResponse({
          id: 'rp-new',
          name: 'New Policy',
          renewal_window_days: 30,
          max_retries: 3,
          retry_interval_seconds: 3600,
          auto_renew: true,
        }),
      );
      await createRenewalPolicy({
        name: 'New Policy',
        renewal_window_days: 30,
        max_retries: 3,
        retry_interval_seconds: 3600,
        auto_renew: true,
      });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/renewal-policies');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body).name).toBe('New Policy');
    });

    it('updateRenewalPolicy sends PUT with partial data', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'rp-default', name: 'Renamed' }));
      await updateRenewalPolicy('rp-default', { name: 'Renamed' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/renewal-policies/rp-default');
      expect(init.method).toBe('PUT');
      expect(JSON.parse(init.body)).toEqual({ name: 'Renamed' });
    });

    it('deleteRenewalPolicy sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteRenewalPolicy('rp-default');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/renewal-policies/rp-default');
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

    it('testTargetConnection sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ status: 'success', message: 'Agent is online' }));
      await testTargetConnection('t-nginx');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/targets/t-nginx/test');
      expect(init.method).toBe('POST');
    });
  });

  // ─── Approval ──────────────────────────────────────

  describe('Renewal Approvals', () => {
    it('approveRenewal sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'approved' }));
      await approveRenewal('job-123');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/jobs/job-123/approve');
      expect(init.method).toBe('POST');
    });

    it('rejectRenewal sends POST with reason', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'rejected' }));
      await rejectRenewal('job-123', 'not authorized');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/jobs/job-123/reject');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ reason: 'not authorized' });
    });
  });

  // ─── Profiles ────────────────────────────────────────

  describe('Profiles', () => {
    it('getProfiles sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getProfiles();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/profiles');
    });

    it('getProfile fetches by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'prof-1', name: 'Standard' }));
      const profile = await getProfile('prof-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/profiles/prof-1');
      expect(profile.id).toBe('prof-1');
    });

    it('createProfile sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'prof-new', name: 'New Profile' }));
      await createProfile({ name: 'New Profile' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/profiles');
      expect(init.method).toBe('POST');
    });

    it('updateProfile sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'prof-1', name: 'Updated' }));
      await updateProfile('prof-1', { name: 'Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/profiles/prof-1');
      expect(init.method).toBe('PUT');
    });

    it('deleteProfile sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteProfile('prof-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/profiles/prof-1');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Owners ──────────────────────────────────────────

  describe('Owners', () => {
    it('getOwners sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getOwners();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/owners');
    });

    it('getOwner fetches by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'o-alice', name: 'Alice' }));
      const owner = await getOwner('o-alice');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/owners/o-alice');
      expect(owner.name).toBe('Alice');
    });

    it('createOwner sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'o-new', name: 'Bob' }));
      await createOwner({ name: 'Bob', email: 'bob@example.com' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/owners');
      expect(init.method).toBe('POST');
    });

    it('updateOwner sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'o-alice', name: 'Alice Updated' }));
      await updateOwner('o-alice', { name: 'Alice Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/owners/o-alice');
      expect(init.method).toBe('PUT');
    });

    it('deleteOwner sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteOwner('o-alice');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/owners/o-alice');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Teams ───────────────────────────────────────────

  describe('Teams', () => {
    it('getTeams sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getTeams();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/teams');
    });

    it('getTeam fetches by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-platform', name: 'Platform' }));
      const team = await getTeam('t-platform');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/teams/t-platform');
      expect(team.name).toBe('Platform');
    });

    it('createTeam sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-new', name: 'New Team' }));
      await createTeam({ name: 'New Team' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/teams');
      expect(init.method).toBe('POST');
    });

    it('updateTeam sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-platform', name: 'Updated' }));
      await updateTeam('t-platform', { name: 'Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/teams/t-platform');
      expect(init.method).toBe('PUT');
    });

    it('deleteTeam sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteTeam('t-platform');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/teams/t-platform');
      expect(init.method).toBe('DELETE');
    });
  });

  // ─── Agent Groups ────────────────────────────────────

  describe('Agent Groups', () => {
    it('getAgentGroups sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getAgentGroups();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/agent-groups');
    });

    it('getAgentGroup fetches by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'ag-linux', name: 'Linux Servers' }));
      const group = await getAgentGroup('ag-linux');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/agent-groups/ag-linux');
      expect(group.name).toBe('Linux Servers');
    });

    it('createAgentGroup sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'ag-new', name: 'New Group' }));
      await createAgentGroup({ name: 'New Group' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/agent-groups');
      expect(init.method).toBe('POST');
    });

    it('updateAgentGroup sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'ag-linux', name: 'Updated' }));
      await updateAgentGroup('ag-linux', { name: 'Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/agent-groups/ag-linux');
      expect(init.method).toBe('PUT');
    });

    it('deleteAgentGroup sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'deleted' }));
      await deleteAgentGroup('ag-linux');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/agent-groups/ag-linux');
      expect(init.method).toBe('DELETE');
    });

    it('getAgentGroupMembers fetches members', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getAgentGroupMembers('ag-linux');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/agent-groups/ag-linux/members');
    });
  });

  // ─── Policy Violations ───────────────────────────────

  describe('Policy Violations', () => {
    it('getPolicyViolations sends GET', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getPolicyViolations('pol-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/policies/pol-1/violations');
    });
  });

  // ─── Issuer Create ───────────────────────────────────

  describe('Issuer Create', () => {
    it('createIssuer sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-new', name: 'New Issuer' }));
      await createIssuer({ name: 'New Issuer', type: 'local_ca' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers');
      expect(init.method).toBe('POST');
    });

    it('createIssuer sends correct payload for VaultPKI type', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-vault', name: 'Vault PKI' }));
      const vaultPayload = {
        name: 'Vault PKI',
        type: 'VaultPKI',
        config: {
          addr: 'https://vault.internal:8200',
          token: 'hvs.test-token',
          mount: 'pki',
          role: 'web-certs',
          ttl: '8760h',
        },
      };
      await createIssuer(vaultPayload);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      expect(body.type).toBe('VaultPKI');
      expect(body.config.addr).toBe('https://vault.internal:8200');
      expect(body.config.role).toBe('web-certs');
    });

    it('createIssuer sends correct payload for DigiCert type', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-digicert', name: 'DigiCert' }));
      const digicertPayload = {
        name: 'DigiCert CertCentral',
        type: 'DigiCert',
        config: {
          api_key: 'test-api-key',
          org_id: '12345',
          product_type: 'ssl_basic',
        },
      };
      await createIssuer(digicertPayload);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      expect(body.type).toBe('DigiCert');
      expect(body.config.org_id).toBe('12345');
      expect(body.config.product_type).toBe('ssl_basic');
    });

    it('createIssuer sends correct payload for ACME with profile', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-acme-shortlived', name: 'ACME Shortlived' }));
      const acmePayload = {
        name: 'ACME Shortlived',
        type: 'acme',
        config: {
          directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
          email: 'admin@example.com',
          challenge_type: 'http-01',
          profile: 'shortlived',
        },
      };
      await createIssuer(acmePayload);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      expect(body.type).toBe('acme');
      expect(body.config.profile).toBe('shortlived');
      expect(body.config.directory_url).toBe('https://acme-v02.api.letsencrypt.org/directory');
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

  // ─── Stats ─────────────────────────────────────────

  describe('Stats', () => {
    it('getDashboardSummary calls /api/v1/stats/summary', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ total_certificates: 10 }));
      const result = await getDashboardSummary();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/summary');
      expect(result.total_certificates).toBe(10);
    });

    it('getCertificatesByStatus calls /api/v1/stats/certificates-by-status', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse([{ status: 'Active', count: 5 }]));
      const result = await getCertificatesByStatus();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/certificates-by-status');
      expect(result).toHaveLength(1);
    });

    it('getExpirationTimeline calls with days parameter', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse([]));
      await getExpirationTimeline(60);
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/expiration-timeline?days=60');
    });

    it('getExpirationTimeline uses default 30 days', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse([]));
      await getExpirationTimeline();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/expiration-timeline?days=30');
    });

    it('getJobTrends calls with days parameter', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse([]));
      await getJobTrends(14);
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/job-trends?days=14');
    });

    it('getIssuanceRate calls with days parameter', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse([]));
      await getIssuanceRate(7);
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/stats/issuance-rate?days=7');
    });

    it('getMetrics calls /api/v1/metrics', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({
        gauge: { certificate_total: 10 },
        counter: { job_completed_total: 5 },
        uptime: { uptime_seconds: 3600 },
      }));
      const result = await getMetrics();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/metrics');
      expect(result.gauge.certificate_total).toBe(10);
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

  // ─── Discovery ────────────────────────────────────

  describe('Discovery', () => {
    it('getDiscoveredCertificates calls with params', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getDiscoveredCertificates({ status: 'Unmanaged' });
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/discovered-certificates');
      expect(mockFetch.mock.calls[0][0]).toContain('status=Unmanaged');
    });

    it('getDiscoveredCertificate calls with id', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'dc-1', common_name: 'test.example.com' }));
      const result = await getDiscoveredCertificate('dc-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/discovered-certificates/dc-1');
      expect(result.common_name).toBe('test.example.com');
    });

    it('claimDiscoveredCertificate sends POST with managed cert id', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'claimed' }));
      await claimDiscoveredCertificate('dc-1', 'mc-api-prod');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/discovered-certificates/dc-1/claim');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ managed_certificate_id: 'mc-api-prod' });
    });

    it('dismissDiscoveredCertificate sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'dismissed' }));
      await dismissDiscoveredCertificate('dc-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/discovered-certificates/dc-1/dismiss');
      expect(init.method).toBe('POST');
    });

    it('getDiscoveryScans calls endpoint', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getDiscoveryScans();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/discovery-scans');
    });

    it('getDiscoverySummary calls endpoint', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ Unmanaged: 5, Managed: 3, Dismissed: 1 }));
      const result = await getDiscoverySummary();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/discovery-summary');
      expect(result.Unmanaged).toBe(5);
    });
  });

  // ─── Network Scan Targets ────────────────────────

  describe('Network Scan Targets', () => {
    it('getNetworkScanTargets calls endpoint', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      await getNetworkScanTargets();
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/network-scan-targets');
    });

    it('getNetworkScanTarget calls with id', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'nst-1', name: 'DMZ' }));
      const result = await getNetworkScanTarget('nst-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/network-scan-targets/nst-1');
      expect(result.name).toBe('DMZ');
    });

    it('createNetworkScanTarget sends POST', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'nst-new', name: 'Production' }));
      await createNetworkScanTarget({ name: 'Production', cidrs: ['10.0.0.0/24'], ports: [443] });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/network-scan-targets');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      expect(body.name).toBe('Production');
      expect(body.cidrs).toEqual(['10.0.0.0/24']);
    });

    it('updateNetworkScanTarget sends PUT', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'nst-1', enabled: false }));
      await updateNetworkScanTarget('nst-1', { enabled: false });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/network-scan-targets/nst-1');
      expect(init.method).toBe('PUT');
    });

    it('deleteNetworkScanTarget sends DELETE', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({}, 204));
      await deleteNetworkScanTarget('nst-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/network-scan-targets/nst-1');
      expect(init.method).toBe('DELETE');
    });

    it('triggerNetworkScan sends POST to scan endpoint', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'scan triggered' }));
      await triggerNetworkScan('nst-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/network-scan-targets/nst-1/scan');
      expect(init.method).toBe('POST');
    });
  });

  // ─── Certificate Export ────────────────────────────────

  describe('Certificate Export', () => {
    // B-1 closure (cat-b-9b97ffb35ef7): exportCertificatePEM was removed
    // from client.ts as a dead duplicate of downloadCertificatePEM.

    it('downloadCertificatePEM fetches blob with download=true', async () => {
      const mockBlob = new Blob(['pem-data'], { type: 'application/x-pem-file' });
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          blob: () => Promise.resolve(mockBlob),
        } as Response)
      );
      const blob = await downloadCertificatePEM('mc-1');
      const [url] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-1/export/pem?download=true');
      expect(blob).toBeInstanceOf(Blob);
    });

    it('downloadCertificatePEM includes auth header', async () => {
      setApiKey('export-key');
      const mockBlob = new Blob(['data']);
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          blob: () => Promise.resolve(mockBlob),
        } as Response)
      );
      await downloadCertificatePEM('mc-1');
      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer export-key');
    });

    it('exportCertificatePKCS12 sends POST with password', async () => {
      const mockBlob = new Blob([new Uint8Array([0x30])], { type: 'application/x-pkcs12' });
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          blob: () => Promise.resolve(mockBlob),
        } as Response)
      );
      const blob = await exportCertificatePKCS12('mc-1', 'mypass');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/certificates/mc-1/export/pkcs12');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body);
      expect(body.password).toBe('mypass');
      expect(blob).toBeInstanceOf(Blob);
    });

    it('exportCertificatePKCS12 uses empty password by default', async () => {
      const mockBlob = new Blob([new Uint8Array([0x30])]);
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          blob: () => Promise.resolve(mockBlob),
        } as Response)
      );
      await exportCertificatePKCS12('mc-1');
      const [, init] = mockFetch.mock.calls[0];
      const body = JSON.parse(init.body);
      expect(body.password).toBe('');
    });
  });

  // ─── Profile (EKU / S/MIME) ─────────────────────────────

  describe('Profile for EKU Display', () => {
    it('getProfile fetches profile by ID with EKU data', async () => {
      const profileData = {
        id: 'prof-smime',
        name: 'S/MIME Email',
        allowed_ekus: ['emailProtection'],
        max_ttl_seconds: 31536000,
        enabled: true,
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse(profileData));
      const result = await getProfile('prof-smime');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/profiles/prof-smime');
      expect(result.allowed_ekus).toEqual(['emailProtection']);
    });

    it('getProfile returns profile with multiple EKUs', async () => {
      const profileData = {
        id: 'prof-tls',
        name: 'TLS Server',
        allowed_ekus: ['serverAuth', 'clientAuth'],
        max_ttl_seconds: 7776000,
        enabled: true,
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse(profileData));
      const result = await getProfile('prof-tls');
      expect(result.allowed_ekus).toHaveLength(2);
      expect(result.allowed_ekus).toContain('serverAuth');
      expect(result.allowed_ekus).toContain('clientAuth');
    });
  });

  // ─── Job Verification Fields ─────────────────────────────

  describe('Job Verification', () => {
    it('getJobs returns jobs with verification fields', async () => {
      const jobData = {
        data: [{
          id: 'job-1',
          certificate_id: 'mc-1',
          type: 'Deployment',
          status: 'Completed',
          verification_status: 'success',
          verified_at: '2026-03-28T12:00:00Z',
          verification_fingerprint: 'abc123',
          verification_error: '',
          attempts: 1,
          max_attempts: 3,
          scheduled_at: '2026-03-28T11:00:00Z',
          completed_at: '2026-03-28T11:05:00Z',
          created_at: '2026-03-28T11:00:00Z',
        }],
        total: 1,
        page: 1,
        per_page: 50,
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse(jobData));
      const result = await getJobs({ certificate_id: 'mc-1' });
      expect(result.data[0].verification_status).toBe('success');
      expect(result.data[0].verified_at).toBe('2026-03-28T12:00:00Z');
      expect(result.data[0].verification_fingerprint).toBe('abc123');
    });

    it('getJobs handles jobs without verification data', async () => {
      const jobData = {
        data: [{
          id: 'job-2',
          certificate_id: 'mc-2',
          type: 'Issuance',
          status: 'Completed',
          attempts: 1,
          max_attempts: 3,
          scheduled_at: '2026-03-28T11:00:00Z',
          completed_at: '2026-03-28T11:05:00Z',
          created_at: '2026-03-28T11:00:00Z',
        }],
        total: 1,
        page: 1,
        per_page: 50,
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse(jobData));
      const result = await getJobs({});
      expect(result.data[0].verification_status).toBeUndefined();
      expect(result.data[0].verified_at).toBeUndefined();
    });
  });

  // ─── Digest ─────────────────────────────

  describe('Digest', () => {
    it('previewDigest fetches HTML preview', async () => {
      const html = '<html><body>Digest Preview</body></html>';
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve(html),
        } as Response)
      );
      const result = await previewDigest();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/digest/preview');
      expect(result).toBe(html);
    });

    it('previewDigest throws on error', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: false,
          status: 503,
          text: () => Promise.resolve('not configured'),
        } as Response)
      );
      await expect(previewDigest()).rejects.toThrow('Digest preview failed: 503');
    });

    it('sendDigest sends POST request', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ message: 'digest sent' }));
      const result = await sendDigest();
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/digest/send');
      expect(init.method).toBe('POST');
      expect(result.message).toBe('digest sent');
    });
  });

  // ─── Job Detail ────────────────────────────

  describe('Job Detail', () => {
    it('getJob fetches single job by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'job-1', type: 'Deployment', status: 'Completed' }));
      const result = await getJob('job-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/jobs/job-1');
      expect(result.id).toBe('job-1');
      expect(result.type).toBe('Deployment');
    });

    it('getJobVerification fetches verification result', async () => {
      const verificationData = {
        job_id: 'job-1',
        target_id: 't-nginx1',
        verified: true,
        actual_fingerprint: 'abc123',
        expected_fingerprint: 'abc123',
        verified_at: '2026-03-28T12:00:00Z',
      };
      mockFetch.mockReturnValueOnce(mockJsonResponse(verificationData));
      const result = await getJobVerification('job-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/jobs/job-1/verification');
      expect(result.verified).toBe(true);
      expect(result.actual_fingerprint).toBe('abc123');
    });
  });

  // ─── Issuer Detail ─────────────────────────

  describe('Issuer Detail', () => {
    it('getIssuer fetches single issuer by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-local', name: 'Local CA', type: 'local_ca', status: 'active' }));
      const result = await getIssuer('iss-local');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/issuers/iss-local');
      expect(result.name).toBe('Local CA');
      expect(result.type).toBe('local_ca');
    });
  });

  // ─── Target Detail ─────────────────────────

  describe('Target Detail', () => {
    it('getTarget fetches single target by ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-nginx1', name: 'Web Server', type: 'nginx', hostname: 'web1.example.com' }));
      const result = await getTarget('t-nginx1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/targets/t-nginx1');
      expect(result.name).toBe('Web Server');
      expect(result.type).toBe('nginx');
    });
  });

  // ─── Prometheus Metrics ────────────────────

  describe('Prometheus Metrics', () => {
    it('getPrometheusMetrics fetches text format', async () => {
      const metricsText = '# HELP certctl_certificate_total Total certificates\ncertctl_certificate_total 10';
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve(metricsText),
        } as Response)
      );
      const result = await getPrometheusMetrics();
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/metrics/prometheus');
      expect(result).toContain('certctl_certificate_total');
    });

    it('getPrometheusMetrics throws on error', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: false,
          status: 500,
          text: () => Promise.resolve('error'),
        } as Response)
      );
      await expect(getPrometheusMetrics()).rejects.toThrow('Prometheus metrics failed: 500');
    });

    it('getPrometheusMetrics includes auth header', async () => {
      setApiKey('prom-key');
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve('metrics'),
        } as Response)
      );
      await getPrometheusMetrics();
      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer prom-key');
    });
  });

  describe('Frontend Audit: New API Functions', () => {
    it('getCertificateDeployments sends GET with cert ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0 }));
      await getCertificateDeployments('mc-1');
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/certificates/mc-1/deployments');
    });

    // M-006: JSON CRL endpoint (`GET /api/v1/crl`) removed entirely — RFC 5280
    // defines only the DER wire format, which is now served unauthenticated at
    // `/.well-known/pki/crl/{issuer_id}` (fetched directly, no GUI wrapper).
    // OCSP likewise relocated to `/.well-known/pki/ocsp/{issuer_id}/{serial}`
    // per RFC 8615.
    it('getOCSPStatus sends GET to /.well-known/pki/ocsp with issuer and serial', async () => {
      const buf = new ArrayBuffer(8);
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          arrayBuffer: () => Promise.resolve(buf),
        } as Response)
      );
      await getOCSPStatus('iss-local', 'ABC123');
      expect(mockFetch.mock.calls[0][0]).toBe('/.well-known/pki/ocsp/iss-local/ABC123');
    });

    it('updateIssuer sends PUT with data', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'iss-1', name: 'Updated' }));
      await updateIssuer('iss-1', { name: 'Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/issuers/iss-1');
      expect(init.method).toBe('PUT');
    });

    it('updateTarget sends PUT with data', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 't-1', name: 'Updated' }));
      await updateTarget('t-1', { name: 'Updated' });
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/v1/targets/t-1');
      expect(init.method).toBe('PUT');
    });

    it('getPolicy sends GET with policy ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'pol-1', name: 'Test' }));
      await getPolicy('pol-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/policies/pol-1');
    });
  });

  describe('Health Checks (M48)', () => {
    it('listHealthChecks sends GET with optional filters', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ data: [], total: 0, page: 1, per_page: 50 }));
      const result = await listHealthChecks({ status: 'degraded' });
      expect(result.total).toBe(0);
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/health-checks');
      expect(mockFetch.mock.calls[0][0]).toContain('status=degraded');
    });

    it('getHealthCheck sends GET with health check ID', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'hc-1', endpoint: 'example.com:443' }));
      const result = await getHealthCheck('hc-1');
      expect(result.id).toBe('hc-1');
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/health-checks/hc-1');
    });

    it('createHealthCheck sends POST with data', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ id: 'hc-1', endpoint: 'example.com:443' }));
      const result = await createHealthCheck({ endpoint: 'example.com:443' });
      expect(result.id).toBe('hc-1');
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toContain('/api/v1/health-checks');
      expect(init.method).toBe('POST');
    });

    it('getHealthCheckSummary sends GET to /health-checks/summary', async () => {
      mockFetch.mockReturnValueOnce(mockJsonResponse({ healthy: 5, degraded: 1, down: 0, cert_mismatch: 0, unknown: 2, total: 8 }));
      const result = await getHealthCheckSummary();
      expect(result.healthy).toBe(5);
      expect(result.total).toBe(8);
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/health-checks/summary');
    });
  });
});
