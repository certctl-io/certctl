import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  setApiKey,
  getCertificates,
  getCertificate,
  createCertificate,
  triggerRenewal,
  revokeCertificate,
  exportCertificatePEM,
  downloadCertificatePEM,
  exportCertificatePKCS12,
  getAgents,
  getAgent,
  registerAgent,
  getJobs,
  cancelJob,
  approveRenewal,
  rejectRenewal,
  getNotifications,
  getAuditEvents,
  getPolicies,
  getIssuers,
  getTargets,
  getDiscoveredCertificates,
  getDiscoveredCertificate,
  claimDiscoveredCertificate,
  dismissDiscoveredCertificate,
  getNetworkScanTargets,
  getNetworkScanTarget,
  createNetworkScanTarget,
  triggerNetworkScan,
  getDashboardSummary,
  getMetrics,
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

function mockBlobResponse(status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    blob: () => Promise.resolve(new Blob(['test data'])),
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

function mockNetworkError() {
  return Promise.reject(new TypeError('Failed to fetch'));
}

describe('API Client - Error Handling', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    setApiKey(null);
  });

  // ─── Certificate Endpoints (Network Errors) ──────────────

  describe('Certificate endpoints - Network errors', () => {
    it('getCertificates propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getCertificates()).rejects.toThrow('Failed to fetch');
    });

    it('getCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getCertificate('mc-test')).rejects.toThrow('Failed to fetch');
    });

    it('createCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(createCertificate({ common_name: 'test.com' })).rejects.toThrow(
        'Failed to fetch',
      );
    });

    it('triggerRenewal propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(triggerRenewal('mc-test')).rejects.toThrow('Failed to fetch');
    });

    it('revokeCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(revokeCertificate('mc-test', 'keyCompromise')).rejects.toThrow(
        'Failed to fetch',
      );
    });

    it('exportCertificatePEM propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(exportCertificatePEM('mc-test')).rejects.toThrow('Failed to fetch');
    });

    it('downloadCertificatePEM propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(downloadCertificatePEM('mc-test')).rejects.toThrow('Failed to fetch');
    });

    it('exportCertificatePKCS12 propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(exportCertificatePKCS12('mc-test', 'password')).rejects.toThrow(
        'Failed to fetch',
      );
    });
  });

  // ─── Certificate Endpoints (HTTP Errors) ─────────────────

  describe('Certificate endpoints - HTTP error responses', () => {
    it('getCertificates with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getCertificates()).rejects.toThrow('Authentication required');
    });

    it('getCertificates with 403 throws Forbidden', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(403, { message: 'Access denied' }));
      await expect(getCertificates()).rejects.toThrow('Access denied');
    });

    it('getCertificate with 404 throws not found message', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(404, { message: 'Certificate not found' }));
      await expect(getCertificate('mc-nonexistent')).rejects.toThrow(
        'Certificate not found',
      );
    });

    it('createCertificate with 400 throws validation error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, { message: 'Invalid common name' }),
      );
      await expect(createCertificate({ common_name: 'invalid' })).rejects.toThrow(
        'Invalid common name',
      );
    });

    it('triggerRenewal with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Internal server error' }),
      );
      await expect(triggerRenewal('mc-test')).rejects.toThrow('Internal server error');
    });

    it('revokeCertificate with 429 throws rate limit error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(429, { message: 'Rate limit exceeded' }),
      );
      await expect(revokeCertificate('mc-test', 'keyCompromise')).rejects.toThrow(
        'Rate limit exceeded',
      );
    });

    it('downloadCertificatePEM with 404 throws Export failed', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(404));
      await expect(downloadCertificatePEM('mc-nonexistent')).rejects.toThrow(
        'Export failed',
      );
    });

    it('exportCertificatePKCS12 with 403 throws Export failed', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(403));
      await expect(exportCertificatePKCS12('mc-test', 'password')).rejects.toThrow(
        'Export failed',
      );
    });

    it('getCertificates falls back to statusText when no message', async () => {
      const response = Promise.resolve({
        ok: false,
        status: 502,
        json: () => Promise.reject(new Error('not json')),
        statusText: 'Bad Gateway',
      } as Response);
      mockFetch.mockReturnValueOnce(response);
      await expect(getCertificates()).rejects.toThrow('Bad Gateway');
    });
  });

  // ─── Certificate Endpoints (Malformed Responses) ─────────

  describe('Certificate endpoints - Malformed responses', () => {
    it('getCertificates with invalid JSON throws parse error', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.reject(new SyntaxError('Unexpected token')),
        } as Response),
      );
      await expect(getCertificates()).rejects.toThrow();
    });

    it('getCertificate with empty response body', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: true,
          status: 204,
          json: () => Promise.resolve({}),
        } as Response),
      );
      const result = await getCertificate('mc-test');
      expect(result).toEqual({});
    });
  });

  // ─── Agent Endpoints (Network Errors) ─────────────────────

  describe('Agent endpoints - Network errors', () => {
    it('getAgents propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getAgents()).rejects.toThrow('Failed to fetch');
    });

    it('getAgent propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getAgent('a-web01')).rejects.toThrow('Failed to fetch');
    });

    it('registerAgent propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(registerAgent({ name: 'agent1' })).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Agent Endpoints (HTTP Errors) ─────────────────────────

  describe('Agent endpoints - HTTP error responses', () => {
    it('getAgents with 401 triggers auth-required event', async () => {
      const listener = vi.fn();
      window.addEventListener('certctl:auth-required', listener);
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getAgents()).rejects.toThrow('Authentication required');
      expect(listener).toHaveBeenCalled();
      window.removeEventListener('certctl:auth-required', listener);
    });

    it('getAgent with 404 throws not found', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(404, { message: 'Agent not found' }));
      await expect(getAgent('a-nonexistent')).rejects.toThrow('Agent not found');
    });

    it('registerAgent with 400 throws validation error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, { message: 'Invalid agent name' }),
      );
      await expect(registerAgent({ name: '' })).rejects.toThrow('Invalid agent name');
    });

    it('getAgents with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Database connection failed' }),
      );
      await expect(getAgents()).rejects.toThrow('Database connection failed');
    });
  });

  // ─── Job Endpoints (Network Errors) ──────────────────────

  describe('Job endpoints - Network errors', () => {
    it('getJobs propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getJobs()).rejects.toThrow('Failed to fetch');
    });

    it('cancelJob propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(cancelJob('job-123')).rejects.toThrow('Failed to fetch');
    });

    it('approveRenewal propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(approveRenewal('job-123')).rejects.toThrow('Failed to fetch');
    });

    it('rejectRenewal propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(rejectRenewal('job-123', 'Not ready')).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Job Endpoints (HTTP Errors) ─────────────────────────

  describe('Job endpoints - HTTP error responses', () => {
    it('getJobs with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getJobs()).rejects.toThrow('Authentication required');
    });

    it('cancelJob with 400 throws invalid state error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, { message: 'Cannot cancel completed job' }),
      );
      await expect(cancelJob('job-123')).rejects.toThrow('Cannot cancel completed job');
    });

    it('approveRenewal with 403 throws Forbidden', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(403, { message: 'Permission denied' }));
      await expect(approveRenewal('job-123')).rejects.toThrow('Permission denied');
    });

    it('rejectRenewal with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Failed to process rejection' }),
      );
      await expect(rejectRenewal('job-123', 'Too risky')).rejects.toThrow(
        'Failed to process rejection',
      );
    });

    it('getJobs with 429 throws rate limit error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(429, { message: 'Too many requests' }),
      );
      await expect(getJobs()).rejects.toThrow('Too many requests');
    });
  });

  // ─── Notification Endpoints (Network Errors) ─────────────

  describe('Notification endpoints - Network errors', () => {
    it('getNotifications propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getNotifications()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Notification Endpoints (HTTP Errors) ────────────────

  describe('Notification endpoints - HTTP error responses', () => {
    it('getNotifications with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getNotifications()).rejects.toThrow('Authentication required');
    });

    it('getNotifications with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Cache unavailable' }),
      );
      await expect(getNotifications()).rejects.toThrow('Cache unavailable');
    });
  });

  // ─── Audit Endpoints (Network Errors) ────────────────────

  describe('Audit endpoints - Network errors', () => {
    it('getAuditEvents propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getAuditEvents()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Audit Endpoints (HTTP Errors) ───────────────────────

  describe('Audit endpoints - HTTP error responses', () => {
    it('getAuditEvents with 403 throws Forbidden', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(403, { message: 'Audit access denied' }));
      await expect(getAuditEvents()).rejects.toThrow('Audit access denied');
    });

    it('getAuditEvents with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Audit log unavailable' }),
      );
      await expect(getAuditEvents()).rejects.toThrow('Audit log unavailable');
    });
  });

  // ─── Policy Endpoints (Network Errors) ───────────────────

  describe('Policy endpoints - Network errors', () => {
    it('getPolicies propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getPolicies()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Policy Endpoints (HTTP Errors) ──────────────────────

  describe('Policy endpoints - HTTP error responses', () => {
    it('getPolicies with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getPolicies()).rejects.toThrow('Authentication required');
    });

    it('getPolicies with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Policy service error' }),
      );
      await expect(getPolicies()).rejects.toThrow('Policy service error');
    });
  });

  // ─── Issuer Endpoints (Network Errors) ───────────────────

  describe('Issuer endpoints - Network errors', () => {
    it('getIssuers propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getIssuers()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Issuer Endpoints (HTTP Errors) ──────────────────────

  describe('Issuer endpoints - HTTP error responses', () => {
    it('getIssuers with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getIssuers()).rejects.toThrow('Authentication required');
    });

    it('getIssuers with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Issuer registry error' }),
      );
      await expect(getIssuers()).rejects.toThrow('Issuer registry error');
    });
  });

  // ─── Target Endpoints (Network Errors) ───────────────────

  describe('Target endpoints - Network errors', () => {
    it('getTargets propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getTargets()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Target Endpoints (HTTP Errors) ──────────────────────

  describe('Target endpoints - HTTP error responses', () => {
    it('getTargets with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getTargets()).rejects.toThrow('Authentication required');
    });

    it('getTargets with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Target registry error' }),
      );
      await expect(getTargets()).rejects.toThrow('Target registry error');
    });
  });

  // ─── Discovery Endpoints (Network Errors) ────────────────

  describe('Discovery endpoints - Network errors', () => {
    it('getDiscoveredCertificates propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getDiscoveredCertificates()).rejects.toThrow('Failed to fetch');
    });

    it('getDiscoveredCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getDiscoveredCertificate('disc-123')).rejects.toThrow('Failed to fetch');
    });

    it('claimDiscoveredCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(claimDiscoveredCertificate('disc-123', 'mc-test')).rejects.toThrow(
        'Failed to fetch',
      );
    });

    it('dismissDiscoveredCertificate propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(dismissDiscoveredCertificate('disc-123')).rejects.toThrow(
        'Failed to fetch',
      );
    });
  });

  // ─── Discovery Endpoints (HTTP Errors) ───────────────────

  describe('Discovery endpoints - HTTP error responses', () => {
    it('getDiscoveredCertificates with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getDiscoveredCertificates()).rejects.toThrow('Authentication required');
    });

    it('getDiscoveredCertificate with 404 throws not found', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(404, { message: 'Discovered certificate not found' }),
      );
      await expect(getDiscoveredCertificate('disc-nonexistent')).rejects.toThrow(
        'Discovered certificate not found',
      );
    });

    it('claimDiscoveredCertificate with 400 throws validation error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, { message: 'Certificate already claimed' }),
      );
      await expect(claimDiscoveredCertificate('disc-123', 'mc-test')).rejects.toThrow(
        'Certificate already claimed',
      );
    });

    it('dismissDiscoveredCertificate with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Discovery service error' }),
      );
      await expect(dismissDiscoveredCertificate('disc-123')).rejects.toThrow(
        'Discovery service error',
      );
    });

    it('getDiscoveredCertificates with 429 throws rate limit error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(429, { message: 'Rate limit exceeded' }),
      );
      await expect(getDiscoveredCertificates()).rejects.toThrow('Rate limit exceeded');
    });
  });

  // ─── Network Scan Endpoints (Network Errors) ─────────────

  describe('Network scan endpoints - Network errors', () => {
    it('getNetworkScanTargets propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getNetworkScanTargets()).rejects.toThrow('Failed to fetch');
    });

    it('getNetworkScanTarget propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getNetworkScanTarget('scan-123')).rejects.toThrow('Failed to fetch');
    });

    it('createNetworkScanTarget propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(
        createNetworkScanTarget({ name: 'test', cidrs: ['10.0.0.0/24'] }),
      ).rejects.toThrow('Failed to fetch');
    });

    it('triggerNetworkScan propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(triggerNetworkScan('scan-123')).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Network Scan Endpoints (HTTP Errors) ────────────────

  describe('Network scan endpoints - HTTP error responses', () => {
    it('getNetworkScanTargets with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getNetworkScanTargets()).rejects.toThrow('Authentication required');
    });

    it('getNetworkScanTarget with 404 throws not found', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(404, { message: 'Scan target not found' }),
      );
      await expect(getNetworkScanTarget('scan-nonexistent')).rejects.toThrow(
        'Scan target not found',
      );
    });

    it('createNetworkScanTarget with 400 throws validation error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, { message: 'Invalid CIDR range' }),
      );
      await expect(
        createNetworkScanTarget({ name: 'test', cidrs: ['invalid'] }),
      ).rejects.toThrow('Invalid CIDR range');
    });

    it('triggerNetworkScan with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Scanner unavailable' }),
      );
      await expect(triggerNetworkScan('scan-123')).rejects.toThrow('Scanner unavailable');
    });

    it('getNetworkScanTargets with 429 throws rate limit error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(429, { message: 'Scan quota exceeded' }),
      );
      await expect(getNetworkScanTargets()).rejects.toThrow('Scan quota exceeded');
    });
  });

  // ─── Stats/Metrics Endpoints (Network Errors) ────────────

  describe('Stats/Metrics endpoints - Network errors', () => {
    it('getDashboardSummary propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getDashboardSummary()).rejects.toThrow('Failed to fetch');
    });

    it('getMetrics propagates network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(getMetrics()).rejects.toThrow('Failed to fetch');
    });
  });

  // ─── Stats/Metrics Endpoints (HTTP Errors) ───────────────

  describe('Stats/Metrics endpoints - HTTP error responses', () => {
    it('getDashboardSummary with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getDashboardSummary()).rejects.toThrow('Authentication required');
    });

    it('getDashboardSummary with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Stats aggregation failed' }),
      );
      await expect(getDashboardSummary()).rejects.toThrow('Stats aggregation failed');
    });

    it('getMetrics with 401 throws Authentication required', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getMetrics()).rejects.toThrow('Authentication required');
    });

    it('getMetrics with 500 throws server error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Metrics service error' }),
      );
      await expect(getMetrics()).rejects.toThrow('Metrics service error');
    });

    it('getDashboardSummary with 429 throws rate limit error', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(429, { message: 'Metrics rate limit exceeded' }),
      );
      await expect(getDashboardSummary()).rejects.toThrow('Metrics rate limit exceeded');
    });
  });

  // ─── Cross-Cutting Error Handling ────────────────────────

  describe('Cross-cutting error scenarios', () => {
    it('401 on any endpoint triggers auth-required event once', async () => {
      const listener = vi.fn();
      window.addEventListener('certctl:auth-required', listener);

      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getCertificates()).rejects.toThrow('Authentication required');

      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      await expect(getAgents()).rejects.toThrow('Authentication required');

      expect(listener).toHaveBeenCalledTimes(2);
      window.removeEventListener('certctl:auth-required', listener);
    });

    it('prefers message field over error field', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(400, {
          message: 'Validation failed',
          error: 'Fallback error',
        }),
      );
      await expect(getCertificates()).rejects.toThrow('Validation failed');
    });

    it('uses error field when message unavailable', async () => {
      mockFetch.mockReturnValueOnce(
        mockErrorResponse(500, { error: 'Only error field present' }),
      );
      await expect(getCertificates()).rejects.toThrow('Only error field present');
    });

    it('falls back to statusText when both fields missing', async () => {
      mockFetch.mockReturnValueOnce(
        Promise.resolve({
          ok: false,
          status: 418,
          json: () => Promise.resolve({}),
          statusText: "I'm a teapot",
        } as Response),
      );
      await expect(getCertificates()).rejects.toThrow("I'm a teapot");
    });

    it('preserves error context through async chain', async () => {
      const err = new Error('Original error');
      mockFetch.mockReturnValueOnce(Promise.reject(err));
      await expect(getCertificates()).rejects.toBe(err);
    });

    it('handles multiple sequential errors correctly', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(500, { error: 'Error 1' }));
      await expect(getCertificates()).rejects.toThrow('Error 1');

      mockFetch.mockReturnValueOnce(mockErrorResponse(500, { error: 'Error 2' }));
      await expect(getAgents()).rejects.toThrow('Error 2');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  // ─── Binary Response Handling (Export) ────────────────────

  describe('Binary response error handling', () => {
    it('downloadCertificatePEM with network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(downloadCertificatePEM('mc-test')).rejects.toThrow('Failed to fetch');
    });

    it('downloadCertificatePEM with server error', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(500));
      await expect(downloadCertificatePEM('mc-test')).rejects.toThrow('Export failed');
    });

    it('exportCertificatePKCS12 with network error', async () => {
      mockFetch.mockReturnValueOnce(mockNetworkError());
      await expect(exportCertificatePKCS12('mc-test', 'pass')).rejects.toThrow(
        'Failed to fetch',
      );
    });

    it('exportCertificatePKCS12 with server error', async () => {
      mockFetch.mockReturnValueOnce(mockErrorResponse(403));
      await expect(exportCertificatePKCS12('mc-test', 'pass')).rejects.toThrow(
        'Export failed',
      );
    });

    it('downloadCertificatePEM uses Authorization header on error', async () => {
      setApiKey('test-key');
      mockFetch.mockReturnValueOnce(mockErrorResponse(401));
      try {
        await downloadCertificatePEM('mc-test');
      } catch {
        // Expected to fail
      }
      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer test-key');
    });
  });
});
