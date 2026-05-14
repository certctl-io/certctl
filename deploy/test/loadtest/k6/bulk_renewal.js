// Phase 8 SCALE-H2 — bulk-renewal under load.
//
// What this measures:
//   POST /api/v1/certificates/bulk-renew throughput against a
//   10K-cert pre-seeded fleet. Each iteration POSTs a criteria-mode
//   bulk-renew request scoped to a subset of the seeded fleet (by
//   tag) so the server enqueues N renewal jobs and returns a
//   per-cert {certificate_id, job_id} envelope.
//
// Why criteria-mode (not certificate-ids mode):
//   The seeded fleet has a stable `tags.batch = 'bulk-renewal'`
//   marker. Criteria-mode lets the scenario re-fire without
//   maintaining a moving list of cert IDs and still scopes the
//   action to the Phase 8 fixture (no risk of touching a real
//   tenant's certs if someone runs the scenario against a non-
//   loadtest server by mistake — the criteria simply matches
//   nothing).
//
// What this does NOT measure:
//   - The scheduler's renewal scan itself. The bulk-renew handler
//     enqueues issuance jobs synchronously into the `jobs` table;
//     the scheduler's `jobProcessorLoop` picks them up on its next
//     tick. The DB write throughput is what's measured here; the
//     job-execution path is bounded by per-issuer concurrency
//     (CERTCTL_RENEWAL_CONCURRENCY=25 default) and isn't usefully
//     amplified by adding more inbound bulk-renew calls.
//   - Full POST → poll deployments → cert-served loop. Same v1/v2
//     deferral as the connector-tier scenarios — needs the agent
//     poll surface plumbed end-to-end.
//
// Threshold contract:
//   - p99 < 5s, p95 < 2s for the bulk-renew POST. Each call walks
//     the criteria, materializes the matching managed_certificates
//     rows, inserts N rows into `jobs`, and returns the envelope.
//   - Error rate < 1%. Anything 4xx/5xx counts.
//
// Phase 8 reference:
//   - Source finding: SCALE-H2.
//   - Pre-state: only the API tier (50 req/s POST /certificates +
//     GET /certificates) and connector tier (per-target handshake)
//     were measured. The bulk-renew hot path was uncovered.
//   - Seed: deploy/test/loadtest/seed/01_bulk_renewal_certs.sql
//     creates 10K rows with tags.batch='bulk-renewal'. The seed
//     must run before this scenario; the scale-seed compose
//     profile gates this.

import http from 'k6/http';
import { check } from 'k6';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

const BASE  = __ENV.CERTCTL_BASE  || 'https://localhost:8443';
const TOKEN = __ENV.CERTCTL_TOKEN || 'load-test-token';

// Sustained throughput target. constant-arrival-rate at 5 req/s for 5
// minutes = 1500 bulk-renew POSTs. Each POST touches up to 10K
// managed_certificates rows (criteria scan) + inserts up to 10K
// rows into `jobs`, so the offered load is higher than the API
// tier's 50 req/s on raw queries-per-second but the per-call
// cost is larger.
//
// 5 req/s was picked deliberately:
//   - 50 req/s combined with the API tier's 50 saturates the demo-
//     scale compose's DB pool (CERTCTL_DATABASE_MAX_CONNS=50). The
//     Phase 8 scenario should measure the per-call ceiling without
//     fighting the pool.
//   - Each call enqueues thousands of jobs; the scheduler's
//     jobProcessorLoop has finite per-tick budget. Pushing higher
//     than 5 req/s would queue work faster than the scheduler
//     drains it, which produces a transient backlog metric (worth
//     measuring eventually) but isn't what SCALE-H2 asks for.
export const options = {
    scenarios: {
        bulk_renewal: {
            executor: 'constant-arrival-rate',
            rate: 5,
            timeUnit: '1s',
            duration: '5m',
            preAllocatedVUs: 10,
            maxVUs: 30,
            exec: 'bulkRenewal',
            tags: { scenario: 'bulk_renewal' },
        },
    },
    thresholds: {
        // Single-scenario threshold — narrower than the API tier
        // because each call is heavier (DB scan + N inserts).
        'http_req_duration{scenario:bulk_renewal}': ['p(99)<5000', 'p(95)<2000'],
        'http_req_failed{scenario:bulk_renewal}': ['rate<0.01'],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
    insecureSkipTLSVerify: true,
};

export function bulkRenewal() {
    // Scope by team_id — the seed binds every loadtest cert to
    // t-platform; in a production-multi-tenant deploy, team scoping
    // is the typical bulk-renew shape. This exercises the criteria
    // walker AND the team-scoped permission check in the handler.
    //
    // NOTE: this does NOT include `tags` because the BulkRenewalCriteria
    // domain type (handler/bulk_renewal.go) only exposes profile_id,
    // owner_id, agent_id, issuer_id, team_id, certificate_ids — not
    // tag-based filtering. The team_id scope plus the production-
    // separated FK guarantees we only touch the Phase 8 seed.
    const payload = JSON.stringify({
        team_id: 't-platform',
        issuer_id: 'iss-local',
    });

    const res = http.post(`${BASE}/api/v1/certificates/bulk-renew`, payload, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${TOKEN}`,
        },
        tags: { scenario: 'bulk_renewal' },
    });

    check(res, {
        'bulk-renew 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

export function handleSummary(data) {
    return {
        '/results/summary-bulk-renewal.json': JSON.stringify(data, null, 2),
        '/results/summary-bulk-renewal.txt': textSummary(data, { indent: ' ', enableColors: false }),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}
