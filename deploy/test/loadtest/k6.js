// certctl load-test driver — k6 v0.54+ JS API.
//
// Closes the #8 acquisition-readiness blocker from the 2026-05-01 issuer
// coverage audit. Pre-fix, certctl had no benchmarks or load tests for any
// API path. An acquirer evaluating "can certctl handle our 50k-cert fleet
// at 47-day rotation" had nothing to point at; this script gives them
// a reproducible number with a methodology.
//
// What this measures (be honest about scope):
//   - POST /api/v1/certificates: auth + JSON decode + validation + service
//     CreateCertificate + DB insert + response. This is the operator-facing
//     request-acceptance throughput. The downstream issuer-connector call
//     happens asynchronously via the renewal scheduler (and is bounded
//     separately via CERTCTL_RENEWAL_CONCURRENCY — audit fix #9).
//   - GET /api/v1/certificates: read path with pagination. Exercises the
//     cert list query, which is the most-called read endpoint in any UI/
//     automation client.
//
// What this does NOT measure:
//   - Issuer connector latency (DigiCert / ACME / Vault / etc. round-trips
//     to upstream CAs). Those are async; pin via the per-issuer-type
//     metrics instead (audit fix #4: certctl_issuance_duration_seconds).
//   - The full ACME enrollment flow (newOrder → challenge → finalize).
//     The audit prompt mentioned ACME-via-pebble; deferred to a follow-up
//     because driving multi-RTT ACME flows at sustained 100/s requires
//     pebble tuning + k6 crypto helpers that don't exist out of the box.
//
// Threshold contract: any future change that pushes p99 above 5s for the
// issuance-acceptance scenario or 2s for the read scenario, OR any change
// that pushes the error rate above 1%, fails the test. CI gates the run
// behind workflow_dispatch + cron (NOT per-push — load tests are too slow
// to gate per-PR signal).
//
// Audit reference: cowork/issuer-coverage-audit-2026-05-01/RESULTS.md fix #8.

import http from 'k6/http';
import { check } from 'k6';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

// __ENV.* lets the same script run unchanged on the operator's
// workstation (CERTCTL_BASE=https://localhost:8443) and inside the
// docker-compose stack (CERTCTL_BASE=https://certctl-server:8443).
const BASE = __ENV.CERTCTL_BASE || 'https://localhost:8443';
const TOKEN = __ENV.CERTCTL_TOKEN || 'load-test-token';

// Demo seed (CERTCTL_DEMO_SEED=true) creates these rows; CreateCertificate
// requires all four FKs to exist. Pre-baked here so the script has zero
// dependency on test fixtures beyond the seed.
const ISSUER_ID = 'iss-local';
const OWNER_ID = 'o-alice';
const TEAM_ID = 't-platform';
const RENEWAL_POLICY = 'rp-standard';

export const options = {
    scenarios: {
        // Issuance-acceptance throughput. constant-arrival-rate fires
        // requests at a fixed rate regardless of latency, which is the
        // right shape for capacity testing — VU-bound load (constant-vus)
        // would let slow responses backpressure the offered load and
        // mask actual capacity ceilings.
        issuance_acceptance: {
            executor: 'constant-arrival-rate',
            rate: 50,
            timeUnit: '1s',
            duration: '5m',
            preAllocatedVUs: 50,
            maxVUs: 200,
            exec: 'createCertificate',
            tags: { scenario: 'issuance_acceptance' },
        },
        // Read path. Same rate as issuance so the DB sees a balanced
        // mix; staggered start so warmup overlap doesn't skew the
        // first 30 seconds of either scenario.
        list_certificates: {
            executor: 'constant-arrival-rate',
            rate: 50,
            timeUnit: '1s',
            duration: '5m',
            preAllocatedVUs: 50,
            maxVUs: 200,
            exec: 'listCertificates',
            startTime: '5s',
            tags: { scenario: 'list_certificates' },
        },
    },
    thresholds: {
        // Hard floor: 99% of issuance-acceptance requests complete in
        // under 5 seconds. Pre-fix this was unsubstantiated; post-fix
        // this is the regression guard. The number isn't aspirational —
        // it's the worst-acceptable user-facing API SLO from the
        // operator perspective.
        'http_req_duration{scenario:issuance_acceptance}': ['p(99)<5000', 'p(95)<2000'],
        'http_req_duration{scenario:list_certificates}': ['p(99)<2000', 'p(95)<800'],
        // < 1% error rate. The k6 default is "any 4xx/5xx counts as
        // failed"; legitimate 201/200 responses don't count. Auth
        // failures, validation failures, server errors all do.
        'http_req_failed': ['rate<0.01'],
    },
    // Smaller summary payload — strip per-VU metrics we don't read.
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

// uniqueCN returns a deterministic-but-unique CommonName per
// (VU, iter). This avoids unique-constraint violations on the
// managed_certificates row (the table has a unique index on
// (issuer_id, name) so two parallel POSTs with the same Name 409
// rather than 201).
function uniqueCN() {
    return `loadtest-${__VU}-${__ITER}-${Date.now()}.example.test`;
}

export function createCertificate() {
    const cn = uniqueCN();
    const payload = JSON.stringify({
        name: cn,
        common_name: cn,
        issuer_id: ISSUER_ID,
        owner_id: OWNER_ID,
        team_id: TEAM_ID,
        renewal_policy_id: RENEWAL_POLICY,
        environment: 'production',
        sans: [cn],
    });

    const res = http.post(`${BASE}/api/v1/certificates`, payload, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${TOKEN}`,
        },
        tags: { scenario: 'issuance_acceptance' },
    });

    check(res, {
        'create status 201': (r) => r.status === 201,
    });
}

export function listCertificates() {
    const res = http.get(`${BASE}/api/v1/certificates?per_page=50`, {
        headers: {
            'Authorization': `Bearer ${TOKEN}`,
        },
        tags: { scenario: 'list_certificates' },
    });

    check(res, {
        'list status 200': (r) => r.status === 200,
    });
}

// handleSummary writes the full results to /results/summary.{json,txt}
// so the operator can commit the baseline numbers into README.md after
// each run and so CI can ingest the JSON for diffing.
//
// stdout reproduces the textSummary so the docker compose log shows
// the same numbers an operator running it manually would see.
export function handleSummary(data) {
    return {
        '/results/summary.json': JSON.stringify(data, null, 2),
        '/results/summary.txt': textSummary(data, { indent: ' ', enableColors: false }),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}
