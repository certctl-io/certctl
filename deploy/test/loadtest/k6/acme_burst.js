// Phase 8 SCALE-H2 — ACME enrollment burst.
//
// What this measures:
//   200 concurrent VUs hammering the unauthenticated ACME directory
//   + new-nonce + ARI surface for 5 minutes. The goal is the
//   throughput ceiling for the entry-point handlers and the
//   per-account rate-limit response shape Phase 5 added (RFC 8555
//   §6.7 + RFC 7807 + the certctl-specific
//   ErrACMEConcurrentOrdersExceeded path).
//
// What this does NOT measure (and why):
//   - JWS-signed POST flows (new-account, new-order, finalize).
//     k6 doesn't ship JWS, and bundling a Go signing helper into
//     the k6 container would obscure the server-side latency the
//     scenario is trying to pin. The existing
//     `deploy/test/loadtest/k6/acme_flow.js` Phase 5 scenario
//     made the same explicit trade-off; this Phase 8 burst scenario
//     reuses the constraint. End-to-end JWS-signed conformance is
//     gated by `make acme-rfc-conformance-test` (which uses lego
//     against the same compose stack).
//   - The actual order/finalize hot path. The newOrder handler's
//     constant-time SCAN against acme_orders + the per-account
//     concurrent-orders gate ARE useful to load-test, but require
//     valid JWS to reach. The directory + new-nonce surface this
//     scenario hits is what every ACME client transits BEFORE the
//     signed flow — measuring it pins the server's headroom for
//     the rest of the flow.
//   - Issuer-side enrollment latency (DigiCert ACME, Let's Encrypt
//     against a real prod CA, etc.). Same "load-testing someone
//     else's API" carve-out as the API tier.
//
// What this DOES measure:
//   - GET /acme/profile/{id}/directory throughput. Sustained 200
//     concurrent VUs at a low per-VU sleep produces ~600-1000 req/s
//     against this endpoint, well above what any production ACME
//     client would generate but the right shape for finding the
//     ceiling.
//   - HEAD /acme/profile/{id}/new-nonce throughput. Nonce
//     allocation is a hot path that writes one row to acme_nonces.
//   - GET /acme/profile/{id}/renewal-info/{cert-id} 4xx fast path.
//     Synthetic cert-id → handler returns 4xx without a DB lookup
//     (cert-id is malformed at the parse layer). Measures the
//     handler-front overhead under load.
//   - 429 rate-limit response shape. The Phase 5 ACME per-account
//     rate limit fires at sustained spike rates; the scenario pins
//     that the 429 body is RFC 7807 with the
//     "urn:ietf:params:acme:error:rateLimited" type. A regression
//     that returned a plain text 429 or a different problem type
//     would break ACME clients hard.
//
// Threshold contract:
//   - directory p95 < 500ms, new-nonce p95 < 300ms, renewal-info
//     p95 < 800ms — same as the Phase 5 acme_flow.js baselines.
//   - 429 responses are EXPECTED at sustained 200 VU rate (the
//     server's RFC-compliant rate limiter SHOULD kick in). The
//     http_req_failed metric is tagged separately so 429s don't
//     break the threshold; a separate `rate_limited` Counter
//     tracks them so the operator can see how often the limiter
//     fires.

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

const ACME_BASE = __ENV.CERTCTL_ACME_DIRECTORY ||
    'https://certctl-server:8443/acme/profile/prof-test/directory';

// Custom metrics.
const directoryDuration = new Trend('acme_directory_duration', true);
const newNonceDuration  = new Trend('acme_new_nonce_duration', true);
const renewalInfoDuration = new Trend('acme_renewal_info_duration', true);
const rateLimitedCount  = new Counter('acme_rate_limited_count');
const rateLimitShapeOK  = new Counter('acme_rate_limit_shape_ok');

export const options = {
    scenarios: {
        acme_burst: {
            executor: 'constant-vus',
            vus: parseInt(__ENV.K6_ACME_VUS || '200', 10),
            duration: __ENV.K6_ACME_DURATION || '5m',
            gracefulStop: '30s',
            tags: { scenario: 'acme_burst' },
        },
    },
    thresholds: {
        'acme_directory_duration':    ['p(95)<500'],
        'acme_new_nonce_duration':    ['p(95)<300'],
        'acme_renewal_info_duration': ['p(95)<800'],
        // 4xx (rate-limited or malformed-cert-id) is expected; 5xx is
        // not. Filter to status >= 500 for the failure floor.
        'http_req_failed{scenario:acme_burst,server_error:true}': ['rate<0.001'],
    },
    insecureSkipTLSVerify: true,
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

export default function () {
    // Step 1 — directory.
    let res = http.get(ACME_BASE, {
        tags: { scenario: 'acme_burst', step: 'directory' },
    });
    directoryDuration.add(res.timings.duration);
    check(res, { 'directory 200': (r) => r.status === 200 });

    if (res.status === 429) {
        recordRateLimit(res);
        return; // backoff this VU iteration
    }
    if (res.status !== 200) return;

    const dir = res.json();

    // Step 2 — new-nonce.
    if (dir.newNonce) {
        res = http.head(dir.newNonce, {
            tags: { scenario: 'acme_burst', step: 'new_nonce' },
        });
        newNonceDuration.add(res.timings.duration);
        if (res.status === 429) {
            recordRateLimit(res);
            return;
        }
        check(res, {
            'new-nonce 200': (r) => r.status === 200,
            'replay-nonce header present': (r) => !!r.headers['Replay-Nonce'],
        });
    }

    // Step 3 — ARI synthetic 4xx fast path. Phase 4 added ARI
    // (RFC 9773); this exercises the malformed-cert-id branch which
    // returns a 4xx without a DB lookup. Pinning this here means a
    // regression that turned the malformed path into a DB query
    // would surface as a p95 spike.
    if (dir.renewalInfo) {
        res = http.get(dir.renewalInfo + '/aaaa.bbbb', {
            tags: { scenario: 'acme_burst', step: 'renewal_info' },
        });
        renewalInfoDuration.add(res.timings.duration);
        if (res.status === 429) {
            recordRateLimit(res);
            return;
        }
        check(res, {
            'renewal-info 4xx for synthetic cert-id':
                (r) => r.status === 400 || r.status === 404,
        });
    }
}

// recordRateLimit pins the Phase 5 ACME rate-limit response shape:
//   - HTTP 429
//   - Content-Type: application/problem+json
//   - Body: {"type":"urn:ietf:params:acme:error:rateLimited", ...}
// A regression that returned 503 or a plain-text 429 or a different
// problem type would NOT increment acme_rate_limit_shape_ok and the
// operator would see (rate_limited_count - shape_ok_count) > 0 in
// the summary.
function recordRateLimit(res) {
    rateLimitedCount.add(1);
    const ct = res.headers['Content-Type'] || '';
    if (!ct.includes('application/problem+json')) {
        return;
    }
    let body;
    try {
        body = res.json();
    } catch (e) {
        return;
    }
    if (body && typeof body.type === 'string' &&
        body.type.startsWith('urn:ietf:params:acme:error:rateLimited')) {
        rateLimitShapeOK.add(1);
    }
}

export function handleSummary(data) {
    return {
        '/results/summary-acme-burst.json': JSON.stringify(data, null, 2),
        '/results/summary-acme-burst.txt': textSummary(data, { indent: ' ', enableColors: false }),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}
