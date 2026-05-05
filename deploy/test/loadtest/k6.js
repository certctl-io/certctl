// certctl load-test driver — k6 v0.54+ JS API.
//
// Two tiers of scenarios:
//
//   API tier (issuer-coverage audit fix #8, 2026-05-01):
//     - issuance_acceptance: POST /api/v1/certificates throughput.
//     - list_certificates:   GET  /api/v1/certificates throughput.
//
//   Connector tier (Bundle 10 of the deployment-target audit, 2026-05-02):
//     - nginx_handshake / apache_handshake / haproxy_handshake / f5_handshake:
//       per-target-type TCP+TLS handshake throughput against the four
//       target sidecars at sustained 100 conns/min for 5 minutes. Latency
//       is tagged by target_type so summary.json's connector_tier section
//       breaks out p50/p95/p99 per target.
//
// What the API tier measures (be honest about scope):
//   - POST /api/v1/certificates: auth + JSON decode + validation + service
//     CreateCertificate + DB insert + response. This is the operator-facing
//     request-acceptance throughput. The downstream issuer-connector call
//     happens asynchronously via the renewal scheduler (and is bounded
//     separately via CERTCTL_RENEWAL_CONCURRENCY — issuer audit fix #9).
//   - GET /api/v1/certificates: read path with pagination. Exercises the
//     cert list query, which is the most-called read endpoint in any UI/
//     automation client.
//
// What the connector tier measures:
//   - Per-target-type TCP+TLS handshake completion latency. Validates that
//     each target sidecar (nginx, apache, haproxy, f5-mock) is operational
//     and serving its starter cert under sustained connection load.
//     Procurement asks "can certctl's nginx target handle 5,000 endpoints
//     at 47-day rotation"; the answer requires (a) the connector code
//     handles deploys correctly (covered by per-connector unit tests) AND
//     (b) the underlying daemon serves TLS at the connection rates a
//     5,000-endpoint fleet implies. The connector-tier scenarios pin (b).
//
// What this does NOT measure (documented limits, not lazy gaps):
//   - Issuer connector latency (DigiCert / ACME / Vault / etc. round-trips
//     to upstream CAs). Those are async; pin via the per-issuer-type
//     metrics instead (issuer audit fix #4:
//     certctl_issuance_duration_seconds).
//   - Full ACME enrollment (newOrder → challenge → finalize).
//   - The full agent-driven deploy hot path (POST cert with target
//     binding → poll deployments endpoint → verify served cert matches).
//     v1 of the connector-tier harness measures handshake throughput
//     against the sidecars directly. v2 is a follow-up that needs the
//     agent registration + target-binding API surface plumbed end-to-end
//     in the loadtest stack — a meaningful addition but not a blocker
//     for the Bundle 10 procurement question.
//   - Kubernetes connector. kind-in-docker requires `privileged: true`
//     and is operationally fragile in CI. Deferred until Bundle 2 (real
//     k8s.io/client-go) lands.
//
// Threshold contract:
//   - API tier: p99 < 5s for issuance, < 2s for list, error rate < 1%.
//   - Connector tier: p99 < 3s per handshake target (5s for f5-mock,
//     iControl REST is slower), error rate < 1%.
//   Any change pushing past these fails the workflow.
//
// CI gates the run behind workflow_dispatch + cron (NOT per-push — load
// tests are too slow to gate per-PR signal).
//
// Audit references:
//   - API tier:       2026-05-01 issuer coverage audit fix #8.
//   - Connector tier: 2026-05-02 deployment-target audit Bundle 10.

import http from 'k6/http';
import { check } from 'k6';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

// __ENV.* lets the same script run unchanged on the operator's
// workstation (CERTCTL_BASE=https://localhost:8443) and inside the
// docker-compose stack (CERTCTL_BASE=https://certctl-server:8443).
const BASE = __ENV.CERTCTL_BASE || 'https://localhost:8443';
const TOKEN = __ENV.CERTCTL_TOKEN || 'load-test-token';

// Bundle 10: per-target sidecar URLs. Defaults match the docker-compose
// stack's internal DNS; operators running k6 manually against a different
// stack override these via env. Empty default → the corresponding
// scenario is skipped (the scenarioFor* helper guards).
const NGINX_TARGET_URL   = __ENV.NGINX_TARGET_URL   || 'https://nginx-target:443';
const APACHE_TARGET_URL  = __ENV.APACHE_TARGET_URL  || 'https://apache-target:443';
const HAPROXY_TARGET_URL = __ENV.HAPROXY_TARGET_URL || 'https://haproxy-target:443';
// f5-mock's iControl REST `/healthz` endpoint is the CI-friendly
// per-handshake probe — hits the path the F5 connector itself uses for
// reachability. Real F5 BIG-IP also exposes /healthz under /mgmt/.
const F5_TARGET_URL      = __ENV.F5_TARGET_URL      || 'https://f5-mock-target:443';

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

        // Bundle 10: connector-tier per-target-type handshake scenarios.
        // 100 conns/min sustained for 5 minutes against each sidecar.
        // The handshake measurement captures TCP connect + TLS
        // handshake + tiny HTTP GET (`/` for nginx/apache/haproxy,
        // `/healthz` for f5-mock); k6's http_req_duration aggregates
        // all three so the numbers are end-to-end "respond to the
        // operator's connection" latency, not isolated TLS-handshake
        // microseconds.
        nginx_handshake: {
            executor: 'constant-arrival-rate',
            rate: 100,
            timeUnit: '1m',
            duration: '5m',
            preAllocatedVUs: 10,
            maxVUs: 50,
            exec: 'nginxHandshake',
            startTime: '10s',
            tags: { scenario: 'nginx_handshake', target_type: 'nginx' },
        },
        apache_handshake: {
            executor: 'constant-arrival-rate',
            rate: 100,
            timeUnit: '1m',
            duration: '5m',
            preAllocatedVUs: 10,
            maxVUs: 50,
            exec: 'apacheHandshake',
            startTime: '10s',
            tags: { scenario: 'apache_handshake', target_type: 'apache' },
        },
        haproxy_handshake: {
            executor: 'constant-arrival-rate',
            rate: 100,
            timeUnit: '1m',
            duration: '5m',
            preAllocatedVUs: 10,
            maxVUs: 50,
            exec: 'haproxyHandshake',
            startTime: '10s',
            tags: { scenario: 'haproxy_handshake', target_type: 'haproxy' },
        },
        f5_handshake: {
            executor: 'constant-arrival-rate',
            rate: 100,
            timeUnit: '1m',
            duration: '5m',
            preAllocatedVUs: 10,
            maxVUs: 50,
            exec: 'f5Handshake',
            startTime: '10s',
            tags: { scenario: 'f5_handshake', target_type: 'f5' },
        },
    },
    thresholds: {
        // API tier — issuer audit fix #8.
        'http_req_duration{scenario:issuance_acceptance}': ['p(99)<5000', 'p(95)<2000'],
        'http_req_duration{scenario:list_certificates}': ['p(99)<2000', 'p(95)<800'],

        // Bundle 10 connector tier. nginx/apache/haproxy are pure TLS
        // termination → tight thresholds. f5-mock includes a tiny Go
        // server response on top of the handshake → slightly looser.
        'http_req_duration{target_type:nginx}':   ['p(99)<3000', 'p(95)<1000'],
        'http_req_duration{target_type:apache}':  ['p(99)<3000', 'p(95)<1000'],
        'http_req_duration{target_type:haproxy}': ['p(99)<3000', 'p(95)<1000'],
        'http_req_duration{target_type:f5}':      ['p(99)<5000', 'p(95)<1500'],

        // < 1% error rate across ALL scenarios. Auth failures, validation
        // failures, server errors, connection refused all count.
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

// --- Bundle 10: connector-tier handshake scenarios ---
//
// Each per-target function does a single HTTPS GET against its target
// sidecar. k6's http_req_duration metric captures TCP connect + TLS
// handshake + HTTP request/response — that's the end-to-end "connection
// readiness" latency a deploy connector cares about. The target_type
// tag groups results in summary.json's connector_tier section.
//
// Status-check threshold: any 4xx/5xx counts as failed (k6 default
// behaviour for http_req_failed). f5-mock's /healthz returns 200; the
// other three nginx/apache/haproxy default vhost configs all return
// 200 on `/`.
//
// Bundle 10 of the 2026-05-02 deployment-target audit.

export function nginxHandshake() {
    const res = http.get(`${NGINX_TARGET_URL}/`, {
        tags: { scenario: 'nginx_handshake', target_type: 'nginx' },
    });
    check(res, {
        'nginx 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

export function apacheHandshake() {
    const res = http.get(`${APACHE_TARGET_URL}/`, {
        tags: { scenario: 'apache_handshake', target_type: 'apache' },
    });
    check(res, {
        'apache 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

export function haproxyHandshake() {
    const res = http.get(`${HAPROXY_TARGET_URL}/`, {
        tags: { scenario: 'haproxy_handshake', target_type: 'haproxy' },
    });
    check(res, {
        'haproxy 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

export function f5Handshake() {
    const res = http.get(`${F5_TARGET_URL}/healthz`, {
        tags: { scenario: 'f5_handshake', target_type: 'f5' },
    });
    check(res, {
        'f5 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

// handleSummary writes the full results to /results/summary.{json,txt}
// so the operator can commit the baseline numbers into README.md after
// each run and so CI can ingest the JSON for diffing.
//
// Bundle 10 added a `connector_tier` aggregation alongside the API tier
// — same source data (data.metrics), grouped by target_type tag for
// per-connector-type p50/p95/p99/error breakdowns. Operators tracking a
// connector regression diff `connector_tier.<type>` between runs.
//
// stdout reproduces the textSummary so the docker compose log shows
// the same numbers an operator running it manually would see.
export function handleSummary(data) {
    const enriched = enrichWithConnectorTier(data);
    return {
        '/results/summary.json': JSON.stringify(enriched, null, 2),
        '/results/summary.txt': textSummary(data, { indent: ' ', enableColors: false }),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}

// enrichWithConnectorTier appends a connector_tier object to the k6
// summary data. Each target_type entry contains:
//   { p50, p95, p99, max, avg, error_rate, iterations }
// Missing tags (e.g. an operator runs only the API tier scenarios) are
// reported as null so callers can detect them without a separate scan.
function enrichWithConnectorTier(data) {
    const targetTypes = ['nginx', 'apache', 'haproxy', 'f5'];
    const connectorTier = {};
    for (const t of targetTypes) {
        const reqDurKey = `http_req_duration{target_type:${t}}`;
        const reqFailKey = `http_req_failed{target_type:${t}}`;
        const iterKey = `iterations{target_type:${t}}`;

        const dur = data.metrics[reqDurKey];
        const fail = data.metrics[reqFailKey];
        const iters = data.metrics[iterKey];

        if (!dur || !dur.values) {
            connectorTier[t] = null;
            continue;
        }
        connectorTier[t] = {
            p50: dur.values['med'] ?? null,
            p95: dur.values['p(95)'] ?? null,
            p99: dur.values['p(99)'] ?? null,
            max: dur.values['max'] ?? null,
            avg: dur.values['avg'] ?? null,
            error_rate: fail && fail.values ? (fail.values['rate'] ?? null) : null,
            iterations: iters && iters.values ? (iters.values['count'] ?? null) : null,
        };
    }
    // Shallow-merge so existing summary fields (data.metrics, data.options,
    // etc.) stay untouched. The connector_tier key is additive.
    return Object.assign({}, data, { connector_tier: connectorTier });
}
