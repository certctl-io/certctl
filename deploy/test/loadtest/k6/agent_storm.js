// Phase 8 SCALE-H2 — agent fleet heartbeat storm.
//
// What this measures:
//   5,000 agents heartbeating at 30s intervals = ~167 heartbeats/sec
//   sustained. Each heartbeat is POST /api/v1/agents/{id}/heartbeat
//   with optional metadata. Pre-seeded fleet provided by
//   deploy/test/loadtest/seed/02_agent_fleet.sql.
//
// What this does NOT measure:
//   - The agent work-poll path (GET /api/v1/agents/{id}/work). The
//     heartbeat hot path is the highest-frequency call on a typical
//     fleet (work-poll cadence is 30s default like heartbeat, but
//     work-poll returns the empty set 99% of the time and is cheap;
//     heartbeat does an UPDATE on every call). v2 of the harness
//     could combine them.
//   - The agent CSR-submit path (POST /api/v1/agents/{id}/csr). That
//     fires on per-cert issuance, not per heartbeat, and is exercised
//     by the existing API tier's POST /api/v1/certificates scenario.
//   - Auth-key per-agent rotation. The loadtest stack runs with a
//     single api-key (`load-test-token`); per-agent api-key
//     hashing/rotation isn't a load axis.
//
// Why constant-arrival-rate (not constant-vus):
//   The point is to model what 5K real agents would offer the server
//   at their native cadence. 5K agents * (1 heartbeat / 30s) =
//   166.67 req/s offered. constant-arrival-rate fires at exactly
//   that rate regardless of latency; if the server backpressures,
//   queue builds and p99 shows it. constant-vus would let slow
//   responses block, masking the actual ceiling.
//
// Threshold contract:
//   - p99 < 1s for the heartbeat POST. The handler does an UPDATE on
//     agents.last_heartbeat_at (+ optional metadata columns) and an
//     RBAC check. Even at 200 req/s a tight UPDATE on an indexed
//     primary key should stay sub-second.
//   - p95 < 500ms.
//   - Error rate < 0.1%. The seeded agents are all status='Online'
//     so no 410 Gone (retired-agent) responses; anything 4xx is a
//     bug. 5xx is a server health regression.
//
// Phase 8 reference:
//   - Source finding: SCALE-H2.
//   - Pre-state: heartbeat path not load-tested. The 100-agent demo
//     seed in seed_demo.sql produces ~3 heartbeats/sec, orders of
//     magnitude below fleet scale.

import http from 'k6/http';
import { check } from 'k6';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

const BASE  = __ENV.CERTCTL_BASE  || 'https://certctl-server:8443';
const TOKEN = __ENV.CERTCTL_TOKEN || 'load-test-token';

// 5000 agents * (1 / 30s) = 166.67 heartbeats/sec. Round to 167.
const TARGET_RATE = parseInt(__ENV.K6_AGENT_RATE || '167', 10);

// Total agents in the fleet seed. The k6 scenario picks an agent at
// random per iteration (deterministic via __ITER) to spread the
// per-row UPDATE pressure across the table.
const FLEET_SIZE = parseInt(__ENV.K6_AGENT_FLEET || '5000', 10);

export const options = {
    scenarios: {
        agent_storm: {
            executor: 'constant-arrival-rate',
            rate: TARGET_RATE,
            timeUnit: '1s',
            duration: '5m',
            preAllocatedVUs: 50,
            maxVUs: 200,
            exec: 'heartbeat',
            tags: { scenario: 'agent_storm' },
        },
    },
    thresholds: {
        'http_req_duration{scenario:agent_storm}': ['p(99)<1000', 'p(95)<500'],
        'http_req_failed{scenario:agent_storm}': ['rate<0.001'],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
    insecureSkipTLSVerify: true,
};

// agentID returns a deterministic agent id from the loadtest fleet
// seed. Spreading round-robin across the fleet means the UPDATE
// pressure hits every row equally rather than the same hot row over
// and over.
function agentID() {
    // __ITER is k6's per-VU iteration counter; combined with __VU
    // (the VU index) we get a unique-per-call number that spans
    // 0..FLEET_SIZE on the modulo.
    const idx = (__VU * 1000 + __ITER) % FLEET_SIZE;
    return 'ag-loadtest-' + String(idx + 1).padStart(5, '0');
}

export function heartbeat() {
    const id = agentID();
    // Optional metadata; the heartbeat handler tolerates an empty body
    // (no metadata) but real agents send their version + hostname on
    // every call so we include them here.
    const payload = JSON.stringify({
        version: '2.1.0',
        hostname: 'loadtest-' + id.slice(-5) + '.fleet.example.test',
        os: 'linux',
        architecture: 'amd64',
    });

    const res = http.post(`${BASE}/api/v1/agents/${id}/heartbeat`, payload, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${TOKEN}`,
        },
        tags: { scenario: 'agent_storm' },
    });

    check(res, {
        'heartbeat 2xx': (r) => r.status >= 200 && r.status < 300,
    });
}

export function handleSummary(data) {
    return {
        '/results/summary-agent-storm.json': JSON.stringify(data, null, 2),
        '/results/summary-agent-storm.txt': textSummary(data, { indent: ' ', enableColors: false }),
        stdout: textSummary(data, { indent: ' ', enableColors: true }),
    };
}
