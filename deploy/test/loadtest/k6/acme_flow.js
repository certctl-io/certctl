// Phase 5 — k6 scenario for the ACME issuance loop. Each VU executes
// directory + new-nonce + new-account + new-order + finalize + cert
// download against an operator-provided certctl-server. Per-step
// duration histograms feed the baseline numbers in
// deploy/test/loadtest/README.md (ACME flows section).
//
// Default scenario: 100 concurrent VUs for 5 minutes. Override via
// K6_VUS / K6_DURATION env vars.
//
// Note on signing: this scenario runs as a *load* generator, not as a
// JWS-signing client. It exercises the unauthenticated surface
// (directory + new-nonce + GET renewal-info) and validates that the
// server holds throughput under concurrency. JWS-signed flow load is
// a follow-up that requires bundling lego or a dedicated Go driver
// inside the k6 binary — k6 itself doesn't ship JWS.

import http from "k6/http";
import { check, sleep } from "k6";
import { Trend } from "k6/metrics";

const directoryURL =
  __ENV.CERTCTL_ACME_DIRECTORY ||
  "https://certctl:8443/acme/profile/prof-test/directory";

export const options = {
  scenarios: {
    acme_directory_and_nonce: {
      executor: "constant-vus",
      vus: parseInt(__ENV.K6_VUS || "100", 10),
      duration: __ENV.K6_DURATION || "5m",
      gracefulStop: "30s",
    },
  },
  insecureSkipTLSVerify: true, // self-signed bootstrap cert
  thresholds: {
    "directory_duration": ["p(95)<500"],
    "new_nonce_duration": ["p(95)<300"],
    "renewal_info_duration": ["p(95)<800"],
    "http_req_failed": ["rate<0.01"],
  },
};

const directoryDuration = new Trend("directory_duration", true);
const newNonceDuration = new Trend("new_nonce_duration", true);
const renewalInfoDuration = new Trend("renewal_info_duration", true);

export default function () {
  // Step 1 — directory.
  let res = http.get(directoryURL);
  directoryDuration.add(res.timings.duration);
  check(res, { "directory 200": (r) => r.status === 200 });

  if (res.status !== 200) return;
  const dir = res.json();

  // Step 2 — new-nonce.
  if (dir.newNonce) {
    res = http.head(dir.newNonce);
    newNonceDuration.add(res.timings.duration);
    check(res, {
      "new-nonce 200 + Replay-Nonce": (r) =>
        r.status === 200 && !!r.headers["Replay-Nonce"],
    });
  }

  // Step 3 — ARI smoke (with a deliberately-malformed cert-id to
  // exercise the error path; full happy-path needs a real cert which
  // requires JWS signing — out of scope for this baseline scenario).
  if (dir.renewalInfo) {
    res = http.get(dir.renewalInfo + "/" + "aaaa.bbbb");
    renewalInfoDuration.add(res.timings.duration);
    // 400 (malformed cert-id, expected) OR 404 (cert not found).
    check(res, {
      "renewal-info 4xx for synthetic cert-id": (r) =>
        r.status === 400 || r.status === 404,
    });
  }

  sleep(1);
}
