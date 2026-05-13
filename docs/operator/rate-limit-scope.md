# Rate-Limit Scope

> Last reviewed: 2026-05-13

How certctl's rate limiters behave under multi-replica and restart, and where the boundaries are. Closes Bundle 4 audit findings **MED-1** (process-local rate limits) and **MED-2** (rate-limit semantics across replicas).

## TL;DR

Every rate limiter in certctl is **process-local**: in-memory `sync.Mutex`-guarded maps in the `internal/ratelimit` package. The effective rate-limit across an N-replica deployment is **N × the configured per-replica limit**. Limiter state is lost on restart — no persistent ledger, no shared store. This is intentional for v2.1.0 and documented; shared rate limits across replicas (via Redis or a Postgres-backed token bucket) is a v3 work item tracked in `WORKSPACE-ROADMAP.md`.

## Limiter inventory

The shared primitive lives at `internal/ratelimit/sliding_window.go::SlidingWindowLimiter`. It's a sliding-window log algorithm (each key holds timestamps within the configured window; on `Allow` the bucket prunes timestamps older than `now - window` and admits or rejects based on the post-prune count).

Five call sites exercise it across `cmd/server/main.go`:

| Call site | Key | Window | Cap | What it protects |
|---|---|---|---|---|
| `ocspLimiter` | source IP | 1 minute | `CERTCTL_OCSP_RATE_LIMIT_PER_IP_MIN` (default 1000) | RFC 6960 OCSP responder against scan amplification. |
| `exportLimiter` | actor ID | 1 hour | `CERTCTL_CERT_EXPORT_RATE_LIMIT_PER_ACTOR_HR` (default 50) | `/api/v1/certificates/{id}/export` bulk-cert-pull abuse. |
| EST per-principal | CN | 24 hours | per-profile `RateLimitPerPrincipal24h` | EST RFC 7030 device enrollment abuse. |
| EST failed-auth | source IP | 1 hour | 10 attempts | EST HTTP-Basic brute force. |
| Intune dispatcher | (Subject, Issuer) | 24 hours | per-profile `PerDeviceRateLimit24h` | SCEP + Intune duplicate-enrollment cap. |

The HTTP middleware rate-limiter (`internal/api/middleware/middleware.go::RateLimitConfig`, knobs `CERTCTL_RATE_LIMIT_RPS` + `CERTCTL_RATE_LIMIT_BURST`) is a separate token-bucket implementation but follows the same process-local scope.

## What is in scope

- **Per-process abuse mitigation**. A scanner hitting one replica's OCSP responder at 5000 rps gets dropped to 1000 rps by `ocspLimiter`. A compromised API key trying to bulk-export 1000 certs in an hour against one replica gets dropped to 50.
- **Bounded memory footprint**. Each limiter caps its key-tracking map at the size passed to `NewSlidingWindowLimiter` (50 000 for OCSP/export, 100 000 for EST/Intune per-device). The at-cap eviction janitor drops the oldest entry by newest-timestamp so a key explosion (random source IPs from a botnet, random CNs from a misconfigured fleet) never bloats memory.
- **Restart safety**. The sliding-window state is per-process in-memory. On a server restart the limiter state resets — any attacker who'd burned through their window cap before the restart gets a fresh window after. Conversely, a legitimate caller that had hit their cap right before a restart gets immediately unblocked. Both directions are intentional: we don't ship a persistent state store, so the post-restart state is "fresh start".

## What is NOT in scope

- **Shared limits across replicas**. With `server.replicas: N`, an attacker hitting all replicas in parallel gets N × the per-replica cap. For the default OCSP knob (1000 rps per IP per minute) at N=3, that's 3000 rps per IP per minute before any single replica drops the traffic. The chart's default is N=1; operators running multi-replica should multiply published per-replica caps by the replica count to get the cluster-wide effective cap.
- **Cross-restart persistence**. See "Restart safety" above — this is by-design but operators need to know.
- **First-party (`Authorization: Bearer ...`) request rate-limit cohesion across replicas**. The middleware-level RPS/burst rate-limit (`CERTCTL_RATE_LIMIT_RPS`) is also process-local. At N=3 replicas with default `RPS=50, Burst=100`, the effective cluster-wide rate is 150 rps with 300 burst.

## Operator guidance

**Single-replica deployments** (Helm chart default `server.replicas: 1`): published caps are the effective caps. No mental math.

**Multi-replica deployments**: multiply every published cap by `server.replicas` to get the effective per-key cap. If your threat model needs strict cluster-wide rate limits (e.g., SOC 2 control mapping that quotes "≤ 1000 OCSP requests per IP per minute"), one of:

1. **Pin to single replica** and scale vertically. The default v2.1.0 posture; works for substantial fleets.
2. **Front the cluster with a rate-limited gateway** (NGINX `limit_req_zone`, Envoy global rate-limit service, Cloudflare WAF Bypass rules) and treat the cluster-internal limiter as defense-in-depth.
3. **Wait for the v3 shared-rate-limit work** (tracked in WORKSPACE-ROADMAP.md). Likely Redis or Postgres-backed token-bucket plumbed through the same `internal/ratelimit` package so call sites stay unchanged.

## Source-of-truth references

- Shared primitive: `internal/ratelimit/sliding_window.go` (the package comment at the top is the canonical algorithm + concurrency reference).
- Middleware rate limiter: `internal/api/middleware/middleware.go::RateLimitConfig`.
- Call sites: `grep -n "ratelimit.NewSlidingWindowLimiter\|RateLimitConfig" cmd/server/main.go`.
- Configuration knobs: `docs/reference/configuration.md` (search "rate limit").
