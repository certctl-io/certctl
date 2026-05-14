-- Phase 8 SCALE-H2: agent-fleet heartbeat-storm scenario seed.
--
-- Generates 5,000 agents rows so the heartbeat-storm k6 scenario can
-- model a fleet-scale heartbeat pattern (5K agents heartbeating at the
-- native 30s cadence = ~167 heartbeats/sec sustained) instead of the
-- ~10-agent demo seed.
--
-- Behavior:
--   - Idempotent. ON CONFLICT (id) DO NOTHING — re-runnable against an
--     already-seeded DB.
--   - name is unique (a UNIQUE constraint in migration 000001) so the
--     name suffix mirrors the id suffix.
--   - status = 'Online' so the heartbeat handler's retire-check
--     (service.ErrAgentRetired) doesn't 410 the storm.
--   - last_heartbeat_at staggered across the prior 60 seconds so the
--     stale-agent reaper (agentHealthCheckLoop) doesn't immediately
--     flip half the fleet to 'Offline' during the first scheduler
--     tick of the load run.
--   - api_key_hash = 'loadtest_no_auth'. The loadtest compose runs
--     CERTCTL_AUTH_TYPE=api-key with a single static token
--     (load-test-token), which bypasses per-agent key check the same
--     way the existing API tier scenarios do. Production deploys with
--     CERTCTL_AUTH_TYPE=agent-key per-agent would seed real bcrypt'd
--     hashes; this column is opaque to the load-test path.
--   - registered_at = NOW() - random 1-90 day interval so agent age
--     looks realistic and any age-based query plans are exercised.
--
-- Volume target: 5,000 rows. The agents schema is much narrower than
-- managed_certificates so the insert is sub-second on the loadtest
-- stack. The 5K agents do not own any deployment_targets in this
-- fixture (the scenario only measures the heartbeat hot path, not
-- the work-poll path which depends on cert + target wiring).
--
-- Phase 8 entry point — runs only when the loadtest compose stack is
-- explicitly opted into the scale-seed via LOADTEST_SCALE_SEED=true.

INSERT INTO agents (
    id,
    name,
    hostname,
    status,
    last_heartbeat_at,
    registered_at,
    api_key_hash,
    os,
    architecture,
    ip_address,
    version
)
SELECT
    'ag-loadtest-' || lpad(g::text, 5, '0'),
    'loadtest-agent-' || lpad(g::text, 5, '0'),
    'loadtest-' || lpad(g::text, 5, '0') || '.fleet.example.test',
    'Online',
    -- Stagger last_heartbeat_at across the prior 60 seconds (= 2x the
    -- agent's native poll interval) so the first wave of incoming
    -- heartbeats doesn't all arrive in lockstep at t=0.
    NOW() - ((g % 60) || ' seconds')::interval,
    -- Registered_at randomized 1-90 days back.
    NOW() - ((g % 90 + 1) || ' days')::interval,
    'loadtest_no_auth',
    -- Mix linux/windows/darwin so the OS distribution column in the
    -- agents page isn't pure-linux during the storm.
    CASE (g % 10)
        WHEN 0 THEN 'windows'
        WHEN 1 THEN 'darwin'
        ELSE 'linux'
    END,
    -- amd64 dominates; arm64 minority.
    CASE WHEN (g % 5) = 0 THEN 'arm64' ELSE 'amd64' END,
    -- IPv4 in the 10.42.0.0/16 fleet range, deterministic per id.
    '10.42.' || ((g / 256) % 256)::text || '.' || (g % 256)::text,
    '2.1.0'
FROM generate_series(1, 5000) AS g
ON CONFLICT (id) DO NOTHING;

DO $$
DECLARE
    agent_count integer;
BEGIN
    SELECT COUNT(*) INTO agent_count
    FROM agents
    WHERE id LIKE 'ag-loadtest-%';
    RAISE NOTICE 'Phase 8 agent-storm seed: % agents rows present', agent_count;
END $$;
