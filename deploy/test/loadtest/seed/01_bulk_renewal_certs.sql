-- Phase 8 SCALE-H2: bulk-renewal scenario seed.
--
-- Generates 10,000 managed_certificates rows linked to the existing
-- seed_demo.sql FKs (iss-local, o-alice, t-platform, rp-standard) so
-- the bulk-renewal k6 scenario can POST /api/v1/certificates/bulk-renew
-- against a fleet-scale dataset instead of the 15-row demo seed.
--
-- Behavior:
--   - Idempotent. ON CONFLICT (name) DO NOTHING — re-running the seed
--     against an already-seeded DB is a no-op.
--   - expires_at is uniformly distributed across the next 30 days so
--     a renewal_window_days = 30 policy considers every row eligible.
--   - status = 'active' so the renewal selector treats them as
--     live (the scheduler skips status IN ('pending', 'failed',
--     'revoked', 'retired')).
--   - name is generated as 'loadtest-bulk-NNNNN.example.test' for a
--     stable, predictable identifier the k6 scenario can pattern-match
--     to scope its criteria to the seeded set (the production fleet
--     wouldn't share this prefix).
--
-- Volume target: 10,000 rows. Insert wall time on the loadtest stack
-- (postgres:16-alpine, 2 CPU / 4 GiB): typically < 5 seconds via the
-- single-statement generate_series + INSERT pattern below. The
-- compose seed-init container runs this BEFORE the k6 driver starts,
-- so the steady-state load measurement isn't affected by seed time.
--
-- Why not generated in Go via a fixtures helper:
--   - The certctl-server boots from a clean DB and runs migrations +
--     seed_demo.sql automatically when CERTCTL_DEMO_SEED=true. Adding
--     a Go-side fixtures helper would require either (a) a new
--     CERTCTL_LOADTEST_SEED flag wired into cmd/server/main.go (cross-
--     cutting change for one test path) or (b) a separate seed binary
--     (more compose surface). Raw SQL is the smallest viable change.
--
-- Phase 8 entry point — runs only when the loadtest compose stack is
-- explicitly opted into the scale-seed via LOADTEST_SCALE_SEED=true.

INSERT INTO managed_certificates (
    id,
    name,
    common_name,
    sans,
    environment,
    owner_id,
    team_id,
    issuer_id,
    renewal_policy_id,
    status,
    expires_at,
    tags,
    created_at,
    updated_at
)
SELECT
    'cert-loadtest-bulk-' || lpad(g::text, 5, '0'),
    'loadtest-bulk-' || lpad(g::text, 5, '0') || '.example.test',
    'loadtest-bulk-' || lpad(g::text, 5, '0') || '.example.test',
    ARRAY['loadtest-bulk-' || lpad(g::text, 5, '0') || '.example.test'],
    'loadtest',
    'o-alice',
    't-platform',
    'iss-local',
    'rp-standard',
    'active',
    -- Distribute expires_at uniformly across the next 30 days so a
    -- 30-day-window renewal policy sees every row as eligible.
    NOW() + ((g % 30) || ' days')::interval + ((g % 24) || ' hours')::interval,
    jsonb_build_object('source', 'loadtest-phase8', 'batch', 'bulk-renewal'),
    NOW(),
    NOW()
FROM generate_series(1, 10000) AS g
ON CONFLICT (name) DO NOTHING;

-- Confirmation row count — the seed-init container greps this in its
-- logs to verify the fleet shape post-insert. The output appears in
-- `docker compose logs certctl-loadtest-scale-seed` after the run.
DO $$
DECLARE
    cert_count integer;
BEGIN
    SELECT COUNT(*) INTO cert_count
    FROM managed_certificates
    WHERE name LIKE 'loadtest-bulk-%';
    RAISE NOTICE 'Phase 8 bulk-renewal seed: % managed_certificates rows present', cert_count;
END $$;
