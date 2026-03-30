-- =============================================================================
-- Comprehensive Referential Integrity Check for seed_demo.sql
-- Run AFTER migrations and seed data are loaded
-- =============================================================================

-- 1. Verify certificate_versions.certificate_id references valid managed_certificates.id
SELECT 'FK VIOLATION: certificate_versions.certificate_id' AS issue, cv.id, cv.certificate_id
FROM certificate_versions cv
WHERE cv.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY cv.id;

-- 2. Verify certificate_target_mappings references valid IDs
SELECT 'FK VIOLATION: certificate_target_mappings.certificate_id' AS issue, ctm.certificate_id
FROM certificate_target_mappings ctm
WHERE ctm.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY ctm.certificate_id;

SELECT 'FK VIOLATION: certificate_target_mappings.target_id' AS issue, ctm.target_id
FROM certificate_target_mappings ctm
WHERE ctm.target_id NOT IN (SELECT id FROM deployment_targets)
ORDER BY ctm.target_id;

-- 3. Verify jobs references valid IDs
SELECT 'FK VIOLATION: jobs.certificate_id' AS issue, j.id, j.certificate_id
FROM jobs j
WHERE j.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY j.id;

SELECT 'FK VIOLATION: jobs.target_id' AS issue, j.id, j.target_id
FROM jobs j
WHERE j.target_id IS NOT NULL AND j.target_id NOT IN (SELECT id FROM deployment_targets)
ORDER BY j.id;

SELECT 'FK VIOLATION: jobs.agent_id' AS issue, j.id, j.agent_id
FROM jobs j
WHERE j.agent_id NOT IN (SELECT id FROM agents)
ORDER BY j.id;

-- 4. Verify discovered_certificates references valid IDs
SELECT 'FK VIOLATION: discovered_certificates.agent_id' AS issue, dc.id, dc.agent_id
FROM discovered_certificates dc
WHERE dc.agent_id NOT IN (SELECT id FROM agents)
ORDER BY dc.id;

SELECT 'FK VIOLATION: discovered_certificates.discovery_scan_id' AS issue, dc.id, dc.discovery_scan_id
FROM discovered_certificates dc
WHERE dc.discovery_scan_id IS NOT NULL AND dc.discovery_scan_id NOT IN (SELECT id FROM discovery_scans)
ORDER BY dc.id;

-- 5. Verify notification_events references valid certificate_id
SELECT 'FK VIOLATION: notification_events.certificate_id' AS issue, ne.id, ne.certificate_id
FROM notification_events ne
WHERE ne.certificate_id IS NOT NULL AND ne.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY ne.id;

-- 6. Verify policy_violations references valid certificate_id
SELECT 'FK VIOLATION: policy_violations.certificate_id' AS issue, pv.id, pv.certificate_id
FROM policy_violations pv
WHERE pv.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY pv.id;

-- 7. Verify certificate_revocations references valid IDs
SELECT 'FK VIOLATION: certificate_revocations.certificate_id' AS issue, cr.id, cr.certificate_id
FROM certificate_revocations cr
WHERE cr.certificate_id NOT IN (SELECT id FROM managed_certificates)
ORDER BY cr.id;

SELECT 'FK VIOLATION: certificate_revocations.issuer_id' AS issue, cr.id, cr.issuer_id
FROM certificate_revocations cr
WHERE cr.issuer_id NOT IN (SELECT id FROM issuers)
ORDER BY cr.id;

-- 8. Verify agent_group_members references valid IDs
SELECT 'FK VIOLATION: agent_group_members.agent_group_id' AS issue, agm.agent_group_id
FROM agent_group_members agm
WHERE agm.agent_group_id NOT IN (SELECT id FROM agent_groups)
ORDER BY agm.agent_group_id;

SELECT 'FK VIOLATION: agent_group_members.agent_id' AS issue, agm.agent_id
FROM agent_group_members agm
WHERE agm.agent_id NOT IN (SELECT id FROM agents)
ORDER BY agm.agent_id;

-- 9. Verify owners.team_id references valid teams.id
SELECT 'FK VIOLATION: owners.team_id' AS issue, o.id, o.team_id
FROM owners o
WHERE o.team_id IS NOT NULL AND o.team_id NOT IN (SELECT id FROM teams)
ORDER BY o.id;

-- 10. Verify deployment_targets.agent_id references valid agents.id
SELECT 'FK VIOLATION: deployment_targets.agent_id' AS issue, dt.id, dt.agent_id
FROM deployment_targets dt
WHERE dt.agent_id NOT IN (SELECT id FROM agents)
ORDER BY dt.id;

-- 11. Verify managed_certificates FK columns
SELECT 'FK VIOLATION: managed_certificates.owner_id' AS issue, mc.id, mc.owner_id
FROM managed_certificates mc
WHERE mc.owner_id IS NOT NULL AND mc.owner_id NOT IN (SELECT id FROM owners)
ORDER BY mc.id;

SELECT 'FK VIOLATION: managed_certificates.team_id' AS issue, mc.id, mc.team_id
FROM managed_certificates mc
WHERE mc.team_id IS NOT NULL AND mc.team_id NOT IN (SELECT id FROM teams)
ORDER BY mc.id;

SELECT 'FK VIOLATION: managed_certificates.issuer_id' AS issue, mc.id, mc.issuer_id
FROM managed_certificates mc
WHERE mc.issuer_id NOT IN (SELECT id FROM issuers)
ORDER BY mc.id;

SELECT 'FK VIOLATION: managed_certificates.renewal_policy_id' AS issue, mc.id, mc.renewal_policy_id
FROM managed_certificates mc
WHERE mc.renewal_policy_id IS NOT NULL AND mc.renewal_policy_id NOT IN (SELECT id FROM renewal_policies)
ORDER BY mc.id;

-- 12. Check for duplicate primary keys
SELECT 'DUPLICATE PK: teams' AS issue, id, COUNT(*) as count
FROM teams GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: owners' AS issue, id, COUNT(*) as count
FROM owners GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: agents' AS issue, id, COUNT(*) as count
FROM agents GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: deployment_targets' AS issue, id, COUNT(*) as count
FROM deployment_targets GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: managed_certificates' AS issue, id, COUNT(*) as count
FROM managed_certificates GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: certificate_versions' AS issue, id, COUNT(*) as count
FROM certificate_versions GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: issuers' AS issue, id, COUNT(*) as count
FROM issuers GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: renewal_policies' AS issue, id, COUNT(*) as count
FROM renewal_policies GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: jobs' AS issue, id, COUNT(*) as count
FROM jobs GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: certificate_profiles' AS issue, id, COUNT(*) as count
FROM certificate_profiles GROUP BY id HAVING COUNT(*) > 1;

SELECT 'DUPLICATE PK: certificate_revocations' AS issue, id, COUNT(*) as count
FROM certificate_revocations GROUP BY id HAVING COUNT(*) > 1;

-- 13. Check fingerprint_sha256 uniqueness in certificate_versions
SELECT 'DUPLICATE FINGERPRINT: certificate_versions' AS issue, fingerprint_sha256, COUNT(*) as count
FROM certificate_versions
WHERE fingerprint_sha256 IS NOT NULL
GROUP BY fingerprint_sha256
HAVING COUNT(*) > 1;

-- 14. Check serial number uniqueness in certificate_versions
SELECT 'DUPLICATE SERIAL: certificate_versions' AS issue, serial_number, COUNT(*) as count
FROM certificate_versions
WHERE serial_number IS NOT NULL
GROUP BY serial_number
HAVING COUNT(*) > 1;

-- 15. Verify discovery_scan_id references are valid
SELECT 'FK VIOLATION: discovered_certificates.discovery_scan_id references' AS issue,
  dc.id, dc.discovery_scan_id, ds.id
FROM discovered_certificates dc
LEFT JOIN discovery_scans ds ON dc.discovery_scan_id = ds.id
WHERE dc.discovery_scan_id IS NOT NULL AND ds.id IS NULL;

-- Summary: Count total records
SELECT 'SUMMARY: teams' AS table_name, COUNT(*) as count FROM teams UNION ALL
SELECT 'SUMMARY: owners', COUNT(*) FROM owners UNION ALL
SELECT 'SUMMARY: agents', COUNT(*) FROM agents UNION ALL
SELECT 'SUMMARY: deployment_targets', COUNT(*) FROM deployment_targets UNION ALL
SELECT 'SUMMARY: managed_certificates', COUNT(*) FROM managed_certificates UNION ALL
SELECT 'SUMMARY: certificate_versions', COUNT(*) FROM certificate_versions UNION ALL
SELECT 'SUMMARY: certificate_target_mappings', COUNT(*) FROM certificate_target_mappings UNION ALL
SELECT 'SUMMARY: issuers', COUNT(*) FROM issuers UNION ALL
SELECT 'SUMMARY: renewal_policies', COUNT(*) FROM renewal_policies UNION ALL
SELECT 'SUMMARY: jobs', COUNT(*) FROM jobs UNION ALL
SELECT 'SUMMARY: certificate_profiles', COUNT(*) FROM certificate_profiles UNION ALL
SELECT 'SUMMARY: certificate_revocations', COUNT(*) FROM certificate_revocations UNION ALL
SELECT 'SUMMARY: audit_events', COUNT(*) FROM audit_events UNION ALL
SELECT 'SUMMARY: discovery_scans', COUNT(*) FROM discovery_scans UNION ALL
SELECT 'SUMMARY: discovered_certificates', COUNT(*) FROM discovered_certificates;
