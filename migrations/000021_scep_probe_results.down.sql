-- Down migration for 000021_scep_probe_results.

DROP INDEX IF EXISTS idx_scep_probe_results_target_url;
DROP INDEX IF EXISTS idx_scep_probe_results_probed_at;
DROP TABLE IF EXISTS scep_probe_results;
