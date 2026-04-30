// Package deploy provides the shared atomic-write + validate + rollback
// primitive consumed by every target connector under
// internal/connector/target/*.
//
// The deploy package closes the three procurement-checklist items where
// commercial competitors (Venafi, DigiCert Certificate Manager, Sectigo)
// historically beat certctl on a head-to-head deployment-grade
// comparison:
//
//  1. Atomic deploy with rollback — every file write is "all or nothing".
//     A connector can never leave a target in a half-deployed state where
//     the cert is updated but the chain isn't (or vice versa). Ships via
//     Plan + Apply: temp-write all files together, run validate, atomic
//     rename them all, run reload; on reload failure restore previous
//     bytes + reload again.
//  2. Post-deploy TLS verification — the Apply caller wires its own
//     PostCommit to do a TLS handshake against the target endpoint and
//     compare the leaf-cert SHA-256 against what was just written. The
//     deploy package surfaces the rollback wire when PostCommit fails;
//     the connector decides what failure means.
//  3. (Vendor-specific deployment recipes — out of scope for the deploy
//     package; covered in Bundle II.)
//
// Design tenets — all load-bearing for 13 connectors:
//
//   - All-or-nothing across files. A Plan with N File entries either
//     succeeds for all N or rolls back all N. No "two of three written"
//     intermediate states are possible from a successful or failed Apply.
//   - Cross-filesystem safety. Temp files always live in the same
//     directory as the final destination, so os.Rename is guaranteed
//     atomic on POSIX (a rename within the same filesystem). Writing
//     temp files in /tmp would silently fall back to copy-and-rename
//     across filesystems, breaking atomicity.
//   - Idempotency. If every File's destination already has identical
//     bytes (SHA-256 match), Apply returns SkippedAsIdempotent=true and
//     calls neither PreCommit nor PostCommit. Defends against agent
//     restart retry storms that would otherwise hammer the target with
//     no-op reloads.
//   - Ownership + mode preservation. The single most common
//     silent-failure mode in cert deploys is the agent running as root
//     calling os.WriteFile(path, bytes, 0600), which clobbers the
//     existing nginx:nginx 0640 ownership and locks NGINX out of the
//     key file. Apply preserves the existing destination's
//     owner+group+mode unless the per-target config overrides; for new
//     files it falls back to per-target-type defaults (e.g. nginx:nginx
//     0640).
//   - Per-file serialization. The package keeps a sync.Map of file-level
//     mutexes so two concurrent Apply calls touching the same path
//     serialize. (Per-target serialization is Phase 2's job in the
//     agent dispatch; this is a finer-grained file-level guard.)
//   - Backup retention. Each successful write copies the previous bytes
//     to <path>.certctl-bak.<unix-nanos>. A janitor prunes to the last
//     N backups (default 3, configurable via Plan.BackupRetention or
//     the CERTCTL_DEPLOY_BACKUP_RETENTION env var the agent passes in).
//     Setting retention to 0 disables backups entirely — rollback
//     becomes impossible; documented as a foot-gun.
//
// Origin: this package was created in the deploy-hardening I master
// bundle (Phase 1) as the load-bearing replacement for the duplicated
// os.WriteFile flows in 13 connectors. The Apply API mirrors the F5
// transaction model already at internal/connector/target/f5/f5.go:267
// — F5 was the only connector with rollback semantics before this
// bundle. Apply lifts that pattern up so every other connector gets
// the same atomicity bar without re-implementing it.
//
// Concurrency: every exported function is safe for concurrent callers.
// File-level serialization is automatic via the package-internal
// sync.Map of mutexes; callers do not need their own per-file lock.
package deploy
