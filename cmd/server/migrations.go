// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"database/sql"
	"log/slog"
	"os"
	"strings"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// Phase 9 ARCH-M2 closure Sprint 8b (2026-05-14): the deferred half of
// Sprint 8. Extracts the boot-time migration handling from main()'s
// inline body into two unexported helpers. Different shape from
// Sprints 1-7 (data-type relocation) and from Sprint 8a (existing
// helper-function relocation) — this sprint crosses the
// behavior-change boundary Sprint 8 first identified.
//
// What lives here
// ===============
//   parseMigrateOnlyFlag() bool
//     Hand-parses os.Args for `--migrate-only` (NOT flag.Parse — the
//     server's config surface is otherwise env-var driven via
//     config.Load; introducing flag.Parse's global state risks
//     conflicting with other binaries that may import cmd/server later).
//
//   runBootMigrations(cfg, db, logger, migrateOnly) (exitNow bool)
//     Owns the Phase 4 DEPL-M1 migration-via-hook posture: the
//     migrationsViaHook env-var read, the RunMigrations + RunSeed
//     gate, the --migrate-only early-exit signal, and the
//     CERTCTL_DEMO_SEED demo-overlay branch.
//
//     Returns true ONLY when --migrate-only was set and migrations +
//     seed completed cleanly. The caller (main) translates that to
//     `return` rather than os.Exit(0) — which is the SOLE intentional
//     behavior change in this sprint (see below).
//
// Behavior preservation contract
// ==============================
// Every error path inside runBootMigrations calls os.Exit(1)
// directly, matching the original inline behavior byte-for-byte
// (same log message, same exit code, same no-defer-run-on-fatal
// semantics). The error-path os.Exit(1) is intentional: when
// migration fails at boot, the server cannot recover, and bailing
// out without running defers is the original Go-idiomatic shape.
//
// The ONE behavior change: the --migrate-only SUCCESS path now
// returns to main() rather than calling os.Exit(0) inline. This
// has one observable effect: the `defer db.Close()` registered in
// main() now runs at clean exit instead of being skipped. That's
// strictly better hygiene (clean DB connection shutdown vs OS
// reclaim). The migration work is synchronous + complete before
// the return; nothing async is left running that db.Close() could
// truncate.
//
// All other paths — the migration log messages, the seed log
// messages, the migrationsViaHook env-var read order, the
// RunDemoSeed gating, the per-step success/skip log lines — are
// byte-identical to the pre-Sprint-8b inline form. Verified via
// `go test ./cmd/server/... -count=1 -short` (which runs the
// existing main_test.go assertions through the new call site).
//
// Why this is a separate commit
// =============================
// Sprint 8a (commit see git log) extracted the bottom-of-file
// helpers + adapter types — pure mechanical relocation that
// couldn't change runtime semantics. Sprint 8b crosses the boundary
// where mechanical relocation ends: introducing a new function
// call frame changes defer scope, panic recovery, and (in this
// case) the exit semantics for the --migrate-only path. The
// Phase 9 prompt's "refactor is mechanical relocation; behavior
// change is a separate concern" rule guards against exactly this
// shape of risk being landed without a focused review.
//
// Splitting Sprint 8a (mechanical) from Sprint 8b (behavior-aware)
// means the operator's git log shows:
//   3f1344e8 ... wire.go         — no behavior change possible
//   <this>   ... migrations.go    — one specific behavior shift,
//                                   documented + intentional
//
// Anyone bisecting a future bug to one of these two commits gets a
// clean "is it mechanical or did the behavior change" signal.

// parseMigrateOnlyFlag scans os.Args for the `--migrate-only` token
// and returns true if found. Hand-parsed instead of using flag.Parse
// because:
//
//  1. The server's entire config surface is env-var driven via
//     config.Load(). flag.Parse() introduces a global package-state
//     dependency that future binaries importing cmd/server (test
//     harnesses, CLI tools, embedded variants) would have to
//     coordinate around.
//  2. The only flag we care about is the migration-vs-server-lifecycle
//     toggle; a hand-parser is 6 lines and has no transitive cost.
//  3. The flag is Helm-pre-install-hook-facing (see
//     deploy/helm/certctl/templates/migration-job.yaml). Its shape is
//     pinned by that template, not by anything else; we don't need
//     flag.Parse's auto-help generation or type coercion.
//
// Bare arg match — no `=` value form, no short alias, no override
// from env. Anyone passing `--migrate-only` ANYWHERE in os.Args[1:]
// flips the flag on. Matches the original inline behavior exactly.
func parseMigrateOnlyFlag() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--migrate-only" {
			return true
		}
	}
	return false
}

// runBootMigrations owns the Phase 4 DEPL-M1 boot-time migration
// posture. Three lifecycles to support:
//
//	(a) Compose / VM / bare-metal: server runs migrations at boot.
//	    Default behavior — preserved unchanged.
//	(b) Helm with pre-install/pre-upgrade hook: the migration Job
//	    runs `certctl-server --migrate-only`, does its work, and
//	    exits. The server Deployment's pods then start with
//	    CERTCTL_MIGRATIONS_VIA_HOOK=true set; they see the env
//	    var and skip their boot-time RunMigrations call so the
//	    Job's work isn't duplicated.
//	(c) Bare `certctl-server --migrate-only` invocation (e.g.
//	    operator running a one-shot migration from the CLI):
//	    runs migrations + seed and returns true so main returns
//	    cleanly without starting the HTTP listener / scheduler /
//	    signing setup.
//
// migrateOnly captures case (c); CERTCTL_MIGRATIONS_VIA_HOOK
// captures case (b). Both paths converge on the same RunMigrations
// + RunSeed code below.
//
// Returns true ONLY when migrateOnly is set; caller (main) handles
// the clean exit via `return` so deferred cleanup (db.Close) runs.
// Returns false in every other case — caller continues normal boot.
// On any migration / seed error: os.Exit(1) inline (matches the
// pre-extraction shape; recovery is not possible at this boot
// stage).
func runBootMigrations(cfg *config.Config, db *sql.DB, logger *slog.Logger, migrateOnly bool) bool {
	migrationsViaHook := strings.EqualFold(os.Getenv("CERTCTL_MIGRATIONS_VIA_HOOK"), "true")

	if migrateOnly || !migrationsViaHook {
		logger.Info("running migrations", "path", cfg.Database.MigrationsPath)
		if err := postgres.RunMigrations(db, cfg.Database.MigrationsPath); err != nil {
			logger.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
		logger.Info("migrations completed")
	} else {
		logger.Info("skipping migrations at boot (CERTCTL_MIGRATIONS_VIA_HOOK=true — Helm pre-install/pre-upgrade hook owns this work)")
	}

	// Apply baseline seed data.
	//
	// U-3 (P1, cat-u-seed_initdb_schema_drift): pre-U-3 seed.sql was mounted
	// into postgres `/docker-entrypoint-initdb.d/` alongside a hand-curated
	// subset of migrations. Adding a migration that introduced a new column
	// referenced by seed.sql (cat-o-retry_interval_unit_mismatch /
	// policy_rules.severity / etc.) without also updating the compose volume
	// mounts caused initdb to crash on first up. Post-U-3 the compose stack
	// drops all initdb mounts; postgres comes up with empty schema, the
	// server runs RunMigrations above, then this RunSeed call lands the
	// baseline data — all from a single source of truth (this binary).
	// See internal/repository/postgres/db.go::RunSeed for the contract.
	//
	// Phase 4 DEPL-M1: same migration-via-hook gating as RunMigrations.
	// When the hook owns migrations it also owns the seed pass.
	if migrateOnly || !migrationsViaHook {
		logger.Info("applying baseline seed", "path", cfg.Database.MigrationsPath)
		if err := postgres.RunSeed(db, cfg.Database.MigrationsPath); err != nil {
			logger.Error("failed to apply seed data", "error", err)
			os.Exit(1)
		}
		logger.Info("seed completed")
	} else {
		logger.Info("skipping baseline seed at boot (CERTCTL_MIGRATIONS_VIA_HOOK=true — hook applies seed alongside migrations)")
	}

	// Phase 4 DEPL-M1: --migrate-only early-exit. Migrations + seed are
	// done; the operator only asked for the migration pass. Signal main
	// to return cleanly so deferred db.Close runs (Sprint 8b improvement
	// over the pre-extraction os.Exit(0) which skipped defers).
	if migrateOnly {
		logger.Info("--migrate-only: migrations + seed complete; exiting without starting server lifecycle")
		return true
	}

	// Apply demo overlay seed when CERTCTL_DEMO_SEED=true. Pre-U-3 the demo
	// overlay (deploy/docker-compose.demo.yml) mounted seed_demo.sql into
	// postgres `/docker-entrypoint-initdb.d/`; that broke once U-3 dropped
	// the initdb migration mounts (the demo seed references tables that
	// wouldn't exist at initdb time). The runtime path here is the
	// post-U-3 replacement. Default-off so a vanilla deploy never lands
	// fake-history rows. See postgres.RunDemoSeed for the contract.
	if cfg.Database.DemoSeed {
		logger.Info("applying demo seed (CERTCTL_DEMO_SEED=true)", "path", cfg.Database.MigrationsPath)
		if err := postgres.RunDemoSeed(db, cfg.Database.MigrationsPath); err != nil {
			logger.Error("failed to apply demo seed data", "error", err)
			os.Exit(1)
		}
		logger.Info("demo seed completed")
	}

	return false
}
