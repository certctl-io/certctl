package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Apply executes plan as one atomic deployment. See package doc and
// the Plan-type comments for the full algorithm contract; the
// summary:
//
//  1. Validate the plan shape (no empty paths, no dupes).
//  2. Per-file SHA-256 check; if every file already has identical
//     bytes and !plan.SkipIdempotent, return early with
//     SkippedAsIdempotent=true.
//  3. Lock every file path in the plan (sorted to avoid deadlocks
//     when two concurrent Applies share some paths).
//  4. Backup every existing destination.
//  5. Write every file to its sibling .certctl-tmp.<unix-nanos>;
//     apply ownership (chmod + chown) to each temp.
//  6. Call PreCommit(ctx, tempPaths). On error: clean up all temp
//     files; backups stay (operator may want to restore manually).
//     Return ErrValidateFailed.
//  7. os.Rename every temp → final, in plan-order. We don't try to
//     "rollback" a partial rename mid-loop — we trust os.Rename to
//     either succeed or fail-fast within the same filesystem; if a
//     mid-loop rename fails, we attempt rollback of the renames
//     that already succeeded.
//  8. Call PostCommit(ctx). On success: prune old backups; return.
//  9. On PostCommit error: restore each File from its backup;
//     re-call PostCommit. If second PostCommit also fails, return
//     ErrRollbackFailed (operator-actionable; deploy is in known-
//     bad state).
//
// The PreCommit/PostCommit hooks may be nil; nil = "no-op step".
func Apply(ctx context.Context, plan Plan) (*Result, error) {
	start := time.Now()

	if err := validatePlan(plan); err != nil {
		return nil, err
	}

	// Lock every path in sorted order to defend against the
	// classic AB/BA deadlock when two concurrent Applies overlap
	// in their file sets.
	absPaths := make([]string, len(plan.Files))
	for i, f := range plan.Files {
		abs, err := filepath.Abs(f.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve path %s: %w", f.Path, err)
		}
		absPaths[i] = abs
	}
	sortedPaths := append([]string(nil), absPaths...)
	sort.Strings(sortedPaths)
	unlocks := make([]func(), 0, len(sortedPaths))
	defer func() {
		// Release in reverse order. Standard mutex hygiene.
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}()
	for _, p := range sortedPaths {
		unlocks = append(unlocks, lockFile(p))
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res := &Result{
		BackupPaths: make(map[string]string, len(plan.Files)),
	}

	// 2. Idempotency short-circuit.
	if !plan.SkipIdempotent {
		allMatch := true
		for i, f := range plan.Files {
			abs := absPaths[i]
			existing, err := os.ReadFile(abs)
			if err != nil {
				allMatch = false
				break
			}
			if !sha256Eq(existing, f.Bytes) {
				allMatch = false
				break
			}
		}
		if allMatch {
			res.SkippedAsIdempotent = true
			res.Duration = time.Since(start)
			return res, nil
		}
	}

	// 3. For each file: stat existing, resolve ownership, prep
	// the per-file work plan.
	preps := make([]*filePrep, len(plan.Files))
	for i, f := range plan.Files {
		abs := absPaths[i]
		stat, statErr := os.Stat(abs)
		existed := statErr == nil
		owner, err := resolveOwnership(f, plan.Defaults, ownershipStat(stat, statErr))
		if err != nil {
			return nil, fmt.Errorf("file %d (%s): resolve ownership: %w", i, abs, err)
		}
		preps[i] = &filePrep{
			abs:     abs,
			file:    f,
			owner:   owner,
			hadOrig: existed,
		}
	}

	// 4. Backup every existing destination BEFORE writing any
	// temp file. If any backup fails, abort with no on-disk
	// changes to live files.
	if plan.BackupRetention != -1 {
		for _, p := range preps {
			if !p.hadOrig {
				res.BackupPaths[p.abs] = ""
				continue
			}
			backupPath, err := backupFile(p.abs)
			if err != nil {
				// Clean up any backups already taken.
				cleanupBackups(res.BackupPaths)
				return nil, fmt.Errorf("backup %s: %w", p.abs, err)
			}
			p.backupTo = backupPath
			res.BackupPaths[p.abs] = backupPath
		}
	}

	// 5. Write every file to a sibling temp + apply ownership.
	tempPaths := make(map[string]string, len(preps))
	cleanupTemps := func() {
		for _, p := range preps {
			if p.tempPath != "" {
				_ = os.Remove(p.tempPath)
			}
		}
	}
	for _, p := range preps {
		tempPath, err := writeTempFile(p.abs, p.file.Bytes)
		if err != nil {
			cleanupTemps()
			return nil, fmt.Errorf("write temp for %s: %w", p.abs, err)
		}
		p.tempPath = tempPath
		tempPaths[p.abs] = tempPath
		if err := applyOwnership(tempPath, p.owner); err != nil {
			cleanupTemps()
			return nil, fmt.Errorf("apply ownership to temp for %s: %w", p.abs, err)
		}
	}

	// 6. PreCommit (validate-with-the-target).
	if plan.PreCommit != nil {
		if err := plan.PreCommit(ctx, tempPaths); err != nil {
			cleanupTemps()
			return nil, fmt.Errorf("%w: %v", ErrValidateFailed, err)
		}
	}
	res.ValidateOK = true

	// 7. Atomic rename each temp → final. If a mid-loop rename
	// fails, attempt to restore the renames that already
	// succeeded (a degraded form of rollback — better than
	// leaving a half-deployed state).
	doneRenames := make([]*filePrep, 0, len(preps))
	for _, p := range preps {
		if err := os.Rename(p.tempPath, p.abs); err != nil {
			// Mid-loop rename failure. Roll back what we did.
			rollbackErr := restoreFromBackups(doneRenames)
			cleanupTemps()
			if rollbackErr != nil {
				return res, fmt.Errorf("%w: rename %s mid-loop, rollback also failed: %v (rename: %v)", ErrRollbackFailed, p.abs, rollbackErr, err)
			}
			return res, fmt.Errorf("rename %s: %w", p.abs, err)
		}
		doneRenames = append(doneRenames, p)
	}

	// 8. PostCommit (reload).
	if plan.PostCommit != nil {
		if err := plan.PostCommit(ctx); err != nil {
			// Rollback: restore + re-PostCommit.
			rollbackErr := restoreFromBackups(preps)
			if rollbackErr != nil {
				res.Duration = time.Since(start)
				return res, fmt.Errorf("%w: PostCommit failed (%v) AND rollback restore failed (%v)", ErrRollbackFailed, err, rollbackErr)
			}
			// Restore succeeded; re-call PostCommit against the
			// previous bytes. This is the second PostCommit; if
			// IT also fails, we're in operator-actionable state.
			if err2 := plan.PostCommit(ctx); err2 != nil {
				res.Duration = time.Since(start)
				return res, fmt.Errorf("%w: PostCommit failed (%v) AND second PostCommit after restore also failed (%v)", ErrRollbackFailed, err, err2)
			}
			res.RolledBack = true
			res.Duration = time.Since(start)
			return res, fmt.Errorf("%w: %v", ErrReloadFailed, err)
		}
	}
	res.Reloaded = true

	// 9. Janitor: prune backups beyond retention.
	retention := plan.BackupRetention
	if retention == 0 {
		retention = DefaultBackupRetention
	}
	if retention > 0 {
		for _, p := range preps {
			_ = pruneBackups(p.abs, retention)
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}

// validatePlan rejects malformed plans before any I/O.
func validatePlan(plan Plan) error {
	if len(plan.Files) == 0 {
		return fmt.Errorf("%w: no files", ErrPlanInvalid)
	}
	seen := make(map[string]struct{}, len(plan.Files))
	for i, f := range plan.Files {
		if f.Path == "" {
			return fmt.Errorf("%w: file %d has empty path", ErrPlanInvalid, i)
		}
		abs, err := filepath.Abs(f.Path)
		if err != nil {
			return fmt.Errorf("%w: file %d (%s): %v", ErrPlanInvalid, i, f.Path, err)
		}
		if _, dup := seen[abs]; dup {
			return fmt.Errorf("%w: duplicate destination %s", ErrPlanInvalid, abs)
		}
		seen[abs] = struct{}{}
	}
	return nil
}

// filePrep is the per-file working state for one Apply call.
// Held by Apply's slice; passed to restoreFromBackups during
// rollback.
type filePrep struct {
	abs      string
	file     File
	tempPath string
	owner    resolvedOwnership
	hadOrig  bool
	backupTo string
}

// restoreFromBackups copies each prep's backup back into place.
// Used during rollback (PostCommit failure or mid-loop rename
// failure).
func restoreFromBackups(preps []*filePrep) error {
	var firstErr error
	for _, p := range preps {
		if p.backupTo == "" {
			// File didn't exist before deploy — restore = remove.
			if err := os.Remove(p.abs); err != nil && !errors.Is(err, os.ErrNotExist) {
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		// Read backup; atomically rewrite destination via the
		// same temp + rename dance so this restore is itself
		// atomic. We DON'T call AtomicWriteFile because we want
		// to skip the per-file mutex (we already hold it from
		// the outer Apply) and skip the backup-of-the-restore
		// (we don't want a backup chain explosion).
		bytes, err := os.ReadFile(p.backupTo)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read backup %s: %w", p.backupTo, err)
			}
			continue
		}
		tempPath, err := writeTempFile(p.abs, bytes)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("write restore temp for %s: %w", p.abs, err)
			}
			continue
		}
		// Reapply original ownership (preserved from existing
		// stat at prep time).
		if err := applyOwnership(tempPath, p.owner); err != nil {
			_ = os.Remove(tempPath)
			if firstErr == nil {
				firstErr = fmt.Errorf("apply ownership during restore for %s: %w", p.abs, err)
			}
			continue
		}
		if err := os.Rename(tempPath, p.abs); err != nil {
			_ = os.Remove(tempPath)
			if firstErr == nil {
				firstErr = fmt.Errorf("rename during restore for %s: %w", p.abs, err)
			}
			continue
		}
	}
	return firstErr
}

// cleanupBackups removes a partial set of backups. Used when an
// early backup step fails — we want to leave the destination
// directory clean.
func cleanupBackups(backupPaths map[string]string) {
	for _, bp := range backupPaths {
		if bp != "" {
			_ = os.Remove(bp)
		}
	}
}
