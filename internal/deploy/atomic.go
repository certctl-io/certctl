package deploy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// fileMutexes serializes concurrent Apply / AtomicWriteFile calls
// against the same destination path. Coarse-grained file-level lock
// — sufficient for cert deploy throughput (operator-grade tens per
// minute, not high-throughput).
//
// Per-target serialization (Phase 2) is a separate concern at the
// agent dispatch layer; this file-level lock defends against
// accidental same-path racing within a single connector pipeline.
var fileMutexes sync.Map // map[string]*sync.Mutex

func lockFile(path string) func() {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	v, _ := fileMutexes.LoadOrStore(abs, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// AtomicWriteFile writes data to path atomically.
//
// Algorithm:
//
//  1. Acquire the package-internal file-level mutex for path.
//  2. SHA-256 short-circuit: if path exists and has identical bytes
//     and !opts.SkipIdempotent, return WriteResult{Idempotent: true}
//     with no I/O.
//  3. Resolve final ownership (mode/uid/gid) per the precedence in
//     resolveOwnership.
//  4. Write to <path>.certctl-tmp.<unix-nanos> in filepath.Dir(path)
//     (same-filesystem guarantees os.Rename atomicity).
//  5. fsync the temp file (durability across power loss).
//  6. Apply chmod / chown to the temp file BEFORE rename (so the
//     atomic-rename atomically swaps in a fully-permissioned file).
//  7. Backup the existing destination to
//     <path>.certctl-bak.<unix-nanos> (skipped when destination did
//     not exist OR opts.BackupRetention == -1).
//  8. os.Rename(temp, path) — atomic on POSIX same-filesystem.
//  9. Janitor pass: prune backups beyond retention.
//
// Returns ErrPlanInvalid for malformed inputs (empty path, empty
// data + nil-with-existing-file ambiguity is preserved — empty
// data writes an empty file).
func AtomicWriteFile(ctx context.Context, path string, data []byte, opts WriteOptions) (*WriteResult, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrPlanInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	unlock := lockFile(abs)
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res := &WriteResult{Path: abs}

	// 2. Idempotency check.
	existingStat, statErr := os.Stat(abs)
	existed := statErr == nil
	if existed && !opts.SkipIdempotent {
		existingBytes, err := os.ReadFile(abs)
		if err == nil && sha256Eq(existingBytes, data) {
			res.Idempotent = true
			return res, nil
		}
	}

	// 3. Resolve ownership.
	owner, err := resolveOwnership(File{
		Path:  abs,
		Bytes: data,
		Mode:  opts.Mode,
		Owner: opts.Owner,
		Group: opts.Group,
	}, FileDefaults{
		Mode:  opts.DefaultMode,
		Owner: opts.DefaultOwner,
		Group: opts.DefaultGroup,
	}, ownershipStat(existingStat, statErr))
	if err != nil {
		return nil, fmt.Errorf("resolve ownership: %w", err)
	}

	// 4. Write to temp in same dir.
	tempPath, err := writeTempFile(abs, data)
	if err != nil {
		return nil, fmt.Errorf("write temp: %w", err)
	}
	tempCleanup := func() { _ = os.Remove(tempPath) }
	defer func() {
		// On any error path we want to remove the temp file. Successful
		// rename moves it away, so this remove is a no-op on success.
		// We don't care about the error from the cleanup.
		tempCleanup()
	}()

	// 5. Apply ownership to temp BEFORE rename so the rename
	// atomically swaps in a properly-permissioned file (no
	// brief window where the destination has wrong perms).
	if err := applyOwnership(tempPath, owner); err != nil {
		return nil, fmt.Errorf("apply ownership to temp: %w", err)
	}

	// 6. Backup existing destination.
	if existed && opts.BackupRetention != -1 {
		backupPath, err := backupFile(abs)
		if err != nil {
			return nil, fmt.Errorf("backup existing: %w", err)
		}
		res.BackupPath = backupPath
	}

	// 7. Atomic rename. On the rare case Rename fails after backup,
	// we leave the backup in place (operator can manually restore).
	if err := os.Rename(tempPath, abs); err != nil {
		return nil, fmt.Errorf("atomic rename: %w", err)
	}
	res.Replaced = existed

	// 8. Janitor: prune backups beyond retention.
	retention := opts.BackupRetention
	if retention == 0 {
		retention = DefaultBackupRetention
	}
	if retention > 0 {
		if err := pruneBackups(abs, retention); err != nil {
			// Janitor errors are non-fatal — the deploy succeeded.
			// Surface only if the caller wired a logger somewhere
			// upstream. We choose to swallow and continue.
			_ = err
		}
	}

	return res, nil
}

// ownershipStat returns nil when the destination didn't exist,
// otherwise the os.FileInfo. Encapsulates the existed/not-existed
// branch so resolveOwnership's signature stays clean.
func ownershipStat(fi os.FileInfo, statErr error) os.FileInfo {
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
	}
	return fi
}

// writeTempFile writes data to <abs>.certctl-tmp.<unix-nanos> in
// the same directory as abs. Returns the temp path. fsync's the
// file before close to defend against power-loss-during-rename
// corruption (rename guarantees atomic visibility but the file's
// data blocks must be on disk first).
func writeTempFile(abs string, data []byte) (string, error) {
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	tempName := base + TempSuffix + nowNanosStr()
	tempPath := filepath.Join(dir, tempName)

	// O_WRONLY|O_CREATE|O_EXCL guarantees we don't clobber a
	// half-written temp from a concurrent AtomicWriteFile call.
	// fileMutexes already serialize same-abs callers; O_EXCL is
	// belt-and-braces for the "wow, monotonic clock collided"
	// corner case.
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return "", err
	}
	// fsync defends against power-loss between rename + data flush.
	// On POSIX, rename's atomicity is metadata-only — the new file's
	// data must be on disk first or a power-loss-then-recover sees
	// an empty file at the destination.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	return tempPath, nil
}

// backupFile copies abs's current bytes to
// <abs>.certctl-bak.<unix-nanos>. Used by AtomicWriteFile as a
// pre-write snapshot for rollback.
func backupFile(abs string) (string, error) {
	src, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("read for backup: %w", err)
	}
	srcStat, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat for backup: %w", err)
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	backupName := base + BackupSuffix + nowNanosStr()
	backupPath := filepath.Join(dir, backupName)
	if err := os.WriteFile(backupPath, src, srcStat.Mode().Perm()); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	// Best-effort: preserve uid/gid of the original. The backup is
	// for emergency restore; if we can't chown (non-root + chown
	// denied), the operator can still cat/diff it as the agent user.
	if uid, gid, ok := unixOwnerFromStat(srcStat); ok {
		_ = os.Chown(backupPath, uid, gid)
	}
	return backupPath, nil
}

// pruneBackups deletes older backups for abs, keeping the most
// recent `keep` entries. Sorted lexicographically — which is also
// chronological because nowNanosStr is monotonic-ish.
func pruneBackups(abs string, keep int) error {
	if keep <= 0 {
		return nil
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	prefix := base + BackupSuffix
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), prefix) {
			matches = append(matches, e.Name())
		}
	}
	if len(matches) <= keep {
		return nil
	}
	sort.Strings(matches)
	// Older ones come first; trim to keep the last `keep`.
	toRemove := matches[:len(matches)-keep]
	var firstErr error
	for _, name := range toRemove {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// sha256Eq returns true when two byte slices have identical
// SHA-256 hashes. We compute both side hashes (rather than
// bytes.Equal directly) because the call sites typically already
// have a "hash for the wire" need elsewhere — keeping the same
// primitive everywhere makes future audit-log entries consistent.
func sha256Eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return ha == hb
}

// nowNanosStr returns time.Now().UnixNano() formatted as a
// fixed-width zero-padded decimal so lexicographic sort matches
// chronological order. The padding matters for pruneBackups —
// without it, "100" would sort before "99".
func nowNanosStr() string {
	return fmt.Sprintf("%019d", time.Now().UnixNano())
}
