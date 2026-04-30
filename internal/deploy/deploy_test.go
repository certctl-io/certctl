package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 1 of the deploy-hardening I master bundle. The 12 named
// tests below pin the load-bearing invariants of the
// internal/deploy/ package: atomic-or-nothing across files,
// validate-fail-cleans-up, reload-fail-rolls-back,
// rollback-also-fails-escalates, SHA-256 idempotency,
// owner/mode preservation + override, file-level serialization,
// backup retention janitor, and AtomicWriteFile temp-file +
// rename-race correctness.
//
// All 12 are required by the prompt at
// cowork/deploy-hardening-i-prompt.md::"Test plan (Phase 1
// ships ≥95% coverage on the new package)".
//
// The tests run in non-root environments — they do NOT exercise
// cross-user chown (which requires CAP_CHOWN). The chown wiring
// is exercised via the same-user case (chown to os.Getuid()
// always succeeds) + the resolveOwnership white-box tests.

const testCert1 = "-----BEGIN CERTIFICATE-----\nFAKE-CERT-1-PAYLOAD\n-----END CERTIFICATE-----\n"
const testCert2 = "-----BEGIN CERTIFICATE-----\nFAKE-CERT-2-DIFFERENT\n-----END CERTIFICATE-----\n"

// TestApply_HappyPath_PreCommitSucceeds_PostCommitSucceeds_FilesAtomic
// pins the canonical happy path: write multiple files, validate
// passes, all atomic-rename, reload passes. Every File ends up
// with the new bytes; PreCommit + PostCommit each fired once.
func TestApply_HappyPath_PreCommitSucceeds_PostCommitSucceeds_FilesAtomic(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")

	preCalls, postCalls := 0, 0
	var seenTempPaths map[string]string
	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
			{Path: key, Bytes: []byte(testCert2)},
		},
		PreCommit: func(ctx context.Context, tempPaths map[string]string) error {
			preCalls++
			seenTempPaths = tempPaths
			// Both temp files exist + readable + carry the new
			// bytes (the load-bearing invariant for "validate-
			// against-temp" semantics).
			for finalPath, tempPath := range tempPaths {
				if _, err := os.Stat(tempPath); err != nil {
					return fmt.Errorf("temp for %s missing: %w", finalPath, err)
				}
			}
			return nil
		},
		PostCommit: func(ctx context.Context) error {
			postCalls++
			return nil
		},
	}

	res, err := Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.SkippedAsIdempotent {
		t.Errorf("expected fresh write, got idempotent skip")
	}
	if !res.ValidateOK || !res.Reloaded {
		t.Errorf("ValidateOK=%v Reloaded=%v, want true/true", res.ValidateOK, res.Reloaded)
	}
	if preCalls != 1 || postCalls != 1 {
		t.Errorf("PreCommit/PostCommit calls = %d/%d, want 1/1", preCalls, postCalls)
	}
	if len(seenTempPaths) != 2 {
		t.Errorf("PreCommit saw %d temp paths, want 2", len(seenTempPaths))
	}
	// Final files have new bytes.
	if got, _ := os.ReadFile(cert); string(got) != testCert1 {
		t.Errorf("cert content = %q, want %q", got, testCert1)
	}
	if got, _ := os.ReadFile(key); string(got) != testCert2 {
		t.Errorf("key content = %q, want %q", got, testCert2)
	}
}

// TestApply_PreCommitFails_NoFilesChanged pins the all-or-nothing
// invariant on the validate path: PreCommit returns an error →
// neither destination is touched, ErrValidateFailed is returned.
func TestApply_PreCommitFails_NoFilesChanged(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cert, []byte("ORIGINAL-CERT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("ORIGINAL-KEY"), 0600); err != nil {
		t.Fatal(err)
	}

	postCalls := 0
	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
			{Path: key, Bytes: []byte(testCert2)},
		},
		PreCommit: func(ctx context.Context, tempPaths map[string]string) error {
			return errors.New("nginx -t says: invalid SAN")
		},
		PostCommit: func(ctx context.Context) error {
			postCalls++
			return nil
		},
	}

	_, err := Apply(context.Background(), plan)
	if !errors.Is(err, ErrValidateFailed) {
		t.Fatalf("expected ErrValidateFailed, got %v", err)
	}
	if postCalls != 0 {
		t.Errorf("PostCommit called %d times after PreCommit failure, want 0", postCalls)
	}
	// Both destinations untouched.
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL-CERT" {
		t.Errorf("cert was modified despite PreCommit failure: %q", got)
	}
	if got, _ := os.ReadFile(key); string(got) != "ORIGINAL-KEY" {
		t.Errorf("key was modified despite PreCommit failure: %q", got)
	}
	// No temp files leaked.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), TempSuffix) {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

// TestApply_PostCommitFails_FilesRolledBack pins the rollback
// wire: PostCommit fails → restore from backup → re-call
// PostCommit → second one succeeds → return ErrReloadFailed +
// RolledBack=true. The destinations now hold the ORIGINAL bytes.
func TestApply_PostCommitFails_FilesRolledBack(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}

	postCalls := 0
	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
		},
		PostCommit: func(ctx context.Context) error {
			postCalls++
			if postCalls == 1 {
				return errors.New("nginx -s reload exited 1")
			}
			return nil
		},
	}

	res, err := Apply(context.Background(), plan)
	if !errors.Is(err, ErrReloadFailed) {
		t.Fatalf("expected ErrReloadFailed, got %v", err)
	}
	if !res.RolledBack {
		t.Error("expected RolledBack=true")
	}
	if res.Reloaded {
		t.Error("expected Reloaded=false after rollback")
	}
	if postCalls != 2 {
		t.Errorf("PostCommit calls = %d, want 2 (once for the new bytes, once for the restored bytes)", postCalls)
	}
	if got, _ := os.ReadFile(cert); string(got) != "ORIGINAL" {
		t.Errorf("cert after rollback = %q, want %q", got, "ORIGINAL")
	}
}

// TestApply_RollbackAlsoFails_ReturnsErrRollbackFailed is the
// escalation path: PostCommit fails + the second PostCommit (after
// restore) also fails. ErrRollbackFailed surfaces;
// operator-actionable.
func TestApply_RollbackAlsoFails_ReturnsErrRollbackFailed(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}

	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
		},
		PostCommit: func(ctx context.Context) error {
			return errors.New("nginx is wedged")
		},
	}

	_, err := Apply(context.Background(), plan)
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("expected ErrRollbackFailed, got %v", err)
	}
}

// TestApply_IdempotentSkip_SHA256Match pins the idempotency
// short-circuit: when every File's destination already matches
// SHA-256, neither PreCommit nor PostCommit fires; the result
// reports SkippedAsIdempotent=true.
func TestApply_IdempotentSkip_SHA256Match(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte(testCert1), 0644); err != nil {
		t.Fatal(err)
	}

	preCalls, postCalls := 0, 0
	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
		},
		PreCommit: func(ctx context.Context, _ map[string]string) error {
			preCalls++
			return nil
		},
		PostCommit: func(ctx context.Context) error {
			postCalls++
			return nil
		},
	}
	res, err := Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.SkippedAsIdempotent {
		t.Error("expected SkippedAsIdempotent=true")
	}
	if preCalls != 0 || postCalls != 0 {
		t.Errorf("expected no Pre/PostCommit calls, got %d/%d", preCalls, postCalls)
	}
	if len(res.BackupPaths) != 0 {
		t.Errorf("expected zero backups for idempotent skip, got %d", len(res.BackupPaths))
	}

	// Verify SkipIdempotent forces the calls.
	plan.SkipIdempotent = true
	res, err = Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply with SkipIdempotent: %v", err)
	}
	if res.SkippedAsIdempotent {
		t.Error("expected SkipIdempotent override to force the deploy")
	}
	if preCalls != 1 || postCalls != 1 {
		t.Errorf("expected 1/1 calls under SkipIdempotent, got %d/%d", preCalls, postCalls)
	}
}

// TestApply_PreservesExistingOwnerAndMode_WhenNotOverridden pins
// the silent-failure-mode-defense: an existing nginx:nginx 0640
// file MUST stay nginx:nginx 0640 across a renewal, NOT get
// clobbered to root:root 0600.
//
// We can't actually create a non-current-user file in a non-root
// test, so this test verifies mode preservation only (the chown
// preservation is exercised by the resolveOwnership unit test
// below).
func TestApply_PreservesExistingOwnerAndMode_WhenNotOverridden(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	// Pre-existing file with very specific mode.
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0640); err != nil {
		t.Fatal(err)
	}
	// Some umasks downgrade 0640 → 0620; force the desired bits
	// after creation.
	if err := os.Chmod(cert, 0640); err != nil {
		t.Fatal(err)
	}

	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)}, // no Mode/Owner/Group set
		},
	}
	if _, err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	stat, err := os.Stat(cert)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0640 {
		t.Errorf("mode after deploy = %#o, want %#o (preservation broken)", stat.Mode().Perm(), os.FileMode(0640))
	}
}

// TestApply_RespectsOverrides_OwnerGroupMode pins the override
// path: when File.Mode is set, the existing mode is overridden.
// We use the current user/group so chown succeeds on non-root.
func TestApply_RespectsOverrides_OwnerGroupMode(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cert, 0640); err != nil {
		t.Fatal(err)
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatal(err)
	}

	plan := Plan{
		Files: []File{{
			Path:  cert,
			Bytes: []byte(testCert1),
			Mode:  0644,
			Owner: currentUser.Username,
			Group: currentGroup.Name,
		}},
	}
	if _, err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	stat, err := os.Stat(cert)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0644 {
		t.Errorf("override mode = %#o, want 0644", stat.Mode().Perm())
	}
}

// TestApply_ConcurrentApplyToSameFile_Serializes pins the
// file-level mutex: 10 concurrent Applies to the same destination
// see exactly 10 PostCommit invocations and the file ends with
// one of the writers' bytes (no torn write).
func TestApply_ConcurrentApplyToSameFile_Serializes(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")

	const N = 10
	var inFlight, maxInFlight int32
	var postCount int32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			plan := Plan{
				Files: []File{{
					Path:  cert,
					Bytes: []byte(fmt.Sprintf("WRITER-%d", idx)),
				}},
				SkipIdempotent: true, // force every call through the full path
				PostCommit: func(ctx context.Context) error {
					n := atomic.AddInt32(&inFlight, 1)
					for {
						m := atomic.LoadInt32(&maxInFlight)
						if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
							break
						}
					}
					time.Sleep(2 * time.Millisecond)
					atomic.AddInt32(&inFlight, -1)
					atomic.AddInt32(&postCount, 1)
					return nil
				},
			}
			if _, err := Apply(context.Background(), plan); err != nil {
				t.Errorf("Apply: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if postCount != N {
		t.Errorf("postCount = %d, want %d", postCount, N)
	}
	if maxInFlight > 1 {
		t.Errorf("max concurrent PostCommit = %d, want 1 (serialization broken)", maxInFlight)
	}
	// File must contain exactly one of the writers' contents.
	got, _ := os.ReadFile(cert)
	if !strings.HasPrefix(string(got), "WRITER-") {
		t.Errorf("file content not from any writer: %q", got)
	}
}

// TestApply_BackupRetention_KeepsLastN pins the janitor: after
// many deploys, only the last N backups remain.
func TestApply_BackupRetention_KeepsLastN(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")

	// Initial file.
	if err := os.WriteFile(cert, []byte("V0"), 0644); err != nil {
		t.Fatal(err)
	}

	const keep = 2
	for i := 1; i <= 5; i++ {
		plan := Plan{
			Files: []File{{
				Path:  cert,
				Bytes: []byte(fmt.Sprintf("V%d", i)),
			}},
			BackupRetention: keep,
		}
		if _, err := Apply(context.Background(), plan); err != nil {
			t.Fatalf("Apply iter %d: %v", i, err)
		}
		// Stagger to ensure distinct nanosecond stamps.
		time.Sleep(2 * time.Millisecond)
	}

	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), BackupSuffix) {
			count++
		}
	}
	if count != keep {
		t.Errorf("backup count after 5 deploys with retention=%d = %d, want %d", keep, count, keep)
	}
}

// TestApply_NoExistingFile_UsesDefaultsForOwnerGroupMode covers
// the first-deploy path: destination doesn't exist; FileDefaults
// applies. We verify the mode default lands; owner/group default
// is exercised in resolveOwnership unit tests (would require root
// for cross-user chown).
func TestApply_NoExistingFile_UsesDefaultsForOwnerGroupMode(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")

	plan := Plan{
		Files: []File{
			{Path: cert, Bytes: []byte(testCert1)},
		},
		Defaults: FileDefaults{Mode: 0640},
	}
	if _, err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	stat, err := os.Stat(cert)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0640 {
		t.Errorf("default mode for new file = %#o, want 0640", stat.Mode().Perm())
	}
}

// TestAtomicWriteFile_TempFileCleanedUpOnError checks that a
// failure mid-flight (we simulate by passing an unwritable
// directory) leaves no .certctl-tmp.* file behind.
func TestAtomicWriteFile_TempFileCleanedUpOnError(t *testing.T) {
	dir := t.TempDir()
	// Make the directory read-only AFTER the temp open would fail.
	// Easier: target a path inside a directory that doesn't exist.
	ghost := filepath.Join(dir, "does-not-exist", "tls.crt")
	_, err := AtomicWriteFile(context.Background(), ghost, []byte(testCert1), WriteOptions{})
	if err == nil {
		t.Fatal("expected error writing into nonexistent directory")
	}
	// No leaked temps in the parent (which does exist).
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), TempSuffix) {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

// TestAtomicWriteFile_RenameRaceWithReader_AtomicReadAlwaysSeesOldOrNew
// pins the load-bearing POSIX-rename atomicity: a concurrent
// reader hitting the destination during a write either sees the
// pre-write bytes or the post-write bytes; never an intermediate
// state.
func TestAtomicWriteFile_RenameRaceWithReader_AtomicReadAlwaysSeesOldOrNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.crt")
	old := []byte(strings.Repeat("OLD", 1000))
	newer := []byte(strings.Repeat("NEW", 1000))
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var torn atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			s := string(b)
			if s != string(old) && s != string(newer) {
				torn.Store(true)
				return
			}
		}
	}()

	// Issue many writes back and forth.
	for i := 0; i < 30; i++ {
		writeBytes := old
		if i%2 == 0 {
			writeBytes = newer
		}
		if _, err := AtomicWriteFile(context.Background(), path, writeBytes, WriteOptions{
			SkipIdempotent: true,
		}); err != nil {
			t.Fatalf("AtomicWriteFile %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if torn.Load() {
		t.Error("torn read observed (rename was not atomic)")
	}
}

// --- White-box tests for resolveOwnership (chown semantics under
// non-root require this, since we can't write a chown-to-root
// integration test without sudo). ---

// TestResolveOwnership_ExplicitOverride_Wins verifies that an
// explicit File.Mode/Owner/Group beats both existing-file
// preservation and Defaults fallback.
func TestResolveOwnership_ExplicitOverride_Wins(t *testing.T) {
	currentUser, _ := user.Current()
	currentGroup, _ := user.LookupGroupId(currentUser.Gid)

	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	res, err := resolveOwnership(File{
		Path:  path,
		Mode:  0644,
		Owner: currentUser.Username,
		Group: currentGroup.Name,
	}, FileDefaults{Mode: 0400, Owner: "nobody", Group: "nogroup"}, stat)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != 0644 {
		t.Errorf("mode = %#o, want 0644 (override should win)", res.Mode)
	}
	if res.OwnerLabel != currentUser.Username {
		t.Errorf("owner label = %q, want %q (override should win)", res.OwnerLabel, currentUser.Username)
	}
}

// TestResolveOwnership_PreservesExisting_WhenNoOverride verifies
// the preservation path: no explicit override + existing file →
// existing uid/gid/mode are returned.
func TestResolveOwnership_PreservesExisting_WhenNoOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)

	res, err := resolveOwnership(File{Path: path}, FileDefaults{Mode: 0400}, stat)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != 0640 {
		t.Errorf("mode = %#o, want 0640 (preservation)", res.Mode)
	}
	uid, gid, ok := unixOwnerFromStat(stat)
	if !ok {
		t.Skip("non-unix platform")
	}
	if res.UID != uid || res.GID != gid {
		t.Errorf("uid/gid = %d/%d, want %d/%d", res.UID, res.GID, uid, gid)
	}
}

// TestResolveOwnership_NewFile_FallsBackToDefaults verifies the
// defaults path: no override + no existing file → Plan.Defaults.
func TestResolveOwnership_NewFile_FallsBackToDefaults(t *testing.T) {
	currentUser, _ := user.Current()
	currentGroup, _ := user.LookupGroupId(currentUser.Gid)

	res, err := resolveOwnership(File{Path: "/tmp/never"}, FileDefaults{
		Mode:  0640,
		Owner: currentUser.Username,
		Group: currentGroup.Name,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != 0640 {
		t.Errorf("mode = %#o, want 0640 (default)", res.Mode)
	}
	if res.OwnerLabel != currentUser.Username {
		t.Errorf("owner = %q, want %q (default)", res.OwnerLabel, currentUser.Username)
	}
}

// TestApply_RejectsInvalidPlan_NoFiles + duplicate-paths + empty-
// path. Pin the validatePlan gate.
func TestApply_RejectsInvalidPlan(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
	}{
		{"no files", Plan{}},
		{"empty path", Plan{Files: []File{{Path: "", Bytes: []byte("x")}}}},
		{"duplicate", Plan{Files: []File{
			{Path: "/tmp/dup", Bytes: []byte("a")},
			{Path: "/tmp/dup", Bytes: []byte("b")},
		}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Apply(context.Background(), tc.plan)
			if !errors.Is(err, ErrPlanInvalid) {
				t.Errorf("got %v, want ErrPlanInvalid", err)
			}
		})
	}
}

// TestApply_ContextCancelledBeforeStart_AbortsCleanly pins the
// context-respect contract: a cancelled context aborts before
// any I/O.
func TestApply_ContextCancelledBeforeStart_AbortsCleanly(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Apply(ctx, Plan{
		Files: []File{{Path: cert, Bytes: []byte(testCert1)}},
	})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
	if _, statErr := os.Stat(cert); statErr == nil {
		t.Error("file was created despite cancelled context")
	}
}

// TestApply_NoBackupRetention_DisablesBackups pins
// BackupRetention = -1 sentinel: no backup created; rollback
// becomes impossible.
func TestApply_NoBackupRetention_DisablesBackups(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte("ORIGINAL"), 0644); err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		Files:           []File{{Path: cert, Bytes: []byte(testCert1)}},
		BackupRetention: -1,
	}
	if _, err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), BackupSuffix) {
			t.Errorf("backup created despite BackupRetention=-1: %s", e.Name())
		}
	}
}

// TestAtomicWriteFile_HappyPath_ReplacesExistingAtomically covers
// the simple AtomicWriteFile path used by F5 + K8s connectors.
func TestAtomicWriteFile_HappyPath_ReplacesExistingAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("OLD"), 0644); err != nil {
		t.Fatal(err)
	}
	res, err := AtomicWriteFile(context.Background(), path, []byte("NEW"), WriteOptions{})
	if err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	if !res.Replaced {
		t.Error("Replaced=false; want true")
	}
	if res.BackupPath == "" {
		t.Error("expected non-empty BackupPath")
	}
	if got, _ := os.ReadFile(path); string(got) != "NEW" {
		t.Errorf("file = %q, want NEW", got)
	}
}

// TestAtomicWriteFile_IdempotentSkip covers the AtomicWriteFile
// SHA-256 skip — same coverage as Plan.Apply but for the lower-
// level entry point used by F5/K8s.
func TestAtomicWriteFile_IdempotentSkip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("SAME"), 0644); err != nil {
		t.Fatal(err)
	}
	res, err := AtomicWriteFile(context.Background(), path, []byte("SAME"), WriteOptions{})
	if err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	if !res.Idempotent {
		t.Error("Idempotent=false; want true")
	}
	if res.Replaced {
		t.Error("Replaced=true on idempotent skip; want false")
	}
}

// TestAtomicWriteFile_RejectsEmptyPath pins the input validation.
func TestAtomicWriteFile_RejectsEmptyPath(t *testing.T) {
	_, err := AtomicWriteFile(context.Background(), "", []byte("x"), WriteOptions{})
	if !errors.Is(err, ErrPlanInvalid) {
		t.Errorf("got %v, want ErrPlanInvalid", err)
	}
}

// TestPruneBackups_NoOp_WhenUnderRetention pins the early return
// when there are fewer backups than the retention bar.
func TestPruneBackups_NoOp_WhenUnderRetention(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "f")
	// Create two backup-style files.
	os.WriteFile(abs+BackupSuffix+"0000000000000000001", []byte("a"), 0644)
	os.WriteFile(abs+BackupSuffix+"0000000000000000002", []byte("b"), 0644)
	if err := pruneBackups(abs, 5); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), BackupSuffix) {
			count++
		}
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (no pruning under retention)", count)
	}
}

// TestLookupUID_Numeric covers the "numeric passthrough" branch
// of lookupUID — agents can configure with either "nginx" or "1000".
func TestLookupUID_Numeric(t *testing.T) {
	uid, err := lookupUID("12345")
	if err != nil {
		t.Fatal(err)
	}
	if uid != 12345 {
		t.Errorf("uid = %d, want 12345", uid)
	}
}

// TestLookupGID_Numeric mirror.
func TestLookupGID_Numeric(t *testing.T) {
	gid, err := lookupGID("54321")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 54321 {
		t.Errorf("gid = %d, want 54321", gid)
	}
}

// TestSHA256Eq_EdgeCases pins the helper used by the idempotency
// short-circuit.
func TestSHA256Eq_EdgeCases(t *testing.T) {
	if !sha256Eq([]byte{}, []byte{}) {
		t.Error("empty == empty failed")
	}
	if sha256Eq([]byte("a"), []byte("b")) {
		t.Error("a == b unexpectedly true")
	}
	if sha256Eq([]byte("ab"), []byte("ac")) {
		t.Error("ab == ac unexpectedly true")
	}
	if !sha256Eq([]byte("abc"), []byte("abc")) {
		t.Error("abc == abc failed")
	}
}
