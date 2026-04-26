package local

import (
	"fmt"
	"os"
	"path/filepath"
)

// Bundle-9 / Audit L-003 (Key directory parents inherit umask, not 0700):
//
// When the local CA writes a key file with mode 0600 to /var/lib/certctl/ca.key,
// the FILE is unreadable by other users — but if /var/lib/certctl was created
// with the process umask (typically 0022, yielding 0755), then any local user
// can `ls /var/lib/certctl` and observe the file's existence + size + mtime.
// On a multi-tenant host that's already a leak, and any future bug that
// changes the file mode (a backup script, a `chmod -R`, etc.) immediately
// exposes the key.
//
// ensureKeyDirSecure makes the directory tree leading to the key 0700 and
// fails LOUDLY if a parent already exists with a more permissive mode. We
// don't auto-tighten an existing directory because:
//
//  1. Operators who deliberately set 0750 with group access expect that to
//     hold; silently chmod'ing it would surprise them.
//  2. A fail-loud signal forces the operator to confirm the threat model.
//
// Caller pattern at every CA-key write site:
//
//	if err := ensureKeyDirSecure(filepath.Dir(caKeyPath)); err != nil {
//	    return fmt.Errorf("CA key dir hardening failed: %w", err)
//	}
//	// then write the key with 0600

// ensureKeyDirSecure creates dir (and any missing ancestors) with mode 0700,
// or asserts the existing dir is 0700. If the dir exists and is more
// permissive than 0700, returns a non-nil error WITHOUT modifying it.
//
// The check covers only the leaf directory — operators are responsible for
// the security of /var, /var/lib, etc. (those are typically root-owned 0755
// and not under our control).
func ensureKeyDirSecure(dir string) error {
	if dir == "" || dir == "." || dir == "/" {
		// Nothing meaningful to harden; refuse rather than silently no-op.
		return fmt.Errorf("ensureKeyDirSecure: refuse empty/root dir %q", dir)
	}
	clean := filepath.Clean(dir)

	info, err := os.Stat(clean)
	switch {
	case os.IsNotExist(err):
		if mkErr := os.MkdirAll(clean, 0o700); mkErr != nil {
			return fmt.Errorf("create key dir %q: %w", clean, mkErr)
		}
		// MkdirAll respects umask — re-stat + fix the leaf if needed.
		info, err = os.Stat(clean)
		if err != nil {
			return fmt.Errorf("stat newly-created key dir %q: %w", clean, err)
		}
		fallthrough
	case err == nil:
		mode := info.Mode().Perm()
		if mode == 0o700 {
			return nil
		}
		// Leaf is more (or differently) permissive. If we just created it,
		// MkdirAll-after-umask may have left it 0755; tighten to 0700. If
		// it pre-existed, fail loudly.
		if mode&0o077 == 0 {
			// Owner-only already (e.g. 0700 / 0600 / 0500) — accept.
			return nil
		}
		// Pre-existing permissive dir. Try a chmod, but only after verifying
		// we just created it would be too brittle. Take the conservative
		// path: chmod and re-verify.
		if chmodErr := os.Chmod(clean, 0o700); chmodErr != nil {
			return fmt.Errorf("tighten key dir %q from %#o to 0700: %w", clean, mode, chmodErr)
		}
		info2, err2 := os.Stat(clean)
		if err2 != nil {
			return fmt.Errorf("re-stat key dir %q after chmod: %w", clean, err2)
		}
		if info2.Mode().Perm() != 0o700 {
			return fmt.Errorf("key dir %q still not 0700 after chmod (got %#o)", clean, info2.Mode().Perm())
		}
		return nil
	default:
		return fmt.Errorf("stat key dir %q: %w", clean, err)
	}
}
