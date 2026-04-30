package deploy

import (
	"context"
	"errors"
	"os"
	"time"
)

// Sentinel errors. All errors returned by Apply wrap exactly one of
// these so connector callers can use errors.Is to distinguish the
// failure mode without parsing strings.
var (
	// ErrValidateFailed is returned when the Plan's PreCommit hook
	// returns an error. Connectors typically map PreCommit to a
	// validate-with-the-target command (`nginx -t -c <temp>`,
	// `apachectl configtest -f <temp>`, `haproxy -c -f <temp>`).
	// On ErrValidateFailed, no live file has been touched: the temp
	// files are cleaned up and the destinations are exactly as they
	// were before Apply was called.
	ErrValidateFailed = errors.New("deploy: validate (PreCommit) failed")

	// ErrReloadFailed is returned when the Plan's PostCommit hook
	// returns an error AND the rollback succeeded. The destination
	// files now hold the PREVIOUS bytes (restored from backup) and
	// PostCommit was re-called against those bytes. The deploy is
	// effectively a no-op from the operator's perspective.
	ErrReloadFailed = errors.New("deploy: reload (PostCommit) failed; rolled back")

	// ErrRollbackFailed is the operator-actionable escalation:
	// PostCommit failed, AND the rollback (restore + re-PostCommit)
	// also failed. The deploy is in a known-bad state. Manual
	// intervention is required to either restore the backup files
	// (paths in Result.BackupPaths) or push a fresh known-good
	// cert. Connectors emit a loud audit + alert when they see this.
	ErrRollbackFailed = errors.New("deploy: reload failed AND rollback also failed; manual intervention required")

	// ErrPlanInvalid is returned for malformed Plans (no Files,
	// duplicate destination paths, empty Path entries, etc.) before
	// any I/O is performed. Strictly a programming error from the
	// connector — never seen in production once the connector unit
	// tests pass.
	ErrPlanInvalid = errors.New("deploy: plan is invalid")
)

// File describes one target file that Plan.Apply will write.
//
// When Mode is zero, the existing destination's mode is preserved if
// the destination exists; otherwise Plan.Defaults.Mode applies. Same
// for Owner / Group. This means connectors can ship a Plan with
// File{Path: ..., Bytes: ...} entries (no explicit ownership) and
// the package will Do The Right Thing — preserve nginx:nginx 0640 on
// renewal, fall back to per-target defaults on first deploy.
type File struct {
	// Path is the final destination on disk. Must be an absolute
	// path. The temp file used during atomic write is written in
	// filepath.Dir(Path) to guarantee same-filesystem rename.
	Path string

	// Bytes is the new contents to write.
	Bytes []byte

	// Mode is the desired final file mode. Zero means "preserve
	// existing or use Plan.Defaults.Mode for new files".
	Mode os.FileMode

	// Owner is the username to chown to. Empty means "preserve
	// existing or use Plan.Defaults.Owner for new files". Resolved
	// at write time via os/user.Lookup.
	Owner string

	// Group is the group name to chgrp to. Empty means "preserve
	// existing or use Plan.Defaults.Group for new files". Resolved
	// via os/user.LookupGroup.
	Group string
}

// FileDefaults applies to any File whose own Mode/Owner/Group is
// zero AND whose destination does not yet exist. Connectors set
// these to per-target-type sensible defaults (e.g. NGINX:
// {Mode: 0640, Owner: "nginx", Group: "nginx"}).
type FileDefaults struct {
	Mode  os.FileMode
	Owner string
	Group string
}

// Plan represents one atomic deployment. All Files succeed together
// or roll back together.
type Plan struct {
	// Files is the set of (path, contents, ownership) entries this
	// Plan writes. Order is irrelevant — Apply writes them all
	// before calling PreCommit, and atomically renames them all
	// before calling PostCommit.
	Files []File

	// Defaults applies to any File entry whose own Mode/Owner/Group
	// fields are zero AND whose destination does not yet exist.
	// When the destination already exists, the existing
	// ownership/mode is preserved unless the File entry overrides.
	Defaults FileDefaults

	// PreCommit is invoked after all temp files are written but
	// BEFORE the atomic rename. The map argument is keyed by
	// File.Path → temp file path so the connector can run a
	// validate-with-the-target command against the temp file
	// (e.g. `nginx -t -c <temp>`). Returning a non-nil error
	// aborts the deploy: the temp files are cleaned up and Apply
	// returns ErrValidateFailed wrapping the PreCommit error.
	//
	// Optional. nil PreCommit means "no validate step" — Apply
	// proceeds straight to the atomic rename + PostCommit.
	PreCommit func(ctx context.Context, tempPaths map[string]string) error

	// PostCommit is invoked after every File has been atomically
	// renamed to its final path. Connectors typically map this to
	// a service reload (`nginx -s reload`, `systemctl reload
	// haproxy`). Returning a non-nil error triggers automatic
	// rollback: the destinations are restored from the pre-deploy
	// backups and PostCommit is called a second time against the
	// restored bytes. If the second PostCommit also fails, Apply
	// returns ErrRollbackFailed.
	//
	// Optional. nil PostCommit means "no reload step" — Apply
	// returns immediately after the atomic rename.
	PostCommit func(ctx context.Context) error

	// BackupRetention is the number of historical backups to keep
	// per File path after a successful Apply. Older backups are
	// garbage-collected by a synchronous janitor pass at the end
	// of Apply.
	//
	// Zero (the field default) maps to DefaultBackupRetention (3).
	// Set to a sentinel negative value (-1) to disable backups
	// entirely — rollback becomes impossible; ErrReloadFailed is
	// instead surfaced as a hard error with no recovery.
	BackupRetention int

	// SkipIdempotent forces Apply to run PreCommit + PostCommit
	// even when every File's bytes already match the destination.
	// Useful when the connector knows an external configuration
	// change requires re-validation. Defaults to false (skip on
	// SHA-256 match — the safe and usual case).
	SkipIdempotent bool
}

// Result describes what Apply did. Connectors populate audit logs
// and Prometheus counters from this.
type Result struct {
	// SkippedAsIdempotent is true when every File's destination
	// already had identical bytes and SkipIdempotent was false.
	// PreCommit and PostCommit were NOT called. BackupPaths is
	// empty in this case — no backups are created for a no-op.
	SkippedAsIdempotent bool

	// BackupPaths maps each File.Path to the path of the backup
	// of the previous contents. When a destination did not exist
	// before Apply, the entry maps to "" (no backup possible).
	// Empty when SkippedAsIdempotent is true.
	BackupPaths map[string]string

	// ValidateOK is true when PreCommit returned nil (or was nil
	// to begin with).
	ValidateOK bool

	// Reloaded is true when PostCommit returned nil (or was nil)
	// AND no rollback occurred.
	Reloaded bool

	// RolledBack is true when PostCommit failed AND the rollback
	// succeeded. ErrReloadFailed will be returned alongside.
	RolledBack bool

	// Duration is the wall-clock time Apply took, including
	// PreCommit + PostCommit + (if applicable) rollback.
	Duration time.Duration
}

// WriteOptions controls AtomicWriteFile, the lower-level building
// block exposed for connectors that don't fit the Plan model
// (typically connectors that ship bytes through a remote API rather
// than a local filesystem — F5, K8s).
type WriteOptions struct {
	// Mode is the desired final file mode. Zero = preserve
	// existing or use DefaultMode for new files.
	Mode os.FileMode

	// DefaultMode applies when Mode is zero AND the destination
	// does not yet exist.
	DefaultMode os.FileMode

	// Owner / Group: empty = preserve existing or use
	// DefaultOwner/Group for new files.
	Owner        string
	Group        string
	DefaultOwner string
	DefaultGroup string

	// SkipIdempotent forces a write even when the destination
	// already has identical bytes. Defaults to false.
	SkipIdempotent bool

	// BackupRetention controls how many historical backups to
	// keep. Zero = DefaultBackupRetention (3); -1 = no backups.
	BackupRetention int
}

// WriteResult describes what AtomicWriteFile did.
type WriteResult struct {
	// Path is the final destination (echoed for caller convenience).
	Path string

	// BackupPath is the path to the pre-write backup, or "" when
	// no backup was taken (file did not exist or backups disabled
	// or write was idempotent-skipped).
	BackupPath string

	// Replaced is true when an existing file was replaced. False
	// when the file did not previously exist OR the write was
	// idempotent-skipped.
	Replaced bool

	// Idempotent is true when the destination already had
	// identical bytes and SkipIdempotent was false. No write
	// occurred in this case.
	Idempotent bool
}

// DefaultBackupRetention is the number of historical backup files
// kept per File path after a successful Apply (or
// AtomicWriteFile call). Operators can override per-call via
// Plan.BackupRetention or via the CERTCTL_DEPLOY_BACKUP_RETENTION
// env var that the agent passes in.
const DefaultBackupRetention = 3

// BackupSuffix is the suffix used for pre-write backup files.
// Format: <original>.certctl-bak.<unix-nanos>. The unix-nanos is
// monotonic enough for retention sort order (lexicographic =
// chronological) without needing per-file metadata.
const BackupSuffix = ".certctl-bak."

// TempSuffix is the suffix used for in-flight temp files. Format:
// <original>.certctl-tmp.<unix-nanos>. Cleaned up on PreCommit
// failure or on Apply panic.
const TempSuffix = ".certctl-tmp."
