// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

// Windows stub for unixOwnerFromStat. Windows has no uid/gid concept
// the way Unix does — file ownership is expressed via SIDs (Security
// Identifiers) and ACLs (Access Control Lists), and os.FileInfo.Sys()
// returns *syscall.Win32FileAttributeData which carries no
// ownership data the deploy package's existing call sites can use.
//
// All four callers — applyOwnership at ownership.go:75,
// preserveSourceOwner at atomic.go:237, and two test sites — already
// handle the ok=false return path by falling back to Plan.Defaults
// or the runtime's umask. Returning false here is the correct
// platform contract: "no native ownership available on this
// platform; use the supplied defaults."
//
// Hotfix #16 (2026-05-14): created to unblock the
// cross-platform-build Windows matrix in CI, which had been
// red since the agent's deploy package gained ownership-
// preservation semantics. The agent binary still compiles for
// Windows; ownership operations on Windows are no-ops (which
// matches operator expectations — the certctl-agent's
// chown/chmod codepaths gate on `runningAsRoot()` and Windows
// runs the agent as a service under a SID that doesn't
// translate to a uid anyway).

package deploy

import "os"

func unixOwnerFromStat(_ os.FileInfo) (uid int, gid int, ok bool) {
	return -1, -1, false
}
