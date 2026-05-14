// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

//go:build unix

// Unix-side implementation of unixOwnerFromStat. The `unix` build
// constraint (Go 1.19+) covers linux / darwin / freebsd / openbsd /
// netbsd / dragonfly / solaris — every GOOS where *syscall.Stat_t
// is a valid type assertion target for os.FileInfo.Sys().
//
// Hotfix #16 (2026-05-14): pre-split, this function lived inline in
// ownership.go with an unconditional `syscall.Stat_t` reference. That
// failed `GOOS=windows go build` because the type is undefined on
// that platform. The split is the standard Go pattern — the same
// function name + signature is satisfied by either build of the
// package, callers don't know or care which.

package deploy

import (
	"os"
	"syscall"
)

func unixOwnerFromStat(fi os.FileInfo) (uid int, gid int, ok bool) {
	if fi == nil {
		return -1, -1, false
	}
	if sysStat, isUnix := fi.Sys().(*syscall.Stat_t); isUnix {
		return int(sysStat.Uid), int(sysStat.Gid), true
	}
	return -1, -1, false
}
