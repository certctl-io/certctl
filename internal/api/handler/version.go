package handler

import (
	"net/http"
	"runtime"
	"runtime/debug"
)

// VersionHandler exposes the running server's build identity at
// /api/v1/version. U-3 ride-along (cat-u-no_version_endpoint, P2): pre-U-3
// there was no in-band way for an operator (or an automated rollout system)
// to ask "what version of certctl is this binary?" — they had to either read
// the container image tag externally or trust whatever the README said. The
// gap matters for the same operability story U-3 closes: when fresh-clone
// quickstarts fail, the very first question is "what code did I actually
// build", and the only honest answer needs to come from the binary itself.
//
// VersionInfo is populated from three sources, in priority order:
//
//  1. The Version field — typically supplied at build time via
//     `-ldflags='-X github.com/shankar0123/certctl/internal/api/handler.Version=v2.0.50'`.
//     Production releases set this from the git tag (see release.yml).
//
//  2. runtime/debug.ReadBuildInfo() — populated by Go 1.18+ for any binary
//     built from a module. Provides the VCS commit SHA, dirty flag, and
//     build timestamp. We read these fields directly so a `go build` from a
//     working tree (no -ldflags incantation) still produces a useful
//     /api/v1/version payload — the failure mode pre-U-3 was that everything
//     looked like "dev" everywhere, which made "is the bug fixed in this
//     binary" unanswerable.
//
//  3. Static fallbacks ("dev" / "unknown") — only reached when neither
//     ldflags nor build-info are populated, which in practice means
//     `go run` from a non-VCS-tracked workspace.
//
// The handler runs through the no-auth bypass dispatch in cmd/server/main.go
// so probes and rollout systems can query it without presenting Bearer
// credentials, mirroring how /health and /ready are reachable. Audit logging
// excludes /api/v1/version for the same reason — the path is hot under
// rollout polling and would otherwise dominate the audit trail.
type VersionHandler struct{}

// Version is overridden at build time via:
//
//	-ldflags='-X github.com/shankar0123/certctl/internal/api/handler.Version=<tag>'
//
// release.yml does this for the server container and CLI/agent binaries.
// The empty default (rather than "dev") lets the Handler fall back to the
// runtime/debug VCS revision when ldflags wasn't supplied — preferable to
// returning a literal "dev" that masks the actual git SHA the binary was
// built from.
var Version = ""

// NewVersionHandler returns a value (not a pointer) to match the
// HealthHandler convention — the handler holds no mutable state and is
// safe to copy.
func NewVersionHandler() VersionHandler {
	return VersionHandler{}
}

// VersionInfo is the JSON shape returned by GET /api/v1/version.
//
// Field ordering and tag names are part of the contract — operator tooling
// (k8s rollout checks, CI smoke tests, /api/v1/version Prometheus blackbox
// probes) parses this payload and must continue to work across releases.
// Don't rename a field without an OpenAPI bump and a deprecation cycle.
type VersionInfo struct {
	// Version is the human-readable release identifier (e.g. "v2.0.50").
	// Falls back to the VCS revision when ldflags wasn't set, and to "dev"
	// when the build wasn't VCS-tracked at all.
	Version string `json:"version"`

	// Commit is the git SHA of HEAD at build time, sourced from
	// runtime/debug.BuildInfo.Settings["vcs.revision"]. Empty string when
	// the binary was built outside a VCS-tracked workspace (rare —
	// `go build` from a tarball does this).
	Commit string `json:"commit"`

	// Modified reports whether the build had uncommitted changes
	// (debug.BuildInfo.Settings["vcs.modified"]). True for developer
	// builds, false for release builds out of CI.
	Modified bool `json:"modified"`

	// BuildTime is the RFC 3339 timestamp captured at build time
	// (debug.BuildInfo.Settings["vcs.time"]). Empty when not VCS-tracked.
	BuildTime string `json:"build_time"`

	// GoVersion is the Go toolchain version that compiled the binary
	// (runtime.Version, e.g. "go1.25.9"). Useful when triaging stdlib
	// behavior differences ("the deploy that broke was on 1.24, this one
	// is on 1.25").
	GoVersion string `json:"go_version"`
}

// readBuildInfo extracts the VCS settings from debug.BuildInfo and pairs
// them with the ldflags-supplied Version. Split out from ServeHTTP so the
// handler can be unit-tested by injecting synthetic BuildInfo (see
// version_handler_test.go) without depending on the test binary's actual
// debug info.
//
// debug.ReadBuildInfo returns ok=false when the binary was built without
// module info — extremely rare for a Go 1.18+ build, but we guard it so
// the handler degrades to "dev / unknown / runtime.Version()" instead of
// nil-deref panicking.
func readBuildInfo() VersionInfo {
	info := VersionInfo{
		Version:   Version,
		GoVersion: runtime.Version(),
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		// Pre-Go 1.18 binary or a stripped build with no buildinfo segment.
		// Both are pathological in 2026 but worth the two-line guard.
		if info.Version == "" {
			info.Version = "dev"
		}
		return info
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.modified":
			// debug.BuildInfo encodes this as the literal string "true" or
			// "false"; comparing to "true" is the canonical pattern (mirrors
			// how the standard library's own version sub-command parses it).
			info.Modified = s.Value == "true"
		case "vcs.time":
			info.BuildTime = s.Value
		}
	}

	// Fallback ladder for Version: ldflags > VCS commit > "dev". The git
	// SHA is more useful than "dev" because it's at least groundable — an
	// operator can `git show <sha>` to see what code is actually running.
	if info.Version == "" {
		if info.Commit != "" {
			info.Version = info.Commit
		} else {
			info.Version = "dev"
		}
	}

	return info
}

// ServeHTTP implements http.Handler. Returns the VersionInfo payload as
// JSON with a 200 status. GET-only — any other method returns 405, matching
// the HealthHandler convention.
func (h VersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	JSON(w, http.StatusOK, readBuildInfo())
}
