// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package ciparity hosts cross-surface contract-parity tests.
//
// Per post-v2.1.0 anti-rot item 2 (Auditable Codebase Bundle), this
// package contains tests that walk source files (router.go,
// openapi.yaml, the MCP tools*.go catalogue, cmd/cli/main.go) and
// assert invariants ACROSS those surfaces — e.g. "every MCP tool
// follows the canonical naming convention" or "the MCP tool count
// does not regress below the documented floor."
//
// The package is stdlib-only by design: the tests read source files
// with os.ReadFile and parse them with regexp + go/ast. This keeps
// the test runnable without pulling in the rest of the codebase's
// transitive dependencies — a developer running `go test ./internal/ciparity/...`
// gets a fast, self-contained signal.
//
// The router ↔ openapi.yaml parity test lives separately in
// internal/api/router/openapi_parity_test.go (TestRouter_OpenAPIParity)
// because it predates this package and operates on the same AST that
// TestRouterRBACGateCoverage already needs. Don't duplicate it here.
package ciparity
