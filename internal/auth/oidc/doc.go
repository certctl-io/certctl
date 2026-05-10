// Package oidc is the Bundle 2 OpenID Connect integration: server-side
// validation of ID tokens issued by an enterprise IdP (Okta / Azure AD /
// Google Workspace / Keycloak / Authentik / Auth0), JWKS rotation,
// configurable group-claim parsing, and the HTTP handlers under
// /auth/oidc/* that wire to the session middleware.
//
// Package layout (post-Bundle-2):
//
//   - internal/auth/oidc/             - this package (Phase 3 ships service.go).
//   - internal/auth/oidc/domain/      - Phase 1 ships OIDCProvider + GroupRoleMapping.
//   - internal/auth/oidc/groupclaim/  - Phase 3 ships the hand-rolled group-claim resolver
//     (no JSON-path library; ~40 LOC walking dot-paths through map[string]interface{}).
//   - internal/auth/oidc/testfixtures/ - Phase 10 ships the `//go:build integration`
//     Keycloak harness backing the multi-IdP test surface.
//
// Phase 0 (this commit) reserves the package directory and pins
// coreos/go-oidc/v3 + golang.org/x/oauth2 as direct go.mod requires
// via the blank imports below. Without these blanks, `go mod tidy`
// would demote both back to // indirect because no Go file under this
// tree imports them yet (the actual imports land in Phase 3's
// service.go). The blank imports are deliberate Phase-0 transitional
// scaffolding; Phase 3 replaces them with real symbol use and these
// blanks are removed.
//
// Audit context (do not lose):
//   - Apache-2.0 license, OSV.dev shows zero advisories ever on
//     coreos/go-oidc/v3 at audit time. Used by Hashicorp Vault, Dex,
//     Hydra, Authentik, every Kubernetes OIDC integration. The
//     ecosystem-standard Go OIDC client.
//   - golang.org/x/oauth2 maintained by the Go team itself; v0.36.0 (the
//     pinned version) is OSV-clean. Two historical CVEs both fixed in
//     earlier versions.
//   - No JSON-path library is added. Phase 3's group-claim resolver is
//     hand-rolled; the dependency audit explicitly forbids
//     PaesslerAG/jsonpath, ohler55/ojg, tidwall/gjson, or any sibling
//     transitive bloat for what is a 40-line problem.
package oidc

import (
	// Phase 0: lift coreos/go-oidc/v3 + golang.org/x/oauth2 to direct
	// go.mod requires so a future `go mod tidy` keeps them out of the
	// // indirect block. Phase 3 replaces these blank imports with real
	// symbol use (oidc.Provider, oauth2.Config, etc.) at which point
	// these lines are removed.
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "golang.org/x/oauth2"
)
