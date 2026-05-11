// Package oidc is the Bundle 2 OpenID Connect integration: server-side
// validation of ID tokens issued by an enterprise IdP (Okta / Azure AD /
// Google Workspace / Keycloak / Authentik / Auth0), JWKS rotation,
// configurable group-claim parsing, and the HTTP handlers under
// /auth/oidc/* that wire to the session middleware.
//
// Package layout (post-Bundle-2):
//
//   - internal/auth/oidc/             - this package; service.go ships in Phase 3.
//   - internal/auth/oidc/domain/      - Phase 1 ships OIDCProvider + GroupRoleMapping.
//   - internal/auth/oidc/groupclaim/  - Phase 3 ships the hand-rolled group-claim resolver
//     (no JSON-path library; ~40 LOC walking dot-paths through map[string]interface{}).
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
