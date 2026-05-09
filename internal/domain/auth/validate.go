package auth

// Seed identifiers and constants used by the Phase 1 migration and the
// service / handler layers. Centralised here so production code, tests,
// and migration SQL stay in lockstep on the canonical role / permission
// names.

// DefaultTenantID is the seeded tenant created by migration
// 000029_rbac.up.sql. Bundle 1 ships single-tenant; every actor_role
// row carries this tenant_id by default.
const DefaultTenantID = "t-default"

// Seeded role IDs. Stable identifiers used by the migration backfill
// and the demo-mode synthetic-actor seed.
const (
	RoleIDAdmin    = "r-admin"
	RoleIDOperator = "r-operator"
	RoleIDViewer   = "r-viewer"
	RoleIDAgent    = "r-agent"
	RoleIDMCP      = "r-mcp"
	RoleIDCLI      = "r-cli"
	RoleIDAuditor  = "r-auditor"
)

// DemoAnonActorID is the synthetic actor used when
// CERTCTL_AUTH_TYPE=none is configured (the demo path). Phase 1
// migration seeds the actor + admin role assignment unconditionally;
// Phase 3 of Bundle 1 wires the middleware to inject this actor into
// the request context when no-auth mode is active. Reserved system
// actor: the API rejects mutations / deletions targeting this id.
const DemoAnonActorID = "actor-demo-anon"

// CanonicalPermissions is the canonical Bundle 1 permission catalog,
// seeded by migration 000029_rbac.up.sql. Bundle 2 extends with
// auth.session.* and auth.oidc.* permissions (those land in Bundle 2
// Phase 5's migration).
//
// Naming convention: <namespace>.<verb>. Read permissions use
// `<resource>.read`; mutations use `.create`, `.edit`, `.delete`,
// `.assign`, `.revoke`, `.use`, `.export`, etc. The catalog is the
// single source of truth referenced by:
//   - migration 000029_rbac.up.sql (seeds the rows)
//   - service layer (RoleService.Create rejects unknown permissions)
//   - handler layer (auth.RequirePermission perm string)
var CanonicalPermissions = []string{
	// Certificate lifecycle
	"cert.read",
	"cert.issue",
	"cert.revoke",
	"cert.delete",

	// Profile management
	"profile.read",
	"profile.edit",
	"profile.delete",

	// Issuer management
	"issuer.read",
	"issuer.edit",
	"issuer.delete",

	// Target management
	"target.read",
	"target.edit",
	"target.delete",

	// Agent management
	"agent.read",
	"agent.edit",
	"agent.retire",
	"agent.heartbeat",
	"agent.job.poll",
	"agent.job.complete",
	"agent.job.report",

	// Audit access (Phase 8 introduces the auditor split)
	"audit.read",
	"audit.export",

	// RBAC primitive (Phase 4 surfaces these via /v1/auth/roles)
	"auth.role.list",
	"auth.role.create",
	"auth.role.edit",
	"auth.role.delete",
	"auth.role.assign",
	"auth.role.revoke",

	// API-key management (Phase 4 + Phase 7 scope-down)
	"auth.key.list",
	"auth.key.create",
	"auth.key.rotate",
	"auth.key.delete",

	// Bootstrap path (Phase 6)
	"auth.bootstrap.use",

	// Bundle 1 Phase 3.5: admin-only fine-grained perms for the
	// legacy admin handlers, seeded by migration 000030. Wrapped at
	// the router level via auth.RequirePermission middleware; the
	// in-handler auth.IsAdmin checks have been removed in Phase 3.5.
	"cert.bulk_revoke",
	"crl.admin",
	"scep.admin",
	"est.admin",
	"ca.hierarchy.manage",
}

// DefaultRoles describes the seven default roles seeded by the
// migration, mapped to the permissions each role holds at global
// scope. Permissions not in CanonicalPermissions cause the migration
// to fail-closed.
var DefaultRoles = map[string][]string{
	RoleIDAdmin: CanonicalPermissions, // admin gets every permission

	RoleIDOperator: {
		"cert.read", "cert.issue", "cert.revoke", "cert.delete",
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit", "target.delete",
		"agent.read", "agent.edit",
		"audit.read",
	},

	RoleIDViewer: {
		"cert.read",
		"profile.read",
		"issuer.read",
		"target.read",
		"agent.read",
		"audit.read",
	},

	RoleIDAgent: {
		"cert.read",
		"agent.heartbeat",
		"agent.job.poll",
		"agent.job.complete",
		"agent.job.report",
	},

	RoleIDMCP: {
		// MCP gets operator-equivalent minus destructive ops.
		// Defense in depth for Claude / IDE integrations where
		// destructive verbs warrant additional scrutiny.
		"cert.read", "cert.issue", "cert.revoke",
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit",
		"agent.read",
		"audit.read",
	},

	RoleIDCLI: {
		// CLI = operator-equivalent. Operators can scope down via
		// `certctl auth keys scope-down` if they want narrower CLI
		// access in production.
		"cert.read", "cert.issue", "cert.revoke", "cert.delete",
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit", "target.delete",
		"agent.read", "agent.edit",
		"audit.read",
		"auth.key.list", "auth.key.create", "auth.key.rotate",
	},

	RoleIDAuditor: {
		// Phase 8 ships the auditor split. Phase 1 reserves the
		// role id + the read-only permission set so subsequent
		// phases don't have to renumber.
		"audit.read",
		"audit.export",
	},
}
