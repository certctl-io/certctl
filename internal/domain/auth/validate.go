// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

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

// CanonicalPermissions is the canonical permission catalog seeded by
// migrations 000029 / 000030 / 000037 / 000038 / 000039. Bundle 2
// extended with auth.session.* and auth.oidc.* permissions; the
// 2026-05-10 audit (CRIT-1 closure) seeded the legacy-CRUD perms
// (policy/team/owner/job/approval/notification/discovery/network_scan/
// healthcheck/digest/verification/stats/metrics + cert.edit) via
// migration 000039.
//
// Naming convention: <namespace>.<verb>. Read permissions use
// `<resource>.read`; mutations use `.create`, `.edit`, `.delete`,
// `.assign`, `.revoke`, `.use`, `.export`, etc. The catalog is the
// single source of truth referenced by:
//   - migration 000029_rbac.up.sql + 000030 + 000037 + 000038 + 000039 (seed the rows)
//   - service layer (RoleService.Create rejects unknown permissions)
//   - handler layer (auth.RequirePermission perm string)
//   - router layer (rbacGate(reg.Checker, "<perm>", ...) at every
//     state-changing route + read endpoints)
//
// TestRouterRBACGateCoverage in internal/api/router/router_test.go is
// the AST-level CI guard that pins router enforcement to this catalogue.
var CanonicalPermissions = []string{
	// Certificate lifecycle
	"cert.read",
	"cert.issue",
	"cert.edit", // metadata updates, deploy triggers, bulk-reassign (Audit CRIT-1)
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

	// Bundle 2 Phase 5 — session + OIDC management permissions
	// seeded by migration 000037. auth.session.list / .revoke gate
	// "list/revoke any session in tenant" (own-session paths bypass
	// the gate via "is path.actor_id == ctx.actor_id?" check at the
	// handler layer); auth.session.list.all gates the all-actors
	// admin view. auth.oidc.{list,create,edit,delete} gates the
	// OIDC-provider-config + group-mapping CRUD endpoints.
	"auth.session.list",
	"auth.session.list.all",
	"auth.session.revoke",
	"auth.oidc.list",
	"auth.oidc.create",
	"auth.oidc.edit",
	"auth.oidc.delete",

	// Bundle 2 Phase 7.5 — break-glass admin permissions seeded by
	// migration 000038. auth.breakglass.admin gates set/rotate/unlock/
	// remove operations on any actor's break-glass credential.
	// auth.breakglass.login is granted to each actor when their
	// break-glass credential is set, so they can use the local-
	// password recovery path during SSO outages. The whole surface
	// is gated on CERTCTL_BREAKGLASS_ENABLED at the service layer
	// (Service.Enabled() short-circuits every operation when false).
	"auth.breakglass.admin",
	"auth.breakglass.login",

	// Audit 2026-05-10 CRIT-1 closure — legacy-CRUD permission set.
	// Seeded by migration 000039 + wrapped at the router level by
	// rbacGate / rbacGateScoped on every state-changing + read route.
	// Job lifecycle.
	"job.read",
	"job.cancel",

	// Approval workflow (Rank 7 primitive — was previously ungated).
	"approval.read",
	"approval.approve",
	"approval.reject",

	// Policy management (compliance rules).
	"policy.read",
	"policy.edit",
	"policy.delete",

	// Team management.
	"team.read",
	"team.edit",
	"team.delete",

	// Owner management.
	"owner.read",
	"owner.edit",
	"owner.delete",

	// Notifications.
	"notification.read",
	"notification.edit", // mark-read, requeue

	// Discovery (agent-submitted + cloud-secret-store scans).
	"discovery.read",
	"discovery.run",   // agents submit discovery reports
	"discovery.claim", // claim/dismiss discovered certs

	// Network scan + SCEP probing.
	"network_scan.read",
	"network_scan.edit",
	"network_scan.run",

	// Health checks (uptime monitors).
	"healthcheck.read",
	"healthcheck.edit",
	"healthcheck.delete",
	"healthcheck.acknowledge",

	// Digest (operator-summary emails).
	"digest.read",
	"digest.send",

	// Verification (post-deploy probe).
	"verification.read",
	"verification.run",

	// Read-only observability.
	"stats.read",
	"metrics.read",
}

// DefaultRoles describes the seven default roles seeded by the
// migration, mapped to the permissions each role holds at global
// scope. Permissions not in CanonicalPermissions cause the migration
// to fail-closed.
//
// r-auditor is invariant: exactly {audit.read, audit.export} per the
// auditor_test.go pin. Adding a new permission here that ends up in
// r-auditor breaks the pin — by design.
var DefaultRoles = map[string][]string{
	RoleIDAdmin: CanonicalPermissions, // admin gets every permission

	RoleIDOperator: {
		// Cert lifecycle (full)
		"cert.read", "cert.issue", "cert.edit", "cert.revoke", "cert.delete",
		// Profile / issuer / target / agent — read + edit (no delete on issuer)
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit", "target.delete",
		"agent.read", "agent.edit",
		// Audit read
		"audit.read",
		// New CRIT-1 perms — operator-level CRUD
		"job.read", "job.cancel",
		"approval.read", "approval.approve", "approval.reject",
		"policy.read", "policy.edit", "policy.delete",
		"team.read", "team.edit", "team.delete",
		"owner.read", "owner.edit", "owner.delete",
		"notification.read", "notification.edit",
		"discovery.read", "discovery.run", "discovery.claim",
		"network_scan.read", "network_scan.edit", "network_scan.run",
		"healthcheck.read", "healthcheck.edit", "healthcheck.delete", "healthcheck.acknowledge",
		"digest.read", "digest.send",
		"verification.read", "verification.run",
		"stats.read", "metrics.read",
	},

	RoleIDViewer: {
		"cert.read",
		"profile.read",
		"issuer.read",
		"target.read",
		"agent.read",
		"audit.read",
		// New CRIT-1 read-only perms
		"job.read",
		"approval.read",
		"policy.read",
		"team.read",
		"owner.read",
		"notification.read",
		"discovery.read",
		"network_scan.read",
		"healthcheck.read",
		"digest.read",
		"verification.read",
		"stats.read",
		"metrics.read",
	},

	RoleIDAgent: {
		"cert.read",
		"agent.heartbeat",
		"agent.job.poll",
		"agent.job.complete",
		"agent.job.report",
		// Agents submit discovery reports.
		"discovery.run",
	},

	RoleIDMCP: {
		// MCP gets operator-equivalent minus destructive ops.
		// Defense in depth for Claude / IDE integrations where
		// destructive verbs warrant additional scrutiny.
		"cert.read", "cert.issue", "cert.edit", "cert.revoke",
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit",
		"agent.read",
		"audit.read",
		// New CRIT-1 — read + non-destructive verbs
		"job.read", "job.cancel",
		"approval.read", "approval.approve", "approval.reject",
		"policy.read",
		"team.read", "owner.read",
		"notification.read", "notification.edit",
		"discovery.read", "discovery.claim",
		"network_scan.read", "network_scan.run",
		"healthcheck.read", "healthcheck.acknowledge",
		"digest.read",
		"verification.read", "verification.run",
		"stats.read", "metrics.read",
	},

	RoleIDCLI: {
		// CLI = operator-equivalent. Operators can scope down via
		// `certctl auth keys scope-down` if they want narrower CLI
		// access in production.
		"cert.read", "cert.issue", "cert.edit", "cert.revoke", "cert.delete",
		"profile.read", "profile.edit",
		"issuer.read", "issuer.edit",
		"target.read", "target.edit", "target.delete",
		"agent.read", "agent.edit",
		"audit.read",
		"auth.key.list", "auth.key.create", "auth.key.rotate",
		// New CRIT-1 — CLI gets operator-tier
		"job.read", "job.cancel",
		"approval.read", "approval.approve", "approval.reject",
		"policy.read", "policy.edit", "policy.delete",
		"team.read", "team.edit",
		"owner.read", "owner.edit",
		"notification.read", "notification.edit",
		"discovery.read", "discovery.run", "discovery.claim",
		"network_scan.read", "network_scan.edit", "network_scan.run",
		"healthcheck.read", "healthcheck.edit", "healthcheck.acknowledge",
		"digest.read", "digest.send",
		"verification.read", "verification.run",
		"stats.read", "metrics.read",
	},

	RoleIDAuditor: {
		// Phase 8 ships the auditor split. Phase 1 reserves the
		// role id + the read-only permission set so subsequent
		// phases don't have to renumber. Audit 2026-05-10 CRIT-1
		// closure intentionally adds NOTHING here — auditor pins
		// stay invariant at audit.read + audit.export.
		"audit.read",
		"audit.export",
	},
}
