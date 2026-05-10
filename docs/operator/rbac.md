# RBAC operator reference

> Last reviewed: 2026-05-09

This is the operator-facing reference for the role-based access
control primitive that ships with Bundle 1 (auth bundle 1) of certctl.
Read this if you're running certctl in production and need to grant /
revoke access to API keys, set up the auditor split, or onboard the
first admin.

For the threat model behind these controls, see
[`auth-threat-model.md`](auth-threat-model.md). For the migration
flow from a pre-Bundle-1 deployment, see
[`docs/migration/api-keys-to-rbac.md`](../migration/api-keys-to-rbac.md).

## Mental model

Every action against the certctl HTTP / CLI / MCP / GUI surface is
performed by an **actor** (an API key, an agent's machine identity,
the synthetic demo-anon actor when the server runs in
`CERTCTL_AUTH_TYPE=none` mode). Each actor holds zero or more
**roles**. Each role grants a set of **permissions** at a **scope**.
A request to a gated endpoint succeeds when the actor's effective
permission set (the union across all held roles) contains the
permission the endpoint requires.

The schema lives in `migrations/000029_rbac.up.sql` and ships with
seven seeded default roles + a 33-permission canonical catalogue.
The middleware that gates requests lives at
`internal/auth/require_permission.go`. The service-layer authorizer
that resolves "actor → permissions" lives at
`internal/service/auth/authorizer.go`.

## Default roles (seeded by migration 000029)

| Role | ID | Use case | Permission shape |
|---|---|---|---|
| Admin | `r-admin` | Operator with full control | Every permission in the canonical catalogue |
| Operator | `r-operator` | Day-to-day cert lifecycle | `cert.*`, `profile.read`, `issuer.read`, `target.*`, `agent.read`, `audit.read` |
| Viewer | `r-viewer` | Read-only console access | `*.read` for every resource type |
| Agent | `r-agent` | Machine identity for `certctl-agent` | `cert.read` + `agent.heartbeat` + `agent.job.poll` + `agent.job.complete` + `agent.job.report` |
| MCP | `r-mcp` | Operator-equivalent for the MCP server, minus destructive ops | Like Operator without `*.delete` |
| CLI | `r-cli` | Day-to-day operator CLI | Like Operator + `auth.key.list` / `auth.key.create` / `auth.key.rotate` |
| Auditor | `r-auditor` | Compliance reviewer | `audit.read` + `audit.export` ONLY |

**Note on actor-type binding (Audit 2026-05-10 LOW-8):** Roles in
the catalogue are NOT bound to a specific `actor_type`. `r-mcp` is
named for clarity ("the role MCP service accounts hold") but the
schema permits granting it to any actor — including a human OIDC
user. Same goes for `r-cli` and `r-agent`. The role-grant API accepts
`{actor_id, actor_type, role_id}` tuples; the `actor_type` constraint
lives on the grant row, not the role definition. Operators who want
to enforce "only API-key actors hold r-mcp" should write that as an
operator-side policy + verify via a periodic audit query against
`actor_roles` joined to `api_keys` / `users`. Native role-to-
actor-type binding is on the v2 roadmap.

The auditor split is the load-bearing one: an auditor cannot read
certificates, profiles, or issuers - only audit events. That makes the
role legitimate to hand to a SOC 2 / FedRAMP / PCI auditor without
giving them the keys to the kingdom. The
`internal/domain/auth/auditor_test.go` invariants pin this set going
forward.

The five **admin-only fine-grained perms** seeded by migration
000030 (Phase 3.5 conversion) gate the high-blast-radius endpoints:

- `cert.bulk_revoke` - `POST /api/v1/certificates/bulk-revoke` and the EST sibling
- `crl.admin` - `/api/v1/admin/crl/cache`
- `scep.admin` - `/api/v1/admin/scep/intune/*`
- `est.admin` - `/api/v1/admin/est/*`
- `ca.hierarchy.manage` - `/api/v1/issuers/{id}/intermediates`, `/api/v1/intermediates/{id}`

Only `r-admin` holds these by default. To delegate one, create a
custom role with the specific perm and grant it to the right actor.

## Permission catalogue

The catalogue is namespaced. Permission strings are stable across
releases; new permissions add to the namespace, never reshape an
existing one. Run
`certctl-cli auth permissions list` (or `GET /api/v1/auth/permissions`)
for the live catalogue.

| Namespace | Examples | What the namespace gates |
|---|---|---|
| `cert.*` | `cert.read`, `cert.issue`, `cert.revoke`, `cert.delete`, `cert.bulk_revoke` | The certificate lifecycle surface (`/api/v1/certificates`) |
| `profile.*` | `profile.read`, `profile.edit`, `profile.delete` | `CertificateProfile` CRUD |
| `issuer.*` | `issuer.read`, `issuer.edit`, `issuer.delete` | Issuer connector config |
| `target.*` | `target.read`, `target.edit`, `target.delete` | Deployment target config |
| `agent.*` | `agent.read`, `agent.edit`, `agent.retire`, `agent.heartbeat`, `agent.job.*` | Agent fleet + agent self-service endpoints |
| `audit.*` | `audit.read`, `audit.export` | The audit-events surface |
| `auth.role.*` | `auth.role.list`, `auth.role.create`, `auth.role.edit`, `auth.role.delete`, `auth.role.assign` | RBAC management |
| `auth.key.*` | `auth.key.list`, `auth.key.create`, `auth.key.rotate`, `auth.key.delete` | API key management |
| `auth.bootstrap.*` | `auth.bootstrap.use` | Day-0 first-admin path |
| `crl.admin`, `scep.admin`, `est.admin`, `ca.hierarchy.manage` | (single perms) | The five admin-only fine-grained perms (see above) |
| `job.*` | `job.read`, `job.cancel` | Deployment job lifecycle |
| `approval.*` | `approval.read`, `approval.approve`, `approval.reject` | Two-person approval workflow (cert-issuance + profile-edit) |
| `policy.*` | `policy.read`, `policy.edit`, `policy.delete` | Compliance policies + renewal policies |
| `team.*`, `owner.*` | `team.read`, `team.edit`, `team.delete`, `owner.*` | Organizational metadata |
| `notification.*` | `notification.read`, `notification.edit` | Notification queue + requeue |
| `discovery.*` | `discovery.read`, `discovery.run`, `discovery.claim` | Agent + cloud-secret-store discovery |
| `network_scan.*` | `network_scan.read`, `network_scan.edit`, `network_scan.run` | TLS network scanning + SCEP probing |
| `healthcheck.*` | `healthcheck.read`, `healthcheck.edit`, `healthcheck.delete`, `healthcheck.acknowledge` | Uptime monitors |
| `digest.*` | `digest.read`, `digest.send` | Operator-summary digest emails |
| `verification.*` | `verification.read`, `verification.run` | Post-deploy verification |
| `stats.read`, `metrics.read` | (single perms) | Dashboard summary + Prometheus exposition |

The full catalogue lives in
[`internal/domain/auth/validate.go`](../../internal/domain/auth/validate.go).
The router-level enforcement sits in
[`internal/api/router/router.go`](../../internal/api/router/router.go);
the AST-level CI guard
[`TestRouterRBACGateCoverage`](../../internal/api/router/router_rbac_coverage_test.go)
pins the contract — adding a new state-changing or read endpoint
without an `rbacGate` / `rbacGateScoped` wrap fails CI.

## Scope semantics

Permissions are granted at one of three scopes:

- **`global`** - applies to every resource in the tenant. The
  default for the seeded role grants. A `cert.read` grant at global
  scope lets the actor read any certificate.
- **`profile`** - applies only to the named `CertificateProfile`
  (matched by ID). `cert.issue` at scope `profile`/`p-corp-cdn` lets
  the actor issue against `p-corp-cdn` only.
- **`issuer`** - applies only to the named issuer. Lets you grant
  `issuer.edit` on the production issuer to a senior operator
  without giving them edit on every issuer.

Global beats specific: an actor with `cert.read` at global scope
passes a `cert.read` check against any specific profile or issuer
even if no scoped grant exists. The reverse is also true - a
scoped grant doesn't satisfy a request against a different scope.
The Authorizer's `CheckPermission` is the single point of truth.

> **Note (Bundle 1 deferral):** the `scope_id` column is not
> currently FK-constrained against the resource tables. An
> operator can grant a permission at scope `profile`/`p-bogus`
> without `p-bogus` existing; the gate still works (no rows match
> at request time), but the API does not 404 the grant. Bundle 2
> tracks the strict-FK closure. See
> `internal/repository/postgres/auth.go::AddPermission`'s
> `TODO(bundle-2)` comment.

## Granting + revoking access

### From the GUI

`/auth/roles` lists every role; click into one to see its
permissions and (if you hold `auth.role.edit`) add or remove a
permission. `/auth/keys` lists every actor with role grants;
click "Assign role" to grant, click the × on a role tag to revoke.

The synthetic `actor-demo-anon` row is shown but flagged
"system-managed" with the mutation buttons hidden - the server-side
reserved-actor guard rejects mutations against it regardless.

### From the CLI

```bash
# Identity probe - what can the current API key actually do?
certctl-cli auth me

# Roles
certctl-cli auth roles list
certctl-cli auth roles get r-admin

# Permissions catalogue
certctl-cli auth permissions list

# Key → role assignment
certctl-cli auth keys list
certctl-cli auth keys assign alice --role r-operator
certctl-cli auth keys revoke alice --role r-admin

# Walk-every-key prompt for downgrade
certctl-cli auth keys scope-down

# Audit-driven role suggestion (last 30 days of audit events)
certctl-cli auth keys scope-down --suggest
certctl-cli auth keys scope-down --suggest --apply

# JSON-driven scope-down for automation (Helm post-upgrade hook etc.)
certctl-cli auth keys scope-down --non-interactive ./scope-down.json
```

The mutating role-lifecycle commands (`certctl-cli auth roles
create / update / delete` + `roles add-permission / remove-permission`)
are tracked as Bundle 1 Phase 5.5 follow-up; today, manage custom
roles via the HTTP API or GUI.

### From the HTTP API

Every endpoint is documented in `api/openapi.yaml` under the `[Auth]`
tag. Quick reference:

| Endpoint | Permission |
|---|---|
| `GET /v1/auth/me` | (none - own data) |
| `GET /v1/auth/roles` | `auth.role.list` |
| `GET /v1/auth/roles/{id}` | `auth.role.list` |
| `POST /v1/auth/roles` | `auth.role.create` |
| `PUT /v1/auth/roles/{id}` | `auth.role.edit` |
| `DELETE /v1/auth/roles/{id}` | `auth.role.delete` |
| `GET /v1/auth/permissions` | `auth.role.list` |
| `POST /v1/auth/roles/{id}/permissions` | `auth.role.edit` |
| `DELETE /v1/auth/roles/{id}/permissions/{perm}` | `auth.role.edit` |
| `GET /v1/auth/keys` | `auth.role.list` |
| `POST /v1/auth/keys/{id}/roles` | `auth.role.assign` |
| `DELETE /v1/auth/keys/{id}/roles/{role_id}` | `auth.role.assign` |
| `GET /v1/auth/check` | (authenticated; surfaces effective perms) |
| `GET /v1/auth/bootstrap` + `POST /v1/auth/bootstrap` | (auth-exempt; gated by env-var token) |

### From the MCP server

Bundle 1 Phase 11 ships 12 RBAC tools:
`certctl_auth_me`, `certctl_auth_list_roles`, `certctl_auth_get_role`,
`certctl_auth_create_role`, `certctl_auth_update_role`,
`certctl_auth_delete_role`, `certctl_auth_list_permissions`,
`certctl_auth_add_permission_to_role`,
`certctl_auth_remove_permission_from_role`,
`certctl_auth_list_keys`, `certctl_auth_assign_role_to_key`,
`certctl_auth_revoke_role_from_key`. Each routes through the same
HTTP surface above; permission gates fire server-side.

## The auditor pattern

Hand the auditor key to compliance reviewers. They get:

- `GET /api/v1/audit?category=auth` - every auth/authz mutation
  in the system (role creates, role grants on actors, bootstrap
  consumption, etc.).
- `GET /api/v1/audit?category=cert_lifecycle` - every cert event.
- `GET /api/v1/audit?category=config` - every issuer / target /
  settings edit.
- `GET /api/v1/audit/export` - bulk export.

They do NOT get cert read, profile read, issuer read, or any
mutating permission. The categorization is enforced by the database
CHECK constraint (migration 000032); the WORM trigger from
migration 000018 keeps the audit table append-only at the DB layer.

To create an auditor key:

1. `certctl-cli auth keys assign <key-id> --role r-auditor`
2. (Optional) Revoke any other roles the key holds with
   `certctl-cli auth keys revoke <key-id> --role r-...`
3. Confirm via `certctl-cli auth me` while authenticated as the
   auditor key - the response should show only `audit.read` and
   `audit.export` in `effective_permissions`.

## Day-0 bootstrap (first-admin path)

Bundle 1 Phase 6 ships a one-shot bootstrap endpoint for fresh
deployments where no admin actor exists yet.

1. Set `CERTCTL_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)` in the
   server environment.
2. Boot the server. Logs include
   "bootstrap endpoint enabled - POST /api/v1/auth/bootstrap to
   mint the first admin key (one-shot)" when the path is callable.
3. Run a single curl:

   ```bash
   curl -X POST $URL/api/v1/auth/bootstrap \
     -H 'Content-Type: application/json' \
     -d '{"token":"<the-token>","actor_name":"first-admin"}'
   ```

4. Capture the `key_value` from the response. **It is shown ONCE.**
   The server never logs it.
5. Use the new key to authenticate against the rest of the API.
   The bootstrap path is now closed: subsequent calls return HTTP
   410 Gone, even with the same valid token, because an admin
   actor exists.

The token is constant-time-compared. The server logs a startup
warning if `CERTCTL_BOOTSTRAP_TOKEN` is set AND admin actors
already exist (config-drift signal). For OIDC-first-admin (the
"first user who signs in via SSO becomes admin" pattern), wait for
Bundle 2.

## Demo mode (`CERTCTL_AUTH_TYPE=none`)

When auth is disabled, the server injects a synthetic actor
`actor-demo-anon` into every request context. That actor holds
`r-admin` at global scope (seeded by migration 000029), so every
gated route resolves with a populated actor and admin grants. The
synthetic actor is reserved: the API rejects any mutation that
targets it (HTTP 409 with `ErrAuthReservedActor`).

Production deployments MUST NOT use demo mode - there is no
per-request actor identity for the audit trail, and every request
flows as admin. Use it for the `docker compose up` demo + the five
example folders only.

## Where to look next

- [Threat model](auth-threat-model.md) - what attacks this primitive
  defends against and which it does not
- [Migration guide](../migration/api-keys-to-rbac.md) - moving
  pre-Bundle-1 deployments onto RBAC
- [Profiles](../reference/profiles.md) - the `RequiresApproval=true`
  flow that Bundle 1 Phase 9 closure protects from flip-flop
- [Approval workflow](approval-workflow.md) - the Rank 7 Infisical
  deep-research deliverable that the Phase 9 closure piggybacks on
- `internal/auth/` - the middleware + keystore + RequirePermission
- `internal/service/auth/` - the service-layer Authorizer
- `cowork/auth-bundle-1-prompt.md` - the design + phase plan
- `cowork/auth-bundles-index.md` - the per-phase status tracker
