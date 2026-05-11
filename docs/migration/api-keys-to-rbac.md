# Migrating API keys to RBAC (v2.0.x → v2.1.0)

> Last reviewed: 2026-05-09

This is the upgrade guide for an existing certctl deployment moving
from v2.0.x's "every API key is admin or not" model to v2.1.0's
RBAC primitive. Everything keeps working through the upgrade - the
migration backfills every existing API key to the
`r-admin` role on first boot, so the pre-existing automation that
was using those keys does not change behavior. **However**, most
keys do not need full admin power; this guide walks the operator
through the post-upgrade scope-down flow.

## ⚠️ SECURITY: AUDIT YOUR API KEYS

v2.1.0 maps **every** existing `CERTCTL_API_KEYS_NAMED` entry
(and every legacy `CERTCTL_AUTH_SECRET`-synthesized key) to the
`r-admin` role on the first boot after migration 000029 applies.
This is the safe-for-back-compat default - your CI / agents / scripts
keep working without changes - but if you don't downgrade keys, every
key in your fleet has full admin permissions including bulk-revoke,
CRL admin, and CA hierarchy management.

**Run the scope-down flow before tagging the next release.** The
release notes for v2.1.0 lead with this callout for a reason.

## Upgrade flow

### 1. Apply the migration

The migration runner is idempotent. Re-applying is a no-op if the
schema is already at the target version. The five RBAC migrations
that ship in v2.1.0:

| Migration | What it does |
|---|---|
| `000029_rbac.up.sql` | Creates `tenants`, `roles`, `permissions`, `role_permissions`, `actor_roles`. Seeds 7 default roles + 33-permission catalogue + the synthetic `actor-demo-anon` admin grant. Backfills every named API key into `actor_roles` with the `r-admin` role. |
| `000030_rbac_admin_perms.up.sql` | Seeds 5 admin-only fine-grained permissions (`cert.bulk_revoke`, `crl.admin`, `scep.admin`, `est.admin`, `ca.hierarchy.manage`) into `r-admin` only. |
| `000031_api_keys.up.sql` | Creates the `api_keys` table for runtime-minted keys (day-0 bootstrap path). |
| `000032_audit_category.up.sql` | Adds `event_category` column to `audit_events` with the closed enum (`cert_lifecycle` / `auth` / `config`). |
| `000033_approval_kinds.up.sql` | Adds `approval_kind` + `payload` to `issuance_approval_requests` for the approval-bypass closure. |

The v2.1.0 server applies these on first boot. No operator
action is required other than running the upgrade.

### 2. Verify the backfill landed

```bash
# Inspect the seeded actor_roles rows. You should see one row per
# entry in CERTCTL_API_KEYS_NAMED (Admin=true keys → r-admin,
# Admin=false keys → r-viewer) plus the seeded actor-demo-anon
# admin row.
psql -d certctl -c "SELECT actor_id, role_id, granted_by, granted_at FROM actor_roles ORDER BY granted_at;"
```

If the table is empty, the boot-loader hook in
`cmd/server/auth_backfill.go::backfillNamedKeyActorRoles` did not
run; re-check that `CERTCTL_AUTH_TYPE` is `api-key` (the boot
hook is gated on `cfg.Auth.Type != none`).

### 3. List + scope-down keys

The `certctl-cli` ships a four-mode scope-down command. Pick the
mode that matches your fleet size + automation posture.

#### Interactive walk

```bash
certctl-cli auth keys scope-down
```

Walks every actor (skips the synthetic `actor-demo-anon`) and
prompts for a target role. Empty input keeps the existing role.
Type one of `admin`, `operator`, `viewer`, `agent`, `mcp`, `cli`,
`auditor` to replace.

#### Non-interactive JSON config (Helm post-upgrade hook)

```bash
cat > scope-down.json <<EOF
{
  "ci-bot":         "operator",
  "agent-prod-1":   "agent",
  "agent-prod-2":   "agent",
  "monitoring-bot": "viewer",
  "compliance-bot": "auditor"
}
EOF

certctl-cli auth keys scope-down --non-interactive ./scope-down.json
```

Empty role values revoke every current grant WITHOUT granting a
replacement; assign roles selectively with
`certctl-cli auth keys assign`.

#### Audit-driven suggestion

```bash
# Preview suggestions based on the last 30 days of audit history
certctl-cli auth keys scope-down --suggest

# Apply the suggestions
certctl-cli auth keys scope-down --suggest --apply
```

The classifier (pure function in `internal/cli/auth_scope_down.go::SuggestRoleFromAuditEvents`)
walks the actor's audit events and emits one of:

| Suggestion | Trigger |
|---|---|
| `admin` | Any auth.role.* / auth.key.* / ca.hierarchy.* / *.bulk_revoke / *.admin action |
| `mcp` | All observed actions are MCP-shaped (`mcp.*`) |
| `viewer` | All observed actions are read-only (`*.read` or `*.list`) |
| `agent` | All observed actions are agent-shaped (`agent.*`, `cert.read`, `cert.issue`) |
| `operator` | Cert / profile / target lifecycle mutations without admin signals |

The classifier is conservative - when in doubt, it prefers the
narrower role. The operator confirms each suggestion before any
mutation lands (unless `--apply` is set).

### 4. Mint a fresh admin via bootstrap (optional, for fresh deployments)

If you're standing up a fresh deployment instead of upgrading an
existing one, the bootstrap path mints the first admin key without
needing the operator to know the env-var format:

```bash
# Set the bootstrap token in the server environment.
export CERTCTL_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)

# Boot the server. Logs include "bootstrap endpoint enabled".
docker compose up -d

# Mint the first admin key.
curl -X POST $URL/api/v1/auth/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"token":"'$CERTCTL_BOOTSTRAP_TOKEN'","actor_name":"first-admin"}'
```

The response carries the plaintext `key_value` once. Capture it
and use it as the Bearer token for subsequent calls. Subsequent
bootstrap calls return HTTP 410 Gone.

See [`docs/operator/rbac.md`](../operator/rbac.md) for the full
bootstrap flow + the threat model.

## What changes for code that called `IsAdmin`

In v2.0.x, the five admin handlers checked `auth.IsAdmin(ctx)`
directly in the body. v2.1.0 moved those checks to
the router via the `auth.RequirePermission` middleware (wrapped
through the `rbacGate` helper in
`internal/api/router/router.go`). The behavior contract is
unchanged: `r-admin`-roled callers reach the handler, anyone else
gets HTTP 403 BEFORE the body runs.

If your code consumed `auth.IsAdmin` directly (it shouldn't - 
the helper is internal), the new convention is:

1. Wrap the route in `rbacGate(reg.Checker, "<perm>", handler)`
   in `router.go`.
2. Add the perm to `migrations/000030_rbac_admin_perms.up.sql`
   (or `migrations/000029_rbac.up.sql`'s catalogue).
3. Grant the perm to the right default roles.

The five admin-only fine-grained perms stay on `r-admin` only by
default. Operators delegate by creating custom roles with the
specific perm.

## Helm-specific upgrade

The certctl Helm chart applies migrations on container start via
the standard migrations runner. No chart changes are required;
the `helm upgrade` command runs identically:

```bash
helm upgrade certctl certctl/certctl \
  --version <new-version> \
  --reuse-values
```

Post-upgrade, the boot loader runs the named-key actor-role
backfill against the `CERTCTL_API_KEYS_NAMED` env-var-injected
into the deployment. The "AUDIT YOUR API KEYS" callout applies - 
add a post-upgrade Job to your release pipeline that runs
`certctl-cli auth keys scope-down --non-interactive` against a
checked-in JSON config, so the role narrowing is deterministic
across upgrade rollouts.

Example post-upgrade Job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: certctl-scope-down
spec:
  template:
    spec:
      containers:
 - name: scope-down
        image: ghcr.io/certctl-io/certctl-cli:<tag>
        command:
 - certctl-cli
 - auth
 - keys
 - scope-down
 - --non-interactive
 - /config/scope-down.json
        envFrom:
 - secretRef:
              name: certctl-cli-credentials
        volumeMounts:
 - name: scope-down-config
            mountPath: /config
      volumes:
 - name: scope-down-config
          configMap:
            name: certctl-scope-down-config
      restartPolicy: OnFailure
```

The ConfigMap holds the `{actor_id: role_id}` map; the Secret
holds the API key the Job uses to call `/v1/auth/keys/.../roles`.

## Docker Compose-specific upgrade

For `deploy/docker-compose.yml` deployments:

1. Pull the new images: `docker compose pull`
2. Verify your `CERTCTL_AUTH_TYPE` value before restarting. If it
   was `none` (the demo path), the post-upgrade server will boot
   in demo mode again - the synthetic `actor-demo-anon` admin
   covers every request, no scope-down is meaningful. If you're
   moving from `none` to `api-key` mode, set
   `CERTCTL_API_KEYS_NAMED` first, then restart.
3. `docker compose up -d` to apply.
4. `docker compose logs certctl-server | grep -i 'loaded persisted api_keys'`
   to verify the boot loader ran. The first-boot log line includes
   the count of keys loaded into the runtime keystore.
5. Run `certctl-cli auth keys scope-down` against the running
   server.

The five examples in `examples/` (acme-nginx, private-ca-traefik,
step-ca-haproxy, multi-issuer, acme-wildcard-dns01) all run in
demo mode (`CERTCTL_AUTH_TYPE=none`) and are unaffected by the
RBAC migration - the synthetic actor-demo-anon admin grant covers
every request.

## Verifying the upgrade landed

After the scope-down flow completes:

1. `certctl-cli auth me` while authenticated as each named key
   confirms the right `effective_permissions` for that role.
2. `psql -c "SELECT actor_id, array_agg(role_id ORDER BY role_id) FROM actor_roles GROUP BY actor_id;"`
   gives the full picture in one query.
3. The audit trail
   (`GET /api/v1/audit?category=auth`)
   shows the `auth.role.assign` and `auth.role.revoke` rows for
   every change you made - confirm via the GUI's
   `/audit?category=auth` view.
4. Read the updated [`docs/operator/rbac.md`](../operator/rbac.md)
   for day-2 RBAC management.

## Rollback

If the upgrade goes wrong, the down migrations exist in lockstep:

```bash
# Roll back via your migration runner (golang-migrate, Atlas, etc.).
# Migrations 000029-000033 each have a .down.sql that reverses the
# .up.sql. Down migrations are destructive on data added by the up
# migration (api_keys rows, role grants on actors, profile-edit
# approvals); take a backup first.
```

After rollback, the v2.0.x binary works against the v2.0.x
schema unchanged. The operator's API keys still authenticate (the
in-memory hash table is rebuilt from `CERTCTL_API_KEYS_NAMED` on
boot regardless of schema version).

## Cross-references

- [`docs/operator/rbac.md`](../operator/rbac.md) - the operator
  how-to for the new RBAC primitive
- [`docs/operator/auth-threat-model.md`](../operator/auth-threat-model.md) - 
  what the new controls defend against
- [`docs/reference/profiles.md`](../reference/profiles.md) - the
  approval-bypass closure on `RequiresApproval` profile edits
- [`docs/operator/security.md`](../operator/security.md) - the
  full security posture
- `CHANGELOG.md` - the v2.1.0 release notes lead with this guide
