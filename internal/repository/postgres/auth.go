package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// canonicalPermissionSet is built once at package init from the
// authdomain.CanonicalPermissions catalogue. Lookup is O(1); used by
// PermissionRepository.IsCanonical so the service layer can fail-fast
// before issuing a DB round-trip.
var canonicalPermissionSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(authdomain.CanonicalPermissions))
	for _, p := range authdomain.CanonicalPermissions {
		m[p] = struct{}{}
	}
	return m
}()

// =============================================================================
// TenantRepository
// =============================================================================

// TenantRepository is the postgres implementation of
// repository.TenantRepository.
type TenantRepository struct {
	db *sql.DB
}

// NewTenantRepository constructs a TenantRepository.
func NewTenantRepository(db *sql.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

func (r *TenantRepository) Get(ctx context.Context, id string) (*authdomain.Tenant, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at, updated_at FROM tenants WHERE id = $1`, id)
	var t authdomain.Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.Description, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrAuthNotFound
		}
		return nil, fmt.Errorf("tenant.get: %w", err)
	}
	return &t, nil
}

func (r *TenantRepository) List(ctx context.Context) ([]*authdomain.Tenant, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, description, created_at, updated_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("tenant.list: %w", err)
	}
	defer rows.Close()
	var out []*authdomain.Tenant
	for rows.Next() {
		var t authdomain.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("tenant.list scan: %w", err)
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (r *TenantRepository) EnsureDefault(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenants (id, name, description)
		VALUES ($1, 'default', 'Single-tenant default seeded by Bundle 1 Phase 1.')
		ON CONFLICT (id) DO NOTHING
	`, authdomain.DefaultTenantID)
	return err
}

// =============================================================================
// RoleRepository
// =============================================================================

// RoleRepository is the postgres implementation of repository.RoleRepository.
type RoleRepository struct {
	db *sql.DB
}

func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

func (r *RoleRepository) Get(ctx context.Context, id string) (*authdomain.Role, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, name, description, created_at, updated_at
		 FROM roles WHERE id = $1`, id)
	return scanRole(row)
}

func (r *RoleRepository) GetByName(ctx context.Context, tenantID, name string) (*authdomain.Role, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, name, description, created_at, updated_at
		 FROM roles WHERE tenant_id = $1 AND name = $2`, tenantID, name)
	return scanRole(row)
}

func (r *RoleRepository) List(ctx context.Context, tenantID string) ([]*authdomain.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, tenant_id, name, description, created_at, updated_at
		 FROM roles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("role.list: %w", err)
	}
	defer rows.Close()
	var out []*authdomain.Role
	for rows.Next() {
		var role authdomain.Role
		if err := rows.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("role.list scan: %w", err)
		}
		out = append(out, &role)
	}
	return out, rows.Err()
}

func (r *RoleRepository) Create(ctx context.Context, role *authdomain.Role) error {
	if role.ID == "" {
		role.ID = "r-" + uuid.NewString()
	}
	if role.TenantID == "" {
		role.TenantID = authdomain.DefaultTenantID
	}
	now := time.Now().UTC()
	if role.CreatedAt.IsZero() {
		role.CreatedAt = now
	}
	if role.UpdatedAt.IsZero() {
		role.UpdatedAt = now
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, role.ID, role.TenantID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrAuthDuplicateName
		}
		return fmt.Errorf("role.create: %w", err)
	}
	return nil
}

func (r *RoleRepository) Update(ctx context.Context, role *authdomain.Role) error {
	role.UpdatedAt = time.Now().UTC()
	res, err := r.db.ExecContext(ctx, `
		UPDATE roles SET name = $1, description = $2, updated_at = $3
		WHERE id = $4
	`, role.Name, role.Description, role.UpdatedAt, role.ID)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrAuthDuplicateName
		}
		return fmt.Errorf("role.update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrAuthNotFound
	}
	return nil
}

func (r *RoleRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return repository.ErrAuthRoleInUse
		}
		return fmt.Errorf("role.delete: %w", err)
	}
	return nil
}

func (r *RoleRepository) ListPermissions(ctx context.Context, roleID string) ([]*authdomain.RolePermission, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT rp.role_id, rp.permission_id, rp.scope_type, rp.scope_id
		FROM role_permissions rp
		WHERE rp.role_id = $1
		ORDER BY rp.permission_id, rp.scope_type
	`, roleID)
	if err != nil {
		return nil, fmt.Errorf("role.listPermissions: %w", err)
	}
	defer rows.Close()
	var out []*authdomain.RolePermission
	for rows.Next() {
		var rp authdomain.RolePermission
		var scopeType string
		var scopeID sql.NullString
		if err := rows.Scan(&rp.RoleID, &rp.PermissionID, &scopeType, &scopeID); err != nil {
			return nil, fmt.Errorf("role.listPermissions scan: %w", err)
		}
		rp.ScopeType = authdomain.ScopeType(scopeType)
		if scopeID.Valid {
			s := scopeID.String
			rp.ScopeID = &s
		}
		out = append(out, &rp)
	}
	return out, rows.Err()
}

func (r *RoleRepository) AddPermission(ctx context.Context, g *authdomain.RolePermission) error {
	// TODO(bundle-2): Bundle 1 Phase 12 deferral — scope_id is NOT
	// currently FK-constrained against the resource tables
	// (certificate_profiles, issuers). This means an operator can
	// grant a permission at scope_type=profile / scope_id=p-bogus
	// without the bogus profile existing; the gate still works
	// (no permission rows match the bogus scope at request time)
	// but a strict 404 on grant would be cleaner. Adding the FK
	// requires a migration that confirms every existing
	// role_permissions row references a real resource and is
	// tracked as Bundle 2 work. See
	// cowork/auth-bundle-1-prompt.md negative-test path #12.
	var scopeID interface{}
	if g.ScopeID != nil {
		scopeID = *g.ScopeID
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING
	`, g.RoleID, g.PermissionID, string(g.ScopeType), scopeID)
	if err != nil {
		return fmt.Errorf("role.addPermission: %w", err)
	}
	return nil
}

func (r *RoleRepository) RemovePermission(ctx context.Context, g *authdomain.RolePermission) error {
	var scopeIDArg interface{}
	scopeClause := "scope_id IS NULL"
	args := []interface{}{g.RoleID, g.PermissionID, string(g.ScopeType)}
	if g.ScopeID != nil {
		scopeClause = "scope_id = $4"
		scopeIDArg = *g.ScopeID
		args = append(args, scopeIDArg)
	}
	q := fmt.Sprintf(
		`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2 AND scope_type = $3 AND %s`,
		scopeClause)
	_, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("role.removePermission: %w", err)
	}
	return nil
}

func scanRole(row *sql.Row) (*authdomain.Role, error) {
	var role authdomain.Role
	if err := row.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrAuthNotFound
		}
		return nil, fmt.Errorf("role scan: %w", err)
	}
	return &role, nil
}

// =============================================================================
// PermissionRepository
// =============================================================================

type PermissionRepository struct {
	db *sql.DB
}

func NewPermissionRepository(db *sql.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

func (r *PermissionRepository) List(ctx context.Context) ([]*authdomain.Permission, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, namespace FROM permissions ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("permission.list: %w", err)
	}
	defer rows.Close()
	var out []*authdomain.Permission
	for rows.Next() {
		var p authdomain.Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Namespace); err != nil {
			return nil, fmt.Errorf("permission.list scan: %w", err)
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*authdomain.Permission, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, namespace FROM permissions WHERE name = $1`, name)
	var p authdomain.Permission
	if err := row.Scan(&p.ID, &p.Name, &p.Namespace); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrAuthNotFound
		}
		return nil, fmt.Errorf("permission.getByName: %w", err)
	}
	return &p, nil
}

// IsCanonical satisfies repository.PermissionRepository.
func (r *PermissionRepository) IsCanonical(name string) bool {
	_, ok := canonicalPermissionSet[name]
	return ok
}

// =============================================================================
// ActorRoleRepository
// =============================================================================

type ActorRoleRepository struct {
	db *sql.DB
}

func NewActorRoleRepository(db *sql.DB) *ActorRoleRepository {
	return &ActorRoleRepository{db: db}
}

func (r *ActorRoleRepository) ListByActor(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, tenantID string) ([]*authdomain.ActorRole, error) {
	// Audit 2026-05-11 A-1 — include scope_type + scope_id in the
	// SELECT so the GUI / MCP surface can render which scope an
	// actor's grant is bound to. Pre-fix, these columns were
	// persisted by Grant (HIGH-10 closure) but never surfaced on
	// read — operators couldn't see what they configured.
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, actor_id, actor_type, role_id, granted_at, expires_at, granted_by, tenant_id, scope_type, scope_id
		FROM actor_roles
		WHERE actor_id = $1 AND actor_type = $2 AND tenant_id = $3
		ORDER BY granted_at
	`, actorID, string(actorType), tenantID)
	if err != nil {
		return nil, fmt.Errorf("actorRole.listByActor: %w", err)
	}
	return scanActorRoles(rows)
}

func (r *ActorRoleRepository) ListByRole(ctx context.Context, roleID string) ([]*authdomain.ActorRole, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, actor_id, actor_type, role_id, granted_at, expires_at, granted_by, tenant_id, scope_type, scope_id
		FROM actor_roles
		WHERE role_id = $1
		ORDER BY granted_at
	`, roleID)
	if err != nil {
		return nil, fmt.Errorf("actorRole.listByRole: %w", err)
	}
	return scanActorRoles(rows)
}

func (r *ActorRoleRepository) Grant(ctx context.Context, ar *authdomain.ActorRole) error {
	if ar.ID == "" {
		ar.ID = "ar-" + uuid.NewString()
	}
	if ar.TenantID == "" {
		ar.TenantID = authdomain.DefaultTenantID
	}
	if ar.GrantedAt.IsZero() {
		ar.GrantedAt = time.Now().UTC()
	}
	if ar.GrantedBy == "" {
		ar.GrantedBy = "system"
	}
	var expires interface{}
	if ar.ExpiresAt != nil {
		expires = *ar.ExpiresAt
	}
	// Audit 2026-05-10 HIGH-10 — per-actor scope columns. Default to
	// "global"+NULL when the caller didn't supply them (back-compat
	// with pre-migration code paths). Migration 000043's schema-level
	// DEFAULT 'global' covers the same case; passing explicitly here
	// makes the Go-level write deterministic.
	scopeType := string(ar.ScopeType)
	if scopeType == "" {
		scopeType = string(authdomain.ScopeTypeGlobal)
	}
	var scopeID interface{}
	if ar.ScopeID != nil && *ar.ScopeID != "" {
		scopeID = *ar.ScopeID
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO actor_roles (id, actor_id, actor_type, role_id, granted_at, expires_at, granted_by, tenant_id, scope_type, scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (actor_id, actor_type, role_id, scope_type, scope_id, tenant_id) DO NOTHING
	`, ar.ID, ar.ActorID, string(ar.ActorType), ar.RoleID, ar.GrantedAt, expires, ar.GrantedBy, ar.TenantID, scopeType, scopeID)
	if err != nil {
		return fmt.Errorf("actorRole.grant: %w", err)
	}
	return nil
}

// Audit 2026-05-11 A-4 — scope-aware revoke. The pre-fix SQL omitted
// (scope_type, scope_id) from the WHERE clause; combined with HIGH-10's
// UNIQUE (actor_id, actor_type, role_id, scope_type, scope_id, tenant_id)
// uniqueness extension, an operator who granted the same role to the
// same actor at two different scopes had no selective-revoke path —
// every Revoke call nuked both rows. The new behaviour:
//
//   - opts.ScopeType == "" (legacy call shape): drop the scope from the
//     WHERE clause; delete every variant. Zero-row delete is NOT an
//     error (preserves the GUI's pre-A-4 idempotence contract).
//
//   - opts.ScopeType != "": narrow WHERE with
//     `scope_type = $5 AND scope_id IS NOT DISTINCT FROM $6` (the
//     IS-NOT-DISTINCT-FROM handles the `global → scope_id IS NULL`
//     case cleanly — Postgres `= NULL` would silently match nothing).
//     Zero-row delete IS an error (ErrActorRoleNotFound, mapped to
//     HTTP 404 upstream) so operators get feedback when they target a
//     scope variant that doesn't exist.
func (r *ActorRoleRepository) Revoke(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, roleID, tenantID string, opts repository.ActorRoleRevokeOptions) error {
	if opts.ScopeType == "" {
		// Legacy "revoke all variants" path. Zero-row delete = no-op.
		_, err := r.db.ExecContext(ctx, `
			DELETE FROM actor_roles
			WHERE actor_id = $1 AND actor_type = $2 AND role_id = $3 AND tenant_id = $4
		`, actorID, string(actorType), roleID, tenantID)
		if err != nil {
			return fmt.Errorf("actorRole.revoke: %w", err)
		}
		return nil
	}
	// Scoped path. `scope_id IS NOT DISTINCT FROM $6` makes
	// (global, NULL) match (global, NULL) cleanly — vanilla `=` would
	// drop on NULL ≠ NULL.
	var scopeID interface{}
	if opts.ScopeID != nil && *opts.ScopeID != "" {
		scopeID = *opts.ScopeID
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM actor_roles
		WHERE actor_id = $1
		  AND actor_type = $2
		  AND role_id = $3
		  AND tenant_id = $4
		  AND scope_type = $5
		  AND scope_id IS NOT DISTINCT FROM $6
	`, actorID, string(actorType), roleID, tenantID, string(opts.ScopeType), scopeID)
	if err != nil {
		return fmt.Errorf("actorRole.revoke: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrActorRoleNotFound
	}
	return nil
}

func (r *ActorRoleRepository) ListDistinctActors(ctx context.Context, tenantID string) ([]repository.ActorWithRoles, error) {
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT actor_id, actor_type,
		       array_agg(role_id ORDER BY role_id) AS role_ids
		FROM actor_roles
		WHERE tenant_id = $1
		  AND (expires_at IS NULL OR expires_at > NOW())
		GROUP BY actor_id, actor_type
		ORDER BY actor_id ASC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("actorRole.listDistinctActors: %w", err)
	}
	defer rows.Close()
	var out []repository.ActorWithRoles
	for rows.Next() {
		var a repository.ActorWithRoles
		var actorType string
		// pq.StringArray decodes the postgres array_agg result.
		var roles pq.StringArray
		if err := rows.Scan(&a.ActorID, &actorType, &roles); err != nil {
			return nil, fmt.Errorf("actorRole.listDistinctActors scan: %w", err)
		}
		a.ActorType = authdomain.ActorTypeValue(actorType)
		a.TenantID = tenantID
		a.RoleIDs = []string(roles)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *ActorRoleRepository) AdminExists(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}
	// Exclude the seeded synthetic demo actor so a demo deploy that
	// later switches to api-key mode can still bootstrap the first
	// real admin. Matches the carve-out documented on the interface.
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM actor_roles
		WHERE role_id = $1
		  AND tenant_id = $2
		  AND actor_id != $3
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, authdomain.RoleIDAdmin, tenantID, authdomain.DemoAnonActorID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("actorRole.adminExists: %w", err)
	}
	return count > 0, nil
}

func (r *ActorRoleRepository) EffectivePermissions(ctx context.Context, actorID string, actorType authdomain.ActorTypeValue, tenantID string) ([]repository.EffectivePermission, error) {
	// Audit 2026-05-11 A-1 — effective scope is the intersection of
	// the actor-role's scope (ar.scope_*) AND the role-permission's
	// scope (rp.scope_*). Pre-fix, only rp.scope_* was read; an
	// actor granted r-operator scoped to profile=p-prod silently
	// got every r-operator permission at every scope rp emitted
	// (typically global), defeating HIGH-10's per-actor scope knob.
	//
	// Matching rules (the inner CASE encodes them):
	//
	//   ar.scope    rp.scope    effective_scope
	//   ─────────   ─────────   ──────────────────────
	//   global      global      global / NULL
	//   global      profile=X   profile=X      (rp narrows)
	//   profile=X   global      profile=X      (ar narrows)
	//   profile=X   profile=X   profile=X      (both agree)
	//   profile=X   profile=Y   ROW DROPPED    (disjoint scopes — no permission flows)
	//   profile=X   issuer=*    ROW DROPPED    (scope-type mismatch)
	//
	// The HAVING-style filter is implemented via a subquery — Postgres
	// doesn't allow referencing a CASE alias from HAVING in a SELECT
	// DISTINCT context without a wrapping CTE.
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT permission_name, effective_scope_type, effective_scope_id
		FROM (
			SELECT
				p.name AS permission_name,
				CASE
					WHEN ar.scope_type = 'global' AND rp.scope_type = 'global' THEN 'global'
					WHEN ar.scope_type = 'global' THEN rp.scope_type
					WHEN rp.scope_type = 'global' THEN ar.scope_type
					WHEN ar.scope_type = rp.scope_type AND ar.scope_id IS NOT DISTINCT FROM rp.scope_id THEN ar.scope_type
					ELSE NULL
				END AS effective_scope_type,
				CASE
					WHEN ar.scope_type = 'global' AND rp.scope_type = 'global' THEN NULL
					WHEN ar.scope_type = 'global' THEN rp.scope_id
					WHEN rp.scope_type = 'global' THEN ar.scope_id
					WHEN ar.scope_type = rp.scope_type AND ar.scope_id IS NOT DISTINCT FROM rp.scope_id THEN ar.scope_id
					ELSE NULL
				END AS effective_scope_id
			FROM actor_roles ar
			JOIN role_permissions rp ON rp.role_id = ar.role_id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE ar.actor_id = $1
			  AND ar.actor_type = $2
			  AND ar.tenant_id = $3
			  AND (ar.expires_at IS NULL OR ar.expires_at > NOW())
		) AS intersected
		WHERE effective_scope_type IS NOT NULL
	`, actorID, string(actorType), tenantID)
	if err != nil {
		return nil, fmt.Errorf("actorRole.effective: %w", err)
	}
	defer rows.Close()
	var out []repository.EffectivePermission
	for rows.Next() {
		var ep repository.EffectivePermission
		var scopeType string
		var scopeID sql.NullString
		if err := rows.Scan(&ep.PermissionName, &scopeType, &scopeID); err != nil {
			return nil, fmt.Errorf("actorRole.effective scan: %w", err)
		}
		ep.ScopeType = authdomain.ScopeType(scopeType)
		if scopeID.Valid {
			s := scopeID.String
			ep.ScopeID = &s
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func scanActorRoles(rows *sql.Rows) ([]*authdomain.ActorRole, error) {
	defer rows.Close()
	var out []*authdomain.ActorRole
	for rows.Next() {
		var ar authdomain.ActorRole
		var actorType, scopeType string
		var expires sql.NullTime
		var scopeID sql.NullString
		// Audit 2026-05-11 A-1 — scope_type + scope_id are persisted
		// by Grant (HIGH-10 closure, migration 000043). Pre-fix they
		// were never scanned, so callers received ActorRole with
		// zero-value scope fields regardless of what the row held.
		// EffectivePermissions narrowing depends on these being
		// populated correctly.
		if err := rows.Scan(&ar.ID, &ar.ActorID, &actorType, &ar.RoleID, &ar.GrantedAt, &expires, &ar.GrantedBy, &ar.TenantID, &scopeType, &scopeID); err != nil {
			return nil, fmt.Errorf("actorRole scan: %w", err)
		}
		ar.ActorType = authdomain.ActorTypeValue(actorType)
		if expires.Valid {
			t := expires.Time
			ar.ExpiresAt = &t
		}
		ar.ScopeType = authdomain.ScopeType(scopeType)
		if scopeID.Valid {
			s := scopeID.String
			ar.ScopeID = &s
		}
		out = append(out, &ar)
	}
	return out, rows.Err()
}

// =============================================================================
// APIKeyRepository (Bundle 1 Phase 6 — bootstrap path)
// =============================================================================

// APIKeyRepository is the postgres implementation of
// repository.APIKeyRepository. Stores SHA-256 hashes only; the
// plaintext key value is never persisted.
type APIKeyRepository struct {
	db *sql.DB
}

// NewAPIKeyRepository constructs an APIKeyRepository.
func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

func (r *APIKeyRepository) Create(ctx context.Context, k *authdomain.APIKey) error {
	if k.ID == "" {
		k.ID = "ak-" + uuid.NewString()
	}
	if k.TenantID == "" {
		k.TenantID = authdomain.DefaultTenantID
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	var expires interface{}
	if k.ExpiresAt != nil {
		expires = *k.ExpiresAt
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, name, key_hash, tenant_id, admin, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, k.ID, k.Name, k.KeyHash, k.TenantID, k.Admin, k.CreatedBy, k.CreatedAt, expires)
	if err != nil {
		// Translate UNIQUE-constraint violations to the canonical
		// auth sentinel so the service layer can return 409.
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return repository.ErrAuthDuplicateName
		}
		return fmt.Errorf("apiKey.create: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) GetByName(ctx context.Context, name string) (*authdomain.APIKey, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, tenant_id, admin, created_by, created_at, expires_at, last_used_at
		FROM api_keys WHERE name = $1
	`, name)
	var k authdomain.APIKey
	var expires, lastUsed sql.NullTime
	if err := row.Scan(&k.ID, &k.Name, &k.KeyHash, &k.TenantID, &k.Admin, &k.CreatedBy, &k.CreatedAt, &expires, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrAuthNotFound
		}
		return nil, fmt.Errorf("apiKey.getByName: %w", err)
	}
	if expires.Valid {
		t := expires.Time
		k.ExpiresAt = &t
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}
	return &k, nil
}

func (r *APIKeyRepository) List(ctx context.Context, tenantID string) ([]*authdomain.APIKey, error) {
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, key_hash, tenant_id, admin, created_by, created_at, expires_at, last_used_at
		FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("apiKey.list: %w", err)
	}
	defer rows.Close()
	var out []*authdomain.APIKey
	for rows.Next() {
		var k authdomain.APIKey
		var expires, lastUsed sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.TenantID, &k.Admin, &k.CreatedBy, &k.CreatedAt, &expires, &lastUsed); err != nil {
			return nil, fmt.Errorf("apiKey.list scan: %w", err)
		}
		if expires.Valid {
			t := expires.Time
			k.ExpiresAt = &t
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			k.LastUsedAt = &t
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (r *APIKeyRepository) Delete(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM api_keys WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("apiKey.delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return repository.ErrAuthNotFound
	}
	return nil
}
