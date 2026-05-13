// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// OIDCProviderRepository (Auth Bundle 2 Phase 2)
// =============================================================================

// OIDCProviderRepository is the postgres implementation of
// repository.OIDCProviderRepository.
type OIDCProviderRepository struct {
	db *sql.DB
}

// NewOIDCProviderRepository constructs an OIDCProviderRepository.
func NewOIDCProviderRepository(db *sql.DB) *OIDCProviderRepository {
	return &OIDCProviderRepository{db: db}
}

// Audit 2026-05-10 MED-9: `enabled` column added to the SELECT/INSERT/
// UPDATE column list. Migration 000042 added the column with default
// TRUE; existing rows are all enabled post-migration.
const oidcProviderColumns = `id, tenant_id, name, issuer_url, client_id,
		client_secret_encrypted, redirect_uri, groups_claim_path,
		groups_claim_format, fetch_userinfo, scopes,
		allowed_email_domains, iat_window_seconds,
		jwks_cache_ttl_seconds, enabled, created_at, updated_at`

func scanOIDCProvider(row interface{ Scan(...interface{}) error }) (*oidcdomain.OIDCProvider, error) {
	var p oidcdomain.OIDCProvider
	var scopes, domains pq.StringArray
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.IssuerURL, &p.ClientID,
		&p.ClientSecretEncrypted, &p.RedirectURI, &p.GroupsClaimPath,
		&p.GroupsClaimFormat, &p.FetchUserinfo, &scopes,
		&domains, &p.IATWindowSeconds,
		&p.JWKSCacheTTLSeconds, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	p.Scopes = []string(scopes)
	p.AllowedEmailDomains = []string(domains)
	return &p, nil
}

// List returns every configured OIDC provider in the tenant, ordered
// by created_at ASC for stable GUI rendering.
func (r *OIDCProviderRepository) List(ctx context.Context, tenantID string) ([]*oidcdomain.OIDCProvider, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE tenant_id = $1 ORDER BY created_at ASC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oidc_providers list: %w", err)
	}
	defer rows.Close()

	var out []*oidcdomain.OIDCProvider
	for rows.Next() {
		p, err := scanOIDCProvider(rows)
		if err != nil {
			return nil, fmt.Errorf("oidc_providers scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns one provider by id. ErrOIDCProviderNotFound on miss.
func (r *OIDCProviderRepository) Get(ctx context.Context, id string) (*oidcdomain.OIDCProvider, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE id = $1`, id)
	p, err := scanOIDCProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrOIDCProviderNotFound
		}
		return nil, fmt.Errorf("oidc_providers get: %w", err)
	}
	return p, nil
}

// GetByName returns one provider by (tenant_id, name).
func (r *OIDCProviderRepository) GetByName(ctx context.Context, tenantID, name string) (*oidcdomain.OIDCProvider, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE tenant_id = $1 AND name = $2`, tenantID, name)
	p, err := scanOIDCProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrOIDCProviderNotFound
		}
		return nil, fmt.Errorf("oidc_providers get_by_name: %w", err)
	}
	return p, nil
}

// Create persists a new provider. Caller MUST have called p.Validate()
// and encrypted ClientSecretEncrypted via internal/crypto/encryption.go.
// Translates SQLSTATE 23505 (unique_violation) to
// ErrOIDCProviderDuplicateName.
func (r *OIDCProviderRepository) Create(ctx context.Context, p *oidcdomain.OIDCProvider) error {
	// MED-9: persist `enabled` on Create. New providers default to
	// enabled=true; the schema column also has DEFAULT TRUE, so an
	// older client sending the pre-MED-9 row shape without the column
	// would still get enabled=true. We pass the field explicitly to
	// honor a `Enabled=false` create.
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO oidc_providers (
			id, tenant_id, name, issuer_url, client_id,
			client_secret_encrypted, redirect_uri, groups_claim_path,
			groups_claim_format, fetch_userinfo, scopes,
			allowed_email_domains, iat_window_seconds,
			jwks_cache_ttl_seconds, enabled
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		p.ID, p.TenantID, p.Name, p.IssuerURL, p.ClientID,
		p.ClientSecretEncrypted, p.RedirectURI, p.GroupsClaimPath,
		p.GroupsClaimFormat, p.FetchUserinfo, pq.StringArray(p.Scopes),
		pq.StringArray(p.AllowedEmailDomains), p.IATWindowSeconds,
		p.JWKSCacheTTLSeconds, p.Enabled,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrOIDCProviderDuplicateName
		}
		return fmt.Errorf("oidc_providers create: %w", err)
	}
	return nil
}

// Update writes the mutable fields back. Immutable: id, tenant_id,
// created_at. updated_at = NOW().
func (r *OIDCProviderRepository) Update(ctx context.Context, p *oidcdomain.OIDCProvider) error {
	// MED-9: persist `enabled` on Update so the toggle endpoint and
	// the regular update path share the same write surface.
	res, err := r.db.ExecContext(ctx, `
		UPDATE oidc_providers SET
			name = $2,
			issuer_url = $3,
			client_id = $4,
			client_secret_encrypted = $5,
			redirect_uri = $6,
			groups_claim_path = $7,
			groups_claim_format = $8,
			fetch_userinfo = $9,
			scopes = $10,
			allowed_email_domains = $11,
			iat_window_seconds = $12,
			jwks_cache_ttl_seconds = $13,
			enabled = $14,
			updated_at = NOW()
		WHERE id = $1`,
		p.ID, p.Name, p.IssuerURL, p.ClientID,
		p.ClientSecretEncrypted, p.RedirectURI, p.GroupsClaimPath,
		p.GroupsClaimFormat, p.FetchUserinfo, pq.StringArray(p.Scopes),
		pq.StringArray(p.AllowedEmailDomains), p.IATWindowSeconds,
		p.JWKSCacheTTLSeconds, p.Enabled,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrOIDCProviderDuplicateName
		}
		return fmt.Errorf("oidc_providers update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrOIDCProviderNotFound
	}
	return nil
}

// Delete removes a provider by id. Returns ErrOIDCProviderInUse on
// SQLSTATE 23503 (foreign_key_violation) — the users table's FK ON
// DELETE RESTRICT fires when authenticated users still reference
// this provider.
func (r *OIDCProviderRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM oidc_providers WHERE id = $1`, id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return repository.ErrOIDCProviderInUse
		}
		return fmt.Errorf("oidc_providers delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrOIDCProviderNotFound
	}
	return nil
}

// =============================================================================
// GroupRoleMappingRepository (Auth Bundle 2 Phase 2)
// =============================================================================

// GroupRoleMappingRepository is the postgres implementation of
// repository.GroupRoleMappingRepository.
type GroupRoleMappingRepository struct {
	db *sql.DB
}

// NewGroupRoleMappingRepository constructs a GroupRoleMappingRepository.
func NewGroupRoleMappingRepository(db *sql.DB) *GroupRoleMappingRepository {
	return &GroupRoleMappingRepository{db: db}
}

func scanGroupRoleMapping(row interface{ Scan(...interface{}) error }) (*oidcdomain.GroupRoleMapping, error) {
	var m oidcdomain.GroupRoleMapping
	if err := row.Scan(&m.ID, &m.TenantID, &m.ProviderID, &m.GroupName, &m.RoleID, &m.CreatedAt); err != nil {
		return nil, err
	}
	return &m, nil
}

// ListByProvider returns every mapping for the named provider, ordered
// group_name ASC.
func (r *GroupRoleMappingRepository) ListByProvider(ctx context.Context, providerID string) ([]*oidcdomain.GroupRoleMapping, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, tenant_id, provider_id, group_name, role_id, created_at
		FROM group_role_mappings
		WHERE provider_id = $1
		ORDER BY group_name ASC`, providerID)
	if err != nil {
		return nil, fmt.Errorf("group_role_mappings list_by_provider: %w", err)
	}
	defer rows.Close()

	var out []*oidcdomain.GroupRoleMapping
	for rows.Next() {
		m, err := scanGroupRoleMapping(rows)
		if err != nil {
			return nil, fmt.Errorf("group_role_mappings scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Get returns one mapping by id.
func (r *GroupRoleMappingRepository) Get(ctx context.Context, id string) (*oidcdomain.GroupRoleMapping, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, provider_id, group_name, role_id, created_at
		FROM group_role_mappings WHERE id = $1`, id)
	m, err := scanGroupRoleMapping(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrGroupRoleMappingNotFound
		}
		return nil, fmt.Errorf("group_role_mappings get: %w", err)
	}
	return m, nil
}

// Add persists a new mapping. Translates SQLSTATE 23505 into
// ErrGroupRoleMappingDuplicate.
func (r *GroupRoleMappingRepository) Add(ctx context.Context, m *oidcdomain.GroupRoleMapping) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO group_role_mappings (id, tenant_id, provider_id, group_name, role_id)
		VALUES ($1, $2, $3, $4, $5)`,
		m.ID, m.TenantID, m.ProviderID, m.GroupName, m.RoleID)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrGroupRoleMappingDuplicate
		}
		return fmt.Errorf("group_role_mappings add: %w", err)
	}
	return nil
}

// Remove deletes a mapping by id.
func (r *GroupRoleMappingRepository) Remove(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM group_role_mappings WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("group_role_mappings remove: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrGroupRoleMappingNotFound
	}
	return nil
}

// Map resolves IdP-supplied group names against the provider's
// mappings. Returns the deduplicated set of role IDs the user should
// hold. Empty group_names slice yields empty result; empty result
// means fail-closed (no roles, Phase 3 declines to mint a session).
func (r *GroupRoleMappingRepository) Map(ctx context.Context, providerID string, groupNames []string) ([]string, error) {
	if len(groupNames) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT role_id
		FROM group_role_mappings
		WHERE provider_id = $1 AND group_name = ANY($2)`,
		providerID, pq.StringArray(groupNames))
	if err != nil {
		return nil, fmt.Errorf("group_role_mappings map: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("group_role_mappings map scan: %w", err)
		}
		out = append(out, roleID)
	}
	return out, rows.Err()
}
