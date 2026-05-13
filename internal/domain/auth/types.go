// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package auth holds the RBAC domain types: tenants, roles, permissions,
// role-permission grants, and actor-role assignments. Bundle 1 Phase 1
// ships these as the schema primitive; Phase 2 wires the service layer,
// Phase 3 wires the middleware gate (auth.RequirePermission).
//
// Schema convention follows the rest of certctl per CLAUDE.md
// "Architecture Decisions": TEXT primary keys with prefixes (`t-`, `r-`,
// `p-`, `ar-`), TIMESTAMPTZ for time columns, idempotent migrations.
//
// Multi-tenant readiness: every identity-related row carries a TenantID.
// Bundle 1 ships single-tenant by default (one seeded "t-default" tenant);
// the future managed-service offering activates multi-tenant by adding
// tenants without a schema migration.
package auth

import "time"

// Tenant is a billing / isolation boundary. Bundle 1 ships single-tenant
// (one seeded "t-default" tenant); the column exists from day one so the
// future managed-service offering activates multi-tenant by adding
// tenants without a schema migration.
type Tenant struct {
	ID          string    `json:"id"` // prefix `t-`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Role is a named bag of permissions assigned to actors. Bundle 1 seeds
// seven default roles: admin, operator, viewer, agent, mcp, cli, auditor
// (auditor reserved for Phase 8). Operators can create custom roles via
// the RBAC API.
type Role struct {
	ID          string    `json:"id"` // prefix `r-`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission is a typed string in the canonical catalog (cert.*,
// profile.*, issuer.*, target.*, agent.*, audit.*, auth.role.*,
// auth.key.*, auth.bootstrap.*). Bundle 2 extends with auth.session.*
// and auth.oidc.* permissions. The schema treats permissions as rows
// for FK joins; the service layer treats them as opaque strings keyed
// by Name.
type Permission struct {
	ID        string `json:"id"` // prefix `p-`
	Name      string `json:"name"`
	Namespace string `json:"namespace"` // e.g. "cert", "auth.role"
}

// ScopeType enumerates what RolePermission.ScopeID refers to. Bundle 1
// MVP supports global, profile, issuer scopes; per-cert / per-deployment-
// target scoping deferred to a future bundle.
type ScopeType string

const (
	// ScopeTypeGlobal applies the permission across all resources.
	// ScopeID is NULL for ScopeTypeGlobal grants.
	ScopeTypeGlobal ScopeType = "global"

	// ScopeTypeProfile applies the permission only to the named
	// CertificateProfile (matched by ID).
	ScopeTypeProfile ScopeType = "profile"

	// ScopeTypeIssuer applies the permission only to the named Issuer
	// (matched by ID).
	ScopeTypeIssuer ScopeType = "issuer"
)

// RolePermission is a (role, permission, scope) triple. A role grants
// the permission at the named scope to all actors holding the role.
// Most rows are global-scoped (ScopeID NULL); per-profile and per-issuer
// scopes are operator-configurable.
type RolePermission struct {
	RoleID       string    `json:"role_id"`
	PermissionID string    `json:"permission_id"`
	ScopeType    ScopeType `json:"scope_type"`
	ScopeID      *string   `json:"scope_id,omitempty"` // NULL for global
}

// ActorRole assigns a Role to an Actor (an API key, an OIDC-federated
// user, an agent, or the synthetic demo-anon actor). The schema reserves
// ExpiresAt + GrantedBy columns so future time-bound grants and JIT
// elevation can be added without a migration.
type ActorRole struct {
	ID        string         `json:"id"` // prefix `ar-`
	ActorID   string         `json:"actor_id"`
	ActorType ActorTypeValue `json:"actor_type"`
	RoleID    string         `json:"role_id"`
	GrantedAt time.Time      `json:"granted_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	GrantedBy string         `json:"granted_by"`
	TenantID  string         `json:"tenant_id"`

	// Audit 2026-05-10 HIGH-10 closure — per-actor scope override on
	// the grant. Pre-fix, scope was per-role only; now operators can
	// grant the standing r-operator role to Alice scoped to profile-X
	// via (ScopeType="profile", ScopeID="p-X"). Authorizer.CheckPermission
	// already understands the tuple via role_permissions. Migration
	// 000043 ships the schema columns + uniqueness extension.
	//
	// ScopeType ∈ {global, profile, issuer}. Empty/missing defaults
	// to "global" at the persistence layer (schema column DEFAULT).
	// ScopeID is required when ScopeType != "global"; nil otherwise.
	ScopeType ScopeType `json:"scope_type,omitempty"`
	ScopeID   *string   `json:"scope_id,omitempty"`
}

// ActorTypeValue is the typed-string actor identifier used in
// ActorRole.ActorType. It mirrors the values in
// internal/domain.ActorType (User, System, Agent, APIKey, Anonymous);
// callers should reference internal/domain constants directly when
// possible. This package-local alias exists so the auth subpackage
// avoids importing the parent domain package and creating a cycle.
type ActorTypeValue string
