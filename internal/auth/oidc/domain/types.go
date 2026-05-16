// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package domain holds the OIDC integration's persisted-shape types.
//
// Auth Bundle 2 Phase 1: types only, no service or repository wiring.
// Phase 2 ships the SQL migration that materializes these into tables;
// Phase 3 ships the service layer that consumes them.
//
// Layout convention follows the rest of certctl per CLAUDE.md
// "Architecture Decisions": TEXT primary keys with prefixes (`op-`,
// `grm-`), TIMESTAMPTZ for time columns, idempotent migrations,
// `tenant_id` on every identity-related row from day one for the
// future managed-service multi-tenant activation.
package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/validation"
)

// OIDCProvider describes a configured OpenID Connect identity provider
// (Okta / Azure AD / Google Workspace / Keycloak / Authentik / Auth0).
// Stored as a row per provider; certctl supports N providers from day
// one (per the forward-compat seam in the prompt) so a future managed
// customer can plug in multiple IdPs.
//
// `client_secret_encrypted` is opaque from this layer's POV: it is the
// v2 blob (`magic byte 0x02 || salt(16) || nonce(12) || ciphertext+tag`)
// produced by `internal/crypto/encryption.go`. Validation here checks
// the field is non-empty + carries the v2 magic byte; actual
// encryption / decryption happens in the service layer.
type OIDCProvider struct {
	ID                    string   `json:"id"` // prefix `op-`
	TenantID              string   `json:"tenant_id"`
	Name                  string   `json:"name"`
	IssuerURL             string   `json:"issuer_url"`
	ClientID              string   `json:"client_id"`
	ClientSecretEncrypted []byte   `json:"-"` // v2 blob; never JSON-encoded
	RedirectURI           string   `json:"redirect_uri"`
	GroupsClaimPath       string   `json:"groups_claim_path"`
	GroupsClaimFormat     string   `json:"groups_claim_format"`
	FetchUserinfo         bool     `json:"fetch_userinfo"`
	Scopes                []string `json:"scopes"`
	AllowedEmailDomains   []string `json:"allowed_email_domains"`
	IATWindowSeconds      int      `json:"iat_window_seconds"`
	JWKSCacheTTLSeconds   int      `json:"jwks_cache_ttl_seconds"`
	// Enabled gates whether the provider is offered on the LoginPage and
	// accepted at HandleAuthRequest. Audit 2026-05-10 MED-9 closure:
	// pre-fix the only way to take a provider offline was DELETE (which
	// breaks active user_oidc_provider FK references); now operators can
	// flip Enabled=false to keep the row + group mappings around while
	// suppressing new logins. Default true (existing rows are enabled
	// post-migration).
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GroupRoleMapping maps a group name (string from the IdP's group
// claim) to a certctl role id. Operators configure these via the GUI's
// Group→Role Mapping page (Phase 8). Name-based per the forward-compat
// seam: if the IdP renames a group, the operator updates the mapping.
// This avoids depending on IdP-internal identifiers (which differ per
// IdP and resist documentation).
type GroupRoleMapping struct {
	ID         string    `json:"id"` // prefix `grm-`
	ProviderID string    `json:"provider_id"`
	GroupName  string    `json:"group_name"`
	RoleID     string    `json:"role_id"`
	TenantID   string    `json:"tenant_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// OIDCProvider configuration constants.
const (
	// GroupsClaimFormatStringArray expects the resolved claim to be
	// `[]string` directly (the default; matches Okta / Auth0 standard
	// `groups` claim, Azure AD object-ID claims, etc.).
	GroupsClaimFormatStringArray = "string-array"

	// GroupsClaimFormatJSONPath expects the resolved claim to need
	// path-walking into a nested object (e.g. Keycloak's
	// `realm_access.roles`). The hand-rolled resolver in
	// `internal/auth/oidc/groupclaim/` walks dot-separated paths
	// through nested `map[string]interface{}` chains. URL-shape paths
	// (`https://your-namespace/groups`) are treated as a single
	// literal key.
	GroupsClaimFormatJSONPath = "json-path"

	// DefaultGroupsClaimPath is the OIDC convention for the group
	// claim. Most IdPs default to this.
	DefaultGroupsClaimPath = "groups"

	// DefaultIATWindowSeconds is the maximum age of an ID token's
	// `iat` claim that the verifier accepts, in seconds. 300s = 5
	// minutes. Phase 3 service caps the configurable value at 600s.
	DefaultIATWindowSeconds = 300

	// MaxIATWindowSeconds is the upper bound on configurable IAT
	// windows. Beyond 10 minutes the replay-attack window is too
	// permissive.
	MaxIATWindowSeconds = 600

	// DefaultJWKSCacheTTLSeconds caps how long the JWKS cache stays
	// stale before a refresh. 1 hour. Min configurable: 60s.
	DefaultJWKSCacheTTLSeconds = 3600

	// MinJWKSCacheTTLSeconds is the floor for the JWKS cache TTL.
	// Anything lower than 60s would cause excessive JWKS endpoint
	// traffic at the IdP.
	MinJWKSCacheTTLSeconds = 60
)

// Domain validation errors. Service layer maps these to HTTP 400.
var (
	ErrOIDCInvalidID                  = errors.New("oidc: id must start with 'op-'")
	ErrOIDCEmptyName                  = errors.New("oidc: name is required")
	ErrOIDCIssuerNotHTTPS             = errors.New("oidc: issuer_url must be https://")
	ErrOIDCEmptyClientID              = errors.New("oidc: client_id is required")
	ErrOIDCEmptyClientSecret          = errors.New("oidc: client_secret_encrypted is required")
	ErrOIDCRedirectNotHTTPS           = errors.New("oidc: redirect_uri must be https://")
	ErrOIDCInvalidGroupsClaimFormat   = errors.New("oidc: groups_claim_format must be 'string-array' or 'json-path'")
	ErrOIDCMissingOpenIDScope         = errors.New("oidc: scopes must include 'openid' (RFC 6749 + OIDC core require it)")
	ErrOIDCInvalidIATWindow           = errors.New("oidc: iat_window_seconds must be > 0 and <= 600")
	ErrOIDCInvalidJWKSCacheTTL        = errors.New("oidc: jwks_cache_ttl_seconds must be >= 60")
	ErrOIDCEmptyTenantID              = errors.New("oidc: tenant_id is required")
	ErrGroupRoleMappingInvalidID      = errors.New("oidc: group-role mapping id must start with 'grm-'")
	ErrGroupRoleMappingInvalidProvID  = errors.New("oidc: group-role mapping provider_id must start with 'op-'")
	ErrGroupRoleMappingEmptyGroupName = errors.New("oidc: group-role mapping group_name is required")
	ErrGroupRoleMappingInvalidRoleID  = errors.New("oidc: group-role mapping role_id must start with 'r-'")
	ErrGroupRoleMappingEmptyTenantID  = errors.New("oidc: group-role mapping tenant_id is required")
)

// Validate runs the persisted-shape invariants on an OIDCProvider.
// Returns the first error encountered. Service-layer callers (Phase 3)
// invoke Validate() before persisting / accepting input from operator
// API calls.
//
// Defaults applied in-place when fields are unset (zero values are
// upgraded to their canonical defaults). Callers SHOULD pass a
// pointer-mutable instance.
func (p *OIDCProvider) Validate() error {
	if !strings.HasPrefix(p.ID, "op-") {
		return ErrOIDCInvalidID
	}
	if strings.TrimSpace(p.Name) == "" {
		return ErrOIDCEmptyName
	}
	// Phase 3 contract: JWKS endpoint MUST be HTTPS. Reject at
	// provider creation time.
	if !strings.HasPrefix(p.IssuerURL, "https://") {
		return ErrOIDCIssuerNotHTTPS
	}
	if _, err := url.Parse(p.IssuerURL); err != nil {
		return fmt.Errorf("oidc: issuer_url is not a valid URL: %w", err)
	}
	// SEC-001 closure (Sprint 1, 2026-05-16): reject reserved-address
	// issuers (loopback / RFC 1918 / link-local / cloud metadata) at
	// provider-creation time. Defense-in-depth alongside
	// oidc.SafeOIDCContext, which is the authoritative dial-time
	// re-resolution + reject. The static URL check stops the obvious
	// case ("https://169.254.169.254/...") before the row is persisted
	// or the dry-run validator runs.
	if err := validation.ValidateSafeURL(p.IssuerURL); err != nil {
		return fmt.Errorf("oidc: issuer_url failed SSRF policy: %w", err)
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return ErrOIDCEmptyClientID
	}
	if len(p.ClientSecretEncrypted) == 0 {
		return ErrOIDCEmptyClientSecret
	}
	// Phase 3 contract: control plane is HTTPS-only post v2.0.47, so
	// the redirect_uri MUST be https. No loopback exception (the test
	// IdP harness in Phase 10 runs Keycloak in a docker network with
	// HTTPS endpoints; localhost http isn't a supported deploy mode).
	if !strings.HasPrefix(p.RedirectURI, "https://") {
		return ErrOIDCRedirectNotHTTPS
	}
	if _, err := url.Parse(p.RedirectURI); err != nil {
		return fmt.Errorf("oidc: redirect_uri is not a valid URL: %w", err)
	}
	// Default the claim path / format if unset.
	if p.GroupsClaimPath == "" {
		p.GroupsClaimPath = DefaultGroupsClaimPath
	}
	if p.GroupsClaimFormat == "" {
		p.GroupsClaimFormat = GroupsClaimFormatStringArray
	}
	switch p.GroupsClaimFormat {
	case GroupsClaimFormatStringArray, GroupsClaimFormatJSONPath:
		// ok
	default:
		return ErrOIDCInvalidGroupsClaimFormat
	}
	// Default scopes if empty; ensure "openid" is present.
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "profile", "email"}
	}
	hasOpenID := false
	for _, s := range p.Scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return ErrOIDCMissingOpenIDScope
	}
	// IAT window default + bounds.
	if p.IATWindowSeconds == 0 {
		p.IATWindowSeconds = DefaultIATWindowSeconds
	}
	if p.IATWindowSeconds <= 0 || p.IATWindowSeconds > MaxIATWindowSeconds {
		return ErrOIDCInvalidIATWindow
	}
	// JWKS cache TTL default + bounds.
	if p.JWKSCacheTTLSeconds == 0 {
		p.JWKSCacheTTLSeconds = DefaultJWKSCacheTTLSeconds
	}
	if p.JWKSCacheTTLSeconds < MinJWKSCacheTTLSeconds {
		return ErrOIDCInvalidJWKSCacheTTL
	}
	if strings.TrimSpace(p.TenantID) == "" {
		p.TenantID = authdomain.DefaultTenantID
	}
	return nil
}

// Validate runs the persisted-shape invariants on a GroupRoleMapping.
func (m *GroupRoleMapping) Validate() error {
	if !strings.HasPrefix(m.ID, "grm-") {
		return ErrGroupRoleMappingInvalidID
	}
	if !strings.HasPrefix(m.ProviderID, "op-") {
		return ErrGroupRoleMappingInvalidProvID
	}
	if strings.TrimSpace(m.GroupName) == "" {
		return ErrGroupRoleMappingEmptyGroupName
	}
	if !strings.HasPrefix(m.RoleID, "r-") {
		return ErrGroupRoleMappingInvalidRoleID
	}
	if strings.TrimSpace(m.TenantID) == "" {
		m.TenantID = authdomain.DefaultTenantID
	}
	return nil
}
