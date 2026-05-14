// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 11 (2026-05-14): extracted from
// internal/api/handler/auth_session_oidc.go via the Option B
// sibling-file pattern.
//
// This file holds Section 3 of the original three-section layout:
// OIDC PROVIDER + GROUP-MAPPING CRUD (RBAC-gated). Eight
// endpoints across two related resources:
//
//   GET    /api/v1/auth/oidc/providers            -> auth.oidc.list
//   POST   /api/v1/auth/oidc/providers            -> auth.oidc.create
//   PUT    /api/v1/auth/oidc/providers/{id}       -> auth.oidc.edit
//   DELETE /api/v1/auth/oidc/providers/{id}       -> auth.oidc.delete
//   POST   /api/v1/auth/oidc/providers/{id}/test  -> auth.oidc.edit
//   POST   /api/v1/auth/oidc/providers/{id}/refresh -> auth.oidc.edit
//   GET    /api/v1/auth/oidc/group-mappings       -> auth.oidc.list
//   POST   /api/v1/auth/oidc/group-mappings       -> auth.oidc.edit
//   DELETE /api/v1/auth/oidc/group-mappings/{id}  -> auth.oidc.edit
//
// The four request/response projection types (oidcProviderRequest,
// oidcProviderResponse, groupMappingRequest, groupMappingResponse)
// move with their handler callers. The encryptClientSecret +
// recordAudit + randomB64URLForHandler + defaultIfBlank +
// defaultIntIfZero helpers stay in auth_session_oidc.go — they're
// also consumed elsewhere (recordAudit is used by every section)
// or are generic utilities that don't have a single owner.
//
// NOTE: the audit's verb-based prescription (login / callback /
// refresh / logout / backchannel) named "refresh" as a separate
// sibling file. The RefreshProvider handler here is the only
// "refresh" in this file, but operationally it's an ADMIN
// operation on a provider's signing-key cache, not a session
// refresh. Sprint 11 keeps it grouped with the rest of the
// provider CRUD where it belongs by call-graph + permission scope
// (auth.oidc.edit, the same RBAC permission as Update/Delete).

// =============================================================================
// 3. OIDC provider + group-mapping CRUD.
// =============================================================================

type oidcProviderResponse struct {
	ID                  string   `json:"id"`
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	IssuerURL           string   `json:"issuer_url"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	GroupsClaimPath     string   `json:"groups_claim_path"`
	GroupsClaimFormat   string   `json:"groups_claim_format"`
	FetchUserinfo       bool     `json:"fetch_userinfo"`
	Scopes              []string `json:"scopes"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	IATWindowSeconds    int      `json:"iat_window_seconds"`
	JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

func providerToResponse(p *oidcdomain.OIDCProvider) oidcProviderResponse {
	return oidcProviderResponse{
		ID: p.ID, TenantID: p.TenantID, Name: p.Name,
		IssuerURL: p.IssuerURL, ClientID: p.ClientID, RedirectURI: p.RedirectURI,
		GroupsClaimPath: p.GroupsClaimPath, GroupsClaimFormat: p.GroupsClaimFormat,
		FetchUserinfo: p.FetchUserinfo, Scopes: p.Scopes, AllowedEmailDomains: p.AllowedEmailDomains,
		IATWindowSeconds: p.IATWindowSeconds, JWKSCacheTTLSeconds: p.JWKSCacheTTLSeconds,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

type oidcProviderRequest struct {
	Name                string   `json:"name"`
	IssuerURL           string   `json:"issuer_url"`
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"` // plaintext on the wire ONLY at create/update; encrypted at rest
	RedirectURI         string   `json:"redirect_uri"`
	GroupsClaimPath     string   `json:"groups_claim_path"`
	GroupsClaimFormat   string   `json:"groups_claim_format"`
	FetchUserinfo       bool     `json:"fetch_userinfo"`
	Scopes              []string `json:"scopes"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	IATWindowSeconds    int      `json:"iat_window_seconds"`
	JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds"`
}

// ListProviders handles GET /api/v1/auth/oidc/providers.
func (h *AuthSessionOIDCHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	if _, err := callerFromRequest(r); err != nil {
		writeAuthError(w, err)
		return
	}
	provs, err := h.providerRepo.List(r.Context(), h.tenantID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "could not list providers")
		return
	}
	out := make([]oidcProviderResponse, 0, len(provs))
	for _, p := range provs {
		out = append(out, providerToResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"providers": out})
}

// CreateProvider handles POST /api/v1/auth/oidc/providers.
func (h *AuthSessionOIDCHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req oidcProviderRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		Error(w, http.StatusBadRequest, "client_secret is required")
		return
	}
	encrypted, eerr := h.encryptClientSecret([]byte(req.ClientSecret))
	if eerr != nil {
		Error(w, http.StatusInternalServerError, "could not encrypt client secret")
		return
	}
	prov := &oidcdomain.OIDCProvider{
		ID:                    "op-" + randomB64URLForHandler(16),
		TenantID:              h.tenantID,
		Name:                  req.Name,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecretEncrypted: encrypted,
		RedirectURI:           req.RedirectURI,
		GroupsClaimPath:       defaultIfBlank(req.GroupsClaimPath, oidcdomain.DefaultGroupsClaimPath),
		GroupsClaimFormat:     defaultIfBlank(req.GroupsClaimFormat, oidcdomain.GroupsClaimFormatStringArray),
		FetchUserinfo:         req.FetchUserinfo,
		Scopes:                req.Scopes,
		AllowedEmailDomains:   req.AllowedEmailDomains,
		IATWindowSeconds:      defaultIntIfZero(req.IATWindowSeconds, oidcdomain.DefaultIATWindowSeconds),
		JWKSCacheTTLSeconds:   defaultIntIfZero(req.JWKSCacheTTLSeconds, oidcdomain.DefaultJWKSCacheTTLSeconds),
	}
	if verr := prov.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if cerr := h.providerRepo.Create(r.Context(), prov); cerr != nil {
		if errors.Is(cerr, repository.ErrOIDCProviderDuplicateName) {
			Error(w, http.StatusConflict, "provider name already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "could not create provider")
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_created", caller.ActorID, caller.ActorType, prov.ID,
		map[string]interface{}{"provider_id": prov.ID, "name": prov.Name, "issuer_url": prov.IssuerURL})
	writeJSON(w, http.StatusCreated, providerToResponse(prov))
}

// UpdateProvider handles PUT /api/v1/auth/oidc/providers/{id}.
func (h *AuthSessionOIDCHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	existing, gerr := h.providerRepo.Get(r.Context(), id)
	if gerr != nil {
		if errors.Is(gerr, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not load provider")
		return
	}
	var req oidcProviderRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Mutable fields only (id / tenant_id / created_at preserved).
	existing.Name = req.Name
	existing.IssuerURL = req.IssuerURL
	existing.ClientID = req.ClientID
	existing.RedirectURI = req.RedirectURI
	existing.GroupsClaimPath = defaultIfBlank(req.GroupsClaimPath, existing.GroupsClaimPath)
	existing.GroupsClaimFormat = defaultIfBlank(req.GroupsClaimFormat, existing.GroupsClaimFormat)
	existing.FetchUserinfo = req.FetchUserinfo
	existing.Scopes = req.Scopes
	existing.AllowedEmailDomains = req.AllowedEmailDomains
	if req.IATWindowSeconds != 0 {
		existing.IATWindowSeconds = req.IATWindowSeconds
	}
	if req.JWKSCacheTTLSeconds != 0 {
		existing.JWKSCacheTTLSeconds = req.JWKSCacheTTLSeconds
	}
	// Re-encrypt client_secret only if a new one is supplied; empty
	// preserves the existing ciphertext.
	if strings.TrimSpace(req.ClientSecret) != "" {
		encrypted, eerr := h.encryptClientSecret([]byte(req.ClientSecret))
		if eerr != nil {
			Error(w, http.StatusInternalServerError, "could not encrypt client secret")
			return
		}
		existing.ClientSecretEncrypted = encrypted
	}
	if verr := existing.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if uerr := h.providerRepo.Update(r.Context(), existing); uerr != nil {
		Error(w, http.StatusInternalServerError, "could not update provider")
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_updated", caller.ActorID, caller.ActorType, existing.ID,
		map[string]interface{}{"provider_id": existing.ID, "name": existing.Name})
	writeJSON(w, http.StatusOK, providerToResponse(existing))
}

// DeleteProvider handles DELETE /api/v1/auth/oidc/providers/{id}.
// Refused when at least one user has authenticated via this provider.
func (h *AuthSessionOIDCHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	if derr := h.providerRepo.Delete(r.Context(), id); derr != nil {
		switch {
		case errors.Is(derr, repository.ErrOIDCProviderNotFound):
			Error(w, http.StatusNotFound, "provider not found")
		case errors.Is(derr, repository.ErrOIDCProviderInUse):
			Error(w, http.StatusConflict, "provider has authenticated users; revoke all sessions before delete")
		default:
			Error(w, http.StatusInternalServerError, "could not delete provider")
		}
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_deleted", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"provider_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// TestProvider handles POST /api/v1/auth/oidc/test.
//
// Audit 2026-05-10 MED-5 closure. Dry-run validator for an OIDC
// provider config: runs OIDC discovery, the alg-downgrade defense,
// the RFC 9207 iss-parameter detection, and a JWKS fetch — without
// persisting anything. Body: `{issuer_url, client_id, scopes}`
// (client_secret accepted but ignored — discovery + JWKS don't
// require it). Response: TestDiscoveryResult; HTTP 200 even when
// individual checks fail (the response Errors field carries them so
// the GUI can render per-check status rows).
//
// Permission gate: `auth.oidc.create` (the operator is dry-running a
// provider they're about to create; the lookup endpoints have their
// own .list gate so this can't be used as a roundabout reconnaissance
// vector beyond what those already permit).
func (h *AuthSessionOIDCHandler) TestProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req struct {
		IssuerURL    string   `json:"issuer_url"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
	}
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.IssuerURL) == "" {
		Error(w, http.StatusBadRequest, "issuer_url is required")
		return
	}
	// Type-assert to the concrete service so we can reach the
	// TestDiscovery method. The OIDCAuthHandshaker interface is
	// intentionally narrow; rather than widening it (which would force
	// every test stub to implement TestDiscovery) we accept the
	// concrete reference for this single endpoint. Production code
	// always supplies *oidcsvc.Service.
	type discoveryTester interface {
		TestDiscovery(ctx context.Context, issuerURL string) (*oidcsvc.TestDiscoveryResult, error)
	}
	tester, ok := h.oidcSvc.(discoveryTester)
	if !ok {
		Error(w, http.StatusInternalServerError, "OIDC service does not support discovery test")
		return
	}
	res, terr := tester.TestDiscovery(r.Context(), strings.TrimSpace(req.IssuerURL))
	if terr != nil {
		Error(w, http.StatusInternalServerError, "discovery test execution failed")
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_tested", caller.ActorID, caller.ActorType, "",
		map[string]interface{}{
			"issuer_url":          req.IssuerURL,
			"discovery_succeeded": res.DiscoverySucceeded,
			"jwks_reachable":      res.JWKSReachable,
			"iss_param_supported": res.IssParamSupported,
			"error_count":         len(res.Errors),
		})
	writeJSON(w, http.StatusOK, res)
}

// RefreshProvider handles POST /api/v1/auth/oidc/providers/{id}/refresh.
// Forces re-fetch of the IdP discovery doc + JWKS, re-runs the IdP
// downgrade-attack defense.
func (h *AuthSessionOIDCHandler) RefreshProvider(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing provider id")
		return
	}
	if rerr := h.oidcSvc.RefreshKeys(r.Context(), id); rerr != nil {
		if errors.Is(rerr, repository.ErrOIDCProviderNotFound) {
			Error(w, http.StatusNotFound, "provider not found")
			return
		}
		Error(w, http.StatusBadRequest, "refresh failed: "+rerr.Error())
		return
	}
	h.recordAudit(r.Context(), "auth.oidc_provider_refreshed", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"provider_id": id})
	writeJSON(w, http.StatusOK, map[string]interface{}{"refreshed": true})
}

type groupMappingResponse struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	GroupName  string `json:"group_name"`
	RoleID     string `json:"role_id"`
	TenantID   string `json:"tenant_id"`
	CreatedAt  string `json:"created_at"`
}

func mappingToResponse(m *oidcdomain.GroupRoleMapping) groupMappingResponse {
	return groupMappingResponse{
		ID: m.ID, ProviderID: m.ProviderID, GroupName: m.GroupName,
		RoleID: m.RoleID, TenantID: m.TenantID,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type groupMappingRequest struct {
	ProviderID string `json:"provider_id"`
	GroupName  string `json:"group_name"`
	RoleID     string `json:"role_id"`
}

// ListGroupMappings handles GET /api/v1/auth/oidc/group-mappings?provider_id=<id>.
func (h *AuthSessionOIDCHandler) ListGroupMappings(w http.ResponseWriter, r *http.Request) {
	if _, err := callerFromRequest(r); err != nil {
		writeAuthError(w, err)
		return
	}
	providerID := strings.TrimSpace(r.URL.Query().Get("provider_id"))
	if providerID == "" {
		Error(w, http.StatusBadRequest, "missing required query parameter `provider_id`")
		return
	}
	mappings, lerr := h.mappingRepo.ListByProvider(r.Context(), providerID)
	if lerr != nil {
		Error(w, http.StatusInternalServerError, "could not list mappings")
		return
	}
	out := make([]groupMappingResponse, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, mappingToResponse(m))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"mappings": out})
}

// AddGroupMapping handles POST /api/v1/auth/oidc/group-mappings.
func (h *AuthSessionOIDCHandler) AddGroupMapping(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req groupMappingRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	mapping := &oidcdomain.GroupRoleMapping{
		ID:         "grm-" + randomB64URLForHandler(16),
		ProviderID: req.ProviderID,
		GroupName:  req.GroupName,
		RoleID:     req.RoleID,
		TenantID:   h.tenantID,
	}
	if verr := mapping.Validate(); verr != nil {
		Error(w, http.StatusBadRequest, verr.Error())
		return
	}
	if aerr := h.mappingRepo.Add(r.Context(), mapping); aerr != nil {
		if errors.Is(aerr, repository.ErrGroupRoleMappingDuplicate) {
			Error(w, http.StatusConflict, "mapping already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "could not add mapping")
		return
	}
	h.recordAudit(r.Context(), "auth.group_mapping_added", caller.ActorID, caller.ActorType, mapping.ID,
		map[string]interface{}{
			"mapping_id": mapping.ID, "provider_id": mapping.ProviderID,
			"group_name": mapping.GroupName, "role_id": mapping.RoleID,
		})
	writeJSON(w, http.StatusCreated, mappingToResponse(mapping))
}

// RemoveGroupMapping handles DELETE /api/v1/auth/oidc/group-mappings/{id}.
func (h *AuthSessionOIDCHandler) RemoveGroupMapping(w http.ResponseWriter, r *http.Request) {
	caller, err := callerFromRequest(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "missing mapping id")
		return
	}
	if rerr := h.mappingRepo.Remove(r.Context(), id); rerr != nil {
		if errors.Is(rerr, repository.ErrGroupRoleMappingNotFound) {
			Error(w, http.StatusNotFound, "mapping not found")
			return
		}
		Error(w, http.StatusInternalServerError, "could not remove mapping")
		return
	}
	h.recordAudit(r.Context(), "auth.group_mapping_removed", caller.ActorID, caller.ActorType, id,
		map[string]interface{}{"mapping_id": id})
	w.WriteHeader(http.StatusNoContent)
}
