package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// =============================================================================
// CLI auth subcommands. Bundle 1 Phase 5 mirrors the /api/v1/auth/*
// surface introduced in Phase 4. Read operations + key-role assignment +
// the /me identity check; mutating role lifecycle (create / update /
// delete) is a Phase 5.5 follow-up that adds the cobra-style flag
// parsing for description / name fields.
// =============================================================================

// authMeResponse mirrors handler.meResponse without importing the
// handler package (would couple CLI build to the server tree).
type authMeResponse struct {
	ActorID              string `json:"actor_id"`
	ActorType            string `json:"actor_type"`
	TenantID             string `json:"tenant_id"`
	Admin                bool   `json:"admin"`
	Roles                []string `json:"roles"`
	EffectivePermissions []struct {
		Permission string  `json:"permission"`
		ScopeType  string  `json:"scope_type"`
		ScopeID    *string `json:"scope_id,omitempty"`
	} `json:"effective_permissions"`
}

// AuthMe prints the current actor's identity + permissions. Useful for
// debugging RBAC config: confirms which actor the API key resolves to,
// which roles it holds, and the effective permission set.
func (c *Client) AuthMe() error {
	body, err := c.doGET("/api/v1/auth/me")
	if err != nil {
		return err
	}
	if c.format == "json" {
		fmt.Println(string(body))
		return nil
	}
	var me authMeResponse
	if err := json.Unmarshal(body, &me); err != nil {
		return fmt.Errorf("decode /auth/me: %w", err)
	}
	fmt.Printf("Actor:    %s (%s)\n", me.ActorID, me.ActorType)
	fmt.Printf("Tenant:   %s\n", me.TenantID)
	fmt.Printf("Admin:    %t\n", me.Admin)
	fmt.Printf("Roles:    %s\n", strings.Join(me.Roles, ", "))
	fmt.Printf("Effective permissions:\n")
	for _, p := range me.EffectivePermissions {
		scope := p.ScopeType
		if p.ScopeID != nil {
			scope = fmt.Sprintf("%s:%s", p.ScopeType, *p.ScopeID)
		}
		fmt.Printf("  %s @ %s\n", p.Permission, scope)
	}
	return nil
}

// AuthListRoles prints all roles in the tenant.
func (c *Client) AuthListRoles() error {
	body, err := c.doGET("/api/v1/auth/roles")
	if err != nil {
		return err
	}
	if c.format == "json" {
		fmt.Println(string(body))
		return nil
	}
	var resp struct {
		Roles []struct {
			ID, Name, Description string
			TenantID              string `json:"tenant_id"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode roles list: %w", err)
	}
	fmt.Printf("%-15s  %-15s  %s\n", "ID", "NAME", "DESCRIPTION")
	for _, r := range resp.Roles {
		fmt.Printf("%-15s  %-15s  %s\n", r.ID, r.Name, r.Description)
	}
	return nil
}

// AuthGetRole prints a single role + its permission grants.
func (c *Client) AuthGetRole(id string) error {
	body, err := c.doGET("/api/v1/auth/roles/" + id)
	if err != nil {
		return err
	}
	if c.format == "json" {
		fmt.Println(string(body))
		return nil
	}
	var resp struct {
		Role struct {
			ID, Name, Description string
		}
		Permissions []struct {
			PermissionID string  `json:"permission_id"`
			ScopeType    string  `json:"scope_type"`
			ScopeID      *string `json:"scope_id,omitempty"`
		}
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode role: %w", err)
	}
	fmt.Printf("ID:          %s\n", resp.Role.ID)
	fmt.Printf("Name:        %s\n", resp.Role.Name)
	fmt.Printf("Description: %s\n", resp.Role.Description)
	fmt.Printf("Permissions (%d):\n", len(resp.Permissions))
	for _, p := range resp.Permissions {
		scope := p.ScopeType
		if p.ScopeID != nil {
			scope = fmt.Sprintf("%s:%s", p.ScopeType, *p.ScopeID)
		}
		fmt.Printf("  %s @ %s\n", p.PermissionID, scope)
	}
	return nil
}

// AuthListPermissions prints the canonical permission catalogue.
func (c *Client) AuthListPermissions() error {
	body, err := c.doGET("/api/v1/auth/permissions")
	if err != nil {
		return err
	}
	if c.format == "json" {
		fmt.Println(string(body))
		return nil
	}
	var resp struct {
		Permissions []struct {
			ID, Name, Namespace string
		} `json:"permissions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode permissions: %w", err)
	}
	fmt.Printf("%-25s  %s\n", "PERMISSION", "NAMESPACE")
	for _, p := range resp.Permissions {
		fmt.Printf("%-25s  %s\n", p.Name, p.Namespace)
	}
	return nil
}

// AuthAssignRoleToKey grants a role to an API-key-named actor. The
// caller's key must hold auth.role.assign globally; service-layer
// returns 403 otherwise.
func (c *Client) AuthAssignRoleToKey(keyID, roleID string) error {
	body, err := json.Marshal(map[string]string{"role_id": roleID})
	if err != nil {
		return err
	}
	if _, err := c.doPOST("/api/v1/auth/keys/"+keyID+"/roles", body); err != nil {
		return err
	}
	fmt.Printf("granted %s to %s\n", roleID, keyID)
	return nil
}

// AuthRevokeRoleFromKey revokes a role from an API-key-named actor.
// Service-layer rejects revocations against the reserved demo-anon
// actor with 409; CLI surfaces that as a non-zero exit.
func (c *Client) AuthRevokeRoleFromKey(keyID, roleID string) error {
	if err := c.doDELETE("/api/v1/auth/keys/" + keyID + "/roles/" + roleID); err != nil {
		return err
	}
	fmt.Printf("revoked %s from %s\n", roleID, keyID)
	return nil
}

// =============================================================================
// HTTP helpers — minimal wrappers around the underlying http.Client used
// elsewhere in the package. Mirror the pattern from est.go (same
// authentication + TLS + error-handling shape).
// =============================================================================

func (c *Client) doGET(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.doRaw(req)
}

func (c *Client) doPOST(path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.doRaw(req)
}

func (c *Client) doDELETE(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	_, err = c.doRaw(req)
	return err
}

func (c *Client) doRaw(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// readAll wraps io.ReadAll without pulling another import; defined as a
// thin function so we can swap to a bounded reader later if needed.
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}
