// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// =============================================================================
// Bundle 1 Phase 7 — `certctl-cli auth keys list` + scope-down helper.
//
// The Phase 1 migration backfills every CERTCTL_API_KEYS_NAMED entry to
// the admin role on first boot (Decision 7's safe-for-back-compat
// default). Scope-down is the operator-driven downgrade of any keys that
// don't actually need admin power. This file ships:
//
//   - AuthListKeys: GET /api/v1/auth/keys — render every actor + roles
//     in tabular / json form.
//   - AuthScopeDown: interactive flow that walks every key (skipping
//     the synthetic actor-demo-anon) and prompts for a target role.
//   - AuthScopeDownNonInteractive: take a JSON config {actor_id: role_id}
//     and apply role changes without prompts; for automation.
//   - AuthScopeDownSuggest: read 30 days of audit events per key and
//     suggest a narrower role based on actual call patterns. The suggest
//     mode still requires confirmation (or --apply for non-interactive).
//
// The scope-down flow uses revoke + grant as separate API calls
// (no batch endpoint yet — by design; auditing each role mutation
// individually is a Bundle 1 invariant).
// =============================================================================

// AuthKeyEntry mirrors handler.ListKeys's response shape without
// importing the handler package.
type AuthKeyEntry struct {
	ActorID   string   `json:"actor_id"`
	ActorType string   `json:"actor_type"`
	TenantID  string   `json:"tenant_id"`
	RoleIDs   []string `json:"role_ids"`
}

type authKeysListResponse struct {
	Keys []AuthKeyEntry `json:"keys"`
}

// AuthListKeys prints every actor in the tenant with their current role
// assignments. The synthetic actor-demo-anon is shown but flagged as
// "system-managed" so operators don't accidentally try to mutate it.
func (c *Client) AuthListKeys() error {
	keys, err := c.fetchAuthKeys()
	if err != nil {
		return err
	}
	if c.format == "json" {
		blob, _ := json.MarshalIndent(authKeysListResponse{Keys: keys}, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	fmt.Printf("%-28s  %-12s  %s\n", "ACTOR", "TYPE", "ROLES")
	for _, k := range keys {
		notes := ""
		if k.ActorID == DemoAnonActorID {
			notes = "  (system-managed; scope-down skips this)"
		}
		fmt.Printf("%-28s  %-12s  %s%s\n", k.ActorID, k.ActorType, strings.Join(k.RoleIDs, ","), notes)
	}
	return nil
}

// DemoAnonActorID is replicated from internal/auth/context.go so the
// CLI doesn't import internal/auth (the CLI binary stays small).
const DemoAnonActorID = "actor-demo-anon"

// AuthScopeDown runs the interactive scope-down flow against stdin /
// stdout. Each non-system actor is shown with its current roles and
// the operator picks one of: keep, admin, operator, viewer, agent,
// mcp, cli, auditor. Empty input keeps the current assignment.
func (c *Client) AuthScopeDown() error {
	keys, err := c.fetchAuthKeys()
	if err != nil {
		return err
	}
	keys = filterScopeDownCandidates(keys)
	if len(keys) == 0 {
		fmt.Println("no actors eligible for scope-down (only the system-managed actor-demo-anon exists, or no actors hold roles).")
		return nil
	}
	fmt.Println("certctl-cli auth keys scope-down")
	fmt.Println("================================")
	fmt.Printf("Bundle 1 ships role-based authorization. Existing API keys backfill to r-admin (full power).\n")
	fmt.Printf("Walk each key below and select a role that matches its actual usage. Empty input keeps the\n")
	fmt.Printf("current assignment; type a single role name to replace it.\n\n")
	reader := bufio.NewReader(os.Stdin)
	plan, err := buildScopeDownPlan(keys, reader, os.Stdout)
	if err != nil {
		return err
	}
	return c.applyScopeDownPlan(plan)
}

// AuthScopeDownNonInteractive applies a {actor_id: role_id} JSON
// config without prompts. Useful for automation / Helm post-upgrade
// hooks. Empty role_id revokes all current roles WITHOUT granting a
// replacement; the operator can then assign roles selectively via
// `certctl-cli auth keys assign`.
func (c *Client) AuthScopeDownNonInteractive(configPath string) error {
	blob, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %s: %w", configPath, err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(blob, &cfg); err != nil {
		return fmt.Errorf("decode config %s: %w", configPath, err)
	}
	keys, err := c.fetchAuthKeys()
	if err != nil {
		return err
	}
	currentRoles := map[string][]string{}
	for _, k := range keys {
		currentRoles[k.ActorID] = k.RoleIDs
	}
	plan := []scopeDownAction{}
	for actor, target := range cfg {
		if actor == DemoAnonActorID {
			fmt.Fprintf(os.Stderr, "skipping %s: reserved system actor\n", actor)
			continue
		}
		current, ok := currentRoles[actor]
		if !ok {
			fmt.Fprintf(os.Stderr, "skipping %s: not in actor_roles (no grants to revoke)\n", actor)
			continue
		}
		plan = append(plan, scopeDownAction{
			ActorID:      actor,
			CurrentRoles: current,
			TargetRole:   target,
		})
	}
	return c.applyScopeDownPlan(plan)
}

// AuthScopeDownSuggest analyses 30 days of audit events per key and
// prints suggested role assignments. With apply=false (default) the
// suggestions are advisory and the operator follows up with a manual
// scope-down or scope-down-non-interactive call. With apply=true the
// suggestions are applied directly.
func (c *Client) AuthScopeDownSuggest(apply bool) error {
	keys, err := c.fetchAuthKeys()
	if err != nil {
		return err
	}
	keys = filterScopeDownCandidates(keys)
	plan := []scopeDownAction{}
	fmt.Println("certctl-cli auth keys scope-down --suggest")
	fmt.Println("==========================================")
	fmt.Printf("%-28s  %-15s  %-15s  %s\n", "ACTOR", "CURRENT ROLES", "SUGGESTED", "REASON")
	for _, k := range keys {
		events, fetchErr := c.fetchAuditEventsForActor(k.ActorID, 1000)
		if fetchErr != nil {
			fmt.Fprintf(os.Stderr, "fetch audit for %s: %v\n", k.ActorID, fetchErr)
			continue
		}
		suggested, reason := SuggestRoleFromAuditEvents(events)
		fmt.Printf("%-28s  %-15s  %-15s  %s\n",
			k.ActorID,
			strings.Join(k.RoleIDs, ","),
			suggested,
			reason)
		plan = append(plan, scopeDownAction{
			ActorID:      k.ActorID,
			CurrentRoles: k.RoleIDs,
			TargetRole:   suggested,
		})
	}
	if !apply {
		fmt.Println("\n(dry run; pass --apply to execute the suggested role changes)")
		return nil
	}
	return c.applyScopeDownPlan(plan)
}

// =============================================================================
// Internals
// =============================================================================

type scopeDownAction struct {
	ActorID      string
	CurrentRoles []string
	TargetRole   string
}

func (c *Client) fetchAuthKeys() ([]AuthKeyEntry, error) {
	body, err := c.doGET("/api/v1/auth/keys")
	if err != nil {
		return nil, err
	}
	var resp authKeysListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode /v1/auth/keys: %w", err)
	}
	return resp.Keys, nil
}

func filterScopeDownCandidates(keys []AuthKeyEntry) []AuthKeyEntry {
	out := make([]AuthKeyEntry, 0, len(keys))
	for _, k := range keys {
		if k.ActorID == DemoAnonActorID {
			continue
		}
		out = append(out, k)
	}
	return out
}

// validRoles is the canonical list scope-down accepts as targets.
// Mirrors the Phase 1 default-role seeds; new operator-defined roles
// can be assigned via `certctl auth keys assign --role <id>` directly.
var validRoles = []string{"admin", "operator", "viewer", "agent", "mcp", "cli", "auditor"}

func isValidRole(s string) bool {
	for _, v := range validRoles {
		if v == s {
			return true
		}
	}
	return false
}

func buildScopeDownPlan(keys []AuthKeyEntry, in *bufio.Reader, out io.Writer) ([]scopeDownAction, error) {
	plan := []scopeDownAction{}
	for _, k := range keys {
		fmt.Fprintf(out, "\n%s (current: %s)\n", k.ActorID, strings.Join(k.RoleIDs, ","))
		fmt.Fprintf(out, "  enter target role [%s] or 'keep' (default): ",
			strings.Join(validRoles, "|"))
		line, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		choice := strings.TrimSpace(line)
		if choice == "" || strings.EqualFold(choice, "keep") {
			fmt.Fprintln(out, "  → keeping existing roles")
			continue
		}
		choice = strings.ToLower(choice)
		if !isValidRole(choice) {
			fmt.Fprintf(out, "  → unknown role %q, keeping existing\n", choice)
			continue
		}
		// Normalize target to r-<name> for the API.
		plan = append(plan, scopeDownAction{
			ActorID:      k.ActorID,
			CurrentRoles: k.RoleIDs,
			TargetRole:   "r-" + choice,
		})
	}
	return plan, nil
}

// applyScopeDownPlan runs revoke+grant pairs for every action.
// Idempotent on the role layer (revoke a missing role yields 404; the
// CLI swallows that).
func (c *Client) applyScopeDownPlan(plan []scopeDownAction) error {
	if len(plan) == 0 {
		fmt.Println("\nno role changes to apply.")
		return nil
	}
	fmt.Println("\nApplying role changes:")
	var changed, kept int
	for _, action := range plan {
		// Skip actions whose target role is already exclusively
		// held (no diff). This avoids spurious revoke+grant churn.
		if len(action.CurrentRoles) == 1 && action.CurrentRoles[0] == action.TargetRole {
			fmt.Printf("  %s: already at %s, skipping\n", action.ActorID, action.TargetRole)
			kept++
			continue
		}
		// Revoke every current role.
		for _, current := range action.CurrentRoles {
			if err := c.AuthRevokeRoleFromKey(action.ActorID, current); err != nil {
				return fmt.Errorf("revoke %s/%s: %w", action.ActorID, current, err)
			}
		}
		// Grant the target. Empty target = revoke-only (operator
		// will assign roles selectively via `auth keys assign`).
		if action.TargetRole != "" {
			if err := c.AuthAssignRoleToKey(action.ActorID, action.TargetRole); err != nil {
				return fmt.Errorf("grant %s/%s: %w", action.ActorID, action.TargetRole, err)
			}
		}
		changed++
	}
	fmt.Printf("\nDone. %d actor(s) changed, %d kept.\n", changed, kept)
	return nil
}

// =============================================================================
// --suggest mode: audit-event analyser. Pure function for ease of
// testing; no I/O.
// =============================================================================

// AuditEventLite is the subset of fields the suggest analyser
// consumes. The audit list endpoint returns full domain.AuditEvent
// rows; we only care about the action / resource_type / resource_id
// path classification.
type AuditEventLite struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
}

// SuggestRoleFromAuditEvents inspects an actor's recent audit-event
// history and returns the narrowest role that covers the observed
// usage pattern, plus a one-line reason.
//
// Classification (priority order):
//
//  1. Any admin-shaped action (role/key/hierarchy/bulk_revoke/admin) → admin.
//  2. Every event is an MCP-shaped action (mcp.*) → mcp.
//  3. Every event is read-only (*.read / *.list) → viewer.
//  4. Every event is agent-shaped (agent.* OR cert.read OR cert.issue) → agent.
//  5. Otherwise → operator.
//
// Empty event list → "viewer" (the safest default).
func SuggestRoleFromAuditEvents(events []AuditEventLite) (role string, reason string) {
	if len(events) == 0 {
		return "viewer", "no audit history; defaulting to read-only"
	}
	var (
		hasAdmin    bool
		allMCP      = true
		allReadOnly = true
		allAgent    = true
	)
	for _, e := range events {
		action := strings.ToLower(e.Action)
		// Admin-only signals — earliest exit.
		if strings.HasPrefix(action, "auth.role.") ||
			strings.HasPrefix(action, "auth.key.") ||
			strings.HasPrefix(action, "ca.hierarchy.") ||
			strings.Contains(action, "bulk_revoke") ||
			strings.HasPrefix(action, "scep.admin") ||
			strings.HasPrefix(action, "est.admin") ||
			strings.HasPrefix(action, "crl.admin") {
			hasAdmin = true
		}
		if !strings.HasPrefix(action, "mcp.") {
			allMCP = false
		}
		if !strings.HasSuffix(action, ".read") && !strings.HasSuffix(action, ".list") {
			allReadOnly = false
		}
		isAgentShape := strings.HasPrefix(action, "agent.") ||
			action == "cert.issue" || action == "cert.read"
		if !isAgentShape {
			allAgent = false
		}
	}
	switch {
	case hasAdmin:
		return "admin", "called admin-only action (role mgmt / bulk revoke / hierarchy)"
	case allMCP:
		return "mcp", "only MCP-shaped actions observed"
	case allReadOnly:
		return "viewer", "all observed actions are read-only"
	case allAgent:
		return "agent", "only agent + cert read/issue actions observed"
	default:
		return "operator", "cert / profile / target lifecycle mutations observed; no admin signals"
	}
}

// fetchAuditEventsForActor pulls audit events filtered by actor=actorID
// from /v1/audit. Bundle 1 Phase 7 doesn't yet ship a per-actor query
// param; we filter client-side from the paginated list endpoint.
func (c *Client) fetchAuditEventsForActor(actorID string, limit int) ([]AuditEventLite, error) {
	body, err := c.doGET(fmt.Sprintf("/api/v1/audit?per_page=%d", limit))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			Actor        string `json:"actor"`
			Action       string `json:"action"`
			ResourceType string `json:"resource_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode /v1/audit: %w", err)
	}
	out := make([]AuditEventLite, 0, len(resp.Data))
	for _, e := range resp.Data {
		if e.Actor != actorID {
			continue
		}
		out = append(out, AuditEventLite{Action: e.Action, ResourceType: e.ResourceType})
	}
	return out, nil
}
