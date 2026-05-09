package auth

import (
	"context"
	"fmt"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// Authorizer is the load-bearing "can this actor do this thing on this
// resource" check. Bundle 1 Phase 3 wires it into the RequirePermission
// middleware factory; every gated request runs through this on the hot
// path.
//
// Semantics: a permission grant matches when ALL of the following hold:
//
//  1. The granted permission name equals the requested permission name.
//  2. Either the grant is global-scoped (covers all resources of that
//     type) OR the grant scope_type + scope_id exactly match the
//     request's scope.
//
// Global beats specific: an actor with `cert.read` at scope `global`
// can read every certificate, regardless of per-cert scoped grants.
// Per-resource grants do NOT shadow global grants; they widen the
// effective set.
//
// The actor's effective permission set is the deduplicated union
// across every role they hold. ActorRoleRepository.EffectivePermissions
// already returns the union via SQL JOIN, so the in-memory matcher
// just walks the result.
type Authorizer struct {
	actorRepo repository.ActorRoleRepository
}

// NewAuthorizer constructs an Authorizer.
func NewAuthorizer(actorRepo repository.ActorRoleRepository) *Authorizer {
	return &Authorizer{actorRepo: actorRepo}
}

// CheckPermission returns true when the actor holds the named
// permission at the requested scope (or globally). Returns false (no
// error) when the actor exists but lacks the permission. Returns an
// error only on repository / database failure; callers treat that as
// a 500-class problem.
//
// The synthetic actor `actor-demo-anon` (used when CERTCTL_AUTH_TYPE=
// none) holds the admin role per the migration seed; CheckPermission
// resolves through that grant just like any other actor.
func (a *Authorizer) CheckPermission(
	ctx context.Context,
	actorID string,
	actorType authdomain.ActorTypeValue,
	tenantID string,
	permission string,
	scopeType authdomain.ScopeType,
	scopeID *string,
) (bool, error) {
	if actorID == "" {
		return false, nil
	}
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}

	effective, err := a.actorRepo.EffectivePermissions(ctx, actorID, actorType, tenantID)
	if err != nil {
		return false, fmt.Errorf("authorizer.CheckPermission: %w", err)
	}

	for _, ep := range effective {
		if ep.PermissionName != permission {
			continue
		}
		// Global grant always matches.
		if ep.ScopeType == authdomain.ScopeTypeGlobal {
			return true, nil
		}
		// Specific grant requires scope_type + scope_id match.
		if ep.ScopeType != scopeType {
			continue
		}
		if scopeID == nil || ep.ScopeID == nil {
			// Scope-typed grant without ID, or request without ID.
			// Treat as no match: per-profile / per-issuer scopes
			// require an explicit ID.
			continue
		}
		if *ep.ScopeID == *scopeID {
			return true, nil
		}
	}
	return false, nil
}

// HoldsAnyOf returns true when the actor holds at least one of the
// named permissions globally. Used by privilege-escalation guards
// (e.g. ActorRoleService.Grant: caller must hold auth.role.assign).
func (a *Authorizer) HoldsAnyOf(
	ctx context.Context,
	actorID string,
	actorType authdomain.ActorTypeValue,
	tenantID string,
	permissions ...string,
) (bool, error) {
	for _, p := range permissions {
		ok, err := a.CheckPermission(ctx, actorID, actorType, tenantID, p, authdomain.ScopeTypeGlobal, nil)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
