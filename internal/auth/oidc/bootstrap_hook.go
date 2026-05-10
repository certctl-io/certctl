// Package oidc — Auth Bundle 2 Phase 7 / OIDC bootstrap hook.
//
// Phase 7 ships the "first OIDC login matching CERTCTL_BOOTSTRAP_ADMIN_GROUPS
// becomes admin" recovery path. This is Decision 3's preferred bootstrap:
// fresh deployments configure the OIDC provider + group mapping, and the
// first user who logs in via OIDC + carries any of the configured
// bootstrap admin groups is auto-granted r-admin. Subsequent logins fall
// through to normal group→role mapping.
//
// The hook is OPTIONAL — when not wired, OIDC behaves byte-identically
// to Phase 3. When wired, it runs after group resolution + user upsert
// and BEFORE the empty-mapping fail-closed check, so a fresh deployment
// with no group_role_mappings can still mint the first admin via the
// bootstrap path. The hook itself is responsible for the AdminExists
// probe (so admin-already-exists deployments fall through to normal
// mapping).
//
// Audit + lockout semantics:
//
//   - The hook emits the bootstrap.oidc_first_admin audit row with
//     event_category=auth on every successful first-admin grant.
//   - The hook is one-shot per process: once an admin exists in the
//     tenant, the AdminExists probe returns true and subsequent OIDC
//     logins skip the bootstrap path entirely.
//   - The hook NEVER grants admin to an actor whose groups don't match
//     CERTCTL_BOOTSTRAP_ADMIN_GROUPS. The intersection is constant-time-
//     length-irrelevant (it walks two slices); the relevant guarantee
//     is that no group string can be inferred from the hook's pass /
//     fail decision because the hook always emits the same audit row
//     shape.
package oidc

import "context"

// AdminBootstrapHook is the optional closure HandleCallback consults
// after group resolution + user upsert. The hook decides whether the
// authenticating user should be auto-granted r-admin via the OIDC
// first-admin bootstrap path.
//
// Parameters:
//   - providerID: the OIDCProvider id (so the hook can match against
//     CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID).
//   - groups: the IdP-supplied group names (so the hook can match
//     against CERTCTL_BOOTSTRAP_ADMIN_GROUPS).
//   - userID: the just-upserted users.id (so the hook can grant r-admin
//     via the ActorRoleRepository).
//
// Returns:
//   - grantAdmin: true => HandleCallback appends r-admin to the user's
//     resolved role IDs (idempotent; r-admin is appended only if not
//     already present from normal mapping).
//   - err: non-nil short-circuits HandleCallback with a wrapped error.
//     The hook should NOT return an error for the non-match case
//     (provider doesn't match / groups don't intersect / admin already
//     exists); those are silent skips returning grantAdmin=false.
type AdminBootstrapHook func(ctx context.Context, providerID string, groups []string, userID string) (grantAdmin bool, err error)

// SetAdminBootstrapHook wires the Phase 7 OIDC bootstrap hook.
// cmd/server/main.go calls this after construction; tests stub it
// inline. Nil resets to no-bootstrap-hook (the default).
func (s *Service) SetAdminBootstrapHook(hook AdminBootstrapHook) {
	s.adminBootstrapHook = hook
}

// appendIfMissing returns ss with v appended IFF v is not already in
// the slice. Used by HandleCallback to extend roleIDs with r-admin
// idempotently when the bootstrap hook fires AND mappings.Map already
// returned r-admin (an unlikely-but-possible config where the same
// role is granted by both paths).
func appendIfMissing(ss []string, v string) []string {
	for _, s := range ss {
		if s == v {
			return ss
		}
	}
	return append(ss, v)
}
