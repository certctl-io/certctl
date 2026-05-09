package auth

import "context"

// WithActor builds a context with UserKey populated, mirroring what
// NewAuthWithNamedKeys produces for a real authenticated request. Used
// by handler / service / middleware tests so they don't construct the
// context manually with internal context-key types.
//
// Phase 0 ships UserKey + AdminKey only; Phase 3 of Bundle 1 introduces
// the RBAC context (ActorIDKey, ActorTypeKey, RolesKey) and this helper
// will be extended to populate those too. Until then, admin should be
// passed via WithAdmin (separate helper below) to mirror the matched-key
// flag.
func WithActor(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, UserKey{}, name)
}

// WithAdmin sets the AdminKey flag on the supplied context. Tests calling
// WithActor + WithAdmin together produce a context indistinguishable from
// what NewAuthWithNamedKeys produces for an admin-flagged NamedAPIKey.
func WithAdmin(ctx context.Context, admin bool) context.Context {
	return context.WithValue(ctx, AdminKey{}, admin)
}

// WithActorAdmin is a convenience for the common "admin caller named X"
// pattern across handler tests.
func WithActorAdmin(ctx context.Context, name string, admin bool) context.Context {
	ctx = WithActor(ctx, name)
	ctx = WithAdmin(ctx, admin)
	return ctx
}
