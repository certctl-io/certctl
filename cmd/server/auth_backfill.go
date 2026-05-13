// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// assembleNamedAPIKeys translates the operator's CERTCTL_API_KEYS_NAMED
// env-var (preferred) or CERTCTL_AUTH_SECRET (legacy) into the
// auth.NamedAPIKey slice the rest of the boot path consumes.
//
// Authentication unification (M-002): every authenticated request now
// carries a named actor in the request context so audit events record
// the real key identity instead of the hardcoded "api-key-user"
// string. Named keys come from CERTCTL_API_KEYS_NAMED (preferred). For
// backward compatibility CERTCTL_AUTH_SECRET is synthesized into
// legacy-key-N entries with Admin=false.
func assembleNamedAPIKeys(cfg *config.Config, logger *slog.Logger) []auth.NamedAPIKey {
	if config.AuthType(cfg.Auth.Type) == config.AuthTypeNone {
		return nil
	}
	var out []auth.NamedAPIKey
	for _, nk := range cfg.Auth.NamedKeys {
		out = append(out, auth.NamedAPIKey{
			Name:  nk.Name,
			Key:   nk.Key,
			Admin: nk.Admin,
		})
	}
	if len(out) == 0 && cfg.Auth.Secret != "" {
		idx := 0
		for _, p := range strings.Split(cfg.Auth.Secret, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			out = append(out, auth.NamedAPIKey{
				Name:  fmt.Sprintf("legacy-key-%d", idx),
				Key:   p,
				Admin: false,
			})
			idx++
		}
		if len(out) > 0 && logger != nil {
			logger.Warn("CERTCTL_AUTH_SECRET is deprecated — set CERTCTL_API_KEYS_NAMED for named actor attribution and admin gating",
				"synthesized_keys", len(out))
		}
	}
	return out
}

// actorRoleGranter is the narrow interface backfillNamedKeyActorRoles
// needs from the postgres ActorRoleRepository. Pulled out so the unit
// test can inject a fake without spinning up the full repo / DB.
type actorRoleGranter interface {
	Grant(ctx context.Context, ar *authdomain.ActorRole) error
}

// backfillNamedKeyActorRoles is the Bundle 1 Phase 3 closure (C2)
// startup hook that ensures every CERTCTL_API_KEYS_NAMED entry — and
// every legacy CERTCTL_AUTH_SECRET synthesized fallback — has an
// actor_roles row before the HTTP server accepts requests. Admin-flagged
// keys grant `r-admin` (full canonical permission set); non-admin keys
// grant `r-viewer` (read-only surface), matching the pre-Phase-3.5
// capability shape.
//
// Idempotent via ON CONFLICT DO NOTHING in the repo Grant — reboots
// don't create duplicates. Failures are logged but non-fatal: the server
// still starts, and the operator can fix the grant via the RBAC API.
//
// The function is package-private + extracted from main() so the unit
// test in auth_backfill_test.go can pin the role-mapping invariant
// without depending on the full server bootstrap path.
func backfillNamedKeyActorRoles(
	ctx context.Context,
	repo actorRoleGranter,
	keys []auth.NamedAPIKey,
	logger *slog.Logger,
) {
	for _, nk := range keys {
		role := authdomain.RoleIDViewer
		if nk.Admin {
			role = authdomain.RoleIDAdmin
		}
		if err := repo.Grant(ctx, &authdomain.ActorRole{
			ActorID:   nk.Name,
			ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey),
			RoleID:    role,
			TenantID:  authdomain.DefaultTenantID,
			GrantedBy: "bootstrap",
		}); err != nil {
			if logger != nil {
				logger.Warn("api-key actor-role backfill failed; key authenticates but RBAC routes will 403 until grant is added via /v1/auth/keys",
					"key", nk.Name, "role", role, "err", err)
			}
		}
	}
}
