// Copyright (c) certctl-io contributors.
//
// Audit 2026-05-11 A-8 — demo-mode residual-grants detector. Closes the
// deferred Phase 2 leg of HIGH-12 (cowork/auth-bundles-fixes-2026-05-10/
// 11-high-12-demo-mode-guard.md). The HIGH-12 closure (`b81588e`) added
// the fail-closed bind-address guard at config.Validate; the deferred
// leg here adds a startup-time WARN (or strict refuse-startup) when
// `actor-demo-anon` has live role grants under a non-`none` auth type.
//
// Why this matters: migration 000029 unconditionally seeds the
// `ar-demo-anon-admin` row granting r-admin to actor-demo-anon. The
// row is dormant under auth_type=api-key|oidc (the middleware chain
// never injects the synthetic actor as the request principal), but
// it represents a security debt: any future regression in the
// middleware chain (a misrouted CORS preflight, a fallback in a new
// auth-exempt route) that resolves to actor-demo-anon would re-elevate
// to admin. The canonical acquisition-readiness narrative — "we have
// an RBAC primitive with no synthetic-admin fallback" — requires this
// row to be either gone or explicitly acknowledged.

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/service"
)

// preflightDemoModeResidual runs after the DB connection is open and
// the audit service is constructed, before the HTTPS listener starts.
//
// Behaviour:
//   - cfg.Auth.Type == "none" (demo mode): no-op. The residual IS the
//     runtime state at that auth type.
//   - cfg.Auth.Type != "none" + no residue: returns nil silently.
//   - cfg.Auth.Type != "none" + residue + strict=false: emits a WARN
//     log AND an `auth.demo_residual_grants_detected` audit row
//     listing the grant IDs, then returns nil.
//   - cfg.Auth.Type != "none" + residue + strict=true: emits the same
//     WARN + audit, then returns a non-nil error so the caller can
//     refuse startup.
//
// The audit row's actor is `system` / ActorTypeSystem; category is
// EventCategoryAuth so audit consumers filtering on auth events see it.
func preflightDemoModeResidual(
	ctx context.Context,
	cfg *config.Config,
	db *sql.DB,
	audit *service.AuditService,
	logger *slog.Logger,
) error {
	if cfg.Auth.Type == "none" {
		// Demo mode itself. The residual is the runtime state at
		// this auth type, so warning about it would be noise.
		return nil
	}

	residue, err := queryDemoAnonResidue(ctx, db)
	if err != nil {
		return fmt.Errorf("preflight demo-mode residual: %w", err)
	}
	if len(residue) == 0 {
		return nil
	}

	formatted := make([]string, 0, len(residue))
	for _, r := range residue {
		formatted = append(formatted, r.String())
	}

	msg := fmt.Sprintf(
		"production startup warning: actor-demo-anon has %d residual role grant(s) "+
			"from the migration 000029 baseline or a prior demo-mode run: %s. "+
			"These grants are DORMANT at the current auth_type (%s) but represent a "+
			"security debt — any future regression that resolves an unauthenticated "+
			"request to actor-demo-anon would re-elevate to admin. Clean up via "+
			"POST /api/v1/auth/demo-residual/cleanup (requires auth.role.assign) or "+
			"`DELETE FROM actor_roles WHERE actor_id = 'actor-demo-anon';`. Set "+
			"CERTCTL_DEMO_MODE_RESIDUAL_STRICT=true to refuse startup until cleanup.",
		len(residue), strings.Join(formatted, "; "), cfg.Auth.Type,
	)
	if logger != nil {
		logger.Warn(msg, "auth_type", cfg.Auth.Type, "residue_count", len(residue))
	} else {
		slog.Warn(msg)
	}

	if audit != nil {
		details := map[string]interface{}{
			"auth_type":     cfg.Auth.Type,
			"residue_count": len(residue),
			"residue":       formatted,
		}
		if err := audit.RecordEventWithCategory(
			ctx, "system", domain.ActorTypeSystem,
			"auth.demo_residual_grants_detected",
			domain.EventCategoryAuth,
			"actor_roles", authdomain.DemoAnonActorID,
			details,
		); err != nil {
			// Don't fail startup over an audit-write error; just log.
			if logger != nil {
				logger.Warn("preflight demo-mode residual: audit record failed", "error", err)
			}
		}
	}

	if cfg.Auth.DemoModeResidualStrict {
		return fmt.Errorf(
			"startup refused: actor-demo-anon has %d residual role grant(s) and "+
				"CERTCTL_DEMO_MODE_RESIDUAL_STRICT=true. Remove the rows before restarting",
			len(residue),
		)
	}
	return nil
}

// demoAnonResidueRow describes a single live actor_roles row whose
// actor_id matches the synthetic demo-anon ID.
type demoAnonResidueRow struct {
	RoleID    string
	ScopeType string
	ScopeID   string
	GrantedAt time.Time
}

// String renders one row as `role@scope (granted ts)`. Used both in
// the WARN log message and in the audit row's residue list.
func (r demoAnonResidueRow) String() string {
	scope := r.ScopeType
	if r.ScopeID != "" {
		scope = fmt.Sprintf("%s/%s", r.ScopeType, r.ScopeID)
	}
	return fmt.Sprintf("%s@%s (granted %s)", r.RoleID, scope, r.GrantedAt.UTC().Format(time.RFC3339))
}

// queryDemoAnonResidue runs the canonical query for the residue
// detector + the cleanup endpoint. Kept in one place so the two
// surfaces can't drift on which rows count as "live".
//
// "Live" = not expired. Rows with expires_at <= NOW() are treated
// as already gone (they have no effect even if the actor were to be
// injected as the principal).
func queryDemoAnonResidue(ctx context.Context, db *sql.DB) ([]demoAnonResidueRow, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT role_id, scope_type, COALESCE(scope_id, '') AS scope_id, granted_at
		FROM actor_roles
		WHERE actor_id = $1
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY granted_at ASC, role_id ASC, scope_type ASC, COALESCE(scope_id, '') ASC
	`, authdomain.DemoAnonActorID)
	if err != nil {
		return nil, fmt.Errorf("query actor_roles: %w", err)
	}
	defer rows.Close()

	var out []demoAnonResidueRow
	for rows.Next() {
		var r demoAnonResidueRow
		if err := rows.Scan(&r.RoleID, &r.ScopeType, &r.ScopeID, &r.GrantedAt); err != nil {
			return nil, fmt.Errorf("scan actor_roles row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate actor_roles rows: %w", err)
	}
	return out, nil
}

// deleteDemoAnonResidue removes every live actor_roles row for the
// synthetic demo-anon actor. Returns the count removed. Used by the
// POST /api/v1/auth/demo-residual/cleanup handler. Idempotent — a
// follow-up call returns 0.
func deleteDemoAnonResidue(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, errors.New("db is nil")
	}
	res, err := db.ExecContext(ctx, `
		DELETE FROM actor_roles
		WHERE actor_id = $1
	`, authdomain.DemoAnonActorID)
	if err != nil {
		return 0, fmt.Errorf("delete actor_roles: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}
