package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/repository/postgres"
	"github.com/certctl-io/certctl/internal/service"
)

// Audit 2026-05-11 A-8 — preflight + cleanup regression tests for the
// demo-mode residual-grants detector. Testcontainers-backed because the
// preflight runs raw SQL against actor_roles; mock-DB-only would not
// catch a SQL-shape regression. Gated by testing.Short() to keep the
// fast loop fast (matching internal/repository/postgres/* pattern).

var (
	a8DBOnce sync.Once
	a8DB     *sql.DB
	a8Skip   bool
	a8SkipMu sync.Mutex
)

func setupA8DB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("preflight A-8 test requires Postgres (testcontainers); skipping under -short")
	}
	a8DBOnce.Do(func() {
		ctx := context.Background()
		req := testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       "certctl_test_a8",
				"POSTGRES_USER":     "certctl",
				"POSTGRES_PASSWORD": "certctl",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		}
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			a8SkipMu.Lock()
			a8Skip = true
			a8SkipMu.Unlock()
			t.Logf("skipping A-8 testcontainers preflight (docker unavailable): %v", err)
			return
		}
		host, err := c.Host(ctx)
		if err != nil {
			t.Fatalf("get container host: %v", err)
		}
		port, err := c.MappedPort(ctx, "5432")
		if err != nil {
			t.Fatalf("get mapped port: %v", err)
		}
		dsn := fmt.Sprintf("postgres://certctl:certctl@%s:%s/certctl_test_a8?sslmode=disable", host, port.Port())

		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		// Run all migrations so actor_roles exists with the migration
		// 000029 seed row (`ar-demo-anon-admin`).
		_, thisFile, _, _ := runtime.Caller(0)
		migrationsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
		if _, err := os.Stat(migrationsDir); err != nil {
			t.Fatalf("locate migrations dir %q: %v", migrationsDir, err)
		}
		if err := postgres.RunMigrations(db, migrationsDir); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		a8DB = db
	})

	a8SkipMu.Lock()
	skip := a8Skip
	a8SkipMu.Unlock()
	if skip {
		t.Skip("A-8 testcontainers unavailable; skipping")
	}
	return a8DB
}

// resetA8Residue clears the actor_roles rows for actor-demo-anon AND
// re-inserts the migration 000029 baseline. Used by tests that need a
// known "post-fresh-migration" state.
func resetA8Residue(t *testing.T, db *sql.DB, seedBaseline bool) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`DELETE FROM actor_roles WHERE actor_id = 'actor-demo-anon'`); err != nil {
		t.Fatalf("reset actor_roles: %v", err)
	}
	if seedBaseline {
		if _, err := db.ExecContext(context.Background(), `
			INSERT INTO actor_roles (id, actor_id, actor_type, role_id, granted_at, granted_by, tenant_id)
			VALUES ('ar-demo-anon-admin', 'actor-demo-anon', 'Anonymous', 'r-admin', NOW(), 'system', 't-default')
		`); err != nil {
			t.Fatalf("reseed baseline: %v", err)
		}
	}
}

// TestPreflightDemoModeResidual_DemoModeActive_Skips proves the
// preflight short-circuits when Auth.Type=none regardless of residue.
// Demo mode IS the active runtime state at that auth type, so warning
// would be noise.
func TestPreflightDemoModeResidual_DemoModeActive_Skips(t *testing.T) {
	db := setupA8DB(t)
	resetA8Residue(t, db, true) // baseline IS present

	cfg := &config.Config{}
	cfg.Auth.Type = "none"
	cfg.Auth.DemoModeResidualStrict = true // would refuse if checked

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := preflightDemoModeResidual(context.Background(), cfg, db, nil, logger)
	if err != nil {
		t.Fatalf("expected nil under Auth.Type=none, got %v", err)
	}
}

// TestPreflightDemoModeResidual_NoResidue_Passes proves a fully-clean
// actor_roles state passes without WARN.
func TestPreflightDemoModeResidual_NoResidue_Passes(t *testing.T) {
	db := setupA8DB(t)
	resetA8Residue(t, db, false) // explicitly empty

	cfg := &config.Config{}
	cfg.Auth.Type = "api-key"

	err := preflightDemoModeResidual(context.Background(), cfg, db, nil, nil)
	if err != nil {
		t.Fatalf("expected nil with empty residue, got %v", err)
	}
}

// TestPreflightDemoModeResidual_HasResidue_LogsAndAudits proves the
// migration 000029 baseline produces a WARN + audit row but does NOT
// fail startup in default (non-strict) mode.
func TestPreflightDemoModeResidual_HasResidue_LogsAndAudits(t *testing.T) {
	db := setupA8DB(t)
	resetA8Residue(t, db, true)

	cfg := &config.Config{}
	cfg.Auth.Type = "api-key"
	cfg.Auth.DemoModeResidualStrict = false

	auditRepo := postgres.NewAuditRepository(db)
	auditService := service.NewAuditService(auditRepo)

	err := preflightDemoModeResidual(context.Background(), cfg, db, auditService, nil)
	if err != nil {
		t.Fatalf("non-strict mode must NOT fail startup with residue, got %v", err)
	}

	// Audit row should be present for the call.
	rows, err := db.QueryContext(context.Background(), `
		SELECT action, event_category, resource_id
		FROM audit_events
		WHERE action = 'auth.demo_residual_grants_detected'
		ORDER BY occurred_at DESC LIMIT 1
	`)
	if err != nil {
		t.Fatalf("audit_events query: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected at least one auth.demo_residual_grants_detected row")
	}
	var action, category, resourceID string
	if err := rows.Scan(&action, &category, &resourceID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if action != "auth.demo_residual_grants_detected" {
		t.Errorf("action = %q, want auth.demo_residual_grants_detected", action)
	}
	if category != "auth" {
		t.Errorf("event_category = %q, want auth", category)
	}
	if resourceID != "actor-demo-anon" {
		t.Errorf("resource_id = %q, want actor-demo-anon", resourceID)
	}
}

// TestPreflightDemoModeResidual_StrictMode_RefusesStartup proves the
// flag pivots WARN → fail.
func TestPreflightDemoModeResidual_StrictMode_RefusesStartup(t *testing.T) {
	db := setupA8DB(t)
	resetA8Residue(t, db, true)

	cfg := &config.Config{}
	cfg.Auth.Type = "api-key"
	cfg.Auth.DemoModeResidualStrict = true

	err := preflightDemoModeResidual(context.Background(), cfg, db, nil, nil)
	if err == nil {
		t.Fatal("strict mode + residue: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "actor-demo-anon") {
		t.Errorf("err = %q, want mention of actor-demo-anon", err.Error())
	}
	if !strings.Contains(err.Error(), "CERTCTL_DEMO_MODE_RESIDUAL_STRICT") {
		t.Errorf("err = %q, want mention of CERTCTL_DEMO_MODE_RESIDUAL_STRICT", err.Error())
	}
}

// TestDemoAnonResidueRow_String pins the formatting of the residue
// detail entry — used both in the WARN log AND the audit row's
// `residue` slice. Two cases: NULL scope_id (global scope) and
// non-empty scope_id (profile/issuer scope).
func TestDemoAnonResidueRow_String(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339, "2026-05-11T12:34:56Z")
	cases := []struct {
		name string
		r    demoAnonResidueRow
		want string
	}{
		{
			name: "global_scope",
			r:    demoAnonResidueRow{RoleID: "r-admin", ScopeType: "global", ScopeID: "", GrantedAt: ts},
			want: "r-admin@global (granted 2026-05-11T12:34:56Z)",
		},
		{
			name: "scoped",
			r:    demoAnonResidueRow{RoleID: "r-operator", ScopeType: "profile", ScopeID: "p-prod", GrantedAt: ts},
			want: "r-operator@profile/p-prod (granted 2026-05-11T12:34:56Z)",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := c.r.String()
			if got != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestDeleteDemoAnonResidue_Idempotent proves the cleanup helper is
// re-entrant: a second call after a successful first call returns 0.
func TestDeleteDemoAnonResidue_Idempotent(t *testing.T) {
	db := setupA8DB(t)
	resetA8Residue(t, db, true)

	n, err := deleteDemoAnonResidue(context.Background(), db)
	if err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if n < 1 {
		t.Fatalf("first delete: count = %d, want >= 1", n)
	}

	n, err = deleteDemoAnonResidue(context.Background(), db)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if n != 0 {
		t.Errorf("second delete (idempotent): count = %d, want 0", n)
	}
}

// TestQueryDemoAnonResidue_NilDB pins the nil-safety contract.
func TestQueryDemoAnonResidue_NilDB(t *testing.T) {
	_, err := queryDemoAnonResidue(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil db, got nil")
	}
}

// TestDeleteDemoAnonResidue_NilDB pins the nil-safety contract.
func TestDeleteDemoAnonResidue_NilDB(t *testing.T) {
	_, err := deleteDemoAnonResidue(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil db, got nil")
	}
}
