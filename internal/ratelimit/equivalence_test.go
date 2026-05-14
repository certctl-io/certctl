// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

	"github.com/certctl-io/certctl/internal/ratelimit"
)

// Phase 13 Sprint 13.2 closure (2026-05-14, architecture diligence audit
// ARCH-M1): backend-equivalence test suite. Runs the same scenario
// surface against both backends (in-memory + postgres) via the shared
// Limiter interface — if the postgres backend's caller-visible
// semantics drift from the memory backend's, this file fails first.
//
// Mirrors the white-box test names in sliding_window_test.go: every
// public-surface behavior pinned there (cap, expiry, disabled bypass,
// empty-key short-circuit, concurrency) gets re-pinned here for the
// postgres backend.
//
// Postgres tests skip under -short (matches the pattern in
// internal/repository/postgres/testutil_test.go); CI's
// `go test -race -short -count=1 ./...` exercises only the memory
// half. The integration job runs the full suite.

// ----------------------------------------------------------------
// Backend-equivalence helpers
// ----------------------------------------------------------------

// limiterFactory builds a fresh Limiter for one test case.
// Memory backends discard `db`; postgres backends use it.
type limiterFactory func(t *testing.T, db *sql.DB, maxN int, window time.Duration) ratelimit.Limiter

func memoryFactory(t *testing.T, _ *sql.DB, maxN int, window time.Duration) ratelimit.Limiter {
	t.Helper()
	// Map cap of 10_000 — large enough that none of the equivalence
	// scenarios trip the LRU-eviction branch (the eviction branch is
	// memory-specific; postgres has no equivalent so it's not part of
	// the cross-backend contract).
	return ratelimit.NewSlidingWindowLimiter(maxN, window, 10_000)
}

func postgresFactory(t *testing.T, db *sql.DB, maxN int, window time.Duration) ratelimit.Limiter {
	t.Helper()
	if db == nil {
		t.Fatal("postgresFactory requires a non-nil *sql.DB")
	}
	return ratelimit.NewPostgresSlidingWindowLimiter(db, maxN, window)
}

// ----------------------------------------------------------------
// Per-backend test entry points
// ----------------------------------------------------------------

func TestSlidingWindowLimiter_Equivalence_Memory(t *testing.T) {
	t.Run("AllowsUpToCap", func(t *testing.T) { caseAllowsUpToCap(t, memoryFactory, nil) })
	t.Run("DistinctKeysIndependent", func(t *testing.T) { caseDistinctKeysIndependent(t, memoryFactory, nil) })
	t.Run("WindowExpiry", func(t *testing.T) { caseWindowExpiry(t, memoryFactory, nil) })
	t.Run("DisabledBypass", func(t *testing.T) { caseDisabledBypass(t, memoryFactory, nil) })
	t.Run("NegativeCapDisabled", func(t *testing.T) { caseNegativeCapDisabled(t, memoryFactory, nil) })
	t.Run("EmptyKeyShortCircuits", func(t *testing.T) { caseEmptyKeyShortCircuits(t, memoryFactory, nil) })
	t.Run("ConcurrentRaceFree", func(t *testing.T) {
		if testing.Short() {
			t.Skip("race-style test under -short")
		}
		caseConcurrentRaceFree(t, memoryFactory, nil)
	})
}

func TestSlidingWindowLimiter_Equivalence_Postgres(t *testing.T) {
	if testing.Short() {
		t.Skip("postgres equivalence tests require testcontainers; skipped under -short")
	}
	tdb := setupTestDB(t)
	defer tdb.teardown(t)

	t.Run("AllowsUpToCap", func(t *testing.T) {
		db := tdb.freshSchema(t, "AllowsUpToCap")
		caseAllowsUpToCap(t, postgresFactory, db)
	})
	t.Run("DistinctKeysIndependent", func(t *testing.T) {
		db := tdb.freshSchema(t, "DistinctKeysIndependent")
		caseDistinctKeysIndependent(t, postgresFactory, db)
	})
	t.Run("WindowExpiry", func(t *testing.T) {
		db := tdb.freshSchema(t, "WindowExpiry")
		caseWindowExpiry(t, postgresFactory, db)
	})
	t.Run("DisabledBypass", func(t *testing.T) {
		db := tdb.freshSchema(t, "DisabledBypass")
		caseDisabledBypass(t, postgresFactory, db)
	})
	t.Run("NegativeCapDisabled", func(t *testing.T) {
		db := tdb.freshSchema(t, "NegativeCapDisabled")
		caseNegativeCapDisabled(t, postgresFactory, db)
	})
	t.Run("EmptyKeyShortCircuits", func(t *testing.T) {
		db := tdb.freshSchema(t, "EmptyKeyShortCircuits")
		caseEmptyKeyShortCircuits(t, postgresFactory, db)
	})
	t.Run("ConcurrentRaceFree", func(t *testing.T) {
		db := tdb.freshSchema(t, "ConcurrentRaceFree")
		caseConcurrentRaceFree(t, postgresFactory, db)
	})
}

// ----------------------------------------------------------------
// Backend-agnostic test cases (one per behavior pinned in
// sliding_window_test.go's public-surface tests)
// ----------------------------------------------------------------

func caseAllowsUpToCap(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, 3, 24*time.Hour)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Allow("k", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("call %d should be allowed: %v", i+1, err)
		}
	}
	if err := l.Allow("k", now.Add(4*time.Minute)); !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("4th call should be rate-limited; got %v", err)
	}
}

func caseDistinctKeysIndependent(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, 1, 24*time.Hour)
	now := time.Now()

	if err := l.Allow("k-1", now); err != nil {
		t.Fatalf("first allow: %v", err)
	}
	if err := l.Allow("k-2", now); err != nil {
		t.Fatalf("different key must have its own bucket: %v", err)
	}
	if err := l.Allow("k-1", now.Add(1*time.Second)); !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("repeat key should be limited; got %v", err)
	}
}

func caseWindowExpiry(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, 2, 1*time.Hour)
	now := time.Now()

	if err := l.Allow("k", now); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow("k", now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Inside window — limited.
	if err := l.Allow("k", now.Add(45*time.Minute)); !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("inside-window 3rd call should be limited: %v", err)
	}
	// Past window — slots reopen.
	if err := l.Allow("k", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("past-window call should be allowed (window reset): %v", err)
	}
}

func caseDisabledBypass(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, 0, 24*time.Hour) // maxN=0 → disabled
	type disablable interface {
		Disabled() bool
	}
	if d, ok := l.(disablable); ok && !d.Disabled() {
		t.Fatal("limiter with maxN=0 must report Disabled()=true")
	}
	now := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Allow("k", now); err != nil {
			t.Fatalf("disabled limiter must allow everything: %v", err)
		}
	}
}

func caseNegativeCapDisabled(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, -1, 24*time.Hour)
	type disablable interface {
		Disabled() bool
	}
	if d, ok := l.(disablable); ok && !d.Disabled() {
		t.Fatal("negative maxN must produce a disabled limiter")
	}
	now := time.Now()
	if err := l.Allow("k", now); err != nil {
		t.Fatalf("disabled limiter must allow: %v", err)
	}
}

func caseEmptyKeyShortCircuits(t *testing.T, mk limiterFactory, db *sql.DB) {
	// Empty key is the caller's defense-in-depth case — caller's
	// validation upstream should reject empty-key events first. Limiter
	// must not build a single shared bucket keyed by empty-key — that
	// would be a chokepoint for every empty-key event.
	l := mk(t, db, 1, 24*time.Hour)
	now := time.Now()
	for i := 0; i < 50; i++ {
		if err := l.Allow("", now); err != nil {
			t.Fatalf("empty key must short-circuit (call %d): %v", i, err)
		}
	}
}

func caseConcurrentRaceFree(t *testing.T, mk limiterFactory, db *sql.DB) {
	l := mk(t, db, 50, 24*time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			key := fmt.Sprintf("k-%d", id)
			for i := 0; i < 30; i++ {
				_ = l.Allow(key, now)
			}
		}(g)
	}
	wg.Wait()
}

// ----------------------------------------------------------------
// Postgres-only testcontainers harness — mirrors
// internal/repository/postgres/testutil_test.go's setupTestDB +
// freshSchema pattern.
// ----------------------------------------------------------------

type testDB struct {
	db        *sql.DB
	container testcontainers.Container
}

func setupTestDB(t *testing.T) *testDB {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_DB":       "certctl_test",
			"POSTGRES_USER":     "certctl",
			"POSTGRES_PASSWORD": "certctl",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}

	connStr := fmt.Sprintf("postgres://certctl:certctl@%s:%s/certctl_test?sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// Pool size > 1 so the multi-goroutine concurrency case can hold
	// multiple connections simultaneously; the row-lock arbitrates.
	db.SetMaxOpenConns(8)

	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	return &testDB{db: db, container: container}
}

func (tdb *testDB) teardown(t *testing.T) {
	t.Helper()
	if tdb.db != nil {
		tdb.db.Close()
	}
	if tdb.container != nil {
		_ = tdb.container.Terminate(context.Background())
	}
}

// freshSchema creates an isolated schema per test case + runs the
// rate_limit_buckets migration inside it. Returns a *sql.DB whose
// search_path is scoped to the new schema.
//
// Note: this helper takes a sub-test label (caller-supplied) so the
// schema name is deterministic-per-case + stable across runs. The
// canonical postgres testutil uses t.Name() but we're inside Run-
// nested subtests where t.Name() includes "/" — flatten it.
func (tdb *testDB) freshSchema(t *testing.T, label string) *sql.DB {
	t.Helper()
	schema := sanitizeSchemaName(label + "_" + t.Name())
	ctx := context.Background()

	// One connection-scoped session so SET search_path persists.
	conn, err := tdb.db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire conn: %v", err)
	}

	if _, err := conn.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET search_path TO %s, public", schema)); err != nil {
		t.Fatalf("set search_path: %v", err)
	}

	// Run the rate_limit_buckets migration in this schema. The migration
	// is the only one that introduces our table; other migrations don't
	// matter for limiter behavior.
	migPath := findMigration("000046_rate_limit_buckets.up.sql")
	body, err := os.ReadFile(migPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := conn.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	t.Cleanup(func() {
		conn.ExecContext(context.Background(), fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
		conn.Close()
	})

	// Wrap the single connection in a *sql.DB-like by returning a fresh
	// pool that goes through the same search_path. Simpler: just return
	// the underlying *sql.DB and SET search_path session-wide by re-
	// running the SET on every checkout. The cleanest move is to use
	// the per-connection helper: return a *sql.DB that's actually a
	// "limited to N=1 connection with search_path pinned" handle.
	//
	// Workaround the easy way: build a fresh *sql.DB whose dsn embeds
	// search_path as a connection-time setting, so every connection
	// auto-applies it.
	dsn := connDSNWithSearchPath(tdb, schema)
	scoped, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open scoped db: %v", err)
	}
	scoped.SetMaxOpenConns(8)
	t.Cleanup(func() { scoped.Close() })

	// Sanity: row exists / table exists.
	if _, err := scoped.ExecContext(ctx, "SELECT 1 FROM rate_limit_buckets LIMIT 1"); err != nil && !strings.Contains(err.Error(), "no rows") {
		// Empty table is fine; only a missing-table error matters.
		// "no rows" never fires here (we used Exec not Query).
		t.Fatalf("smoke select: %v", err)
	}

	return scoped
}

func connDSNWithSearchPath(tdb *testDB, schema string) string {
	// Derive the DSN by introspection of the container's host/port.
	// Couldn't pre-store because freshSchema can be called many times.
	ctx := context.Background()
	host, _ := tdb.container.Host(ctx)
	port, _ := tdb.container.MappedPort(ctx, "5432")
	return fmt.Sprintf(
		"postgres://certctl:certctl@%s:%s/certctl_test?sslmode=disable&search_path=%s,public",
		host, port.Port(), schema,
	)
}

func sanitizeSchemaName(name string) string {
	name = strings.ToLower(name)
	for _, ch := range []string{"/", " ", "-", "."} {
		name = strings.ReplaceAll(name, ch, "_")
	}
	if len(name) > 50 {
		name = name[:50]
	}
	return "test_rl_" + name
}

func findMigration(filename string) string {
	_, here, _, _ := runtime.Caller(0)
	// here = .../internal/ratelimit/equivalence_test.go
	// migrations = .../migrations
	dir := filepath.Dir(here)
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "migrations", filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	return ""
}
