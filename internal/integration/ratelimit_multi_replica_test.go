// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/certctl-io/certctl/internal/ratelimit"
)

// Phase 13 Sprint 13.2 closure (2026-05-14, architecture diligence audit
// ARCH-M1) — the falsifiable closure proof for cross-replica rate-limit
// consistency.
//
// Scenario:
//   - ONE postgres container (representing the shared backend).
//   - N=3 independent *PostgresSlidingWindowLimiter instances pointing
//     at it (representing 3 server replicas — each replica's process
//     has its own constructed limiter, but they all share the same
//     database state).
//   - 100 concurrent Allow("test-key") calls spread across the 3
//     limiters via sync.WaitGroup.
//   - Assert: exactly 10 succeed + 90 return ErrRateLimited.
//
// If the postgres backend's SELECT FOR UPDATE serialization weren't
// arbitrating across the 3 limiters, more than 10 calls would be
// allowed (each replica would independently let through 10/3 ≈ 4
// requests, giving ~12-15 successes depending on scheduling). The
// hard-pass on exactly-10 is what makes ARCH-M1 closure substantive
// rather than wishful.
//
// Gated by //go:build integration matching the rest of
// internal/integration/. Sprint 13.3 promotes this test to a
// required CI status check.

func TestRateLimit_PostgresBackend_CapEnforcedAcrossReplicas(t *testing.T) {
	const (
		replicas      = 3
		cap           = 10
		window        = 1 * time.Minute
		concurrentReq = 100
		key           = "test-key"
	)

	ctx := context.Background()

	// Boot a shared postgres container.
	container, dsn := startPostgresContainer(ctx, t)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	// Each "replica" gets its own *sql.DB pool — same database, different
	// connection pool — matching how N server processes would each open
	// their own pool to the same control-plane database.
	dbs := make([]*sql.DB, replicas)
	for i := 0; i < replicas; i++ {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open db (replica %d): %v", i, err)
		}
		db.SetMaxOpenConns(8)
		if err := db.Ping(); err != nil {
			t.Fatalf("ping (replica %d): %v", i, err)
		}
		t.Cleanup(func() { db.Close() })
		dbs[i] = db
	}

	// Apply the rate_limit_buckets migration via dbs[0]. All replicas
	// see the same schema since they share the same database.
	migPath := findMigrationFromHere("000046_rate_limit_buckets.up.sql")
	body, err := os.ReadFile(migPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := dbs[0].ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	// Instantiate one limiter per replica.
	limiters := make([]*ratelimit.PostgresSlidingWindowLimiter, replicas)
	for i := 0; i < replicas; i++ {
		limiters[i] = ratelimit.NewPostgresSlidingWindowLimiter(dbs[i], cap, window)
	}

	// Fire concurrentReq parallel Allow calls, round-robining across the
	// replicas. Each call uses the SAME key + a SHARED `now` so the
	// scenario is deterministic. The cross-replica row lock is what
	// enforces the cap globally.
	var (
		allowed int64
		denied  int64
		wg      sync.WaitGroup
	)
	now := time.Now()
	for i := 0; i < concurrentReq; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			l := limiters[idx%replicas]
			err := l.Allow(key, now)
			if err == nil {
				atomic.AddInt64(&allowed, 1)
			} else if errors.Is(err, ratelimit.ErrRateLimited) {
				atomic.AddInt64(&denied, 1)
			} else {
				t.Errorf("unexpected error from Allow: %v", err)
			}
		}(i)
	}
	wg.Wait()

	gotAllowed := atomic.LoadInt64(&allowed)
	gotDenied := atomic.LoadInt64(&denied)

	t.Logf("replicas=%d cap=%d concurrent=%d → allowed=%d denied=%d",
		replicas, cap, concurrentReq, gotAllowed, gotDenied)

	if gotAllowed != int64(cap) {
		t.Errorf("allowed = %d, want exactly %d (cross-replica row lock should serialize Allow calls so exactly cap succeed)",
			gotAllowed, cap)
	}
	if gotDenied != int64(concurrentReq-cap) {
		t.Errorf("denied = %d, want %d (concurrentReq - cap)", gotDenied, concurrentReq-cap)
	}
}

// ----------------------------------------------------------------
// Local testcontainers harness. Kept in-file because the rest of
// internal/integration/ uses HTTP-against-running-server smoke tests
// against a docker-compose stack — different shape from ours.
// ----------------------------------------------------------------

func startPostgresContainer(ctx context.Context, t *testing.T) (testcontainers.Container, string) {
	t.Helper()

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
	dsn := fmt.Sprintf("postgres://certctl:certctl@%s:%s/certctl_test?sslmode=disable",
		host, port.Port())
	return container, dsn
}

func findMigrationFromHere(filename string) string {
	_, here, _, _ := runtime.Caller(0)
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
