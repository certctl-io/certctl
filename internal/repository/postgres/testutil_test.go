// Package postgres_test contains integration tests for PostgreSQL repository
// implementations using testcontainers-go. Tests spin up a real PostgreSQL 16
// container and use schema-per-test isolation for parallel safety.
package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testDB holds a shared database connection for a test suite.
// Each test gets its own schema (via search_path) for isolation.
type testDB struct {
	db        *sql.DB
	container testcontainers.Container
}

// setupTestDB starts a PostgreSQL container and runs all migrations.
// Call this once per test file via TestMain or a sync.Once.
func setupTestDB(t *testing.T) *testDB {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

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
		t.Fatalf("failed to start postgres container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get mapped port: %v", err)
	}

	connStr := fmt.Sprintf("postgres://certctl:certctl@%s:%s/certctl_test?sslmode=disable", host, port.Port())

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}

	// Run migrations
	migrationsPath := findMigrationsDir()
	if err := runMigrations(db, migrationsPath); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return &testDB{db: db, container: container}
}

// teardown stops the container and closes the connection.
func (tdb *testDB) teardown(t *testing.T) {
	t.Helper()
	if tdb.db != nil {
		tdb.db.Close()
	}
	if tdb.container != nil {
		tdb.container.Terminate(context.Background())
	}
}

// freshSchema creates a new PostgreSQL schema for test isolation
// and returns a *sql.DB with search_path set to that schema.
// Each test gets a unique schema so tests don't interfere with each other.
func (tdb *testDB) freshSchema(t *testing.T) *sql.DB {
	t.Helper()

	// Create a unique schema name from the test name
	schemaName := sanitizeSchemaName(t.Name())

	ctx := context.Background()

	// Create schema
	_, err := tdb.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName))
	if err != nil {
		t.Fatalf("failed to create schema %s: %v", schemaName, err)
	}

	// Set search_path for this connection to use the new schema
	_, err = tdb.db.ExecContext(ctx, fmt.Sprintf("SET search_path TO %s, public", schemaName))
	if err != nil {
		t.Fatalf("failed to set search_path: %v", err)
	}

	// Run migrations in the new schema
	migrationsPath := findMigrationsDir()
	if err := runMigrationsWithSearchPath(tdb.db, migrationsPath, schemaName); err != nil {
		t.Fatalf("failed to run migrations in schema %s: %v", schemaName, err)
	}

	// Register cleanup
	t.Cleanup(func() {
		tdb.db.ExecContext(context.Background(), fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName))
	})

	return tdb.db
}

// sanitizeSchemaName converts a test name to a valid PostgreSQL schema name.
func sanitizeSchemaName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	// Truncate to 63 chars (PG limit)
	if len(name) > 60 {
		name = name[:60]
	}
	return "test_" + name
}

// findMigrationsDir walks up from the test file to find the migrations/ directory.
func findMigrationsDir() string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)

	// Walk up to find the project root (where migrations/ lives)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "migrations")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}

	// Fallback: try relative from working directory
	return "../../../../migrations"
}

// runMigrations reads and executes all .up.sql migration files.
func runMigrations(db *sql.DB, migrationsPath string) error {
	files, err := os.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory %s: %w", migrationsPath, err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".up.sql") {
			content, err := os.ReadFile(filepath.Join(migrationsPath, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to read migration %s: %w", file.Name(), err)
			}
			if _, err := db.Exec(string(content)); err != nil {
				return fmt.Errorf("failed to execute migration %s: %w", file.Name(), err)
			}
		}
	}
	return nil
}

// runMigrationsWithSearchPath runs migrations within a specific schema.
func runMigrationsWithSearchPath(db *sql.DB, migrationsPath string, schema string) error {
	// Set search_path before running migrations
	if _, err := db.Exec(fmt.Sprintf("SET search_path TO %s, public", schema)); err != nil {
		return fmt.Errorf("failed to set search_path: %w", err)
	}
	return runMigrations(db, migrationsPath)
}
