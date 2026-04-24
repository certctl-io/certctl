package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lib/pq"
)

// pgErrInvalidPassword is the SQLSTATE for class 28 / code 28P01 —
// invalid_password — emitted by PostgreSQL when the client presents
// credentials that don't match pg_authid. Defined locally because the
// lib/pq package does not export named constants for SQLSTATE codes (it
// only exposes the typed string alias pq.ErrorCode and a name-lookup map
// at runtime). Pinned as a string constant rather than a pq.ErrorCode
// literal so the contract is grep-able from operator-facing log lines.
//
// Reference: https://www.postgresql.org/docs/16/errcodes-appendix.html
const pgErrInvalidPassword = "28P01"

// NewDB opens a PostgreSQL database connection and sets up connection pooling.
func NewDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	// Ping to verify connection
	if err := db.Ping(); err != nil {
		return nil, wrapPingError(err)
	}

	return db, nil
}

// wrapPingError converts a db.Ping() failure into an operator-friendly
// diagnostic. The default wrap is the original opaque
// `"failed to ping database: <inner>"` shape. The exception is SQLSTATE 28P01
// (invalid_password): when postgres rejects the server's credentials we emit
// extended guidance that names the most common operator misstep — editing
// POSTGRES_PASSWORD in `.env` after the postgres named volume has already
// been initialized — and lists both the destructive (`docker compose down -v`)
// and non-destructive (`ALTER ROLE`) remediations.
//
// U-1 (P1, GitHub #10): closes the audit-flagged
// cat-u-quickstart_postgres_password_volume_trap finding. The postgres
// docker-entrypoint runs initdb only when /var/lib/postgresql/data is empty;
// on subsequent boots the password baked into pg_authid on first boot wins
// over whatever the env var carries, so the env-vs-pg_authid divergence is
// intrinsic to how the postgres image bootstraps and cannot be fixed by us
// upstream of pg_authid. The ergonomic answer is to surface a clear
// diagnostic at the failure site so operators don't waste an hour on
// "is my password right" before discovering the volume needs to be torn
// down (or the role's password rotated in-place).
//
// The wrap chain is preserved via fmt.Errorf("%w", err) so callers using
// errors.As(err, &*pq.Error) on the returned value continue to work; this
// matches the audit's "no substring matching on err.Error()" requirement
// from the M-1 sentinel-error migration.
//
// Returns nil when err is nil so callers can defensively pipe through this
// helper without an extra branch.
func wrapPingError(err error) error {
	if err == nil {
		return nil
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) && string(pqErr.Code) == pgErrInvalidPassword {
		return fmt.Errorf(
			"failed to ping database: postgres rejected the configured credentials "+
				"(SQLSTATE %s — invalid_password). If you recently rotated POSTGRES_PASSWORD "+
				"on a docker-compose deploy, the postgres container's data volume still "+
				"holds the previous password: initdb seeds POSTGRES_PASSWORD into pg_authid "+
				"only on first boot of a fresh data dir, so editing the env var after that "+
				"point updates only the certctl-server container. Reset destructively with "+
				"`docker compose -f deploy/docker-compose.yml down -v && "+
				"docker compose -f deploy/docker-compose.yml up -d --build` (this DESTROYS "+
				"all data in the postgres volume), or non-destructively with "+
				"`docker compose -f deploy/docker-compose.yml exec postgres "+
				"psql -U certctl -c \"ALTER ROLE certctl PASSWORD '<new-password>';\"` "+
				"and then redeploy with the matching POSTGRES_PASSWORD. Underlying error: %w",
			pgErrInvalidPassword, err)
	}

	return fmt.Errorf("failed to ping database: %w", err)
}

// RunMigrations reads and executes SQL migration files from a directory.
func RunMigrations(db *sql.DB, migrationsPath string) error {
	// Check if migrations directory exists
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory not found: %s", migrationsPath)
	}

	// Read all SQL files from the migrations directory
	files, err := os.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort and filter to only .up.sql migration files (skip .down.sql rollbacks and seed files)
	var sqlFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".up.sql") {
			sqlFiles = append(sqlFiles, file.Name())
		}
	}

	// Execute each migration file in order
	for _, filename := range sqlFiles {
		filePath := filepath.Join(migrationsPath, filename)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		// Execute the SQL content
		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
		}
	}

	return nil
}
