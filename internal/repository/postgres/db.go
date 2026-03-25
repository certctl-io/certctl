package postgres

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/lib/pq"
)

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
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
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
