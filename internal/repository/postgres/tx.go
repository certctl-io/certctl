// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

// WithinTx is the transactional spine for any service-layer operation
// whose audit row must be atomic with the underlying state change.
// Closes the #3 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit (Part 1.5 finding #1: audit row not
// transactional with issuance).
//
// The Querier interface lives in internal/repository (shared with the
// interface declarations) so repository interfaces and the postgres
// concrete types reference the same type without a circular import.
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/shankar0123/certctl/internal/repository"
)

// transactor is the production implementation of repository.Transactor.
// It wraps a *sql.DB and exposes the WithinTx helper as the interface
// method service-layer code calls.
type transactor struct {
	db *sql.DB
}

// NewTransactor returns a repository.Transactor backed by the given
// *sql.DB. Production wiring (cmd/server/main.go) passes the same db
// handle that backs the other repositories; tests pass a mock that
// implements the interface against in-memory state.
func NewTransactor(db *sql.DB) repository.Transactor {
	return &transactor{db: db}
}

// WithinTx delegates to the package-level WithinTx helper, adapting
// the function signature so callers receive repository.Querier instead
// of *sql.Tx (which the interface requires for portability across
// transactor implementations).
func (t *transactor) WithinTx(ctx context.Context, fn func(q repository.Querier) error) error {
	return WithinTx(ctx, t.db, func(tx *sql.Tx) error {
		return fn(tx)
	})
}

// Querier is re-exported from the parent repository package so callers
// inside this package can reference it without an extra import.
//
// Deprecated: external callers should use repository.Querier directly.
// This alias exists for legibility within the postgres package only.

// WithinTx runs fn inside a transaction. The transaction is committed
// if fn returns nil; rolled back if fn returns an error or panics.
//
// Contract:
//
//   - On nil error from fn: tx.Commit() is called. If Commit fails
//     (e.g., serialization conflict, connection drop), the commit
//     error is returned.
//   - On non-nil error from fn: tx.Rollback() is called. If Rollback
//     itself errors, the original fn error is wrapped with the
//     rollback error so operators see both.
//   - On panic in fn: tx.Rollback() is called and the panic is
//     re-raised. The transaction is never left dangling.
//
// Callers must NOT call tx.Commit() or tx.Rollback() inside fn — that's
// WithinTx's job. Returning an error from fn signals "roll back";
// returning nil signals "commit".
//
// BeginTx is called with nil opts; callers needing isolation level
// other than the database default should construct their own tx via
// db.BeginTx and not use this helper.
func WithinTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("%w; rollback: %v", err, rbErr)
			}
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if cmErr := tx.Commit(); cmErr != nil {
		return fmt.Errorf("commit tx: %w", cmErr)
	}
	return nil
}
