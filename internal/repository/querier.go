// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package repository

import (
	"context"
	"database/sql"
)

// Querier is the subset of *sql.DB and *sql.Tx that repository methods
// need. Both stdlib types satisfy it without an adapter.
//
// Repository methods that must participate in a service-layer
// transaction (audit atomicity for issuance / renewal / revocation)
// expose *WithTx variants that take a Querier; the bare methods remain
// for stand-alone use cases that do not need transactional semantics.
//
// Service code uses postgres.WithinTx to begin a tx and pass *sql.Tx
// (which satisfies Querier) into the *WithTx methods. Mock
// implementations in tests take the same Querier parameter and ignore
// it (mocks have no DB; they have in-memory state).
//
// Closes the #3 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit (Part 1.5 finding #1).
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Compile-time guards: *sql.DB and *sql.Tx must satisfy Querier.
var (
	_ Querier = (*sql.DB)(nil)
	_ Querier = (*sql.Tx)(nil)
)

// Transactor abstracts the "begin tx, run fn, commit/rollback" lifecycle
// so service-layer code can run multi-write operations atomically without
// holding a *sql.DB directly. The postgres package provides the
// production implementation via postgres.NewTransactor; tests provide a
// mock implementation that runs fn synchronously against in-memory
// state.
//
// fn receives a Querier — either *sql.Tx (production) or a test stand-
// in. fn returns error to signal "roll back" or nil to signal "commit".
//
// This interface closes the #3 acquisition-readiness blocker from the
// 2026-05-01 issuer coverage audit: audit row + cert insert / revoke
// row + cert update must be atomic with the operation, and the
// service layer must not depend on the postgres concrete types to
// achieve that.
type Transactor interface {
	// WithinTx begins a transaction, runs fn against the resulting
	// Querier, and commits if fn returns nil or rolls back if fn
	// returns an error or panics.
	WithinTx(ctx context.Context, fn func(q Querier) error) error
}
