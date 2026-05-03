// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ACMERepository implements the ACME server's persistence layer
// (RFC 8555 + RFC 9773 ARI). Phase 1a wires only nonce operations
// (IssueNonce + ConsumeNonce); Phase 1b extends with account CRUD,
// Phase 2 with order/authz/challenge CRUD, Phase 4 with the
// key-rollover atomic update path.
type ACMERepository struct {
	db *sql.DB
}

// NewACMERepository constructs an ACMERepository wrapping the supplied
// *sql.DB. The constructor is symmetric with NewAuditRepository,
// NewProfileRepository, etc. — main.go owns the lifecycle.
func NewACMERepository(db *sql.DB) *ACMERepository {
	return &ACMERepository{db: db}
}

// IssueNonce inserts a new ACME nonce row with the given TTL. The
// caller (typically ACMEService.IssueNonce) is responsible for
// generating the nonce string itself via acme.GenerateNonce; this
// method is the persistence write.
//
// RFC 8555 §6.5: nonces issued by the server can be redeemed exactly
// once. The PRIMARY KEY guarantees insertion uniqueness; ConsumeNonce
// flips the `used` column atomically so a replay sees `used=true`.
func (r *ACMERepository) IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_nonces (nonce, issued_at, expires_at, used)
		VALUES ($1, NOW(), $2, FALSE)
	`, nonce, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("acme: insert nonce: %w", err)
	}
	return nil
}

// ConsumeNonce flips the nonce's `used` column to true atomically.
// Returns sql.ErrNoRows if:
//
//   - the nonce was never issued (caller's payload was forged or
//     truncated)
//   - the nonce was already consumed (replay attempt)
//   - the nonce has expired (CERTCTL_ACME_SERVER_NONCE_TTL window
//     elapsed since issuance)
//
// All three failure modes are mapped by the JWS verifier (Phase 1b)
// to urn:ietf:params:acme:error:badNonce per RFC 8555 §6.5.1. Phase
// 1a does not yet call ConsumeNonce — the JWS-authenticated POST
// path arrives in Phase 1b.
//
// The single UPDATE statement is the atomic primitive: a concurrent
// second consume races for the same row, but only one of them flips
// `used` from false → true. Postgres's row-level locking serializes
// the writes; the loser's UPDATE matches zero rows (because used is
// already true) and returns sql.ErrNoRows.
func (r *ACMERepository) ConsumeNonce(ctx context.Context, nonce string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_nonces
		SET used = TRUE
		WHERE nonce = $1
		  AND used = FALSE
		  AND expires_at > NOW()
	`, nonce)
	if err != nil {
		return fmt.Errorf("acme: consume nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: consume nonce rows affected: %w", err)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ErrACMEAccountDuplicateThumbprint is the sentinel returned by
// CreateAccount[WithTx] when the (profile_id, jwk_thumbprint) UNIQUE
// constraint fires. Callers (the new-account flow) translate this
// into "an account already exists for this JWK" — RFC 8555 §7.3.1
// idempotent-semantics path.
var ErrACMEAccountDuplicateThumbprint = errors.New("acme: account already exists for this profile + JWK thumbprint")

// CreateAccount inserts a new acme_accounts row. Use CreateAccountWithTx
// when the insert must be atomic with an audit row.
func (r *ACMERepository) CreateAccount(ctx context.Context, acct *domain.ACMEAccount) error {
	return r.CreateAccountWithTx(ctx, r.db, acct)
}

// CreateAccountWithTx inserts using the supplied Querier (typically
// *sql.Tx from postgres.WithinTx). Returns
// ErrACMEAccountDuplicateThumbprint on the (profile_id, jwk_thumbprint)
// UNIQUE collision per migration 000025.
func (r *ACMERepository) CreateAccountWithTx(ctx context.Context, q repository.Querier, acct *domain.ACMEAccount) error {
	if acct.AccountID == "" || acct.JWKThumbprint == "" || acct.JWKPEM == "" || acct.ProfileID == "" {
		return fmt.Errorf("acme: create account: missing required field")
	}
	if acct.Status == "" {
		acct.Status = domain.ACMEAccountStatusValid
	}
	now := time.Now().UTC()
	if acct.CreatedAt.IsZero() {
		acct.CreatedAt = now
	}
	acct.UpdatedAt = now

	contact := pq.Array(acct.Contact)
	var ownerID interface{}
	if acct.OwnerID != "" {
		ownerID = acct.OwnerID
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO acme_accounts (
			account_id, jwk_thumbprint, jwk_pem, contact, status,
			profile_id, owner_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		acct.AccountID, acct.JWKThumbprint, acct.JWKPEM, contact,
		string(acct.Status), acct.ProfileID, ownerID,
		acct.CreatedAt, acct.UpdatedAt,
	)
	if err != nil {
		// Postgres SQLSTATE 23505 = unique_violation. lib/pq wraps the
		// raw error in *pq.Error; decode and translate to the
		// repository sentinel.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return ErrACMEAccountDuplicateThumbprint
		}
		return fmt.Errorf("acme: insert account: %w", err)
	}
	return nil
}

// GetAccountByID returns the account row for an account ID.
// Returns sql.ErrNoRows wrapped via repository.ErrNotFound when
// no row matches (callers branch on errors.Is(err, repository.ErrNotFound)).
func (r *ACMERepository) GetAccountByID(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT account_id, jwk_thumbprint, jwk_pem, contact, status,
		       profile_id, COALESCE(owner_id, ''), created_at, updated_at
		FROM acme_accounts
		WHERE account_id = $1
	`, accountID)
	return scanACMEAccount(row)
}

// GetAccountByThumbprint returns the account row for a (profile_id,
// jwk_thumbprint) pair. Same sentinel semantics as GetAccountByID.
// The new-account idempotency path queries by thumbprint to detect a
// re-registration of an existing JWK (RFC 8555 §7.3.1).
func (r *ACMERepository) GetAccountByThumbprint(ctx context.Context, profileID, thumbprint string) (*domain.ACMEAccount, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT account_id, jwk_thumbprint, jwk_pem, contact, status,
		       profile_id, COALESCE(owner_id, ''), created_at, updated_at
		FROM acme_accounts
		WHERE profile_id = $1 AND jwk_thumbprint = $2
	`, profileID, thumbprint)
	return scanACMEAccount(row)
}

// UpdateAccountContact replaces the account's contact list. Use the
// WithTx variant when the update must be atomic with an audit row.
func (r *ACMERepository) UpdateAccountContact(ctx context.Context, accountID string, contact []string) error {
	return r.UpdateAccountContactWithTx(ctx, r.db, accountID, contact)
}

// UpdateAccountContactWithTx writes the new contact list using the
// supplied Querier. Returns sql.ErrNoRows-wrapped repository.ErrNotFound
// on missing account.
func (r *ACMERepository) UpdateAccountContactWithTx(ctx context.Context, q repository.Querier, accountID string, contact []string) error {
	res, err := q.ExecContext(ctx, `
		UPDATE acme_accounts
		SET contact = $2, updated_at = NOW()
		WHERE account_id = $1
	`, accountID, pq.Array(contact))
	if err != nil {
		return fmt.Errorf("acme: update account contact: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update account contact rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("account not found: %w", repository.ErrNotFound)
	}
	return nil
}

// UpdateAccountStatus is the persistence path for account
// deactivation. Phase 1b accepts only the "valid" → "deactivated"
// transition (RFC 8555 §7.3.6); operator-initiated revocation is a
// future phase.
func (r *ACMERepository) UpdateAccountStatus(ctx context.Context, accountID string, status domain.ACMEAccountStatus) error {
	return r.UpdateAccountStatusWithTx(ctx, r.db, accountID, status)
}

// UpdateAccountStatusWithTx writes the status transition using the
// supplied Querier. Same sentinel semantics as UpdateAccountContactWithTx.
func (r *ACMERepository) UpdateAccountStatusWithTx(ctx context.Context, q repository.Querier, accountID string, status domain.ACMEAccountStatus) error {
	res, err := q.ExecContext(ctx, `
		UPDATE acme_accounts
		SET status = $2, updated_at = NOW()
		WHERE account_id = $1
	`, accountID, string(status))
	if err != nil {
		return fmt.Errorf("acme: update account status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update account status rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("account not found: %w", repository.ErrNotFound)
	}
	return nil
}

// --- Phase 2 — order / authz / challenge CRUD --------------------------

// CreateOrderWithTx inserts an acme_orders row. Used by ACMEService.CreateOrder
// during new-order processing; the transaction also creates the per-identifier
// authz + challenge rows + audit row in the same WithinTx.
func (r *ACMERepository) CreateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	if order.OrderID == "" || order.AccountID == "" {
		return fmt.Errorf("acme: create order: missing required field")
	}
	now := time.Now().UTC()
	if order.CreatedAt.IsZero() {
		order.CreatedAt = now
	}
	order.UpdatedAt = now
	identifiersJSON, err := jsonMarshalACME(order.Identifiers)
	if err != nil {
		return fmt.Errorf("acme: marshal identifiers: %w", err)
	}
	var (
		notBefore, notAfter interface{}
		errBlob             interface{}
		certID              interface{}
	)
	if order.NotBefore != nil {
		notBefore = *order.NotBefore
	}
	if order.NotAfter != nil {
		notAfter = *order.NotAfter
	}
	if order.Error != nil {
		b, err := jsonMarshalACME(order.Error)
		if err != nil {
			return fmt.Errorf("acme: marshal error: %w", err)
		}
		errBlob = b
	}
	if order.CertificateID != "" {
		certID = order.CertificateID
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO acme_orders (
			order_id, account_id, identifiers, status, expires_at,
			not_before, not_after, error, csr_pem, certificate_id,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		order.OrderID, order.AccountID, identifiersJSON, string(order.Status),
		order.ExpiresAt, notBefore, notAfter, errBlob, order.CSRPEM, certID,
		order.CreatedAt, order.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("acme: insert order: %w", err)
	}
	return nil
}

// GetOrderByID retrieves an order. Returns sql.ErrNoRows-wrapped
// repository.ErrNotFound on miss.
func (r *ACMERepository) GetOrderByID(ctx context.Context, orderID string) (*domain.ACMEOrder, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT order_id, account_id, identifiers, status, expires_at,
		       not_before, not_after, error, COALESCE(csr_pem, ''),
		       COALESCE(certificate_id, ''), created_at, updated_at
		FROM acme_orders
		WHERE order_id = $1
	`, orderID)
	return scanACMEOrder(row)
}

// UpdateOrderWithTx persists changes to an order's mutable fields.
// Used by FinalizeOrder to transition status / set csr_pem /
// certificate_id / error.
func (r *ACMERepository) UpdateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	order.UpdatedAt = time.Now().UTC()
	var (
		errBlob interface{}
		certID  interface{}
	)
	if order.Error != nil {
		b, err := jsonMarshalACME(order.Error)
		if err != nil {
			return fmt.Errorf("acme: marshal error: %w", err)
		}
		errBlob = b
	}
	if order.CertificateID != "" {
		certID = order.CertificateID
	}
	res, err := q.ExecContext(ctx, `
		UPDATE acme_orders SET
			status = $2,
			error = $3,
			csr_pem = $4,
			certificate_id = $5,
			updated_at = $6
		WHERE order_id = $1
	`, order.OrderID, string(order.Status), errBlob, order.CSRPEM, certID, order.UpdatedAt)
	if err != nil {
		return fmt.Errorf("acme: update order: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update order rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("order not found: %w", repository.ErrNotFound)
	}
	return nil
}

// CreateAuthzWithTx inserts an acme_authorizations row.
func (r *ACMERepository) CreateAuthzWithTx(ctx context.Context, q repository.Querier, authz *domain.ACMEAuthorization) error {
	if authz.AuthzID == "" || authz.OrderID == "" {
		return fmt.Errorf("acme: create authz: missing required field")
	}
	now := time.Now().UTC()
	if authz.CreatedAt.IsZero() {
		authz.CreatedAt = now
	}
	authz.UpdatedAt = now
	idJSON, err := jsonMarshalACME(authz.Identifier)
	if err != nil {
		return fmt.Errorf("acme: marshal identifier: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO acme_authorizations (
			authz_id, order_id, identifier, status, expires_at, wildcard,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`,
		authz.AuthzID, authz.OrderID, idJSON, string(authz.Status),
		authz.ExpiresAt, authz.Wildcard, authz.CreatedAt, authz.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("acme: insert authz: %w", err)
	}
	return nil
}

// GetAuthzByID returns the authz row + its child challenges.
func (r *ACMERepository) GetAuthzByID(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT authz_id, order_id, identifier, status, expires_at, wildcard, created_at, updated_at
		FROM acme_authorizations WHERE authz_id = $1
	`, authzID)
	authz, err := scanACMEAuthz(row)
	if err != nil {
		return nil, err
	}
	chs, err := r.ListChallengesByAuthz(ctx, authzID)
	if err != nil {
		return nil, fmt.Errorf("acme: list challenges: %w", err)
	}
	authz.Challenges = chs
	return authz, nil
}

// ListAuthzsByOrder returns the per-order authz rows (without challenges
// — callers needing challenges call GetAuthzByID per entry).
func (r *ACMERepository) ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT authz_id, order_id, identifier, status, expires_at, wildcard, created_at, updated_at
		FROM acme_authorizations WHERE order_id = $1
		ORDER BY created_at ASC
	`, orderID)
	if err != nil {
		return nil, fmt.Errorf("acme: list authzs: %w", err)
	}
	defer rows.Close()
	var out []*domain.ACMEAuthorization
	for rows.Next() {
		a, err := scanACMEAuthz(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateChallengeWithTx inserts an acme_challenges row.
func (r *ACMERepository) CreateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error {
	if ch.ChallengeID == "" || ch.AuthzID == "" || ch.Type == "" || ch.Token == "" {
		return fmt.Errorf("acme: create challenge: missing required field")
	}
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = time.Now().UTC()
	}
	var (
		validatedAt interface{}
		errBlob     interface{}
	)
	if ch.ValidatedAt != nil {
		validatedAt = *ch.ValidatedAt
	}
	if ch.Error != nil {
		b, err := jsonMarshalACME(ch.Error)
		if err != nil {
			return fmt.Errorf("acme: marshal error: %w", err)
		}
		errBlob = b
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO acme_challenges (
			challenge_id, authz_id, type, status, token, validated_at, error, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`,
		ch.ChallengeID, ch.AuthzID, string(ch.Type), string(ch.Status), ch.Token,
		validatedAt, errBlob, ch.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("acme: insert challenge: %w", err)
	}
	return nil
}

// ListChallengesByAuthz returns the challenge rows for an authz.
func (r *ACMERepository) ListChallengesByAuthz(ctx context.Context, authzID string) ([]domain.ACMEChallenge, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT challenge_id, authz_id, type, status, token, validated_at, error, created_at
		FROM acme_challenges WHERE authz_id = $1
		ORDER BY created_at ASC
	`, authzID)
	if err != nil {
		return nil, fmt.Errorf("acme: list challenges: %w", err)
	}
	defer rows.Close()
	var out []domain.ACMEChallenge
	for rows.Next() {
		ch, err := scanACMEChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ch)
	}
	return out, rows.Err()
}

// GetChallengeByID retrieves a challenge row by ID.
func (r *ACMERepository) GetChallengeByID(ctx context.Context, challengeID string) (*domain.ACMEChallenge, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT challenge_id, authz_id, type, status, token, validated_at, error, created_at
		FROM acme_challenges WHERE challenge_id = $1
	`, challengeID)
	return scanACMEChallenge(row)
}

// UpdateChallengeWithTx persists changes to a challenge's mutable
// fields (status, validated_at, error). Used by the Phase 3 validator
// callback after a challenge attempt completes.
func (r *ACMERepository) UpdateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error {
	var (
		validatedAt interface{}
		errBlob     interface{}
	)
	if ch.ValidatedAt != nil {
		validatedAt = *ch.ValidatedAt
	}
	if ch.Error != nil {
		b, err := jsonMarshalACME(ch.Error)
		if err != nil {
			return fmt.Errorf("acme: marshal challenge error: %w", err)
		}
		errBlob = b
	}
	res, err := q.ExecContext(ctx, `
		UPDATE acme_challenges
		SET status = $2, validated_at = $3, error = $4
		WHERE challenge_id = $1
	`, ch.ChallengeID, string(ch.Status), validatedAt, errBlob)
	if err != nil {
		return fmt.Errorf("acme: update challenge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update challenge rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("challenge not found: %w", repository.ErrNotFound)
	}
	return nil
}

// UpdateAuthzStatusWithTx persists an authz status transition. Used
// by the Phase 3 validator callback to flip an authz to valid or
// invalid based on the challenge outcome.
func (r *ACMERepository) UpdateAuthzStatusWithTx(ctx context.Context, q repository.Querier, authzID string, status domain.ACMEAuthzStatus) error {
	res, err := q.ExecContext(ctx, `
		UPDATE acme_authorizations
		SET status = $2, updated_at = NOW()
		WHERE authz_id = $1
	`, authzID, string(status))
	if err != nil {
		return fmt.Errorf("acme: update authz status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update authz status rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("authz not found: %w", repository.ErrNotFound)
	}
	return nil
}

// scanACMEOrder parses an acme_orders row.
func scanACMEOrder(row interface{ Scan(...interface{}) error }) (*domain.ACMEOrder, error) {
	var (
		o           domain.ACMEOrder
		identifiers []byte
		statusStr   string
		notBefore   sql.NullTime
		notAfter    sql.NullTime
		errBlob     sql.NullString
	)
	err := row.Scan(
		&o.OrderID, &o.AccountID, &identifiers, &statusStr, &o.ExpiresAt,
		&notBefore, &notAfter, &errBlob, &o.CSRPEM, &o.CertificateID,
		&o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("order not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("acme: scan order: %w", err)
	}
	o.Status = domain.ACMEOrderStatus(statusStr)
	if err := jsonUnmarshalACME(identifiers, &o.Identifiers); err != nil {
		return nil, fmt.Errorf("acme: unmarshal identifiers: %w", err)
	}
	if notBefore.Valid {
		t := notBefore.Time
		o.NotBefore = &t
	}
	if notAfter.Valid {
		t := notAfter.Time
		o.NotAfter = &t
	}
	if errBlob.Valid && errBlob.String != "" {
		var p domain.ACMEProblem
		if err := jsonUnmarshalACME([]byte(errBlob.String), &p); err == nil {
			o.Error = &p
		}
	}
	return &o, nil
}

// scanACMEAuthz parses an acme_authorizations row.
func scanACMEAuthz(row interface{ Scan(...interface{}) error }) (*domain.ACMEAuthorization, error) {
	var (
		a          domain.ACMEAuthorization
		identifier []byte
		statusStr  string
	)
	err := row.Scan(
		&a.AuthzID, &a.OrderID, &identifier, &statusStr,
		&a.ExpiresAt, &a.Wildcard, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("authz not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("acme: scan authz: %w", err)
	}
	a.Status = domain.ACMEAuthzStatus(statusStr)
	if err := jsonUnmarshalACME(identifier, &a.Identifier); err != nil {
		return nil, fmt.Errorf("acme: unmarshal authz identifier: %w", err)
	}
	return &a, nil
}

// scanACMEChallenge parses an acme_challenges row.
func scanACMEChallenge(row interface{ Scan(...interface{}) error }) (*domain.ACMEChallenge, error) {
	var (
		ch          domain.ACMEChallenge
		typeStr     string
		statusStr   string
		validatedAt sql.NullTime
		errBlob     sql.NullString
	)
	err := row.Scan(
		&ch.ChallengeID, &ch.AuthzID, &typeStr, &statusStr,
		&ch.Token, &validatedAt, &errBlob, &ch.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("challenge not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("acme: scan challenge: %w", err)
	}
	ch.Type = domain.ACMEChallengeType(typeStr)
	ch.Status = domain.ACMEChallengeStatus(statusStr)
	if validatedAt.Valid {
		t := validatedAt.Time
		ch.ValidatedAt = &t
	}
	if errBlob.Valid && errBlob.String != "" {
		var p domain.ACMEProblem
		if err := jsonUnmarshalACME([]byte(errBlob.String), &p); err == nil {
			ch.Error = &p
		}
	}
	return &ch, nil
}

// jsonMarshalACME wraps encoding/json.Marshal — kept as a named
// helper so future per-column custom encoding is a one-line change.
func jsonMarshalACME(v interface{}) ([]byte, error) { return json.Marshal(v) }

// jsonUnmarshalACME tolerates empty input as a no-op (NULL JSONB
// columns scan into zero-length []byte; we treat that as "field
// absent" rather than an unmarshal error).
func jsonUnmarshalACME(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// --- Phase 4 — key rollover + revocation auth helper ------------------

// ErrACMEAccountKeyConcurrentUpdate is returned by UpdateAccountJWKWithTx
// when the row's stored thumbprint no longer matches expectedOldThumbprint.
// This is the "concurrent rollover" race signal: two requests both
// pre-validated their inner JWS against the SAME current key, but only
// one of them got into the WithinTx first. The loser's expectedOldThumb-
// print is now stale → the row's current thumbprint is the WINNER's NEW
// thumbprint. Caller maps to RFC 8555 §7.3.5 "key already exists".
var ErrACMEAccountKeyConcurrentUpdate = errors.New("acme: account key was rotated concurrently; re-fetch and retry")

// UpdateAccountJWKWithTx atomically swaps an account row's JWK
// (thumbprint + PEM) using a SELECT … FOR UPDATE guard plus an
// expectedOldThumbprint precondition.
//
// The row is locked for update; the precondition check then runs
// against the locked row inside the same tx. If a concurrent rollover
// committed first, this caller observes the new thumbprint and returns
// ErrACMEAccountKeyConcurrentUpdate (caller maps to 409). Postgres's
// row-level lock guarantees the two concurrent transactions serialize.
//
// Returns repository.ErrNotFound when the account row is missing.
func (r *ACMERepository) UpdateAccountJWKWithTx(
	ctx context.Context,
	q repository.Querier,
	accountID string,
	expectedOldThumbprint, newThumbprint, newJWKPEM string,
) error {
	// SELECT … FOR UPDATE serializes concurrent rollovers on the same
	// row. The lock is released when the surrounding tx commits / rolls
	// back; the second concurrent caller blocks here until the first
	// commits + then sees the new thumbprint on its read.
	var current string
	err := q.QueryRowContext(ctx, `
		SELECT jwk_thumbprint
		FROM acme_accounts
		WHERE account_id = $1
		FOR UPDATE
	`, accountID).Scan(&current)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("account not found: %w", repository.ErrNotFound)
		}
		return fmt.Errorf("acme: lock account for key rollover: %w", err)
	}
	if current != expectedOldThumbprint {
		return ErrACMEAccountKeyConcurrentUpdate
	}

	res, err := q.ExecContext(ctx, `
		UPDATE acme_accounts
		SET jwk_thumbprint = $2, jwk_pem = $3, updated_at = NOW()
		WHERE account_id = $1 AND jwk_thumbprint = $4
	`, accountID, newThumbprint, newJWKPEM, expectedOldThumbprint)
	if err != nil {
		// Postgres SQLSTATE 23505 = unique_violation on
		// (profile_id, jwk_thumbprint). RFC 8555 §7.3.5 says the
		// server SHOULD return 409 Conflict in that case.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return ErrACMEAccountDuplicateThumbprint
		}
		return fmt.Errorf("acme: update account jwk: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: update account jwk rows affected: %w", err)
	}
	if n == 0 {
		// SELECT … FOR UPDATE found the row but the UPDATE WHERE
		// jwk_thumbprint=$4 did not. That means the thumbprint changed
		// between the SELECT result + the UPDATE — should be impossible
		// under the row lock. Treat defensively as a concurrency error.
		return ErrACMEAccountKeyConcurrentUpdate
	}
	return nil
}

// AccountOwnsCertificate returns true when there is at least one
// acme_orders row with (account_id = accountID, certificate_id =
// certificateID). Used by ACMEService.RevokeCert (kid path) to confirm
// the requesting account had an order that produced the cert. The
// query is a single indexed lookup; we don't materialize the full row.
func (r *ACMERepository) AccountOwnsCertificate(ctx context.Context, accountID, certificateID string) (bool, error) {
	if accountID == "" || certificateID == "" {
		return false, nil
	}
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM acme_orders
		WHERE account_id = $1 AND certificate_id = $2
	`, accountID, certificateID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("acme: account-owns-certificate: %w", err)
	}
	return count > 0, nil
}

// --- Phase 5 — concurrent-orders count + GC sweeps ---------------------

// CountActiveOrdersByAccount returns the number of acme_orders rows
// with the given account_id where status is in
// {pending, ready, processing}. Used by the per-account
// concurrent-orders rate limit.
func (r *ACMERepository) CountActiveOrdersByAccount(ctx context.Context, accountID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM acme_orders
		WHERE account_id = $1
		  AND status IN ('pending', 'ready', 'processing')
	`, accountID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("acme: count active orders: %w", err)
	}
	return count, nil
}

// GCExpiredNonces deletes nonce rows that have been used or have
// passed their expires_at. Returns rows-affected count for telemetry.
// Phase 5 — called every GCInterval from the scheduler.
func (r *ACMERepository) GCExpiredNonces(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM acme_nonces
		WHERE used = TRUE OR expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("acme: gc expired nonces: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("acme: gc expired nonces rows affected: %w", err)
	}
	return n, nil
}

// GCExpireAuthorizations transitions authzs in `pending` whose
// expires_at < NOW() to `expired`. Authzs in valid/invalid are left
// alone (they're already terminal). Returns rows-affected count.
func (r *ACMERepository) GCExpireAuthorizations(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_authorizations
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'pending' AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("acme: gc expire authorizations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("acme: gc expire authorizations rows affected: %w", err)
	}
	return n, nil
}

// GCInvalidateExpiredOrders transitions orders in
// pending/ready/processing whose expires_at < NOW() to `invalid` with
// a server-internal error. Orders in valid/invalid are terminal and
// untouched.
func (r *ACMERepository) GCInvalidateExpiredOrders(ctx context.Context) (int64, error) {
	const errBlob = `{"type":"urn:ietf:params:acme:error:serverInternal","detail":"order expired before issuance","status":500}`
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_orders
		SET status = 'invalid', error = $1::jsonb, updated_at = NOW()
		WHERE status IN ('pending', 'ready', 'processing')
		  AND expires_at < NOW()
	`, errBlob)
	if err != nil {
		return 0, fmt.Errorf("acme: gc invalidate expired orders: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("acme: gc invalidate expired orders rows affected: %w", err)
	}
	return n, nil
}

// scanACMEAccount is the shared shape for the SELECT-by-X account
// queries above. Returns sql.ErrNoRows-wrapped repository.ErrNotFound
// on miss; any other scan failure surfaces verbatim.
func scanACMEAccount(row interface{ Scan(...interface{}) error }) (*domain.ACMEAccount, error) {
	var (
		acct      domain.ACMEAccount
		contact   pq.StringArray
		statusStr string
	)
	err := row.Scan(
		&acct.AccountID, &acct.JWKThumbprint, &acct.JWKPEM, &contact,
		&statusStr, &acct.ProfileID, &acct.OwnerID,
		&acct.CreatedAt, &acct.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("account not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("acme: scan account: %w", err)
	}
	acct.Contact = []string(contact)
	acct.Status = domain.ACMEAccountStatus(statusStr)
	return &acct, nil
}
