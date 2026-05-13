// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package oidc — Bundle 2 Phase 5 / pre-login cookie machinery.
//
// This file implements the production-side PreLoginStore that the
// Phase 3 OIDC service wires into HandleAuthRequest + HandleCallback.
// Phase 3 shipped the interface + an in-memory test stub; Phase 5
// ships the real implementation backed by:
//
//   - oidc_pre_login_sessions table (Phase 5 migration 000037)
//   - the active SessionSigningKey (Phase 4 service)
//
// The cookie wire format is `v1.<pl-id>.<sk-id>.<base64url-no-pad
// HMAC-SHA256>` — IDENTICAL to the post-login session cookie shape so
// both surfaces share the same parser, the same length-prefixed HMAC
// input (defeats concatenation collisions), and the same v1. version
// prefix. Different cookie name (`certctl_oidc_pending` vs
// `certctl_session`) and different id prefix (`pl-` vs `ses-`) keep
// the two surfaces distinguishable; defense-in-depth checks at each
// consumer reject the wrong-prefix shape even if the cookie value
// somehow gets routed to the wrong handler.

package oidc

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// SigningKeyLookup is the slice of SessionSigningKey access the
// pre-login adapter needs. SessionService satisfies this implicitly
// via the Phase 4 SigningKeyRepo (we re-use the interface here rather
// than adding a method to SessionService).
type SigningKeyLookup interface {
	GetActive(ctx context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error)
	Get(ctx context.Context, id string) (*sessiondomain.SessionSigningKey, error)
}

// PreLoginAdapter implements the Phase 3 OIDCService.PreLoginStore
// interface against a real PreLoginRepository + the active
// SessionSigningKey.
//
// The cookie value returned by CreatePreLogin is the wire-format
// `v1.pl-<id>.sk-<id>.<HMAC-SHA256>`; LookupAndConsume parses + HMAC-
// verifies the cookie value before reading + deleting the row.
type PreLoginAdapter struct {
	repo          repository.PreLoginRepository
	keys          SigningKeyLookup
	tenantID      string
	encryptionKey string

	// Injectable for tests so the adapter can be exercised against a
	// deterministic-failure RNG.
	readRand func([]byte) (int, error)
}

// NewPreLoginAdapter constructs a PreLoginAdapter wired against the
// supplied repository + signing-key lookup. encryptionKey is the
// CERTCTL_CONFIG_ENCRYPTION_KEY value used to decrypt the
// SessionSigningKey.KeyMaterialEncrypted blob.
func NewPreLoginAdapter(
	repo repository.PreLoginRepository,
	keys SigningKeyLookup,
	tenantID, encryptionKey string,
) *PreLoginAdapter {
	return &PreLoginAdapter{
		repo:          repo,
		keys:          keys,
		tenantID:      tenantID,
		encryptionKey: encryptionKey,
		readRand:      cryptorand.Read,
	}
}

// SetRandReaderForTest replaces the entropy source. ONLY for tests.
func (a *PreLoginAdapter) SetRandReaderForTest(r func([]byte) (int, error)) {
	a.readRand = r
}

// CreatePreLogin generates a fresh `pl-<random>` id, signs the cookie
// value under the active SessionSigningKey, persists the row, and
// returns the cookie value + the row id.
//
// Audit 2026-05-10 MED-16 — clientIP + userAgent are persisted into
// the row for the callback-time UA/IP binding check.
//
// Implements the Phase 3 OIDCService.PreLoginStore.CreatePreLogin
// interface signature.
func (a *PreLoginAdapter) CreatePreLogin(ctx context.Context, providerID, state, nonce, verifier, clientIP, userAgent string) (cookieValue, sessionID string, err error) {
	active, err := a.keys.GetActive(ctx, a.tenantID)
	if err != nil {
		return "", "", fmt.Errorf("pre-login: get active signing key: %w", err)
	}
	hmacKey, err := session.DecryptKeyMaterial(active.KeyMaterialEncrypted, a.encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("pre-login: decrypt active key: %w", err)
	}
	id, err := a.newID()
	if err != nil {
		return "", "", fmt.Errorf("pre-login: generate id: %w", err)
	}
	row := &repository.PreLoginSession{
		ID:             id,
		TenantID:       a.tenantID,
		SigningKeyID:   active.ID,
		OIDCProviderID: providerID,
		State:          state,
		Nonce:          nonce,
		PKCEVerifier:   verifier,
		ClientIP:       clientIP,
		UserAgent:      userAgent,
	}
	if err := a.repo.Create(ctx, row); err != nil {
		return "", "", fmt.Errorf("pre-login: persist row: %w", err)
	}
	cookieValue = session.SignCookieValue(id, active.ID, hmacKey)
	return cookieValue, id, nil
}

// LookupAndConsume parses + HMAC-verifies the cookie value, looks up
// the row, atomically deletes it, and returns the OIDC handshake
// material the callback handler needs.
//
// Failure semantics:
//   - Malformed cookie / wrong v1. prefix / wrong id prefix /
//     bad base64 HMAC -> ErrPreLoginNotFound (uniform 400 to the wire,
//     no information leak about which check failed).
//   - HMAC mismatch -> ErrPreLoginNotFound (forged cookie).
//   - Signing key id not found -> ErrPreLoginNotFound.
//   - Row not found OR already consumed -> ErrPreLoginNotFound.
//   - Row found but past 10-minute TTL -> ErrPreLoginExpired (row is
//     deleted at the repo layer regardless).
//
// Audit 2026-05-10 MED-16 — also returns the row's stored clientIP +
// userAgent so the service-layer caller can enforce the UA/IP binding.
//
// Implements the Phase 3 OIDCService.PreLoginStore.LookupAndConsume
// interface signature.
func (a *PreLoginAdapter) LookupAndConsume(ctx context.Context, cookieValue string) (providerID, state, nonce, verifier, clientIP, userAgent string, err error) {
	plID, signingKeyID, providedHMAC, perr := session.ParseCookieValue(cookieValue, "pl-")
	if perr != nil {
		return "", "", "", "", "", "", ErrPreLoginNotFound
	}

	signingKey, kerr := a.keys.Get(ctx, signingKeyID)
	if kerr != nil {
		return "", "", "", "", "", "", ErrPreLoginNotFound
	}
	hmacKey, derr := session.DecryptKeyMaterial(signingKey.KeyMaterialEncrypted, a.encryptionKey)
	if derr != nil {
		return "", "", "", "", "", "", ErrPreLoginNotFound
	}
	expectedHMAC := session.ComputeCookieHMAC(plID, signingKeyID, hmacKey)
	if subtle.ConstantTimeCompare(expectedHMAC, providedHMAC) != 1 {
		return "", "", "", "", "", "", ErrPreLoginNotFound
	}

	row, lerr := a.repo.LookupAndConsume(ctx, plID)
	if lerr != nil {
		// Map both not-found AND expired to the same uniform sentinel
		// the OIDC service consumes; the audit row distinguishes via
		// the wrapped error from the repo (which the handler logs).
		if errors.Is(lerr, repository.ErrPreLoginNotFound) {
			return "", "", "", "", "", "", ErrPreLoginNotFound
		}
		if errors.Is(lerr, repository.ErrPreLoginExpired) {
			return "", "", "", "", "", "", ErrPreLoginNotFound
		}
		return "", "", "", "", "", "", fmt.Errorf("pre-login: lookup_and_consume: %w", lerr)
	}

	return row.OIDCProviderID, row.State, row.Nonce, row.PKCEVerifier, row.ClientIP, row.UserAgent, nil
}

// newID returns `pl-<base64url-no-pad>` with 16 bytes of entropy.
func (a *PreLoginAdapter) newID() (string, error) {
	b := make([]byte, 16)
	if _, err := a.readRand(b); err != nil {
		return "", err
	}
	return "pl-" + base64.RawURLEncoding.EncodeToString(b), nil
}
