// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package groupclaim resolves the operator-configured `groups_claim_path`
// against an ID token's parsed claims, returning the user's group
// membership as a `[]string`.
//
// Auth Bundle 2 Phase 3 ships this without a JSON-path library
// dependency per the pre-bundle dep audit. The contract is narrow
// enough that ~40 LOC of straight Go covers every documented use case
// (Keycloak, Auth0, Okta, Azure AD, Google Workspace) without the
// transitive footprint or maintenance liability of pulling in
// PaesslerAG/jsonpath, ohler55/ojg, or tidwall/gjson.
//
// Resolution rules:
//
//  1. URL-shape paths (prefix `https://` or `http://`) are treated as a
//     single literal key. This handles Auth0's namespaced claims like
//     `https://your-namespace/groups`.
//  2. Dot-separated paths (e.g. Keycloak's `realm_access.roles`) are
//     split on `.` and walked through nested `map[string]interface{}`
//     chains. A non-object segment or missing key fails closed with a
//     clear error.
//  3. The resolved value is coerced to `[]string`:
//     - `[]string` → as-is.
//     - `[]interface{}` of strings → coerced.
//     - single `string` → wrapped in a one-element slice.
//     - any other type (bool, number, object, nil) → fails closed.
//
// Phase 3 callers MUST treat the empty-result case as fail-closed: no
// session is minted, an audit row records `auth.oidc_login_unmapped_groups`
// (the user's IdP returned a claim but it didn't match any of the
// operator's mappings).
package groupclaim

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors. Service-layer callers branch on these via errors.Is.
var (
	// ErrPathEmpty is returned when the configured path is the empty
	// string. The operator API layer + domain Validate() catch this
	// upstream; this sentinel exists so the resolver is safe to call
	// even with malformed config.
	ErrPathEmpty = errors.New("groupclaim: path is empty")

	// ErrSegmentMissing is returned when a path segment doesn't exist
	// on the current claims object (e.g. path `realm_access.roles`
	// applied to a token without `realm_access`). Phase 3's
	// HandleCallback maps to "no groups; fail closed".
	ErrSegmentMissing = errors.New("groupclaim: path segment missing")

	// ErrSegmentNotObject is returned when an intermediate path
	// segment resolves to a non-object (e.g. trying to walk into a
	// string). Indicates the IdP token shape doesn't match the
	// operator's configured path.
	ErrSegmentNotObject = errors.New("groupclaim: intermediate segment is not an object")

	// ErrInvalidValueType is returned when the resolved value cannot
	// be coerced to a string array. Bool, number, object, nil all
	// fail closed.
	ErrInvalidValueType = errors.New("groupclaim: resolved value is not coercible to []string")
)

// Resolve walks `path` through `claims` and returns the resolved
// group list. See the package doc for the full contract.
//
// Per Phase 3's "complete path, not easy path" discipline: this
// function does NOT modify `claims` and does NOT log any of its
// inputs. Token-leak hygiene tests assert that paths through this
// function never emit any of `claims`, `path`, or the resolved
// value to the slog buffer.
func Resolve(claims map[string]interface{}, path string) ([]string, error) {
	if path == "" {
		return nil, ErrPathEmpty
	}

	// Rule 1: URL-shape paths are single literal keys.
	var segments []string
	if isURLShapePath(path) {
		segments = []string{path}
	} else {
		segments = strings.Split(path, ".")
	}

	// Walk the segments through the nested map.
	var cur interface{} = claims
	for i, seg := range segments {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%w: segment %q (index %d) applied to non-object", ErrSegmentNotObject, seg, i)
		}
		next, ok := obj[seg]
		if !ok {
			return nil, fmt.Errorf("%w: %q at index %d", ErrSegmentMissing, seg, i)
		}
		cur = next
	}

	// Coerce the resolved value to []string.
	return coerceStringArray(cur)
}

// isURLShapePath reports whether path is a URL-shape (Auth0-style
// namespaced claim). Such paths are NOT split on `.`; they're treated
// as a single literal key against the top-level claims map.
func isURLShapePath(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// coerceStringArray converts the resolved claim value to []string per
// the rules in the package doc. Fails closed on any other type.
func coerceStringArray(v interface{}) ([]string, error) {
	switch x := v.(type) {
	case []string:
		// Already the right type. Return a copy so the caller can't
		// mutate the underlying claims map by surprise.
		out := make([]string, len(x))
		copy(out, x)
		return out, nil
	case []interface{}:
		// JSON unmarshal into map[string]interface{} produces
		// []interface{} for arrays. Coerce each element to string;
		// any non-string element fails the whole resolution.
		out := make([]string, 0, len(x))
		for i, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%w: element %d is %T not string", ErrInvalidValueType, i, e)
			}
			out = append(out, s)
		}
		return out, nil
	case string:
		// Single string: wrap in a one-element slice. Some IdPs
		// return a single role as a bare string rather than a
		// one-element array; the resolver normalizes both shapes.
		return []string{x}, nil
	default:
		return nil, fmt.Errorf("%w: got %T", ErrInvalidValueType, v)
	}
}
