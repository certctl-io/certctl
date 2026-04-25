// Package domain — error sentinels.
//
// S-2 closure (cat-s6-efc7f6f6bd50): pre-S-2 every handler-side
// validation-failure dispatch was a `strings.Contains(err.Error(),
// "invalid")` or `"required"` site, brittle to any domain-layer
// message change. Post-S-2 domain validators that surface a
// 400 Bad Request wrap their per-field errors via fmt.Errorf("...: %w",
// domain.ErrValidation) so handlers can dispatch via errors.Is.
package domain

import "errors"

// ErrValidation is the canonical sentinel for input-validation
// failures surfaced by domain-layer Validate() methods. Handlers that
// surface a 400 Bad Request should `errors.Is(err, domain.ErrValidation)`.
// Per-field error messages are still preserved via fmt.Errorf wrapping
// so the response body retains the actionable detail; the sentinel
// only drives the HTTP status code dispatch.
var ErrValidation = errors.New("domain: validation failed")
