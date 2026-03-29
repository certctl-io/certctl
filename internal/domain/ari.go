package domain

import "time"

// RenewalInfo represents ACME Renewal Information (ARI) per RFC 9702.
// It provides CA-directed renewal timing via a suggested renewal window.
type RenewalInfo struct {
	// SuggestedWindowStart is the beginning of the time window during which the CA suggests renewal.
	SuggestedWindowStart time.Time `json:"suggested_window_start"`

	// SuggestedWindowEnd is the end of the time window during which the CA suggests renewal.
	SuggestedWindowEnd time.Time `json:"suggested_window_end"`

	// RetryAfter is the earliest time the client should re-poll for updated ARI.
	// Zero value means no retry constraint.
	RetryAfter time.Time `json:"retry_after,omitempty"`

	// ExplanationURL is an optional URL with human-readable explanation for the renewal timing.
	ExplanationURL string `json:"explanation_url,omitempty"`
}

// ShouldRenewNow returns true if the current time is within or past the suggested renewal window.
// This is the primary decision point: if true, renewal should proceed immediately.
func (r *RenewalInfo) ShouldRenewNow() bool {
	now := time.Now()
	return !now.Before(r.SuggestedWindowStart)
}

// OptimalRenewalTime returns the midpoint of the suggested renewal window,
// which is the recommended time to initiate renewal per RFC 9702.
// This can be used for scheduling if the current time is before the window.
func (r *RenewalInfo) OptimalRenewalTime() time.Time {
	duration := r.SuggestedWindowEnd.Sub(r.SuggestedWindowStart)
	return r.SuggestedWindowStart.Add(duration / 2)
}
