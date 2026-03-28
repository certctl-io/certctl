package domain

import "time"

// VerificationStatus represents the status of certificate deployment verification.
type VerificationStatus string

const (
	// VerificationPending: verification has not yet been performed.
	VerificationPending VerificationStatus = "pending"
	// VerificationSuccess: the live TLS endpoint serves the expected certificate.
	VerificationSuccess VerificationStatus = "success"
	// VerificationFailed: the live TLS endpoint does not serve the expected certificate.
	VerificationFailed VerificationStatus = "failed"
	// VerificationSkipped: verification was skipped (disabled or not applicable).
	VerificationSkipped VerificationStatus = "skipped"
)

// VerificationResult represents the outcome of verifying a deployed certificate
// against the live TLS endpoint it should be serving.
type VerificationResult struct {
	// JobID is the ID of the deployment job being verified.
	JobID string `json:"job_id"`
	// TargetID is the ID of the deployment target.
	TargetID string `json:"target_id"`
	// ExpectedFingerprint is the SHA-256 fingerprint of the certificate that was deployed.
	ExpectedFingerprint string `json:"expected_fingerprint"`
	// ActualFingerprint is the SHA-256 fingerprint of the certificate currently being served
	// at the live TLS endpoint.
	ActualFingerprint string `json:"actual_fingerprint"`
	// Verified is true if expected and actual fingerprints match.
	Verified bool `json:"verified"`
	// VerifiedAt is the timestamp when verification was performed.
	VerifiedAt time.Time `json:"verified_at"`
	// Error is a non-empty error message if verification failed to complete.
	Error string `json:"error,omitempty"`
}
