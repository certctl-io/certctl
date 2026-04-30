package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// VerificationService defines the service interface for verification operations.
type VerificationService interface {
	// RecordVerificationResult records the outcome of TLS endpoint verification.
	RecordVerificationResult(ctx context.Context, result *domain.VerificationResult) error

	// GetVerificationResult retrieves the verification status for a job.
	GetVerificationResult(ctx context.Context, jobID string) (*domain.VerificationResult, error)
}

// VerificationHandler handles HTTP requests for certificate deployment verification.
type VerificationHandler struct {
	svc VerificationService
}

// NewVerificationHandler creates a new VerificationHandler.
func NewVerificationHandler(svc VerificationService) VerificationHandler {
	return VerificationHandler{svc: svc}
}

// VerifyDeploymentRequest represents the request body for POST /api/v1/jobs/{id}/verify
type VerifyDeploymentRequest struct {
	TargetID            string `json:"target_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	ActualFingerprint   string `json:"actual_fingerprint"`
	Verified            bool   `json:"verified"`
	Error               string `json:"error,omitempty"`
}

// VerifyDeployment handles POST /api/v1/jobs/{id}/verify
// Agents submit verification results after attempting to probe the live TLS endpoint.
// This endpoint records the verification outcome (success or failure) and updates the job status.
func (h VerificationHandler) VerifyDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from URL path: /api/v1/jobs/{id}/verify
	jobID, err := extractIDFromPath(r.URL.Path, "/api/v1/jobs/", "/verify")
	if err != nil || jobID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid job ID", middleware.GetRequestID(r.Context()))
		return
	}

	// Parse request body
	var req VerifyDeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err), middleware.GetRequestID(r.Context()))
		return
	}

	// Validate required fields
	if req.TargetID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "target_id is required", middleware.GetRequestID(r.Context()))
		return
	}
	if req.ExpectedFingerprint == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "expected_fingerprint is required", middleware.GetRequestID(r.Context()))
		return
	}
	if req.ActualFingerprint == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "actual_fingerprint is required", middleware.GetRequestID(r.Context()))
		return
	}

	// Build verification result
	result := &domain.VerificationResult{
		JobID:               jobID,
		TargetID:            req.TargetID,
		ExpectedFingerprint: req.ExpectedFingerprint,
		ActualFingerprint:   req.ActualFingerprint,
		Verified:            req.Verified,
		VerifiedAt:          time.Now().UTC(),
		Error:               req.Error,
	}

	// Record result
	if err := h.svc.RecordVerificationResult(r.Context(), result); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Failed to record verification result: %v", err), middleware.GetRequestID(r.Context()))
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":      jobID,
		"verified":    req.Verified,
		"verified_at": result.VerifiedAt,
	})
}

// GetVerificationStatus handles GET /api/v1/jobs/{id}/verification
// Returns the current verification status for a job.
func (h VerificationHandler) GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from URL path: /api/v1/jobs/{id}/verification
	jobID, err := extractIDFromPath(r.URL.Path, "/api/v1/jobs/", "/verification")
	if err != nil || jobID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid job ID", middleware.GetRequestID(r.Context()))
		return
	}

	// Get verification result
	result, err := h.svc.GetVerificationResult(r.Context(), jobID)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get verification result: %v", err), middleware.GetRequestID(r.Context()))
		return
	}

	// Return result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// extractIDFromPath extracts the resource ID from a path like /api/v1/jobs/{id}/verify
// prefix: "/api/v1/jobs/" suffix: "/verify"
// Returns the extracted ID between prefix and suffix.
func extractIDFromPath(path, prefix, suffix string) (string, error) {
	if len(path) <= len(prefix)+len(suffix) {
		return "", fmt.Errorf("path too short")
	}
	if !HasPrefix(path, prefix) {
		return "", fmt.Errorf("path does not start with prefix")
	}
	// Remove prefix
	remainder := path[len(prefix):]
	// Find suffix
	idx := FindLastOccurrence(remainder, suffix)
	if idx == -1 {
		return "", fmt.Errorf("suffix not found")
	}
	return remainder[:idx], nil
}

// HasPrefix checks if a string starts with a prefix.
func HasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// FindLastOccurrence finds the last occurrence of a substring (simplified version).
func FindLastOccurrence(s, substr string) int {
	if len(substr) == 0 {
		return len(s)
	}
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
