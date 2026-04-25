package handler

import (
	"fmt"

	"github.com/shankar0123/certctl/internal/repository"
)

// Mock errors for testing.
//
// S-2 closure (cat-s6-efc7f6f6bd50): ErrMockNotFound now wraps
// repository.ErrNotFound via fmt.Errorf("...: %w", ...) so the
// post-S-2 handler dispatch — which uses errors.Is(err,
// repository.ErrNotFound) instead of strings.Contains — still
// resolves the mock to a 404. The error message text is preserved
// for log inspection; only the wrapping changes.
var (
	ErrMockServiceFailed = fmt.Errorf("mock service error")
	ErrMockNotFound      = fmt.Errorf("mock not found error: %w", repository.ErrNotFound)
	ErrMockUnauthorized  = fmt.Errorf("mock unauthorized error")
	ErrMockConflict      = fmt.Errorf("mock conflict error")
)
