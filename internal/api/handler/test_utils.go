package handler

import "errors"

var (
	// Mock errors for testing
	ErrMockServiceFailed = errors.New("mock service error")
	ErrMockNotFound      = errors.New("mock not found error")
	ErrMockUnauthorized  = errors.New("mock unauthorized error")
	ErrMockConflict      = errors.New("mock conflict error")
)
