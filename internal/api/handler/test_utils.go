package handler

import (
	"errors"
	"fmt"

	"github.com/shankar0123/certctl/internal/service"
)

// Mock errors for testing.
//
// M-1: Since the handler layer now classifies errors via the typed-sentinel
// dispatch in [errToStatus] (errors.Is on service + repository sentinels rather
// than substring matching on err.Error()), handler mocks MUST wrap the
// appropriate generic sentinel so `errors.Is(err, service.ErrNotFound)` etc.
// succeed. Using raw errors.New() breaks the dispatch and degrades every
// mock-driven negative-path test to a 500 Internal Server Error — the same
// silent-regression trap the migration was designed to eliminate.
//
// ErrMockServiceFailed deliberately stays untyped so it continues to exercise
// the default 500 path.
var (
	ErrMockServiceFailed = errors.New("mock service error")
	ErrMockNotFound      = fmt.Errorf("%w: mock not found", service.ErrNotFound)
	ErrMockUnauthorized  = fmt.Errorf("%w: mock unauthenticated", service.ErrUnauthenticated)
	ErrMockConflict      = fmt.Errorf("%w: mock conflict", service.ErrConflict)
)
