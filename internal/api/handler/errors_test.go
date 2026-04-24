package handler

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/lib/pq"

	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/service"
)

// TestErrToStatus_DispatchMatrix pins the handler's single error → HTTP
// status choke point. Each row covers one branch of the dispatch switch and
// the dispatch order invariants documented in errors.go:
//
//   - ErrAgentRetired FIRST (410 short-circuits before generic checks)
//   - ErrNotFound before ErrForbidden (RFC 7235 existence hiding)
//   - ErrForbidden before ErrValidation (preserves M-003 gate under double-wrap)
//   - Repo sentinels route to 409 alongside ErrConflict
//   - *pq.Error on 23503 / 23505 routes to 409 as the driver-level fallback
//   - Default path is 500
func TestErrToStatus_DispatchMatrix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil → 200", nil, http.StatusOK},

		// Each generic sentinel resolves to its documented status code.
		{"ErrNotFound → 404", service.ErrNotFound, http.StatusNotFound},
		{"ErrValidation → 400", service.ErrValidation, http.StatusBadRequest},
		{"ErrConflict → 409", service.ErrConflict, http.StatusConflict},
		{"ErrForbidden → 403", service.ErrForbidden, http.StatusForbidden},
		{"ErrUnauthenticated → 401", service.ErrUnauthenticated, http.StatusUnauthorized},
		{"ErrNotImplemented → 501", service.ErrNotImplemented, http.StatusNotImplemented},

		// Wrapped domain sentinels route through their generic wrap.
		{"ErrSelfApproval → 403 (via ErrForbidden)", service.ErrSelfApproval, http.StatusForbidden},
		{"ErrAgentIsSentinel → 403 (via ErrForbidden)", service.ErrAgentIsSentinel, http.StatusForbidden},
		{"ErrBlockedByDependencies → 409 (via ErrConflict)", service.ErrBlockedByDependencies, http.StatusConflict},
		{"ErrForceReasonRequired → 400 (via ErrValidation)", service.ErrForceReasonRequired, http.StatusBadRequest},
		{"ErrAgentNotFound → 400 (via ErrValidation)", service.ErrAgentNotFound, http.StatusBadRequest},

		// ErrAgentRetired is standalone — 410 Gone must fire before any
		// generic dispatch. This locks in the semantic-distinct short-circuit.
		{"ErrAgentRetired → 410", service.ErrAgentRetired, http.StatusGone},

		// Repository-layer sentinels (G-1 + M-1).
		{"repo.ErrNotFound → 404", repository.ErrNotFound, http.StatusNotFound},
		{"wrapped repo.ErrNotFound → 404",
			fmt.Errorf("%w: renewal policy rp-foo", repository.ErrNotFound),
			http.StatusNotFound},
		{"repo.ErrRenewalPolicyDuplicateName → 409", repository.ErrRenewalPolicyDuplicateName, http.StatusConflict},
		{"repo.ErrRenewalPolicyInUse → 409", repository.ErrRenewalPolicyInUse, http.StatusConflict},

		// Wrapped errors with additional context survive the dispatch.
		{"wrapped ErrNotFound with context → 404",
			fmt.Errorf("lookup failed: %w", service.ErrNotFound),
			http.StatusNotFound},
		{"wrapped ErrSelfApproval with context → 403",
			fmt.Errorf("approval gate: %w", service.ErrSelfApproval),
			http.StatusForbidden},

		// Driver-level fallback: raw *pq.Error escaping repo layer.
		{"*pq.Error 23503 → 409", &pq.Error{Code: "23503"}, http.StatusConflict},
		{"*pq.Error 23505 → 409", &pq.Error{Code: "23505"}, http.StatusConflict},
		{"*pq.Error 08006 → 500", &pq.Error{Code: "08006"}, http.StatusInternalServerError},

		// Default path.
		{"unknown error → 500", errors.New("something arbitrary"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := errToStatus(c.err)
			if got != c.want {
				t.Errorf("errToStatus(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

// TestErrToStatus_AgentRetiredShortCircuit is a dedicated regression guard
// for the most fragile dispatch invariant: ErrAgentRetired's 410 Gone must
// fire FIRST. If a future commit wraps it under ErrForbidden (e.g., to
// include it in a generic "agent operations forbidden" bucket), this test
// goes red and the agent-binary shutdown at cmd/agent/main.go:1291 would
// silently stop triggering.
func TestErrToStatus_AgentRetiredShortCircuit(t *testing.T) {
	if got := errToStatus(service.ErrAgentRetired); got != http.StatusGone {
		t.Fatalf("ErrAgentRetired → %d, want 410 Gone (short-circuit must fire before any generic dispatch)", got)
	}
}

// TestErrToStatus_NotFoundBeforeForbidden locks the RFC 7235 existence-
// hiding dispatch order. If someone were to reorder the switch arms to put
// ErrForbidden first, an authorization failure on a nonexistent resource
// would leak existence via a 403 instead of masking it with a 404.
func TestErrToStatus_NotFoundBeforeForbidden(t *testing.T) {
	// A hypothetical wrapping where both would match — contrived but the
	// ordering guarantee is what we're testing.
	both := fmt.Errorf("%w: layered with %w", service.ErrNotFound, service.ErrForbidden)
	if got := errToStatus(both); got != http.StatusNotFound {
		t.Errorf("dual-wrapped err → %d, want 404 (ErrNotFound must dispatch before ErrForbidden)", got)
	}
}

// TestErrToStatus_ForbiddenBeforeValidation guards the M-003 self-approval
// gate against a future call site that double-wraps ErrSelfApproval under
// ErrValidation (intentionally or accidentally). The dispatch must pick
// 403, not 400.
func TestErrToStatus_ForbiddenBeforeValidation(t *testing.T) {
	doubled := fmt.Errorf("%w: %w", service.ErrSelfApproval, service.ErrValidation)
	if got := errToStatus(doubled); got != http.StatusForbidden {
		t.Errorf("double-wrapped err → %d, want 403 (ErrForbidden must dispatch before ErrValidation — M-003 gate)", got)
	}
}
