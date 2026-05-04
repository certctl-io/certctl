package f5

import (
	"context"
	"fmt"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// ValidateOnly — Phase 8 of the deploy-hardening I master bundle.
// F5 already has full transactional rollback semantics in
// DeployCertificate (the iControl REST API is transactional —
// `mgmt/tm/transaction` wraps the install + bind together; on
// failure the whole transaction aborts atomically with no live
// VS impact). Phase 8 makes the dry-run explicit by probing the
// BIG-IP control plane health: if the API is reachable and
// authenticated, ValidateOnly returns nil; otherwise it returns
// the wrapped client error so operators can preview a deploy
// without touching the live SSL profile.
//
// Note: a full dry-run that simulates the cert install + bind
// without commit would require F5 to expose a no-commit transaction
// mode (it does not in v15.x; it does in v17.5+ — V3-Pro will add
// per-version dispatch). For V2 the reachability probe is the
// load-bearing safety check.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.client == nil {
		return target.ErrValidateOnlyNotSupported
	}
	// Probe by attempting authentication. The F5 client caches
	// the token after first success, so subsequent ValidateOnly
	// calls are cheap. Failure here means the BIG-IP is
	// unreachable, the operator credentials are wrong, or the
	// auth provider (TACACS+, RADIUS) is down — all reasons to
	// abort a deploy preview.
	if err := c.client.Authenticate(ctx); err != nil {
		return fmt.Errorf("F5 ValidateOnly: BIG-IP control plane probe failed: %w", err)
	}
	return nil
}
