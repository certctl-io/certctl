package caddy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// ValidateOnly — Phase 7 (deploy-hardening I) replaces the stub
// with a real implementation:
//
//   - api mode: probes the admin /config/ endpoint to confirm
//     Caddy is reachable + responding. We don't simulate the cert
//     load itself because Caddy's POST /load doesn't have a true
//     dry-run flag.
//   - file mode: no command-line cert validator exists for
//     individual PEM files (Caddy validates them at load time).
//     Returns ErrValidateOnlyNotSupported.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.config != nil && c.config.Mode == "api" && c.config.AdminAPI != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.AdminAPI+"/config/", nil)
		if err != nil {
			return fmt.Errorf("ValidateOnly: build request: %w", err)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return fmt.Errorf("ValidateOnly: Caddy admin API unreachable: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("ValidateOnly: Caddy admin returned status %d", resp.StatusCode)
		}
		return nil
	}
	return target.ErrValidateOnlyNotSupported
}
