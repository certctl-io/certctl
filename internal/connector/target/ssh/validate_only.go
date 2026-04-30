package ssh

import (
	"context"
	"fmt"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// ValidateOnly — Phase 9 of the deploy-hardening I master bundle.
// Probes the SSH connection by establishing a session + closing
// it cleanly. Confirms the agent has network reachability + the
// configured SSH credentials still work. Failure surfaces as a
// wrapped error so operators see "auth failed" / "connection
// refused" / "host key changed" without touching the live cert.
//
// A true cert-deploy dry-run would require simulating the file
// upload + remote chmod (SCP doesn't have a no-commit mode); for
// V2 the auth probe is the load-bearing safety check.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.client == nil {
		return target.ErrValidateOnlyNotSupported
	}
	if err := c.client.Connect(ctx); err != nil {
		return fmt.Errorf("SSH ValidateOnly: connect failed: %w", err)
	}
	defer c.client.Close()
	return nil
}
