package k8ssecret

import (
	"context"
	"fmt"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// ValidateOnly — Phase 9. K8s does NOT expose a meaningful dry-run
// for cert deploys via Secret update — the API server's dry-run
// mode confirms admission would succeed but does not validate that
// the cert bytes themselves are well-formed (the kubelet decodes
// them later on the pod side). Phase 9 returns ErrValidateOnlyNotSupported
// per frozen decision 0.6, surfaced explicitly here rather than via
// the default stub so operators can errors.Is to know K8s is
// intentionally a sentinel-return connector.
//
// V3-Pro can extend with API server reachability probe + RBAC
// preflight check.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.client == nil {
		return target.ErrValidateOnlyNotSupported
	}
	// Trivial probe: GetSecret on the configured Secret name.
	// If we can read it, we have RBAC + reachability; if not,
	// surface the actual K8s API error.
	if c.config == nil || c.config.Namespace == "" || c.config.SecretName == "" {
		return target.ErrValidateOnlyNotSupported
	}
	_, err := c.client.GetSecret(ctx, c.config.Namespace, c.config.SecretName)
	if err != nil {
		// "not found" is fine — we'd CREATE the Secret on Deploy.
		// Other errors (forbidden, unreachable) surface as wrapped.
		return fmt.Errorf("K8s ValidateOnly: GetSecret probe: %w", err)
	}
	return nil
}
