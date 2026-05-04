package iis

import (
	"context"
	"fmt"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// ValidateOnly — Phase 8 of the deploy-hardening I master bundle.
// IIS already has explicit pre-deploy backup + post-rollback
// re-import semantics in DeployCertificate. Phase 8 adds an
// explicit dry-run via a PowerShell health probe: if the agent
// can run a `Get-WebSite` cmdlet, the IIS PowerShell module is
// loaded and the agent has the right permissions; ValidateOnly
// returns nil. Otherwise it returns the wrapped script error so
// operators can preview a deploy without touching the live cert
// store.
//
// Note: a true cert-bind dry-run would require IIS to expose a
// no-commit `New-WebBinding` mode (it does not). For V2 the
// permission + module probe is the load-bearing safety check.
// V3-Pro can extend this with a temporary cert install + immediate
// remove.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.executor == nil {
		return target.ErrValidateOnlyNotSupported
	}
	// Probe `Get-WebSite -Name <SiteName>` to confirm the IIS
	// PowerShell module is loaded AND the configured site exists.
	// Failure here means the agent isn't on a Windows host with
	// IIS installed, the site name is wrong, or the agent is
	// running as a user without IIS administration privileges.
	script := fmt.Sprintf(`Get-WebSite -Name %q | Select-Object -ExpandProperty Name`, c.config.SiteName)
	out, err := c.executor.Execute(ctx, script)
	if err != nil {
		return fmt.Errorf("IIS ValidateOnly: %w (output: %s)", err, out)
	}
	return nil
}
