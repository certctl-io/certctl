package wincertstore

import (
	"context"
	"fmt"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// ValidateOnly — Phase 9. Probes the Windows certificate store
// via Get-ChildItem against the configured store path. Confirms
// the agent has the right permissions + the store path is valid.
// V3-Pro can extend with temp-import + immediate-remove; V2 ships
// the permission probe.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.executor == nil {
		return target.ErrValidateOnlyNotSupported
	}
	store := c.config.StoreName
	if store == "" {
		store = "My"
	}
	loc := c.config.StoreLocation
	if loc == "" {
		loc = "LocalMachine"
	}
	storePath := fmt.Sprintf(`Cert:\%s\%s`, loc, store)
	script := fmt.Sprintf(`Get-ChildItem -Path %q | Select-Object -First 1 | Format-Table -HideTableHeaders -Property Thumbprint`, storePath)
	out, err := c.executor.Execute(ctx, script)
	if err != nil {
		return fmt.Errorf("WinCertStore ValidateOnly: %w (output: %s)", err, out)
	}
	return nil
}
