package javakeystore

import (
	"context"
	"fmt"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// ValidateOnly — Phase 9. Probes via `keytool -list -keystore
// <path> -storepass <pass>`. Confirms the keystore exists, the
// password is correct, and `keytool` is on PATH. Failure mode
// surfaces the actual keytool stderr (wrong password, missing
// JRE, file not found, etc.).
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	if c.executor == nil || c.config == nil {
		return target.ErrValidateOnlyNotSupported
	}
	if c.config.KeystorePath == "" {
		return target.ErrValidateOnlyNotSupported
	}
	args := []string{"-list", "-keystore", c.config.KeystorePath}
	if c.config.KeystorePassword != "" {
		args = append(args, "-storepass", c.config.KeystorePassword)
	}
	keytool := c.config.KeytoolPath
	if keytool == "" {
		keytool = "keytool"
	}
	out, err := c.executor.Execute(ctx, keytool, args...)
	if err != nil {
		return fmt.Errorf("JavaKeystore ValidateOnly: keytool -list failed: %w (output: %s)", err, out)
	}
	_ = out
	return nil
}
