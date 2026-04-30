package wincertstore

import (
	"context"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// ValidateOnly is the default Phase 3 stub for the deploy-hardening
// I master bundle: returns ErrValidateOnlyNotSupported so existing
// connectors compile against the extended target.Connector interface
// without changing behavior. Phase wincertstore dry-run support arrives when
// the connector's atomic-deploy implementation lands (NGINX in
// Phase 4, Apache in Phase 5, etc.); each phase replaces this stub
// with a real validate-with-the-target implementation.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	return target.ErrValidateOnlyNotSupported
}
