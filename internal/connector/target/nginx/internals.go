package nginx

import (
	"context"
	"encoding/base64"
	"os/user"
	"time"

	"github.com/certctl-io/certctl/internal/tlsprobe"
)

// b64Decode is the base64 decoder used by firstPEMBlock. Wrapping
// the stdlib call in a single-exit function keeps nginx.go's
// import surface minimal.
func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// userLookup is os/user.Lookup with a renamed export so nginx.go
// can call it without importing os/user directly (keeps each file
// to a single-import group). Returns the user record on success.
func userLookup(name string) (*user.User, error) {
	return user.Lookup(name)
}

// groupLookup mirror.
func groupLookup(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}

// SetTestRunValidate replaces the validate-command runner. Used
// only in tests so we don't need a real `nginx -t` binary on PATH.
func (c *Connector) SetTestRunValidate(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runValidate = fn
}

// SetTestRunReload replaces the reload-command runner. Test only.
func (c *Connector) SetTestRunReload(fn func(ctx context.Context, command string) ([]byte, error)) {
	c.runReload = fn
}

// SetTestProbe replaces the post-deploy TLS prober. Test only.
func (c *Connector) SetTestProbe(fn func(ctx context.Context, address string, timeout time.Duration) tlsprobe.ProbeResult) {
	c.probe = fn
}
