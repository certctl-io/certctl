package target_test

// Phase 3 of the deploy-hardening I master bundle: per-connector
// regression smoke pinning the default ValidateOnly stub returns
// the sentinel for every one of the 13 connectors. This test lives
// in target_test (external test package) so it can import each
// connector concretely + assert the interface contract.
//
// As Phases 4-9 replace each connector's stub with a real
// validate-with-the-target implementation, the corresponding
// per-connector entry in TestEveryConnectorDefaultsToSentinel
// MUST be deleted (or the test will fail because the real
// implementation no longer returns the sentinel). That deletion
// IS the bookkeeping that the operator-visible bit + behavior
// change are wired together.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/apache"
	"github.com/shankar0123/certctl/internal/connector/target/caddy"
	"github.com/shankar0123/certctl/internal/connector/target/envoy"
	"github.com/shankar0123/certctl/internal/connector/target/f5"
	"github.com/shankar0123/certctl/internal/connector/target/haproxy"
	"github.com/shankar0123/certctl/internal/connector/target/iis"
	"github.com/shankar0123/certctl/internal/connector/target/javakeystore"
	"github.com/shankar0123/certctl/internal/connector/target/k8ssecret"
	// nginx removed Phase 4 — real ValidateOnly implementation now in nginx.go.
	"github.com/shankar0123/certctl/internal/connector/target/postfix"
	"github.com/shankar0123/certctl/internal/connector/target/ssh"
	"github.com/shankar0123/certctl/internal/connector/target/traefik"
	"github.com/shankar0123/certctl/internal/connector/target/wincertstore"
)

// connectorsAtPhase3 is the canonical list of connectors that, as
// of Phase 3, return ErrValidateOnlyNotSupported from
// ValidateOnly. Each entry is a (name, factory) tuple; the factory
// returns a target.Connector via the connector's bare-NewConnector
// constructor pattern. As Phases 4-9 land, the corresponding
// connector is REMOVED from this list — its real ValidateOnly
// implementation is then exercised in the per-connector test
// suite, NOT here.
//
// CI guard rationale: a future PR that adds a 14th connector
// without wiring ValidateOnly fails this test (the sentinel
// contract is not satisfied). A future PR that implements a real
// ValidateOnly for, say, NGINX, but forgets to remove its entry
// from this list, fails this test (real impl no longer returns
// the sentinel). Both are the load-bearing bookkeeping protections.
var connectorsAtPhase3 = []struct {
	name string
	// new returns a fresh Connector instance. The default
	// ValidateOnly stub doesn't dereference any field on the
	// receiver, so a zero-value &pkg.Connector{} is sufficient
	// to satisfy the interface and exercise the sentinel return.
	// Phases 4-9 introduce real validate-with-the-target impls
	// that DO read fields; those connectors will need a populated
	// constructor here OR (more likely) be removed from this list
	// entirely and exercised in their own per-connector test
	// suite.
	new func() target.Connector
}{
	{"apache", func() target.Connector { return &apache.Connector{} }},
	{"caddy", func() target.Connector { return &caddy.Connector{} }},
	{"envoy", func() target.Connector { return &envoy.Connector{} }},
	{"f5", func() target.Connector { return &f5.Connector{} }},
	{"haproxy", func() target.Connector { return &haproxy.Connector{} }},
	{"iis", func() target.Connector { return &iis.Connector{} }},
	{"javakeystore", func() target.Connector { return &javakeystore.Connector{} }},
	{"k8ssecret", func() target.Connector { return &k8ssecret.Connector{} }},
	// nginx removed Phase 4 — its ValidateOnly is now the real
	// implementation; tested directly in
	// internal/connector/target/nginx/nginx_test.go.
	{"postfix", func() target.Connector { return &postfix.Connector{} }},
	{"ssh", func() target.Connector { return &ssh.Connector{} }},
	{"traefik", func() target.Connector { return &traefik.Connector{} }},
	{"wincertstore", func() target.Connector { return &wincertstore.Connector{} }},
}

func TestEveryConnectorDefaultsToSentinel(t *testing.T) {
	// Expected list size shrinks as Phases 4-9 land their real
	// ValidateOnly implementations. Phase 4 removed nginx.
	const expectedAtCurrentPhase = 12
	if len(connectorsAtPhase3) != expectedAtCurrentPhase {
		t.Fatalf("connectors-at-phase list = %d entries, want %d (drift in the 13-connector inventory)", len(connectorsAtPhase3), expectedAtCurrentPhase)
	}
	for _, c := range connectorsAtPhase3 {
		t.Run(c.name, func(t *testing.T) {
			conn := c.new()
			err := conn.ValidateOnly(context.Background(), target.DeploymentRequest{
				CertPEM:      "ignored-by-stub",
				ChainPEM:     "ignored",
				TargetConfig: json.RawMessage(`{}`),
			})
			if !errors.Is(err, target.ErrValidateOnlyNotSupported) {
				t.Errorf("got %v, want ErrValidateOnlyNotSupported", err)
			}
		})
	}
}
