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

	"github.com/certctl-io/certctl/internal/connector/target"
	// apache removed Phase 5 — real ValidateOnly implementation now in apache.go.
	"github.com/certctl-io/certctl/internal/connector/target/caddy"
	"github.com/certctl-io/certctl/internal/connector/target/envoy"
	// f5 removed Phase 8 — real ValidateOnly implementation now in validate_only.go.
	// haproxy removed Phase 6 — real ValidateOnly implementation now in haproxy.go.
	// iis removed Phase 8 — real ValidateOnly implementation now in validate_only.go.
	// javakeystore removed Phase 9 — real ValidateOnly implementation now in validate_only.go.
	// k8ssecret removed Phase 9 — real ValidateOnly implementation now in validate_only.go.
	// nginx removed Phase 4 — real ValidateOnly implementation now in nginx.go.
	// postfix removed Phase 7 — real ValidateOnly implementation now in postfix.go.
	// ssh removed Phase 9 — real ValidateOnly implementation now in validate_only.go.
	"github.com/certctl-io/certctl/internal/connector/target/traefik"
	// wincertstore removed Phase 9 — real ValidateOnly implementation now in validate_only.go.
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
	// apache removed Phase 5 — its ValidateOnly is now the real
	// implementation; tested directly in apache/apache_atomic_test.go.
	// caddy: file mode returns sentinel (no validate-with-target);
	// api mode is real-impl. Empty Connector hits the file-mode path.
	{"caddy", func() target.Connector { return &caddy.Connector{} }},
	// envoy: no validate-with-target command exists; always sentinel.
	{"envoy", func() target.Connector { return &envoy.Connector{} }},
	// f5 removed Phase 8 — Authenticate-probe real impl.
	// haproxy removed Phase 6 — `haproxy -c -f` real impl.
	// iis removed Phase 8 — Get-WebSite probe real impl.
	// javakeystore removed Phase 9 — `keytool -list` real impl.
	// k8ssecret removed Phase 9 — GetSecret RBAC probe real impl.
	// nginx removed Phase 4 — `nginx -t` real impl.
	// postfix removed Phase 7 — `postfix check` / `doveconf -n` real impl.
	// ssh removed Phase 9 — Connect probe real impl.
	// traefik: no validate-with-target command exists; always sentinel.
	{"traefik", func() target.Connector { return &traefik.Connector{} }},
	// wincertstore removed Phase 9 — `Get-ChildItem Cert:\` probe.
}

func TestEveryConnectorDefaultsToSentinel(t *testing.T) {
	// Expected list size shrinks as Phases 4-9 land their real
	// ValidateOnly implementations. Phase 4 removed nginx.
	const expectedAtCurrentPhase = 3
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
