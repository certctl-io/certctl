// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

//go:build integration

// Phase 5 — kind-driven cert-manager integration test. Verifies the
// certctl ACME server end-to-end against a real cert-manager 1.15+
// deployment in a kind cluster. The test sequences:
//
//  1. Bring up the kind cluster (kind-config.yaml).
//  2. Install cert-manager 1.15 (cert-manager-install.sh).
//  3. Helm-install certctl-server with acmeServer.enabled=true.
//  4. Apply the ClusterIssuer + Certificate.
//  5. Wait for the Certificate to become Ready.
//  6. Assert the Secret has tls.crt + tls.key.
//
// Gated behind KIND_AVAILABLE — CI doesn't run kind and skips this
// cleanly. Operators run locally via `make acme-cert-manager-test`.

package acmeintegration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// kindAvailable returns true when the operator opted into the kind-
// driven test path. CI default is opt-out (env unset → skip).
func kindAvailable() bool {
	return os.Getenv("KIND_AVAILABLE") != ""
}

// kindClusterName is the name passed to `kind create/delete cluster`.
// Kept as a const so the test cleanup uses the exact same name as
// setup (avoid orphan-cluster-after-flake).
const kindClusterName = "certctl-acme-test"

// TestCertManagerTrustAuthenticatedIssuance is the happy-path
// integration: cert-manager submits a new-order against a profile in
// trust_authenticated mode; certctl auto-resolves authzs (no solver
// round-trip in this mode); cert-manager finalizes; the Secret lands.
//
// Runtime: ~6-8 minutes wall-clock on a workstation (most of which is
// kind-create + cert-manager-controller-bootstrap, both cached on
// re-runs after the first). Skips cleanly when KIND_AVAILABLE is
// unset.
func TestCertManagerTrustAuthenticatedIssuance(t *testing.T) {
	if !kindAvailable() {
		t.Skip("KIND_AVAILABLE unset — kind-driven cert-manager integration test skipped")
	}
	ctx := context.Background()

	t.Log("creating kind cluster")
	runCmd(t, ctx, "kind", "create", "cluster",
		"--name", kindClusterName,
		"--config", "kind-config.yaml")
	t.Cleanup(func() {
		// Best-effort cluster teardown — never fail the test on cleanup
		// failure (operator can `kind delete cluster` manually).
		_ = exec.Command("kind", "delete", "cluster", "--name", kindClusterName).Run()
	})

	t.Log("installing cert-manager")
	runCmd(t, ctx, "bash", "cert-manager-install.sh")

	// Step 3 — deploy certctl-server. The Helm chart at
	// deploy/helm/certctl/ takes acmeServer.enabled=true; the operator
	// is expected to have built + pushed (or kind-loaded) a `:test`
	// image tag before the test runs. Document this in docs/acme-server.md.
	t.Log("helm-installing certctl-test")
	runCmd(t, ctx, "helm", "install", "certctl-test", "../../helm/certctl/",
		"--set", "acmeServer.enabled=true",
		"--set", "acmeServer.defaultProfileId=prof-test",
		"--set", "image.tag=test",
	)
	waitForDeploymentReady(t, ctx, "default", "certctl-test", 3*time.Minute)

	t.Log("applying ClusterIssuer + Certificate")
	runCmd(t, ctx, "kubectl", "apply", "-f", "clusterissuer-trust-authenticated.yaml")
	runCmd(t, ctx, "kubectl", "apply", "-f", "certificate-test.yaml")

	t.Log("waiting for Certificate to become Ready")
	waitForCertificateReady(t, ctx, "default", "test-com", 3*time.Minute)

	t.Log("asserting Secret has tls.crt")
	assertSecretHasCert(t, ctx, "default", "test-com-tls")

	t.Log("happy-path issuance verified end-to-end")
}

// runCmd runs the command; failures fail the test immediately. We
// stream combined stdout+stderr to t.Log on completion so the operator
// can read the kubectl/kind output in CI logs (when run there with
// KIND_AVAILABLE=1).
func runCmd(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // ARGS are test-controlled literals.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	t.Logf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
}

// waitForDeploymentReady polls until the named deployment reports
// Available=True. Wraps `kubectl wait` with a Go-level timeout so test
// hangs are bounded.
func waitForDeploymentReady(t *testing.T, ctx context.Context, namespace, name string, timeout time.Duration) {
	t.Helper()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "-n", namespace, "wait",
		"--for=condition=Available", fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())),
		"deployment/"+name) //nolint:gosec // ARGS are test-controlled literals.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deployment %s/%s did not become Ready in %v: %v\n%s",
			namespace, name, timeout, err, out)
	}
}

// waitForCertificateReady polls until the cert-manager Certificate
// resource transitions to Ready=True. cert-manager's own
// reconciliation loop is what advances the state; this just blocks
// until the controller is happy.
func waitForCertificateReady(t *testing.T, ctx context.Context, namespace, name string, timeout time.Duration) {
	t.Helper()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "-n", namespace, "wait",
		"--for=condition=Ready", fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())),
		"certificate/"+name) //nolint:gosec // ARGS are test-controlled literals.
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Dump the Certificate's events on failure so the operator
		// can see exactly which reconciliation step failed.
		describe := exec.Command("kubectl", "-n", namespace, "describe", "certificate", name)
		describeOut, _ := describe.CombinedOutput()
		t.Fatalf("certificate %s/%s did not become Ready in %v: %v\n%s\n--- describe ---\n%s",
			namespace, name, timeout, err, out, describeOut)
	}
}

// assertSecretHasCert checks that the named Secret has a non-empty
// tls.crt entry. We don't validate the chain itself here — that's the
// job of certctl's own integration test layer; this just confirms
// cert-manager wrote something into the Secret on the
// trust_authenticated happy-path.
func assertSecretHasCert(t *testing.T, ctx context.Context, namespace, name string) {
	t.Helper()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "-n", namespace, "get", "secret", name,
		"-o", "jsonpath={.data.tls\\.crt}") //nolint:gosec // ARGS are test-controlled literals.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("get secret %s/%s: %v\n%s", namespace, name, err, out)
	}
	if len(out) == 0 {
		t.Fatalf("secret %s/%s has empty tls.crt", namespace, name)
	}
}
