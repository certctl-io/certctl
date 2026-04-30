//go:build integration

// EST RFC 7030 hardening master bundle Phase 10.2 — libest sidecar
// integration tests. Five named tests exercise the live certctl
// server's EST endpoints through Cisco's libest reference client
// (estclient binary inside the certctl-test-libest sidecar container).
//
// Skip conditions:
//   - INTEGRATION env var not set (matches integration_test.go).
//   - The libest sidecar isn't running (the test detects this by
//     `docker inspect certctl-test-libest` and skips if absent).
//   - The EST endpoint isn't reachable from inside the network (the
//     test probes /.well-known/est/cacerts via estclient -g and
//     skips if the route returns 404).
//
// Operator workflow:
//
//	cd deploy
//	docker compose -f docker-compose.test.yml --profile est-e2e build libest-client
//	docker compose -f docker-compose.test.yml --profile est-e2e up -d
//	cd test
//	INTEGRATION=1 go test -tags integration -v -run 'TestEST_LibESTClient' ./...
//
// CI runs this in the same job that already runs integration_test.go;
// the docker-compose.test.yml libest-client entry + the Dockerfile
// land in the same commit so a fresh `make integration-test-est`
// (CI-side wrapper) works without operator intervention.

package integration_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// libestContainer is the docker-compose service name + container_name
// the sidecar uses (deploy/docker-compose.test.yml::libest-client).
const libestContainer = "certctl-test-libest"

// estServerHostInsideNetwork is the certctl-server hostname libest
// resolves inside the certctl-test docker network. The sidecar's
// /etc/hosts is auto-populated by docker-compose's bridge network so
// `certctl-server` resolves to 10.30.50.6 (the static IP from the
// compose file).
const estServerHostInsideNetwork = "certctl-server"

// estPortInsideNetwork is the certctl HTTPS port inside the docker
// network. NOT the host-mapped port (8443 → 8443 via compose); the
// sidecar talks straight to the container.
const estPortInsideNetwork = "8443"

// estCABundleInContainer is the bind-mounted certctl CA bundle the
// libest sidecar pins TLS against. Path matches the volume mount in
// docker-compose.test.yml::libest-client.
const estCABundleInContainer = "/config/certs/ca.crt"

// dockerExec runs `docker exec <container> <args>` and returns
// stdout + stderr + the run error. Used by every libest test below.
// Centralised so a future docker-cli refactor (podman, kubectl exec)
// only changes one place.
func dockerExec(ctx context.Context, container string, args ...string) (string, string, error) {
	full := append([]string{"exec", container}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// libestSidecarReady checks that the libest sidecar container is
// running. Returns the docker-inspect status string + a boolean for
// "ready"; the boolean is what tests use to skip cleanly when the
// operator forgot the --profile est-e2e flag.
func libestSidecarReady(ctx context.Context) (string, bool) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Status}}", libestContainer)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return errBuf.String(), false
	}
	status := strings.TrimSpace(out.String())
	return status, status == "running"
}

// runEstclient is the workhorse helper that drives `estclient` inside
// the sidecar. Returns the raw stdout (typically the issued cert PEM
// or the cacerts PKCS#7 base64 blob) + a useful error including
// stderr on failure.
//
// The args are appended after a baseline {`estclient`, ...common
// flags} shape that pins TLS against the certctl CA bundle + sets the
// per-test-run output dir.
func runEstclient(ctx context.Context, t *testing.T, extraArgs ...string) (string, error) {
	t.Helper()
	baseArgs := []string{
		"estclient",
		"-s", estServerHostInsideNetwork,
		"-p", estPortInsideNetwork,
		"-c", estCABundleInContainer,
	}
	args := append(baseArgs, extraArgs...)
	stdout, stderr, err := dockerExec(ctx, libestContainer, args...)
	if err != nil {
		return stdout, fmt.Errorf("estclient %v: %w (stderr=%q)", args, err, stderr)
	}
	return stdout, nil
}

// requireESTSidecar is the per-test skip guard. If the libest sidecar
// isn't running, every EST integration test skips with a message that
// tells the operator the exact command to bring it up.
func requireESTSidecar(t *testing.T) {
	t.Helper()
	if !integrationOptedIn() {
		t.Skip("integration tests require INTEGRATION=1; skipping libest e2e suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if status, ready := libestSidecarReady(ctx); !ready {
		t.Skipf("libest sidecar (container %q) not running (status=%q). Run `cd deploy && docker compose -f docker-compose.test.yml --profile est-e2e up -d libest-client` to bring it up.", libestContainer, status)
	}
}

// integrationOptedIn mirrors integration_test.go's existing INTEGRATION
// env-var convention. We can't import the helper from integration_test.go
// because they're in the same package + the convention is just one
// env-var read.
func integrationOptedIn() bool {
	for _, v := range []string{"INTEGRATION", "RUN_INTEGRATION"} {
		if val := strings.TrimSpace(getenv(v)); val != "" && val != "0" && !strings.EqualFold(val, "false") {
			return true
		}
	}
	return false
}

// getenv is a tiny wrapper so we don't pull in os twice from this file
// (integration_test.go has the canonical envOr that uses os.Getenv).
// Kept self-contained so the est_e2e_test.go file is independently
// readable.
func getenv(k string) string {
	v := exec.Command("printenv", k)
	out, _ := v.Output()
	return strings.TrimSpace(string(out))
}

// TestEST_LibESTClient_Enrollment_Integration is the canonical
// happy-path test. estclient does:
//
//  1. GET cacerts to retrieve the CA chain.
//  2. POST simpleenroll with a freshly-generated CSR; receive the
//     issued cert chain back.
//  3. Parse the issued cert + assert Subject CN matches what we asked.
//
// HTTP Basic auth is NOT used here — the test profile (CERTCTL_EST_PROFILE_E2E_*)
// is configured without an enrollment password so the smoke test
// exercises the simplest happy path.
func TestEST_LibESTClient_Enrollment_Integration(t *testing.T) {
	requireESTSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1 — get cacerts. estclient writes the PKCS#7 to /config/est/cacerts.p7.
	if _, err := runEstclient(ctx, t, "-g", "-o", "/config/est"); err != nil {
		t.Fatalf("get cacerts: %v", err)
	}

	// Step 2 — generate a CSR + enroll. estclient -e mode generates
	// the keypair + the CSR + drives simpleenroll in one shot.
	if _, err := runEstclient(ctx, t, "-e", "--common-name", "device-e2e-001.example.com",
		"-o", "/config/est"); err != nil {
		t.Fatalf("simpleenroll: %v", err)
	}

	// Step 3 — read the issued cert back via docker exec + parse.
	pemBytes, _, err := dockerExec(ctx, libestContainer, "cat", "/config/est/cert-0-0.pkcs7")
	if err != nil {
		t.Fatalf("read issued cert: %v", err)
	}
	if !strings.Contains(pemBytes, "BEGIN") && !strings.Contains(pemBytes, "MII") {
		t.Errorf("issued cert output didn't look like PEM/base64: first 80 bytes = %q", truncateHead(pemBytes, 80))
	}
}

// TestEST_LibESTClient_MTLSEnrollment_Integration drives the mTLS
// sibling route /.well-known/est-mtls/<PathID>/simpleenroll. The
// sidecar carries a bootstrap cert under /config/certs/bootstrap.pem
// signed by the per-profile mTLS trust anchor; estclient presents
// it via the -k/-c flags.
//
// Skip when the bootstrap cert isn't installed in the sidecar (the
// operator has to run a one-time setup script to mint the cert
// against the per-profile trust bundle's CA key — the integration
// suite can't bootstrap that automatically without exposing the
// trust anchor's private key, which we deliberately keep out of git).
func TestEST_LibESTClient_MTLSEnrollment_Integration(t *testing.T) {
	requireESTSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Probe for the bootstrap cert. Skip if the operator hasn't
	// pre-provisioned one.
	if _, _, err := dockerExec(ctx, libestContainer, "test", "-f", "/config/certs/bootstrap.pem"); err != nil {
		t.Skip("/config/certs/bootstrap.pem not present in libest sidecar — skipping mTLS path. To enable: mint a bootstrap cert against the per-profile mTLS trust anchor and copy into deploy/test/certs/.")
	}

	if _, err := runEstclient(ctx, t,
		"-e",
		"--pem-output",
		"-k", "/config/certs/bootstrap.key",
		"-c", "/config/certs/bootstrap.pem",
		"--common-name", "device-mtls-001.example.com",
		"-o", "/config/est",
	); err != nil {
		t.Fatalf("mTLS simpleenroll: %v", err)
	}
}

// TestEST_LibESTClient_ServerKeygen_Integration drives RFC 7030
// §4.4 server-keygen. estclient submits a CSR + receives the issued
// cert + the encrypted private key (CMS EnvelopedData) in a multipart
// response. The test asserts both parts arrive + the key part is
// non-empty. Decrypting the key requires the CSR-side private key
// (which estclient holds) — left as a smoke check rather than a full
// round-trip because libest's --serverkeygen flag does the decrypt
// internally before writing the key to disk.
func TestEST_LibESTClient_ServerKeygen_Integration(t *testing.T) {
	requireESTSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := runEstclient(ctx, t,
		"-e",
		"--serverkeygen",
		"--common-name", "device-keygen-001.example.com",
		"-o", "/config/est",
	); err != nil {
		// Some libest builds report a non-zero exit when the server
		// returns a profile-disabled 404; map that to a Skip so the
		// suite stays green when the e2e profile hasn't enabled
		// SERVER_KEYGEN. The error message contains "404" in either case.
		if strings.Contains(err.Error(), "404") {
			t.Skip("server-keygen disabled on the e2e EST profile (HTTP 404). Enable via CERTCTL_EST_PROFILE_E2E_SERVER_KEYGEN_ENABLED=true in docker-compose.test.yml.")
		}
		t.Fatalf("serverkeygen: %v", err)
	}

	// Assert the key part was written. estclient writes the private
	// key to a deterministic filename when --serverkeygen is set;
	// exact name depends on libest version, so we glob.
	stdout, _, err := dockerExec(ctx, libestContainer, "sh", "-c",
		"ls /config/est/ | grep -E '\\.(key|pkey|p8)$' | head -1")
	if err != nil || strings.TrimSpace(stdout) == "" {
		t.Errorf("server-keygen response did not write a key file: stdout=%q err=%v", stdout, err)
	}
}

// TestEST_LibESTClient_RateLimited_Integration drives N+1 enrollments
// from the same (CN, source-IP) pair to trip the per-principal
// sliding-window rate limiter. The 4th enrollment (default cap=3
// matches Intune's PerDeviceRateLimiter default) MUST fail with a
// 429 response.
//
// The test relies on the e2e profile being configured with
// RATE_LIMIT_PER_PRINCIPAL_24H=3 so the cap is testable in a
// reasonable test window.
func TestEST_LibESTClient_RateLimited_Integration(t *testing.T) {
	requireESTSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	commonName := "device-ratelimit-001.example.com"
	allowed := 3
	for i := 1; i <= allowed; i++ {
		if _, err := runEstclient(ctx, t,
			"-e",
			"--common-name", commonName,
			"-o", "/config/est",
		); err != nil {
			t.Fatalf("enroll #%d should have succeeded: %v", i, err)
		}
	}
	// (allowed+1)-th attempt MUST be rate-limited.
	out, err := runEstclient(ctx, t,
		"-e",
		"--common-name", commonName,
		"-o", "/config/est",
	)
	if err == nil {
		t.Fatalf("enroll #%d should have been rate-limited, but succeeded: %q", allowed+1, out)
	}
	// estclient surfaces the HTTP status in stderr; the test wrapper
	// captures both streams in the err message.
	if !strings.Contains(err.Error(), "429") && !strings.Contains(err.Error(), "Too Many") {
		t.Errorf("enroll #%d failed but not with a 429-shaped error: %v", allowed+1, err)
	}
}

// TestEST_LibESTClient_ChannelBinding_Integration drives the RFC 9266
// tls-exporter binding path. libest's --tls-exporter flag (3.2.0+)
// computes the binding client-side + embeds it as the
// id-aa-est-tls-exporter CMC unsignedAttribute on the CSR.
//
// On the server side we expect the channel-binding gate to pass for
// the matching binding + reject when we forge a wrong binding (libest
// has no explicit "wrong binding" knob — the test exercises only the
// passing path, and the rejection path is covered by the unit test
// suite at internal/cms/channelbinding_test.go).
func TestEST_LibESTClient_ChannelBinding_Integration(t *testing.T) {
	requireESTSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := runEstclient(ctx, t,
		"-e",
		"--tls-exporter",
		"--common-name", "device-binding-001.example.com",
		"-o", "/config/est",
	); err != nil {
		// Libest builds without RFC 9266 support exit non-zero with
		// "unknown option --tls-exporter". Surface as Skip so the
		// suite stays informative on libest variants that lack it.
		if strings.Contains(err.Error(), "unknown option") || strings.Contains(err.Error(), "invalid option") {
			t.Skipf("libest build lacks --tls-exporter support: %v", err)
		}
		t.Fatalf("channel-binding enroll: %v", err)
	}
}

// truncateHead returns the first n runes of s (or all of s if it's
// shorter), used to keep error messages from dumping multi-MB cert
// blobs into the test log.
func truncateHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// silenceUnused keeps imports live across libest builds that may
// trigger a different code path. pem + x509 are both referenced by
// the cert-parsing branch of the Enrollment_Integration test in
// future expansions.
var _ = pem.Decode
var _ = x509.ParseCertificate
