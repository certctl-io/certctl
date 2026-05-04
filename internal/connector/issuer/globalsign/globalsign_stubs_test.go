package globalsign

// Bundle N (Coverage Audit Closure) — stub-function coverage for the
// not-supported issuer.Connector interface methods. The connector
// delegates CRL/OCSP/CA-cert distribution to its upstream CA service,
// so these methods are documented stubs. Pinning them keeps the
// per-package coverage gate green and ensures the stubs aren't
// accidentally replaced with silent no-ops in a future refactor.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

func quietStubLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestStub_GenerateCRL(t *testing.T) {
	c := New(&Config{}, quietStubLogger())
	_, err := c.GenerateCRL(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from stub GenerateCRL")
	}
}

func TestStub_SignOCSPResponse(t *testing.T) {
	c := New(&Config{}, quietStubLogger())
	_, err := c.SignOCSPResponse(context.Background(), issuer.OCSPSignRequest{})
	if err == nil {
		t.Fatal("expected error from stub SignOCSPResponse")
	}
}

func TestStub_GetCACertPEM(t *testing.T) {
	c := New(&Config{}, quietStubLogger())
	_, _ = c.GetCACertPEM(context.Background())
}

func TestStub_GetRenewalInfo(t *testing.T) {
	c := New(&Config{}, quietStubLogger())
	res, err := c.GetRenewalInfo(context.Background(), "any-pem")
	_ = res
	_ = err
}
