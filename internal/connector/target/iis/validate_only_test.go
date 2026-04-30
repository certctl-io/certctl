package iis

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Phase 8 of the deploy-hardening I master bundle: IIS ValidateOnly
// real implementation tests. IIS already has explicit pre-deploy
// backup + post-rollback re-import semantics; the new bit is the
// PowerShell health probe via Get-WebSite.

type stubExecutor struct {
	out string
	err error
}

func (s *stubExecutor) Execute(_ context.Context, _ string) (string, error) {
	return s.out, s.err
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestIIS_ValidateOnly_GetWebSite_Succeeds(t *testing.T) {
	c := NewWithExecutor(&Config{SiteName: "Default Web Site"}, quietLogger(), &stubExecutor{out: "Default Web Site"})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestIIS_ValidateOnly_GetWebSite_Fails(t *testing.T) {
	c := NewWithExecutor(&Config{SiteName: "Missing"}, quietLogger(), &stubExecutor{
		out: "Get-WebSite : Cannot find a Web site with name 'Missing'",
		err: errors.New("PowerShell exit 1"),
	})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got sentinel, want wrapped error: %v", err)
	}
	if !strings.Contains(err.Error(), "Cannot find") {
		t.Errorf("error missing PowerShell stderr: %v", err)
	}
}

func TestIIS_ValidateOnly_NilExecutor_ReturnsSentinel(t *testing.T) {
	c := &Connector{config: &Config{SiteName: "x"}, logger: quietLogger()}
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v, want sentinel", err)
	}
}

func TestIIS_ValidateOnly_SiteNameQuoted(t *testing.T) {
	// Verify the script PROPERLY quotes site names with spaces (a common
	// IIS site name pattern).
	captured := ""
	exec := &stubExecutor{out: "Default Web Site"}
	c := NewWithExecutor(&Config{SiteName: "Default Web Site"}, quietLogger(), exec)
	// Wrap exec to capture script.
	c.executor = captureExec{wrapped: exec, captured: &captured}
	c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if !strings.Contains(captured, `"Default Web Site"`) {
		t.Errorf("script missing quoted site name: %q", captured)
	}
}

type captureExec struct {
	wrapped  PowerShellExecutor
	captured *string
}

func (c captureExec) Execute(ctx context.Context, script string) (string, error) {
	*c.captured = script
	return c.wrapped.Execute(ctx, script)
}

func TestIIS_ValidateOnly_OutputContextInError(t *testing.T) {
	c := NewWithExecutor(&Config{SiteName: "DWS"}, quietLogger(), &stubExecutor{
		out: "WARNING: This site is in stopped state",
		err: errors.New("exit 1"),
	})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "stopped state") {
		t.Errorf("got %v", err)
	}
}
