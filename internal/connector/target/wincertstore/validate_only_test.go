package wincertstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
)

type stubExec struct {
	out string
	err error
}

func (s *stubExec) Execute(_ context.Context, _ string) (string, error) { return s.out, s.err }

func TestWinCertStore_ValidateOnly_Succeeds(t *testing.T) {
	c := NewWithExecutor(&Config{StoreName: "My", StoreLocation: "LocalMachine"}, nil, &stubExec{out: "ABC123"})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestWinCertStore_ValidateOnly_Fails(t *testing.T) {
	c := NewWithExecutor(&Config{StoreName: "My"}, nil, &stubExec{err: errors.New("access denied")})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("got %v", err)
	}
}

func TestWinCertStore_ValidateOnly_NilExec_Sentinel(t *testing.T) {
	c := &Connector{config: &Config{}}
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestWinCertStore_ValidateOnly_DefaultStore_LocalMachineMy(t *testing.T) {
	captured := ""
	exec := capture{out: "x", capt: &captured}
	c := NewWithExecutor(&Config{}, nil, &exec)
	c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	// Backslash escaping in PowerShell-string + Go-string: the
	// final script literal contains "Cert:\\LocalMachine\\My" once
	// quoted via %q in fmt.Sprintf. Match against the doubled form.
	if !strings.Contains(captured, `LocalMachine\\My`) && !strings.Contains(captured, `LocalMachine\My`) {
		t.Errorf("default store path not in script: %q", captured)
	}
}

type capture struct {
	out  string
	capt *string
}

func (c capture) Execute(_ context.Context, script string) (string, error) {
	*c.capt = script
	return c.out, nil
}
