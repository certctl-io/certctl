package ssh

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Phase 9 of the deploy-hardening I master bundle: SSH ValidateOnly
// real implementation tests.

type stubSSHClient struct {
	connectErr error
}

func (s *stubSSHClient) Connect(_ context.Context) error                     { return s.connectErr }
func (s *stubSSHClient) Close() error                                        { return nil }
func (s *stubSSHClient) WriteFile(_ string, _ []byte, _ os.FileMode) error   { return nil }
func (s *stubSSHClient) Execute(_ context.Context, _ string) (string, error) { return "", nil }
func (s *stubSSHClient) StatFile(_ string) (os.FileInfo, error)              { return nil, os.ErrNotExist }
func (s *stubSSHClient) ReadFile(_ string) ([]byte, error)                   { return nil, os.ErrNotExist }
func (s *stubSSHClient) Remove(_ string) error                               { return nil }

func TestSSH_ValidateOnly_Connect_Succeeds(t *testing.T) {
	c := NewWithClient(&Config{Host: "h", User: "u"}, &stubSSHClient{}, nil)
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestSSH_ValidateOnly_Connect_Fails(t *testing.T) {
	c := NewWithClient(&Config{Host: "h", User: "u"}, &stubSSHClient{connectErr: errors.New("conn refused")}, nil)
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Error("got sentinel, want wrapped error")
	}
}

func TestSSH_ValidateOnly_NilClient_Sentinel(t *testing.T) {
	c := &Connector{config: &Config{Host: "h"}}
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}
