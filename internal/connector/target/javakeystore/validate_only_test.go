package javakeystore

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

func (s *stubExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return s.out, s.err
}

func TestJavaKeystore_ValidateOnly_Succeeds(t *testing.T) {
	c := NewWithExecutor(&Config{KeystorePath: "/etc/jks/cacerts", KeystorePassword: "changeit"}, nil, &stubExec{out: "Keystore type: jks"})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestJavaKeystore_ValidateOnly_Fails(t *testing.T) {
	c := NewWithExecutor(&Config{KeystorePath: "/missing"}, nil, &stubExec{out: "keystore tampered with", err: errors.New("exit 1")})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Errorf("got %v", err)
	}
}

func TestJavaKeystore_ValidateOnly_NoPath_Sentinel(t *testing.T) {
	c := NewWithExecutor(&Config{}, nil, &stubExec{})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestJavaKeystore_ValidateOnly_NilExec_Sentinel(t *testing.T) {
	c := &Connector{config: &Config{KeystorePath: "/some/jks"}}
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}
