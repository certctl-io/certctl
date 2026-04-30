package k8ssecret

import (
	"context"
	"errors"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
)

type stubK8s struct {
	getErr error
}

func (s *stubK8s) GetSecret(_ context.Context, _, _ string) (*SecretData, error) {
	return nil, s.getErr
}

func (s *stubK8s) CreateSecret(_ context.Context, _ string, _ *SecretData) error { return nil }
func (s *stubK8s) UpdateSecret(_ context.Context, _ string, _ *SecretData) error { return nil }
func (s *stubK8s) DeleteSecret(_ context.Context, _, _ string) error             { return nil }

func TestK8s_ValidateOnly_Succeeds(t *testing.T) {
	c := NewWithClient(&Config{Namespace: "ns", SecretName: "tls"}, &stubK8s{}, nil)
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestK8s_ValidateOnly_RBACError(t *testing.T) {
	c := NewWithClient(&Config{Namespace: "ns", SecretName: "tls"}, &stubK8s{getErr: errors.New("forbidden: secrets is restricted")}, nil)
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Error("got sentinel, want wrapped error")
	}
}

func TestK8s_ValidateOnly_NoConfig_Sentinel(t *testing.T) {
	c := NewWithClient(&Config{}, &stubK8s{}, nil)
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}

func TestK8s_ValidateOnly_NilClient_Sentinel(t *testing.T) {
	c := &Connector{config: &Config{Namespace: "ns", SecretName: "tls"}}
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v", err)
	}
}
