package f5

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Phase 8 of the deploy-hardening I master bundle: F5 ValidateOnly
// real implementation tests. F5 already has full transactional
// rollback via the iControl REST `mgmt/tm/transaction` endpoint;
// the new bit is the explicit dry-run probe via Authenticate.

type stubF5Authenticator struct {
	authErr error
}

func (s *stubF5Authenticator) Authenticate(_ context.Context) error {
	return s.authErr
}

// implement the rest of the F5Client interface as no-ops so the
// stub satisfies the interface.
func (s *stubF5Authenticator) UploadFile(context.Context, string, []byte) error {
	return nil
}
func (s *stubF5Authenticator) InstallCert(context.Context, string, string) error { return nil }
func (s *stubF5Authenticator) InstallKey(context.Context, string, string) error  { return nil }
func (s *stubF5Authenticator) CreateTransaction(context.Context) (string, error) {
	return "", nil
}
func (s *stubF5Authenticator) CommitTransaction(context.Context, string) error {
	return nil
}
func (s *stubF5Authenticator) UpdateSSLProfile(context.Context, string, string, string, string, string, string) error {
	return nil
}
func (s *stubF5Authenticator) GetSSLProfile(context.Context, string, string) (*SSLProfileInfo, error) {
	return nil, nil
}
func (s *stubF5Authenticator) DeleteCert(context.Context, string, string) error { return nil }
func (s *stubF5Authenticator) DeleteKey(context.Context, string, string) error  { return nil }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestF5_ValidateOnly_Auth_Succeeds_ReturnsNil(t *testing.T) {
	c := NewWithClient(&Config{Host: "f5.example", Username: "admin"}, quietLogger(), &stubF5Authenticator{authErr: nil})
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestF5_ValidateOnly_AuthFails_ReturnsWrappedError(t *testing.T) {
	c := NewWithClient(&Config{Host: "f5.example", Username: "admin"}, quietLogger(), &stubF5Authenticator{authErr: errors.New("invalid credentials")})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got sentinel, want wrapped auth error: %v", err)
	}
}

func TestF5_ValidateOnly_NilClient_ReturnsSentinel(t *testing.T) {
	c := &Connector{config: &Config{Host: "f5.example"}, logger: quietLogger()}
	// Don't inject a client.
	if err := c.ValidateOnly(context.Background(), target.DeploymentRequest{}); !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("got %v, want sentinel", err)
	}
}

func TestF5_ValidateOnly_AuthFailureMessageMentionsBIGIP(t *testing.T) {
	c := NewWithClient(&Config{Host: "f5.example"}, quietLogger(), &stubF5Authenticator{authErr: errors.New("conn refused")})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "BIG-IP") {
		t.Errorf("error missing BIG-IP context: %v", err)
	}
}

func TestF5_ValidateOnly_RecoverableAuthErrIsActionable(t *testing.T) {
	// Auth-fail variant that simulates a one-time TACACS+ outage —
	// the operator is meant to see this as actionable.
	c := NewWithClient(&Config{Host: "f5.example"}, quietLogger(), &stubF5Authenticator{authErr: errors.New("TACACS+ auth provider unreachable")})
	err := c.ValidateOnly(context.Background(), target.DeploymentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "TACACS+") {
		t.Errorf("error doesn't surface auth provider info: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 &&
		(len(haystack) >= len(needle)) &&
		(indexOf(haystack, needle) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
