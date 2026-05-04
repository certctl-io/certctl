package domain_test

import (
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

func TestOCSPResponder_NeedsRotation(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	grace := 7 * 24 * time.Hour

	cases := []struct {
		name      string
		responder *domain.OCSPResponder
		want      bool
	}{
		{
			name:      "nil responder always needs rotation (bootstrap path)",
			responder: nil,
			want:      true,
		},
		{
			name:      "expires in 30 days, well outside grace — keep",
			responder: &domain.OCSPResponder{NotAfter: now.Add(30 * 24 * time.Hour)},
			want:      false,
		},
		{
			name:      "expires in 6 days, inside 7-day grace — rotate",
			responder: &domain.OCSPResponder{NotAfter: now.Add(6 * 24 * time.Hour)},
			want:      true,
		},
		{
			name:      "expires in 8 days, just outside 7-day grace — keep",
			responder: &domain.OCSPResponder{NotAfter: now.Add(8 * 24 * time.Hour)},
			want:      false,
		},
		{
			name:      "already expired — rotate",
			responder: &domain.OCSPResponder{NotAfter: now.Add(-time.Hour)},
			want:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.responder.NeedsRotation(now, grace); got != tc.want {
				t.Fatalf("NeedsRotation = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOCSPResponder_NeedsRotation_ZeroGrace(t *testing.T) {
	// Zero grace = strict definition (rotate only when expired).
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	r := &domain.OCSPResponder{NotAfter: now.Add(time.Hour)}
	if r.NeedsRotation(now, 0) {
		t.Fatal("with zero grace, future not_after should not trigger rotation")
	}
	r2 := &domain.OCSPResponder{NotAfter: now.Add(-time.Second)}
	if !r2.NeedsRotation(now, 0) {
		t.Fatal("with zero grace, past not_after should trigger rotation")
	}
}
