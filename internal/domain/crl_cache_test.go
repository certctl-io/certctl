package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

func TestCRLCacheEntry_IsStale(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		nextUpdate time.Time
		want       bool
	}{
		{"future next_update is fresh", now.Add(time.Hour), false},
		{"exactly now is stale (boundary)", now, true},
		{"past next_update is stale", now.Add(-time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := &domain.CRLCacheEntry{NextUpdate: tc.nextUpdate}
			if got := entry.IsStale(now); got != tc.want {
				t.Fatalf("IsStale(%v) = %v, want %v", tc.nextUpdate, got, tc.want)
			}
		})
	}
}

func TestCRLCacheEntry_JSON_OmitsRawDER(t *testing.T) {
	// Raw bytes can be 100s of KB for busy CAs; JSON-encoding them into
	// every admin response would bloat the GUI's polling traffic. The DER
	// is omitted from JSON; admin endpoints set CRLDERBase64 explicitly
	// when they want the bytes shaped for transit.
	entry := &domain.CRLCacheEntry{
		IssuerID: "iss-test",
		CRLDER:   []byte{0x30, 0x82, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef},
	}
	blob, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(blob); contains(got, "deadbeef") || contains(got, "MIIBAA==") {
		t.Fatalf("raw DER should not appear in JSON, got %s", got)
	}
}

func TestCRLGenerationEvent_JSON_RoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	evt := domain.CRLGenerationEvent{
		IssuerID:     "iss-test",
		CRLNumber:    42,
		Duration:     150 * time.Millisecond,
		RevokedCount: 7,
		StartedAt:    now,
		Succeeded:    true,
	}
	blob, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got domain.CRLGenerationEvent
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.IssuerID != evt.IssuerID || got.CRLNumber != evt.CRLNumber || got.Duration != evt.Duration {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, evt)
	}
}

// contains is a local helper to avoid importing strings from a test file
// where the only use is a substring check.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
