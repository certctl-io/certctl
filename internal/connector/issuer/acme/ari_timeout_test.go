package acme

import (
	"log/slog"
	"testing"
	"time"
)

// Bundle C / Audit M-019 (CWE-400): pin the ARI HTTP timeout dispatch
// contract. Config.ARIHTTPTimeoutSeconds = 0 → 15s default. Non-zero
// values override. The 15s default predates Bundle C and is preserved
// byte-for-byte; this test guards against a future refactor that drops
// the default and silently configures HTTP clients with no timeout
// (which would re-open the M-019 stall risk).

func newARITestConnector(t *testing.T, timeoutSec int) *Connector {
	t.Helper()
	cfg := &Config{
		DirectoryURL:          "https://acme.example.invalid/directory",
		ARIEnabled:            true,
		ARIHTTPTimeoutSeconds: timeoutSec,
	}
	return New(cfg, slog.New(slog.NewTextHandler(testDiscardWriter{}, nil)))
}

type testDiscardWriter struct{}

func (testDiscardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestARIHTTPTimeout_DefaultIs15s(t *testing.T) {
	c := newARITestConnector(t, 0)
	got := c.ariHTTPTimeout()
	want := 15 * time.Second
	if got != want {
		t.Errorf("ariHTTPTimeout default: got %s, want %s", got, want)
	}
}

func TestARIHTTPTimeout_NonZeroOverridesDefault(t *testing.T) {
	c := newARITestConnector(t, 45)
	got := c.ariHTTPTimeout()
	want := 45 * time.Second
	if got != want {
		t.Errorf("ariHTTPTimeout override: got %s, want %s", got, want)
	}
}

func TestARIHTTPTimeout_NegativeValuesUseDefault(t *testing.T) {
	// Negative values are nonsensical but should fall back to the
	// default rather than producing an immediate-timeout client.
	c := newARITestConnector(t, -1)
	got := c.ariHTTPTimeout()
	want := 15 * time.Second
	if got != want {
		t.Errorf("negative ariHTTPTimeout should fall back to default: got %s, want %s", got, want)
	}
}

func TestARIHTTPTimeout_NilConfigSafeDefault(t *testing.T) {
	// Defensive: a connector with nil config must not panic and must
	// return the documented default. This is a guard for tests / DI
	// callers that hand in a partially-built Connector.
	c := &Connector{}
	got := c.ariHTTPTimeout()
	want := 15 * time.Second
	if got != want {
		t.Errorf("nil-config ariHTTPTimeout: got %s, want %s", got, want)
	}
}
