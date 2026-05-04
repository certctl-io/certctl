package vault

// Top-10 fix #5 of the 2026-05-03 issuer-coverage audit. Pre-fix,
// Vault PKI authenticated via a static token and never called
// renew-self; long-lived deploys hit token expiry and started failing
// silently — the operator's first signal was failed renewals on
// production targets. This file adds:
//
//   1. Connector.Start(ctx) — spawns a goroutine that calls
//      POST /v1/auth/token/renew-self at TTL/2 cadence (computed
//      from a one-shot LookupSelf at startup).
//   2. Connector.Stop() — cancels the goroutine's context and blocks
//      until it has exited. Idempotent.
//   3. Connector.renewSelf(ctx) — the per-tick HTTP call.
//   4. Connector.lookupSelf(ctx) — a one-shot startup probe to learn
//      the current TTL + renewable flag.
//
// On a `renewable: false` response, the loop logs a WARN and exits
// cleanly; once Vault has decided the token is no longer renewable
// (typically Max TTL reached), retrying is what gets certctl-server
// flagged in the Vault audit log as a misbehaving client.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// minRenewInterval guards against degenerate fast cadence when a
// misconfigured Vault returns a tiny TTL. 5s is short enough that
// the cap rarely fires in practice but long enough that we don't
// hammer Vault's audit log with renew-self calls if something goes
// sideways. Defensive only; production tokens always have TTL ≥ 30m.
const minRenewInterval = 5 * time.Second

// RenewalRecorder is the metric-sink surface the renew-self loop
// uses. result is one of: "success", "failure", "not_renewable".
// Implementations MUST be goroutine-safe — RecordRenewal is called
// from the renewal loop's own goroutine.
//
// service.VaultRenewalMetrics satisfies this interface; cmd/server
// wires the same instance into the registry (which forwards to the
// connector via SetRenewalRecorder) and into the metrics handler
// (for Prometheus exposition).
type RenewalRecorder interface {
	RecordRenewal(result string)
}

// noopRenewalRecorder is the zero-cost default. Used until
// SetRenewalRecorder wires a real metric sink (production) or in
// unit tests that don't care about metrics.
type noopRenewalRecorder struct{}

func (noopRenewalRecorder) RecordRenewal(string) {}

// renewTicker is the small surface the renewal loop uses from
// time.Ticker, extracted so tests can swap in a deterministic
// implementation that fires on cue. Production: time.NewTicker.
type renewTicker interface {
	C() <-chan time.Time
	Stop()
}

// stdTicker is the production implementation, a thin wrapper around
// *time.Ticker that exposes its C channel via a method so it
// satisfies the renewTicker interface (channels can't be method
// values directly).
type stdTicker struct{ t *time.Ticker }

func (s stdTicker) C() <-chan time.Time { return s.t.C }
func (s stdTicker) Stop()               { s.t.Stop() }

// lookupSelfResponse is the subset of /v1/auth/token/lookup-self we
// consume. Vault returns many other fields (policies, accessor, …)
// that are irrelevant to the renewal loop.
type lookupSelfResponse struct {
	Data struct {
		TTL       int  `json:"ttl"`       // seconds remaining on the token
		Renewable bool `json:"renewable"` // whether the token can be renewed
	} `json:"data"`
}

// renewSelfResponse is the subset of /v1/auth/token/renew-self we
// consume. Per Vault's HTTP API, the renewed token's lease info
// lands in `auth.lease_duration` and `auth.renewable`.
type renewSelfResponse struct {
	Auth struct {
		LeaseDuration int  `json:"lease_duration"`
		Renewable     bool `json:"renewable"`
	} `json:"auth"`
}

// lookupSelf calls GET /v1/auth/token/lookup-self and returns the
// remaining TTL + the renewable flag. Used by Start to compute the
// initial tick cadence.
func (c *Connector) lookupSelf(ctx context.Context) (ttl time.Duration, renewable bool, err error) {
	if c.config == nil || c.config.Token.IsEmpty() {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf: token not configured")
	}

	url := c.config.Addr + "/v1/auth/token/lookup-self"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf request build: %w", err)
	}
	if err := c.config.Token.Use(func(buf []byte) error {
		req.Header.Set("X-Vault-Token", string(buf))
		return nil
	}); err != nil {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf token use: %w", err)
	}

	resp, err := c.renewClient.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf body read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed lookupSelfResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, false, fmt.Errorf("vault token-renewal lookupSelf parse: %w", err)
	}

	return time.Duration(parsed.Data.TTL) * time.Second, parsed.Data.Renewable, nil
}

// renewSelfResult is returned by renewSelf — it lets the loop both
// update the in-memory TTL AND react to a renewable=false flip on
// the same call without an extra round-trip.
type renewSelfResult struct {
	NewTTL    time.Duration
	Renewable bool
}

// renewSelf calls POST /v1/auth/token/renew-self with an empty body
// (Vault accepts `{}`) and returns the renewed lease's TTL +
// renewable flag. The caller is responsible for stopping the loop
// when Renewable goes false.
func (c *Connector) renewSelf(ctx context.Context) (renewSelfResult, error) {
	if c.config == nil || c.config.Token.IsEmpty() {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: token not configured; rotate the token before TTL expires")
	}

	url := c.config.Addr + "/v1/auth/token/renew-self"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: request build: %w; rotate the token before TTL expires", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.config.Token.Use(func(buf []byte) error {
		req.Header.Set("X-Vault-Token", string(buf))
		return nil
	}); err != nil {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: token use: %w; rotate the token before TTL expires", err)
	}

	resp, err := c.renewClient.Do(req)
	if err != nil {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: HTTP error: %w; rotate the token before TTL expires", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: body read: %w; rotate the token before TTL expires", err)
	}
	if resp.StatusCode != http.StatusOK {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: status %d: %s; rotate the token before TTL expires", resp.StatusCode, string(body))
	}

	var parsed renewSelfResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return renewSelfResult{}, fmt.Errorf("vault token renewal failed: parse: %w; rotate the token before TTL expires", err)
	}

	return renewSelfResult{
		NewTTL:    time.Duration(parsed.Auth.LeaseDuration) * time.Second,
		Renewable: parsed.Auth.Renewable,
	}, nil
}

// Start kicks off the renew-self goroutine. Implements
// issuer.Lifecycle. Returns nil on success (goroutine running) or an
// error if the initial lookupSelf failed (no goroutine spawned).
//
// Cadence is computed once at startup as TTL/2 (capped at
// minRenewInterval). Each successful renewal updates the in-memory
// TTL and the goroutine resets its ticker to the new TTL/2 — so a
// short bootstrap token that gets renewed up to a longer Max TTL
// shifts to the longer cadence automatically.
//
// On `renewable: false` (initial lookup OR any subsequent renewal),
// Start returns nil but the loop emits a WARN and exits — operator
// must rotate the Vault token before its current TTL expires.
func (c *Connector) Start(ctx context.Context) error {
	c.renewMu.Lock()
	if c.renewStarted {
		c.renewMu.Unlock()
		return nil // idempotent: already running
	}
	if c.config == nil || c.config.Token.IsEmpty() {
		c.renewMu.Unlock()
		return fmt.Errorf("vault token-renewal Start: token not configured (call ValidateConfig first)")
	}
	c.renewMu.Unlock()

	// Initial lookup — short timeout so a misconfigured Vault address
	// fails Start fast rather than blocking the server's startup
	// sequence indefinitely. The renewal goroutine itself uses the
	// per-tick context for its own deadlines.
	lookupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ttl, renewable, err := c.lookupSelf(lookupCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("vault token-renewal Start: initial lookupSelf: %w", err)
	}

	c.logger.Info("vault token-renewal loop starting",
		"addr", c.config.Addr,
		"ttl_seconds", int(ttl.Seconds()),
		"renewable", renewable,
	)

	if !renewable {
		// Don't spawn the goroutine — the token is already non-
		// renewable. Surface via the metric so operators see it in
		// Grafana even before any tick fires.
		c.recordRenewal("not_renewable")
		c.logger.Warn("vault token is not renewable at startup; renew-self loop will not run — rotate the token before its TTL expires",
			"ttl_seconds", int(ttl.Seconds()),
		)
		return nil
	}

	// Spawn the goroutine. Use a derived ctx so Stop() can cancel
	// independently of the parent.
	loopCtx, loopCancel := context.WithCancel(ctx)
	done := make(chan struct{})

	c.renewMu.Lock()
	c.renewStarted = true
	c.renewCancel = loopCancel
	c.renewDone = done
	c.renewMu.Unlock()

	interval := computeInterval(ttl)
	go c.renewLoop(loopCtx, interval, done)

	c.logger.Info("vault token-renewal loop started",
		"interval_seconds", int(interval.Seconds()),
	)

	return nil
}

// Stop blocks until the renew-self goroutine has exited.
// Implements issuer.Lifecycle. Idempotent.
func (c *Connector) Stop() {
	c.renewMu.Lock()
	cancel := c.renewCancel
	done := c.renewDone
	started := c.renewStarted
	c.renewMu.Unlock()

	if !started {
		return
	}
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// renewLoop is the actual goroutine body. Owns the ticker, the
// in-memory TTL, and the renewable-flag state machine. Exits on
// ctx.Done() or on `renewable: false`.
func (c *Connector) renewLoop(ctx context.Context, initial time.Duration, done chan struct{}) {
	defer close(done)

	factory := c.renewTickerFactory
	if factory == nil {
		factory = func(d time.Duration) renewTicker {
			return stdTicker{t: time.NewTicker(d)}
		}
	}

	ticker := factory(initial)
	currentInterval := initial
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("vault token-renewal loop stopping (ctx cancelled)")
			return
		case <-ticker.C():
			// Per-tick deadline derived from the current cadence —
			// renew calls should comfortably finish in <1s, so a
			// budget of min(interval, 30s) is generous.
			tickBudget := currentInterval
			if tickBudget > 30*time.Second {
				tickBudget = 30 * time.Second
			}
			tickCtx, cancel := context.WithTimeout(ctx, tickBudget)
			res, err := c.renewSelf(tickCtx)
			cancel()
			if err != nil {
				c.recordRenewal("failure")
				c.logger.Error(err.Error())
				// Keep ticking — operator may rotate the token
				// out-of-band, or the failure may be transient.
				// Stopping on first failure would mean a 1s
				// network blip kills the loop for the rest of
				// process lifetime.
				continue
			}
			if !res.Renewable {
				c.recordRenewal("not_renewable")
				c.logger.Warn("vault token is no longer renewable; renew-self loop exiting — rotate the token before its current TTL expires",
					"ttl_seconds", int(res.NewTTL.Seconds()),
				)
				return
			}
			c.recordRenewal("success")
			c.logger.Info("vault token renewed",
				"new_ttl_seconds", int(res.NewTTL.Seconds()),
			)

			// If the new TTL/2 differs meaningfully from the
			// current cadence, restart the ticker at the new
			// rate. This handles the bootstrap-→-MaxTTL transition
			// (short initial TTL renews up to a longer Max TTL,
			// which we'd otherwise hammer at the old fast cadence
			// for the rest of the process).
			newInterval := computeInterval(res.NewTTL)
			if differsEnough(currentInterval, newInterval) {
				ticker.Stop()
				ticker = factory(newInterval)
				currentInterval = newInterval
				c.logger.Info("vault token-renewal cadence updated",
					"new_interval_seconds", int(newInterval.Seconds()),
				)
			}
		}
	}
}

// recordRenewal increments the metric counter under the renewal
// recorder. Holds the lock briefly to read the recorder pointer;
// the actual increment happens lock-free (atomic.Uint64 under
// VaultRenewalMetrics).
func (c *Connector) recordRenewal(result string) {
	c.renewMu.Lock()
	rec := c.renewRecorder
	c.renewMu.Unlock()
	if rec != nil {
		rec.RecordRenewal(result)
	}
}

// computeInterval returns TTL/2, floored at minRenewInterval to
// avoid degenerate fast cadence when a misconfigured Vault returns
// a tiny TTL.
func computeInterval(ttl time.Duration) time.Duration {
	half := ttl / 2
	if half < minRenewInterval {
		return minRenewInterval
	}
	return half
}

// differsEnough decides whether to restart the ticker for a new
// cadence. We tolerate ±10% drift to avoid restart-thrash when
// Vault's renewed-lease duration wobbles around the static TTL.
func differsEnough(a, b time.Duration) bool {
	if a == 0 || b == 0 {
		return a != b
	}
	delta := a - b
	if delta < 0 {
		delta = -delta
	}
	tol := a / 10
	if tol < 0 {
		tol = -tol
	}
	return delta > tol
}

// Compile-time assertion that *Connector satisfies the optional
// Lifecycle extension interface. If a future refactor breaks this
// (e.g. drops Stop), the compile error fires here rather than in a
// far-away registry lookup site.
var _ issuer.Lifecycle = (*Connector)(nil)
