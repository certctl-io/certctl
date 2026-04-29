package handler

import "time"

// EST RFC 7030 hardening Phase 3.3 / 4.2: nowFn is the time source that
// the EST handler's per-IP failed-Basic-auth limiter and per-(CN,
// sourceIP) rate limiter consult. Tests can override this to inject a
// deterministic clock without dragging time.Time into the handler API
// surface (the handler's setters take ratelimit.SlidingWindowLimiter
// pointers, not time-injection callbacks — keeping the wire-up simple).
//
// nowFn is package-private + lower-case so external callers can't poke
// at it; the est_clock_test.go helper restoreNowFn is the documented
// override pattern for tests in this package.
var nowFn = time.Now
