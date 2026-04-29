package handler

import (
	"math/big"
	"time"
)

// Shared test helpers for the EST serverkeygen handler tests. Lives in
// its own file so future test additions can reach the same constants
// without copy-pasting.

func bigOne() *big.Int { return big.NewInt(1) }

var (
	serverKeygenTestNotBefore = mustParseTestTime("2020-01-01T00:00:00Z")
	serverKeygenTestNotAfter  = mustParseTestTime("2099-12-31T23:59:59Z")
)

func mustParseTestTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
