package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
)

// MemoryDriver holds keys in process memory. It is intended for tests
// that need a Signer-shaped object without touching the filesystem
// or any external infrastructure. It is NOT for production use:
// keys disappear when the process exits, no hardening of any kind is
// applied, and concurrent Generate calls have no rate limit.
//
// The driver is safe for concurrent use; an internal mutex guards the
// keys map.
type MemoryDriver struct {
	mu   sync.Mutex
	keys map[string]crypto.Signer
	// nextID is incremented on every successful Generate; the returned
	// ref string is "mem-<nextID>" so multiple Generates produce
	// distinct refs even when callers don't supply one.
	nextID int
}

// NewMemoryDriver returns a freshly initialized MemoryDriver. Callers
// holding multiple drivers can rely on each one being independent —
// keys from driver A are not visible to driver B.
func NewMemoryDriver() *MemoryDriver {
	return &MemoryDriver{keys: map[string]crypto.Signer{}}
}

// Name implements Driver.
func (d *MemoryDriver) Name() string { return "memory" }

// Load implements Driver. Returns the Signer for the given ref, or an
// error if the ref was never produced by Generate / Adopt.
func (d *MemoryDriver) Load(ctx context.Context, ref string) (Signer, error) {
	if ref == "" {
		return nil, errors.New("signer.MemoryDriver.Load: empty ref")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key, ok := d.keys[ref]
	if !ok {
		return nil, fmt.Errorf("signer.MemoryDriver.Load: unknown ref %q", ref)
	}
	return Wrap(key)
}

// Generate implements Driver. Creates a fresh in-memory key with the
// requested algorithm and returns the wrapped Signer plus the ref
// string callers can pass to a subsequent Load.
func (d *MemoryDriver) Generate(ctx context.Context, alg Algorithm) (Signer, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("signer.MemoryDriver.Generate: %w", err)
	}

	var key crypto.Signer
	switch alg {
	case AlgorithmRSA2048, AlgorithmRSA3072, AlgorithmRSA4096:
		bits := rsaBitsFor(alg)
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, "", fmt.Errorf("signer.MemoryDriver.Generate: rsa keygen %d: %w", bits, err)
		}
		key = k
	case AlgorithmECDSAP256, AlgorithmECDSAP384:
		curve := ecCurveFor(alg)
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("signer.MemoryDriver.Generate: ecdsa keygen %s: %w", curve.Params().Name, err)
		}
		key = k
	default:
		return nil, "", fmt.Errorf("signer.MemoryDriver.Generate: %w: %s", ErrUnsupportedAlgorithm, alg)
	}

	d.mu.Lock()
	d.nextID++
	ref := fmt.Sprintf("mem-%d", d.nextID)
	d.keys[ref] = key
	d.mu.Unlock()

	wrapped, err := Wrap(key)
	if err != nil {
		return nil, "", fmt.Errorf("signer.MemoryDriver.Generate: wrap: %w", err)
	}
	return wrapped, ref, nil
}

// Adopt registers an externally-generated crypto.Signer under ref so
// subsequent Load calls return it. Returns an error if ref is already
// taken — keep refs unique to avoid silent override surprises.
//
// Useful in tests that want a deterministic key (generated outside
// the driver, e.g. from a fixed PEM fixture) reachable through the
// driver.
func (d *MemoryDriver) Adopt(ref string, key crypto.Signer) error {
	if ref == "" {
		return errors.New("signer.MemoryDriver.Adopt: empty ref")
	}
	if key == nil {
		return errors.New("signer.MemoryDriver.Adopt: nil key")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.keys[ref]; exists {
		return fmt.Errorf("signer.MemoryDriver.Adopt: ref %q already exists", ref)
	}
	d.keys[ref] = key
	return nil
}

// _ guards that MemoryDriver implements Driver (catch interface drift
// at build time, not test time).
var _ Driver = (*MemoryDriver)(nil)

// _ guards that FileDriver implements Driver.
var _ Driver = (*FileDriver)(nil)
