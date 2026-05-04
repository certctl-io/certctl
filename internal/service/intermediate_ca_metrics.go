package service

import (
	"sort"
	"sync"
	"sync/atomic"
)

// IntermediateCAMetrics is a thread-safe counter table for the CA-
// hierarchy management surface (Rank 8). Mirrors the
// ApprovalMetrics + ExpiryAlertMetrics shape: cmd/server/main.go
// constructs ONE instance, passes it to IntermediateCAService
// (recording side) AND metricsHandler (exposing side) so the
// snapshotter is the single source of truth.
//
// Dimensions:
//
//	issuer_id — owning issuer (bounded cardinality; operators have
//	            <100 issuers in production).
//	kind      — closed enum:
//	              "create_root"  — CreateRoot succeeded.
//	              "create_child" — CreateChild succeeded.
//	              "retire_<state>" — Retire transitioned state.
type IntermediateCAMetrics struct {
	mu       sync.RWMutex
	counters map[intermediateCAKey]*atomic.Uint64
}

type intermediateCAKey struct {
	IssuerID string
	Kind     string
}

// NewIntermediateCAMetrics returns a zero-value instance ready for
// concurrent use.
func NewIntermediateCAMetrics() *IntermediateCAMetrics {
	return &IntermediateCAMetrics{
		counters: make(map[intermediateCAKey]*atomic.Uint64),
	}
}

// RecordCreate bumps the create-counter. role ∈ {"root", "child"}.
func (m *IntermediateCAMetrics) RecordCreate(issuerID, role string) {
	m.bump(issuerID, "create_"+role)
}

// RecordRetire bumps the retire-counter. newState ∈
// {"retiring", "retired"}.
func (m *IntermediateCAMetrics) RecordRetire(issuerID, newState string) {
	m.bump(issuerID, "retire_"+newState)
}

func (m *IntermediateCAMetrics) bump(issuerID, kind string) {
	if m == nil {
		return
	}
	key := intermediateCAKey{IssuerID: issuerID, Kind: kind}
	m.mu.RLock()
	c, ok := m.counters[key]
	m.mu.RUnlock()
	if !ok {
		m.mu.Lock()
		c, ok = m.counters[key]
		if !ok {
			c = &atomic.Uint64{}
			m.counters[key] = c
		}
		m.mu.Unlock()
	}
	c.Add(1)
}

// IntermediateCAEntry is a single row of the SnapshotIntermediateCA
// output.
type IntermediateCAEntry struct {
	IssuerID string
	Kind     string
	Count    uint64
}

// SnapshotIntermediateCA returns the current counter table sorted by
// (issuer_id, kind) for deterministic Prometheus exposition.
func (m *IntermediateCAMetrics) SnapshotIntermediateCA() []IntermediateCAEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	out := make([]IntermediateCAEntry, 0, len(m.counters))
	for k, c := range m.counters {
		out = append(out, IntermediateCAEntry{
			IssuerID: k.IssuerID,
			Kind:     k.Kind,
			Count:    c.Load(),
		})
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuerID != out[j].IssuerID {
			return out[i].IssuerID < out[j].IssuerID
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
