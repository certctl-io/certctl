//go:build integration

// Package test contains the deploy-hardening I Phase 11 cross-
// cutting end-to-end integration tests. These exercise the
// internal/deploy package's load-bearing invariants end-to-end:
//
//   - atomicity: kill mid-deploy → file is fully old or fully new;
//     never torn.
//   - post-verify: deploy a wrong-fingerprint cert + the connector's
//     verify hook → the rollback wire restores the previous bytes.
//   - idempotency: deploy the same bytes twice → the second attempt
//     is a no-op (no PreCommit/PostCommit calls).
//   - concurrency: N simultaneous deploys to the same destination
//     serialize via the deploy package's file-level mutex.
//
// Run via `INTEGRATION=1 go test -tags integration -race ./deploy/test/... -run Deploy`.
package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/deploy"
)

// TestDeploy_Atomicity_FileIsAlwaysOldOrNew pins the load-bearing
// POSIX-rename atomicity invariant. A reader hammering the
// destination during 30 alternating writes either sees the OLD
// bytes or the NEW bytes — never an intermediate state. Closes
// the operator-facing question "is my cert deploy interruption-
// safe?".
func TestDeploy_Atomicity_FileIsAlwaysOldOrNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	old := []byte(strings.Repeat("OLD-CERT-PEM-", 200))
	newer := []byte(strings.Repeat("NEW-CERT-PEM-", 200))
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var torn atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			s := string(b)
			if s != string(old) && s != string(newer) {
				torn.Store(true)
				return
			}
		}
	}()

	for i := 0; i < 30; i++ {
		writeBytes := old
		if i%2 == 0 {
			writeBytes = newer
		}
		if _, err := deploy.AtomicWriteFile(context.Background(), path, writeBytes, deploy.WriteOptions{
			SkipIdempotent: true,
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if torn.Load() {
		t.Error("torn read observed (rename atomicity broken)")
	}
}

// TestDeploy_PostVerify_WrongCertTriggersRollback simulates a
// mis-deployed cert: the deploy.Apply succeeds at the file-write
// + reload level, but the connector's post-deploy verify (run
// AFTER Apply returns) detects the SHA-256 mismatch and rolls
// back manually using the BackupPaths that Apply returned. The
// final on-disk state matches the OLD bytes; the rollback wire
// works end-to-end.
func TestDeploy_PostVerify_WrongCertTriggersRollback(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("OLD-CERT"), 0644); err != nil {
		t.Fatal(err)
	}

	plan := deploy.Plan{
		Files: []deploy.File{{Path: cert, Bytes: []byte("WRONG-CERT")}},
		PostCommit: func(_ context.Context) error {
			// Reload would normally verify the cert via the post-deploy
			// TLS handshake. Here we simulate the verify failure by
			// returning an error from PostCommit (which triggers the
			// deploy package's automatic rollback).
			//
			// On the first call (the real deploy), return an error so
			// the rollback fires; on the second call (the rollback's
			// re-PostCommit against the restored bytes), succeed so
			// rollback completes cleanly.
			return errors.New("post-deploy verify: SHA-256 mismatch")
		},
	}

	// First call to PostCommit fails; the rollback's second call
	// would also fail with the same handler — so we use a stateful
	// counter.
	var postCalls int32
	plan.PostCommit = func(_ context.Context) error {
		if atomic.AddInt32(&postCalls, 1) == 1 {
			return errors.New("post-deploy verify: SHA-256 mismatch")
		}
		return nil
	}

	_, err := deploy.Apply(context.Background(), plan)
	if !errors.Is(err, deploy.ErrReloadFailed) {
		t.Fatalf("got %v, want ErrReloadFailed", err)
	}
	got, _ := os.ReadFile(cert)
	if string(got) != "OLD-CERT" {
		t.Errorf("cert after rollback = %q, want OLD-CERT", got)
	}
	if atomic.LoadInt32(&postCalls) != 2 {
		t.Errorf("PostCommit calls = %d, want 2 (1 deploy + 1 rollback re-call)", postCalls)
	}
}

// TestDeploy_Idempotency_SecondDeployIsNoOp pins the SHA-256
// short-circuit. Defends against agent-restart retry storms that
// otherwise hammer targets with no-op reloads.
func TestDeploy_Idempotency_SecondDeployIsNoOp(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	bytes := []byte("STABLE-CERT-PEM")
	if err := os.WriteFile(cert, bytes, 0644); err != nil {
		t.Fatal(err)
	}

	var preCalls, postCalls int32
	plan := deploy.Plan{
		Files: []deploy.File{{Path: cert, Bytes: bytes}},
		PreCommit: func(_ context.Context, _ map[string]string) error {
			atomic.AddInt32(&preCalls, 1)
			return nil
		},
		PostCommit: func(_ context.Context) error {
			atomic.AddInt32(&postCalls, 1)
			return nil
		},
	}
	res, err := deploy.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !res.SkippedAsIdempotent {
		t.Error("expected SkippedAsIdempotent=true")
	}
	if preCalls != 0 || postCalls != 0 {
		t.Errorf("expected 0 calls, got %d/%d", preCalls, postCalls)
	}
}

// TestDeploy_Concurrent_SamePathsSerialize fires N simultaneous
// deploys to the same destination. The deploy package's file-
// level mutex must serialize them: max-in-flight = 1.
func TestDeploy_Concurrent_SamePathsSerialize(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")

	const N = 8
	var inFlight, maxInFlight int32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			plan := deploy.Plan{
				Files: []deploy.File{{
					Path:  cert,
					Bytes: []byte(fmt.Sprintf("WRITER-%d", idx)),
				}},
				SkipIdempotent: true,
				PostCommit: func(_ context.Context) error {
					n := atomic.AddInt32(&inFlight, 1)
					for {
						m := atomic.LoadInt32(&maxInFlight)
						if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
							break
						}
					}
					time.Sleep(2 * time.Millisecond)
					atomic.AddInt32(&inFlight, -1)
					return nil
				},
			}
			if _, err := deploy.Apply(context.Background(), plan); err != nil {
				t.Errorf("Apply %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
	if maxInFlight > 1 {
		t.Errorf("max in-flight = %d, want 1 (mutex broken)", maxInFlight)
	}
	got, _ := os.ReadFile(cert)
	if !strings.HasPrefix(string(got), "WRITER-") {
		t.Errorf("file content not from any writer: %q", got)
	}
}
