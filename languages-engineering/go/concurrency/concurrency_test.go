// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

package concurrency_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardenedlinux/deterministic-engineering/languages-engineering/go/concurrency"
)

// TestSnapshotStoreNonBlockingRCU verifies UiMainThreadRcuSnapshot.qnt:
// 120Hz readers never block while background StageAndPublish performs slow I/O.
func TestSnapshotStoreNonBlockingRCU(t *testing.T) {
	store := concurrency.NewSnapshotStore("v1")
	ioStarted := make(chan struct{})
	ioRelease := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := store.StageAndPublish(
			func(base string) (any, error) {
				close(ioStarted)
				<-ioRelease
				return base + "+staged", nil
			},
			func(_ string, staged any) string { return staged.(string) },
		)
		if err != nil {
			t.Errorf("StageAndPublish failed: %v", err)
		}
	}()

	<-ioStarted
	// Main thread reader MUST complete wait-free while slow I/O is blocked!
	t0 := time.Now()
	snap := store.Load()
	if dur := time.Since(t0); dur > 5*time.Millisecond {
		t.Fatalf("RCU Load blocked during off-lock staging: %v", dur)
	}
	if snap.Gen != 1 || snap.Value != "v1" {
		t.Fatalf("expected gen=1 v1 during staging, got %+v", snap)
	}

	close(ioRelease)
	wg.Wait()

	final := store.Load()
	if final.Gen != 2 || final.Value != "v1+staged" {
		t.Fatalf("expected gen=2 v1+staged after publish, got %+v", final)
	}
}

// TestFencedLaneCoalescingAndStaleSuppression replays FencedCoalescingMailbox.qnt:
// burst requests coalesce and stale completions are deterministically dropped.
func TestFencedLaneCoalescingAndStaleSuppression(t *testing.T) {
	started := make(chan int, 4)
	releaseFirst := make(chan struct{})
	var committed []int
	var mu sync.Mutex

	lane := concurrency.NewFencedLane[int, int](
		func(ctx context.Context, req int) (int, error) {
			started <- req
			if req == 1 {
				<-releaseFirst
			}
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return req * 10, nil
		},
		func(_ uint64, res int) {
			mu.Lock()
			committed = append(committed, res)
			mu.Unlock()
		},
	)
	defer lane.Close()

	lane.Submit(1)
	if r := <-started; r != 1 {
		t.Fatalf("expected worker req 1, got %d", r)
	}
	// Burst submit 2, 3, 4 while 1 is in flight -> coalesced to latest (4).
	lane.Submit(2)
	lane.Submit(3)
	ep4 := lane.Submit(4)
	close(releaseFirst)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if lane.AppliedEpoch() == ep4 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	lane.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(committed) != 1 || committed[0] != 40 {
		t.Fatalf("expected only latest epoch result [40], got %v (stale overwrite!)", committed)
	}
}

// TestPermitPoolBackpressureConservation replays BackpressureOwners.qnt:
// capacity bounds, queue bounds, and non-abortable cleanup permit retention.
func TestPermitPoolBackpressureConservation(t *testing.T) {
	pool := concurrency.NewPermitPool(2, 1)
	j0, err := pool.Admit()
	if err != nil {
		t.Fatalf("admit j0: %v", err)
	}
	// Queue limit = 1 -> second admit before start must be rejected.
	if _, err := pool.Admit(); !errors.Is(err, concurrency.ErrPoolOverloaded) {
		t.Fatalf("expected queue overload, got %v", err)
	}
	if !pool.Start(j0) {
		t.Fatalf("start j0 failed")
	}
	j1, err := pool.Admit()
	if err != nil {
		t.Fatalf("admit j1: %v", err)
	}
	if !pool.Start(j1) {
		t.Fatalf("start j1 failed")
	}
	// Cancel j0 -> enters Cleanup and MUST retain permit until Drain.
	if !pool.BeginCancelCleanup(j0) {
		t.Fatalf("begin cancel cleanup j0 failed")
	}
	if _, err := pool.Admit(); !errors.Is(err, concurrency.ErrPoolOverloaded) {
		t.Fatalf("expected permit retained during cleanup (over-admit violation), got %v", err)
	}
	if !pool.Drain(j0) {
		t.Fatalf("drain cleanup j0 failed")
	}
	if !pool.Complete(j1) || !pool.Drain(j1) {
		t.Fatalf("complete & drain j1 failed")
	}
	if adm, q := pool.Stats(); adm != 0 || q != 0 {
		t.Fatalf("expected quiescence (0, 0), got (%d, %d)", adm, q)
	}
}

// TestStructuredScopeQuiescence replays StructuredCancellation.qnt.
func TestStructuredScopeQuiescence(t *testing.T) {
	scope := concurrency.NewStructuredScope(context.Background())
	var drained atomic.Bool
	if !scope.Go(func(ctx context.Context) {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		drained.Store(true)
	}) {
		t.Fatalf("spawn failed")
	}
	scope.CloseAndDrain()
	if !drained.Load() || scope.ActiveChildren() != 0 {
		t.Fatalf("parent exited before child drained (orphan effect!)")
	}
	if scope.Go(func(context.Context) {}) {
		t.Fatalf("spawn after CloseAndDrain must be rejected")
	}
}

// TestWebViewLifecycleAndFramePacer replays HybridWebViewFocusLifecycle.qnt.
func TestWebViewLifecycleAndFramePacer(t *testing.T) {
	tier2 := concurrency.NewWebViewLifecycle(concurrency.TrustTier2Untrusted)
	if !tier2.RequestAsyncMount() || !tier2.MarkReady() || !tier2.Focus() {
		t.Fatalf("unexpected tier2 lifecycle failure")
	}
	if err := tier2.CheckHostRPC(); !errors.Is(err, concurrency.ErrUntrustedRPCForbidden) {
		t.Fatalf("expected Tier-2 RPC denied, got %v", err)
	}
	tier2.HideTab()
	if _, shown, focused, _ := tier2.Snapshot(); shown || focused {
		t.Fatalf("hidden WebView must revoke focus: shown=%v focused=%v", shown, focused)
	}

	tier0 := concurrency.NewWebViewLifecycle(concurrency.TrustTier0FirstParty)
	_ = tier0.RequestAsyncMount()
	_ = tier0.MarkReady()
	if err := tier0.CheckHostRPC(); err != nil {
		t.Fatalf("expected Tier-0 RPC permitted, got %v", err)
	}
	tier0.MarkCrashed()
	if !tier0.Recover() || !tier0.MarkReady() {
		t.Fatalf("expected crash recovery transition")
	}

	var triggers atomic.Int32
	pacer := concurrency.NewFramePacer(func() { triggers.Add(1) }, 8*time.Millisecond)
	pacer.RequestFrame()
	pacer.RequestFrame()
	pacer.RequestFrame()
	if triggers.Load() != 1 {
		t.Fatalf("expected 3 bursts coalesced to 1 trigger, got %d", triggers.Load())
	}
	pacer.SetWindowFocused(false)
	pacer.SetLiveClockVisible(true)
	if pacer.ShouldTickIdle() {
		t.Fatalf("expected unfocused window to gate idle ticks")
	}
}
