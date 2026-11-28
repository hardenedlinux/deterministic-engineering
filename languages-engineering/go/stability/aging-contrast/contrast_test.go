// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package agingcontrast

import (
	"context"
	"runtime"
	"testing"
	"testing/synctest"
	"time"
)

// TestGoSynctestDeterministicQuiescence uses Go 1.25+ stdlib `testing/synctest`
// bubbles (virtual clock + deterministic scheduler + strict bubble-exit goroutine
// leak detection) to verify SM4/SM6 zero-drift cancellation quiescence in 0ms
// wall time across 100 simulated timeout/cancel cycles.
func TestGoSynctestDeterministicQuiescence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const normalBytes = 1024
		for i := 0; i < 100; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			if i%2 == 0 {
				cancel()
			} else {
				time.Sleep(10 * time.Millisecond) // virtual clock advance inside synctest bubble
			}
			_ = DeterministicChannelWorker(ctx, make([]byte, normalBytes))
			cancel()
		}
		synctest.Wait()
		// Returning from synctest.Test strictly asserts zero leaked goroutines inside the bubble.
	})
}

// TestGoBadBlockedChannelLeaksGoroutines provides a live negative control proving
// Tu et al. (ASPLOS 2019) unbuffered-channel goroutine leaks accumulate monotonically
// when contexts cancel before the worker sends.
func TestGoBadBlockedChannelLeaksGoroutines(t *testing.T) {
	const leakCount = 16
	runtime.GC()
	before := runtime.NumGoroutine()
	for i := 0; i < leakCount; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// Run in a loop until ctx.Done() wins the select race so we deterministically
		// observe leaked blocked workers.
		for BadBlockedChannelWorker(ctx, make([]byte, 64)) {
		}
	}
	// Yield briefly so leaked workers park on the unbuffered send.
	runtime.Gosched()
	after := runtime.NumGoroutine()
	if after < before+leakCount {
		t.Fatalf("expected BadBlockedChannelWorker to leak at least %d goroutines: before=%d after=%d", leakCount, before, after)
	}
}

func TestGoAgingContrastZeroDriftAndBoundedPool(t *testing.T) {
	const (
		normalBytes = 1024
		spikeBytes  = 65536
		slotCap     = 4
		queueCap    = 4
		retryBudget = 1
	)

	// 1. SM4 goroutine quiescence check under cancelled contexts:
	runtime.GC()
	beforeGood := runtime.NumGoroutine()
	for i := 0; i < 64; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = DeterministicChannelWorker(ctx, make([]byte, normalBytes))
	}
	runtime.GC()
	afterGood := runtime.NumGoroutine()
	if afterGood > beforeGood {
		t.Fatalf("deterministic worker leaked goroutines: before=%d after=%d", beforeGood, afterGood)
	}

	// 2. SM3 pool watermark contrast:
	badPool := &BadBufferPool{}
	goodPool := NewDeterministicBufferPool(slotCap, normalBytes)
	for c := 1; c <= 120; c++ {
		sz := normalBytes
		if c%15 == 0 {
			sz = spikeBytes
		}
		b1 := badPool.Acquire(sz)
		b2 := badPool.Acquire(normalBytes)
		badPool.Release(b1)
		badPool.Release(b2)

		g1 := goodPool.Acquire(sz)
		g2 := goodPool.Acquire(normalBytes)
		goodPool.Release(g1)
		goodPool.Release(g2)
	}
	if badPool.RetainedCapacityBytes() <= slotCap*normalBytes {
		t.Fatalf("expected bad pool to ratchet past ceiling, got %d", badPool.RetainedCapacityBytes())
	}
	if goodPool.RetainedCapacityBytes() > slotCap*normalBytes {
		t.Fatalf("deterministic pool exceeded ceiling: %d > %d", goodPool.RetainedCapacityBytes(), slotCap*normalBytes)
	}

	// 3. SM5 congestion shedding & retry budget recovery:
	ctrl := &DeterministicRetryController{QueueCap: queueCap, RetryBudget: retryBudget}
	for c := 1; c <= 60; c++ {
		ctrl.AdmitFresh()
		if c%5 == 0 {
			ctrl.Congested = true
			ctrl.AdmitFresh()
			for k := 0; k < 3; k++ {
				ctrl.OnTimeoutRetry()
			}
		}
		ctrl.Drain(queueCap)
	}
	if ctrl.QueueDepth != 0 || ctrl.RetriesPending != 0 || ctrl.Congested || ctrl.ShedCount == 0 {
		t.Fatalf("unexpected retry controller state: %+v", ctrl)
	}
}
