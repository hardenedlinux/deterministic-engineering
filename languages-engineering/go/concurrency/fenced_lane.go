// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

package concurrency

import (
	"context"
	"sync"
	"sync/atomic"
)

// FencedLane refines engineering.concurrency.fenced-coalescing-mailbox and
// engineering.concurrency.lease-fencing-token:
//   - Single-slot latest-wins coalescing prevents mailbox floods under bursts.
//   - Every Submit advances a monotonic epoch and cancels stale in-flight work.
//   - Completions carrying epoch < activeEpoch are deterministically dropped
//     and can never overwrite newer committed UI state.
type FencedLane[Req, Res any] struct {
	mu           sync.Mutex
	activeEpoch  atomic.Uint64
	appliedEpoch atomic.Uint64
	hasPending   bool
	pendingReq   Req
	pendingEpoch uint64
	running      bool
	cancelRun    context.CancelFunc
	closed       bool
	drained      chan struct{}
	worker       func(ctx context.Context, req Req) (Res, error)
	onCommit     func(epoch uint64, res Res)
}

// NewFencedLane constructs a bounded, generation-fenced coalescing async lane.
func NewFencedLane[Req, Res any](
	worker func(ctx context.Context, req Req) (Res, error),
	onCommit func(epoch uint64, res Res),
) *FencedLane[Req, Res] {
	return &FencedLane[Req, Res]{
		worker:   worker,
		onCommit: onCommit,
	}
}

// Submit enqueues req under a fresh monotonic epoch, coalescing any queued
// request (latest-wins) and cancelling stale in-flight work. Returns the new
// epoch (0 if the lane is already closed).
func (l *FencedLane[Req, Res]) Submit(req Req) uint64 {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return 0
	}
	ep := l.activeEpoch.Add(1)
	l.pendingReq = req
	l.pendingEpoch = ep
	l.hasPending = true
	if l.cancelRun != nil {
		l.cancelRun()
	}
	if !l.running {
		l.running = true
		l.drained = make(chan struct{})
		go l.runLoop()
	}
	l.mu.Unlock()
	return ep
}

// AdvanceEpoch bumps the active epoch directly (e.g. on an immediate synchronous
// user Tab click or preset change) so any in-flight older async completion is
// fenced out and dropped.
func (l *FencedLane[Req, Res]) AdvanceEpoch() uint64 {
	l.mu.Lock()
	ep := l.activeEpoch.Add(1)
	l.appliedEpoch.Store(ep)
	if l.cancelRun != nil {
		l.cancelRun()
	}
	l.mu.Unlock()
	return ep
}

// ActiveEpoch returns the highest issued epoch.
func (l *FencedLane[Req, Res]) ActiveEpoch() uint64 { return l.activeEpoch.Load() }

// AppliedEpoch returns the highest epoch committed via onCommit or AdvanceEpoch.
func (l *FencedLane[Req, Res]) AppliedEpoch() uint64 { return l.appliedEpoch.Load() }

// Close cancels in-flight work, rejects future Submit calls, and waits until
// the worker goroutine drains cleanly (quiescence barrier).
func (l *FencedLane[Req, Res]) Close() {
	l.mu.Lock()
	if l.closed {
		ch := l.drained
		l.mu.Unlock()
		if ch != nil {
			<-ch
		}
		return
	}
	l.closed = true
	l.hasPending = false
	if l.cancelRun != nil {
		l.cancelRun()
	}
	ch := l.drained
	l.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (l *FencedLane[Req, Res]) runLoop() {
	for {
		l.mu.Lock()
		if l.closed || !l.hasPending {
			l.running = false
			l.cancelRun = nil
			ch := l.drained
			l.mu.Unlock()
			if ch != nil {
				close(ch)
			}
			return
		}
		req := l.pendingReq
		ep := l.pendingEpoch
		l.hasPending = false
		ctx, cancel := context.WithCancel(context.Background())
		l.cancelRun = cancel
		l.mu.Unlock()

		res, err := l.worker(ctx, req)
		cancel()

		if err != nil {
			continue
		}
		// Monotonic epoch fence: commit only if no newer epoch superseded ep.
		l.mu.Lock()
		if !l.closed && ep == l.activeEpoch.Load() && ep >= l.appliedEpoch.Load() {
			l.appliedEpoch.Store(ep)
			cb := l.onCommit
			l.mu.Unlock()
			if cb != nil {
				cb(ep, res)
			}
			continue
		}
		l.mu.Unlock()
	}
}
