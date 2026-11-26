// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

package concurrency

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// FramePacer refines demand-driven invalidation coalescing and 120Hz frame
// budget telemetry (8.33ms budget per frame), preventing idle GPU wakeups on
// macOS transparent windows when unfocused or displaying static buffers.
type FramePacer struct {
	pending    atomic.Bool
	focused    atomic.Bool
	clockLive  atomic.Bool
	triggerFn  func()
	slowCount  atomic.Uint64
	frameCount atomic.Uint64
	maxNanos   atomic.Int64
	budget     time.Duration
}

// NewFramePacer creates a FramePacer targeting a 120Hz frame budget (8.33ms default).
func NewFramePacer(trigger func(), budget time.Duration) *FramePacer {
	if budget <= 0 {
		budget = 8333 * time.Microsecond
	}
	p := &FramePacer{triggerFn: trigger, budget: budget}
	p.focused.Store(true)
	return p
}

// RequestFrame coalesces multiple concurrent invalidation requests into a
// single pending trigger until MarkFrameStart consumes it.
func (p *FramePacer) RequestFrame() bool {
	if !p.pending.CompareAndSwap(false, true) {
		return false
	}
	if p.triggerFn != nil {
		p.triggerFn()
	}
	return true
}

// MarkFrameStart clears the coalesced pending flag when rendering begins.
func (p *FramePacer) MarkFrameStart() time.Time {
	p.pending.Store(false)
	return time.Now()
}

// RecordFrame records a completed frame duration and increments the slow-frame
// counter whenever dur exceeds the 120Hz budget.
func (p *FramePacer) RecordFrame(dur time.Duration) {
	p.frameCount.Add(1)
	ns := dur.Nanoseconds()
	for {
		cur := p.maxNanos.Load()
		if ns <= cur || p.maxNanos.CompareAndSwap(cur, ns) {
			break
		}
	}
	if dur > p.budget {
		p.slowCount.Add(1)
	}
}

// SetWindowFocused records OS window activation state for idle GPU power gating.
func (p *FramePacer) SetWindowFocused(focused bool) { p.focused.Store(focused) }

// SetLiveClockVisible records whether a live-ticking surface (e.g. Dashboard
// clock or active motion) is currently visible.
func (p *FramePacer) SetLiveClockVisible(visible bool) { p.clockLive.Store(visible) }

// ShouldTickIdle reports whether a background 1Hz clock tick should trigger a
// redraw (false when unfocused or viewing static buffers, saving 6-8x GPU power).
func (p *FramePacer) ShouldTickIdle() bool {
	return p.focused.Load() && p.clockLive.Load()
}

// Telemetry returns (frames, slowFrames, maxFrameDuration).
func (p *FramePacer) Telemetry() (uint64, uint64, time.Duration) {
	return p.frameCount.Load(), p.slowCount.Load(), time.Duration(p.maxNanos.Load())
}

// WebViewState represents the formal lifecycle states in
// HybridWebViewFocusLifecycle.qnt.
type WebViewState uint8

const (
	WebViewUnmounted WebViewState = iota
	WebViewWarmingAsync
	WebViewReady
	WebViewCrashed
)

// TrustTier classifies hybrid WebView capabilities.
type TrustTier uint8

const (
	TrustTier0FirstParty TrustTier = 0
	TrustTier2Untrusted  TrustTier = 2
)

// ErrUntrustedRPCForbidden is returned when a Tier-2 untrusted island attempts
// to invoke a Tier-0 host RPC capability.
var ErrUntrustedRPCForbidden = errors.New("concurrency: untrusted Tier-2 WebView island cannot invoke Tier-0 RPC")

// WebViewLifecycle refines engineering.concurrency.hybrid-webview-focus-lifecycle.
type WebViewLifecycle struct {
	mu      sync.Mutex
	state   WebViewState
	shown   bool
	focused bool
	tier    TrustTier
}

// NewWebViewLifecycle initializes an unmounted WebView lifecycle for tier.
func NewWebViewLifecycle(tier TrustTier) *WebViewLifecycle {
	return &WebViewLifecycle{state: WebViewUnmounted, tier: tier}
}

// RequestAsyncMount transitions Unmounted -> WarmingAsync without blocking render.
func (w *WebViewLifecycle) RequestAsyncMount() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != WebViewUnmounted {
		return false
	}
	w.state = WebViewWarmingAsync
	w.shown = true
	return true
}

// MarkReady transitions WarmingAsync -> Ready.
func (w *WebViewLifecycle) MarkReady() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != WebViewWarmingAsync {
		return false
	}
	w.state = WebViewReady
	return true
}

// Focus grants focus only when Ready and Shown.
func (w *WebViewLifecycle) Focus() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != WebViewReady || !w.shown {
		return false
	}
	w.focused = true
	return true
}

// HideTab hides the WebView and atomically revokes its keyboard focus back to
// the native GPU frame (preserving invariant: !shown => !focused).
func (w *WebViewLifecycle) HideTab() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.shown = false
	w.focused = false
}

// ShowTab reveals a Ready WebView tab.
func (w *WebViewLifecycle) ShowTab() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != WebViewReady {
		return false
	}
	w.shown = true
	return true
}

// MarkCrashed transitions Ready -> Crashed and revokes focus.
func (w *WebViewLifecycle) MarkCrashed() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == WebViewReady {
		w.state = WebViewCrashed
		w.focused = false
	}
}

// Recover transitions Crashed -> WarmingAsync.
func (w *WebViewLifecycle) Recover() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != WebViewCrashed {
		return false
	}
	w.state = WebViewWarmingAsync
	return true
}

// CheckHostRPC enforces the Tier-0 capability gate.
func (w *WebViewLifecycle) CheckHostRPC() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tier != TrustTier0FirstParty {
		return ErrUntrustedRPCForbidden
	}
	if w.state != WebViewReady {
		return errors.New("concurrency: webview not ready")
	}
	return nil
}

// Snapshot returns (state, shown, focused, tier) for invariant inspection.
func (w *WebViewLifecycle) Snapshot() (WebViewState, bool, bool, TrustTier) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state, w.shown, w.focused, w.tier
}
