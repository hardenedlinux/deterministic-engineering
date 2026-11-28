// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Rust cross-language projection of SM2/SM3/SM4/SM5/SM6 Software Aging mechanisms:
//! 1. Early `?` error / cancel return leaking manual handles vs. RAII HandleGuard zero-drift.
//! 2. `Vec<u8>::clear()` retaining peak spike `capacity()` forever in a pool vs. `max_retain_cap`.
//! 3. Unbounded retry amplification vs. congestion-aware load shedding + retry budget.

use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Err,
    Cancel,
}

// ── 1. Handle Conservation (SM2 / SM4) ──

#[derive(Default)]
struct HandleCounter {
    active: Cell<usize>,
    held: Cell<usize>,
}

fn bad_handle_cycle(c: &HandleCounter, outcome: Outcome) -> Result<(), &'static str> {
    c.active.set(c.active.get() + 1);
    c.held.set(c.held.get() + 1);
    if outcome == Outcome::Err {
        c.active.set(c.active.get() - 1);
        return Err("early-error-skips-release");
    }
    if outcome == Outcome::Cancel {
        c.active.set(c.active.get() - 1);
        return Ok(());
    }
    c.held.set(c.held.get() - 1);
    c.active.set(c.active.get() - 1);
    Ok(())
}

struct HandleGuard<'a>(&'a HandleCounter);

impl<'a> HandleGuard<'a> {
    fn acquire(c: &'a HandleCounter) -> Self {
        c.active.set(c.active.get() + 1);
        c.held.set(c.held.get() + 1);
        Self(c)
    }
}

impl Drop for HandleGuard<'_> {
    fn drop(&mut self) {
        self.0.held.set(self.0.held.get() - 1);
        self.0.active.set(self.0.active.get() - 1);
    }
}

fn deterministic_handle_cycle(c: &HandleCounter, outcome: Outcome) -> Result<(), &'static str> {
    let _guard = HandleGuard::acquire(c);
    match outcome {
        Outcome::Err => Err("error-still-drops-guard"),
        Outcome::Cancel | Outcome::Ok => Ok(()),
    }
}

// ── 2. Vec::clear() Watermark Ratchet vs. Capped Buffer Pool (SM3) ──

#[derive(Default)]
struct BadBufferPool {
    pool: Vec<Vec<u8>>,
}

impl BadBufferPool {
    fn acquire(&mut self, len: usize) -> Vec<u8> {
        let mut buf = match self.pool.pop() {
            Some(existing) => existing,
            None => Vec::new(),
        };
        buf.resize(len, 0);
        buf
    }

    fn release(&mut self, mut buf: Vec<u8>) {
        // SM3 ARB: Vec::clear() sets len=0 but keeps peak spike capacity() forever!
        buf.clear();
        self.pool.push(buf);
    }

    fn retained_capacity_bytes(&self) -> usize {
        self.pool.iter().map(Vec::capacity).sum()
    }
}

struct DeterministicBufferPool {
    slot_cap: usize,
    max_retain_cap: usize,
    pool: Vec<Vec<u8>>,
}

impl DeterministicBufferPool {
    fn new(slot_cap: usize, max_retain_cap: usize) -> Self {
        Self {
            slot_cap,
            max_retain_cap,
            pool: Vec::with_capacity(slot_cap),
        }
    }

    fn acquire(&mut self, len: usize) -> Vec<u8> {
        if len <= self.max_retain_cap {
            if let Some(mut buf) = self.pool.pop() {
                buf.resize(len, 0);
                return buf;
            }
        }
        let mut fresh = Vec::with_capacity(len);
        fresh.resize(len, 0);
        fresh
    }

    fn release(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if buf.capacity() > self.max_retain_cap || self.pool.len() >= self.slot_cap {
            drop(buf);
            return;
        }
        self.pool.push(buf);
    }

    fn retained_capacity_bytes(&self) -> usize {
        self.pool.iter().map(Vec::capacity).sum()
    }
}

// ── 3. Metastable Retry Amplification vs. Congestion Shedding + Retry Budget (SM5) ──

#[derive(Default)]
struct BadRetryCtrl {
    congested: bool,
    queue_depth: usize,
    retries_pending: usize,
}

impl BadRetryCtrl {
    fn admit_fresh(&mut self) {
        self.queue_depth += 1;
    }
    fn on_timeout_retry(&mut self) {
        if self.congested && self.queue_depth > 0 {
            self.queue_depth += 1;
            self.retries_pending += 1;
        }
    }
    fn drain(&mut self, mut budget: usize) {
        while budget > 0 && self.queue_depth > 0 {
            self.queue_depth -= 1;
            self.retries_pending = self.retries_pending.saturating_sub(1);
            budget -= 1;
        }
        if self.queue_depth == 0 {
            self.congested = false;
        }
    }
}

struct DeterministicRetryCtrl {
    queue_cap: usize,
    retry_budget: usize,
    congested: bool,
    queue_depth: usize,
    retries_pending: usize,
    shed_count: usize,
}

impl DeterministicRetryCtrl {
    fn new(queue_cap: usize, retry_budget: usize) -> Self {
        Self {
            queue_cap,
            retry_budget,
            congested: false,
            queue_depth: 0,
            retries_pending: 0,
            shed_count: 0,
        }
    }

    fn admit_fresh(&mut self) -> bool {
        if self.congested || self.queue_depth >= self.queue_cap {
            self.shed_count += 1;
            return false;
        }
        self.queue_depth += 1;
        true
    }

    fn on_timeout_retry(&mut self) -> bool {
        if !self.congested || self.queue_depth == 0 {
            return false;
        }
        if self.retries_pending >= self.retry_budget || self.queue_depth >= self.queue_cap {
            self.shed_count += 1;
            return false;
        }
        self.queue_depth += 1;
        self.retries_pending += 1;
        true
    }

    fn drain(&mut self, mut budget: usize) {
        while budget > 0 && self.queue_depth > 0 {
            self.queue_depth -= 1;
            self.retries_pending = self.retries_pending.saturating_sub(1);
            budget -= 1;
        }
        if self.queue_depth == 0 {
            self.congested = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_aging_contrast_zero_drift_and_bounded_watermark() {
        const NORMAL: usize = 1024;
        const SPIKE: usize = 65536;
        const SLOT_CAP: usize = 4;
        const QUEUE_CAP: usize = 4;
        const RETRY_BUDGET: usize = 1;

        let bad_h = HandleCounter::default();
        let good_h = HandleCounter::default();
        let mut bad_p = BadBufferPool::default();
        let mut good_p = DeterministicBufferPool::new(SLOT_CAP, NORMAL);
        let mut bad_r = BadRetryCtrl::default();
        let mut good_r = DeterministicRetryCtrl::new(QUEUE_CAP, RETRY_BUDGET);

        for c in 1..=120usize {
            let outcome = if c % 7 == 0 {
                Outcome::Err
            } else if c % 11 == 0 {
                Outcome::Cancel
            } else {
                Outcome::Ok
            };
            let _ = bad_handle_cycle(&bad_h, outcome);
            let _ = deterministic_handle_cycle(&good_h, outcome);

            let sz = if c % 15 == 0 { SPIKE } else { NORMAL };
            let b1 = bad_p.acquire(sz);
            let b2 = bad_p.acquire(NORMAL);
            bad_p.release(b1);
            bad_p.release(b2);

            let g1 = good_p.acquire(sz);
            let g2 = good_p.acquire(NORMAL);
            good_p.release(g1);
            good_p.release(g2);

            bad_r.admit_fresh();
            good_r.admit_fresh();
            if c % 5 == 0 {
                bad_r.congested = true;
                good_r.congested = true;
                bad_r.admit_fresh();
                good_r.admit_fresh();
                for _ in 0..3 {
                    bad_r.on_timeout_retry();
                    good_r.on_timeout_retry();
                }
            }
            bad_r.drain(QUEUE_CAP);
            good_r.drain(QUEUE_CAP);
        }

        // Bad Rust aging implementation exhibits handle drift, Vec::capacity() ratchet, and retry backlog:
        assert!(bad_h.held.get() > 0);
        assert!(bad_p.retained_capacity_bytes() > SLOT_CAP * NORMAL);
        assert!(bad_r.queue_depth > 0);

        // Deterministic Rust boundary preserves zero handle drift, strict capacity ceiling, and full recovery:
        assert_eq!(good_h.active.get(), 0);
        assert_eq!(good_h.held.get(), 0);
        assert!(good_p.pool.len() <= SLOT_CAP);
        assert!(good_p.retained_capacity_bytes() <= SLOT_CAP * NORMAL);
        assert_eq!(good_r.queue_depth, 0);
        assert_eq!(good_r.retries_pending, 0);
        assert!(!good_r.congested);
        assert!(good_r.shed_count > 0);
    }

    // ── 4. Slow-Consumer Fan-Out Isolation & Independent OLS Slope Check (SM4b / SM5b / SM6) ──

    fn ols_slope(xs: &[f64], ys: &[f64]) -> f64 {
        let n = xs.len().min(ys.len());
        if n < 2 {
            return 0.0;
        }
        let mx = xs[..n].iter().sum::<f64>() / n as f64;
        let my = ys[..n].iter().sum::<f64>() / n as f64;
        let mut num = 0.0;
        let mut den = 0.0;
        for i in 0..n {
            let dx = xs[i] - mx;
            num += dx * (ys[i] - my);
            den += dx * dx;
        }
        if den == 0.0 { 0.0 } else { num / den }
    }

    #[test]
    fn rust_slow_consumer_eviction_and_slope_oracle() {
        const PER_SUB_CAP: usize = 4;
        const FRAME_BYTES: usize = 512;

        // Bad unbounded fan-out retains frames forever for a stalled subscriber:
        let mut bad_slow_queue: Vec<Vec<u8>> = Vec::new();
        // Deterministic fan-out caps per-subscriber queue and evicts + drains on lag:
        let mut good_slow_connected = true;
        let mut good_slow_queue: Vec<Vec<u8>> = Vec::with_capacity(PER_SUB_CAP);
        let mut good_fast_delivered: usize = 0;

        let mut xs = Vec::new();
        let mut bad_ys = Vec::new();
        let mut good_ys = Vec::new();

        for cycle in 1..=100usize {
            let frame = vec![0u8; FRAME_BYTES];
            bad_slow_queue.push(frame.clone());

            good_fast_delivered += 1;
            if good_slow_connected {
                if good_slow_queue.len() >= PER_SUB_CAP {
                    good_slow_connected = false;
                    good_slow_queue.clear();
                    good_slow_queue.shrink_to_fit();
                } else {
                    good_slow_queue.push(frame);
                }
            }

            if cycle % 10 == 0 {
                xs.push(cycle as f64);
                bad_ys.push((bad_slow_queue.len() * FRAME_BYTES) as f64);
                good_ys.push((good_slow_queue.len() * FRAME_BYTES) as f64);
            }
        }

        assert!(ols_slope(&xs, &bad_ys) > 400.0);
        assert!(!good_slow_connected);
        assert_eq!(good_slow_queue.len(), 0);
        assert_eq!(good_slow_queue.capacity(), 0);
        assert_eq!(good_fast_delivered, 100);
        assert!(ols_slope(&xs, &good_ys) <= 0.0);
    }

    // ── 5. Marlin ui_grpc / marlin_mygo_host Bounded Projection Eviction & Broadcast Lag Resync (SM3c / SM5c) ──

    #[test]
    fn rust_marlin_bridge_eviction_and_lag_resync_soak() {
        use std::collections::{BTreeMap, VecDeque};

        const SESSION_CAP: usize = 16;
        const ARTIFACT_CAP: usize = 8;
        const RING_LAG_CAP: u64 = 4;

        // Bad Marlin pattern: hard 16-session cap without eviction + unbounded artifacts BTreeMap + silent lag disconnect.
        let mut bad_sessions: BTreeMap<usize, bool> = BTreeMap::new();
        let mut bad_artifacts: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        let mut bad_lockouts = 0usize;
        let mut bad_stream_alive = true;
        let bad_client_gen = 0u64;

        // Deterministic Marlin pattern: idle LRU session eviction + FIFO-capped artifacts + generation-fenced lag resync.
        let mut good_sessions: BTreeMap<usize, bool> = BTreeMap::new();
        let mut good_side_meta: BTreeMap<usize, usize> = BTreeMap::new();
        let mut good_artifacts: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        let mut good_artifact_order: VecDeque<usize> = VecDeque::with_capacity(ARTIFACT_CAP);
        let mut good_lockouts = 0usize;
        let mut good_evictions = 0usize;
        let mut good_resyncs = 0usize;
        let mut good_client_gen = 0u64;

        let mut xs = Vec::new();
        let mut bad_bytes_series = Vec::new();
        let mut good_bytes_series = Vec::new();

        for cycle in 1..=64usize {
            // Session open/close churn
            if bad_sessions.len() >= SESSION_CAP {
                bad_lockouts += 1;
            } else {
                bad_sessions.insert(cycle, false);
            }
            if good_sessions.len() >= SESSION_CAP {
                if let Some((&victim, _)) = good_sessions.iter().find(|(_, active)| !**active) {
                    good_sessions.remove(&victim);
                    good_side_meta.remove(&victim); // cascade side-map delete
                    good_evictions += 1;
                } else {
                    good_lockouts += 1;
                }
            }
            good_sessions.insert(cycle, true);
            good_side_meta.insert(cycle, cycle);
            // Close immediately after turn finishes so slot becomes idle-evictable
            good_sessions.insert(cycle, false);

            // Artifact upload churn (1 KiB each)
            bad_artifacts.insert(cycle, vec![0u8; 1024]);
            if good_artifacts.len() >= ARTIFACT_CAP {
                if let Some(oldest) = good_artifact_order.pop_front() {
                    good_artifacts.remove(&oldest);
                }
            }
            good_artifacts.insert(cycle, vec![0u8; 1024]);
            good_artifact_order.push_back(cycle);

            // Broadcast slow-consumer lag every 6 events -> bad drops stream, good resyncs snapshot!
            let server_gen = cycle as u64;
            if cycle % 6 == 0 {
                if bad_stream_alive && server_gen - bad_client_gen > RING_LAG_CAP {
                    bad_stream_alive = false;
                }
                if server_gen - good_client_gen > RING_LAG_CAP {
                    good_client_gen = server_gen;
                    good_resyncs += 1;
                } else {
                    good_client_gen = server_gen;
                }
            }

            if cycle >= 16 && cycle % 4 == 0 {
                xs.push(cycle as f64);
                bad_bytes_series.push(bad_artifacts.values().map(Vec::len).sum::<usize>() as f64);
                good_bytes_series.push(good_artifacts.values().map(Vec::len).sum::<usize>() as f64);
            }
        }

        // Bad Marlin pattern exhibits permanent slot lockout, silent lag disconnect, and linear memory slope:
        assert_eq!(bad_lockouts, 48);
        assert!(!bad_stream_alive);
        assert!(ols_slope(&xs, &bad_bytes_series) > 500.0);

        // Deterministic Marlin pattern achieves zero lockouts, full lag recovery, zero orphaned side-map keys, and 0 slope:
        assert_eq!(good_lockouts, 0);
        assert_eq!(good_evictions, 48);
        assert_eq!(good_sessions.len(), SESSION_CAP);
        assert_eq!(good_side_meta.len(), good_sessions.len());
        assert_eq!(good_artifacts.len(), ARTIFACT_CAP);
        assert!(good_resyncs > 0);
        assert!(ols_slope(&xs, &good_bytes_series) <= 0.0);
    }
}
