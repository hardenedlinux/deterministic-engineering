// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Marlin + MyGo + WebView UI End-to-End Steady-State Soak & Slope Oracle Suite.
 *
 * Models and stress-tests the exact 4-layer downstream architecture audited in Wave 3:
 *   Layer 1 (Rust Host / ui_grpc + marlin_mygo_host): bounded BridgeState projections,
 *           idle-session LRU reclamation (no 64-slot lockout), broadcast Lagged -> snapshot resync.
 *   Layer 2 (Go MyGo Bridge / bridge.go + store.go + session.go): coalesced checkpoint flushing
 *           to eliminate per-token O(N^2) JSON write amplification & bounded idempotency records.
 *   Layer 3 (WebView TS UI / main.ts): SM7 bounded DOM viewport window, O(1) incremental block
 *           rendering, coalesced rAF, and cascade side-map (drafts/queues) cleanup on session delete.
 *   Layer 4 (AI Governance Loop): C2 repair packet & SARIF 2.1.0 convergence across SM3/SM4/SM5/SM7.
 */

import {describe, expect, test} from 'bun:test';
import {
  evaluateSteadyStateSlope,
  type QuiescentSnapshot,
  type SlopeOraclePolicy,
  type SoakHarnessSubject,
} from './slope-oracle.ts';
import {
  formatAgingSarif,
  runGovernedAgingRepairLoop,
  type AgingPatchProposal,
} from './aging-governance-harness.ts';
import {auditFileForAging} from './aging-ast-auditor.ts';

// ── 1. Host BridgeState & Session Table (Bad vs. Deterministic Bounded Eviction) ──

class BadMarlinHostSubject implements SoakHarnessSubject {
  sessions = new Map<string, {active: boolean}>();
  artifacts = new Map<string, Uint8Array>();
  trajectory: string[] = [];
  lockouts = 0;

  runPulseCycle(cycleIndex: number): void {
    const sid = `sess-${cycleIndex}`;
    // Mirrors marlin_mygo_host.rs: hard cap 16 (compressed from 64) with NO idle eviction!
    if (this.sessions.size >= 16) {
      this.lockouts += 1;
    } else {
      this.sessions.set(sid, {active: true});
    }
    this.artifacts.set(`art-${cycleIndex}`, new Uint8Array(2048));
    this.trajectory.push(`ev-${cycleIndex}`);
    const s = this.sessions.get(sid);
    if (s) s.active = false;
  }

  drainToQuiescence(): void {
    // Bad host never evicts idle sessions or trims artifacts/trajectory!
  }

  observeIndependentState(cycleIndex: number): QuiescentSnapshot {
    let bytes = this.sessions.size * 512 + this.trajectory.length * 128;
    for (const v of this.artifacts.values()) bytes += v.byteLength;
    return {
      cycle: cycleIndex,
      heldHandles: this.lockouts,
      activeWork: 0,
      pooledSlots: this.sessions.size,
      retainedBytes: bytes,
      queueDepth: 0,
      retriesPending: 0,
    };
  }
}

class DeterministicMarlinHostSubject implements SoakHarnessSubject {
  private readonly sessionCap = 16;
  private readonly artifactCap = 8;
  private readonly trajectoryCap = 32;
  sessions = new Map<string, {active: boolean}>();
  sideMetadata = new Map<string, string>();
  artifacts = new Map<string, Uint8Array>();
  trajectory: string[] = [];
  lockouts = 0;
  evictions = 0;

  runPulseCycle(cycleIndex: number): void {
    const sid = `sess-${cycleIndex}`;
    if (this.sessions.size >= this.sessionCap) {
      let victim: string | null = null;
      for (const [k, v] of this.sessions) {
        if (!v.active) {
          victim = k;
          break;
        }
      }
      if (!victim) {
        this.lockouts += 1;
      } else {
        this.sessions.delete(victim);
        this.sideMetadata.delete(victim); // cascade side-map cleanup
        this.evictions += 1;
        this.sessions.set(sid, {active: true});
        this.sideMetadata.set(sid, `meta:${sid}`);
      }
    } else {
      this.sessions.set(sid, {active: true});
      this.sideMetadata.set(sid, `meta:${sid}`);
    }

    if (this.artifacts.size >= this.artifactCap) {
      const oldest = this.artifacts.keys().next().value;
      if (oldest !== undefined) this.artifacts.delete(oldest);
    }
    this.artifacts.set(`art-${cycleIndex}`, new Uint8Array(2048));

    if (this.trajectory.length >= this.trajectoryCap) {
      this.trajectory.shift();
    }
    this.trajectory.push(`ev-${cycleIndex}`);

    const s = this.sessions.get(sid);
    if (s) s.active = false;
  }

  drainToQuiescence(): void {
    // All work already quiescent and idle slots are reclaimable on next open.
  }

  orphanedSideKeys(): number {
    let orphans = 0;
    for (const k of this.sideMetadata.keys()) {
      if (!this.sessions.has(k)) orphans += 1;
    }
    return orphans;
  }

  observeIndependentState(cycleIndex: number): QuiescentSnapshot {
    let bytes = this.sessions.size * 512 + this.trajectory.length * 128;
    for (const v of this.artifacts.values()) bytes += v.byteLength;
    return {
      cycle: cycleIndex,
      heldHandles: this.orphanedSideKeys(),
      activeWork: 0,
      pooledSlots: this.sessions.size,
      retainedBytes: bytes,
      queueDepth: 0,
      retriesPending: 0,
    };
  }
}

// ── 2. Broadcast Lag Resync + Coalesced Checkpoint Flush ──

interface LagResyncSummary {
  streamAlive: boolean;
  serverGen: number;
  clientGen: number;
  resyncCount: number;
  flushWrites: number;
  totalRewrittenBytes: number;
}

function simulateBadBroadcastAndPerTokenStore(tokens: number, lagWindow: number): LagResyncSummary {
  let serverGen = 0;
  let clientGen = 0;
  let streamAlive = true;
  let flushWrites = 0;
  let totalRewrittenBytes = 0;
  let transcriptBytes = 0;

  for (let i = 1; i <= tokens; i++) {
    serverGen += 1;
    transcriptBytes += 32;
    // Per-token full-JSON rewrite (O(N^2) write amplification)
    flushWrites += 1;
    totalRewrittenBytes += transcriptBytes;

    // Slow consumer only reads every 4th event; broadcast ring overflows -> silent stream drop!
    if (streamAlive && i % 4 === 0) {
      if (serverGen - clientGen > lagWindow) {
        streamAlive = false; // RecvError::Lagged breaks `while let Ok(...)`!
      } else {
        clientGen = serverGen;
      }
    }
  }
  return {streamAlive, serverGen, clientGen, resyncCount: 0, flushWrites, totalRewrittenBytes};
}

function simulateSteadyLagResyncAndCoalescedStore(
  tokens: number,
  lagWindow: number,
  flushBatch: number,
): LagResyncSummary {
  let serverGen = 0;
  let clientGen = 0;
  let resyncCount = 0;
  let flushWrites = 0;
  let totalRewrittenBytes = 0;
  let transcriptBytes = 0;
  let dirtyTokens = 0;

  for (let i = 1; i <= tokens; i++) {
    serverGen += 1;
    transcriptBytes += 32;
    dirtyTokens += 1;

    if (dirtyTokens >= flushBatch || i === tokens) {
      flushWrites += 1;
      totalRewrittenBytes += transcriptBytes;
      dirtyTokens = 0;
    }

    if (i % 4 === 0 || i === tokens) {
      if (serverGen - clientGen > lagWindow) {
        // Explicit RecvError::Lagged -> generation-fenced full-snapshot resync!
        clientGen = serverGen;
        resyncCount += 1;
      } else {
        clientGen = serverGen;
      }
    }
  }
  return {streamAlive: true, serverGen, clientGen, resyncCount, flushWrites, totalRewrittenBytes};
}

// ── 3. WebView UI SM7 Streaming DOM Window + Incremental Block Renderer ──

class BadWebViewUiSubject implements SoakHarnessSubject {
  domNodes: string[] = [];
  drafts = new Map<string, string>();
  activeSessions = new Set<string>();
  rawBytes = 0;
  lastFrameWorkCost = 0;

  runPulseCycle(cycleIndex: number): void {
    const sid = `s-${cycleIndex}`;
    this.activeSessions.add(sid);
    this.drafts.set(sid, `draft-${sid}`);
    this.domNodes.push(`turn-${this.domNodes.length}`);
    for (let d = 0; d < 8; d++) {
      this.rawBytes += 64;
      // O(N^2) full-transcript Markdown/DOMPurify innerHTML re-parse!
      this.lastFrameWorkCost = this.rawBytes;
    }
    this.activeSessions.delete(sid);
    // Bug: forgets drafts.delete(sid)!
  }

  drainToQuiescence(): void {}

  observeIndependentState(cycleIndex: number): QuiescentSnapshot {
    let orphans = 0;
    for (const k of this.drafts.keys()) {
      if (!this.activeSessions.has(k)) orphans += 1;
    }
    return {
      cycle: cycleIndex,
      heldHandles: orphans,
      activeWork: 0,
      pooledSlots: this.domNodes.length,
      retainedBytes: this.lastFrameWorkCost + this.domNodes.length * 256,
      queueDepth: 0,
      retriesPending: 0,
    };
  }
}

class DeterministicWebViewUiSubject implements SoakHarnessSubject {
  private readonly domWindowCap = 24;
  domNodes: string[] = [];
  drafts = new Map<string, string>();
  activeSessions = new Set<string>();
  lastFrameWorkCost = 0;

  runPulseCycle(cycleIndex: number): void {
    const sid = `s-${cycleIndex}`;
    this.activeSessions.add(sid);
    this.drafts.set(sid, `draft-${sid}`);
    this.domNodes.push(`turn-${this.domNodes.length}`);
    while (this.domNodes.length > this.domWindowCap) {
      this.domNodes.shift();
    }
    // O(1) incremental block rendering: each coalesced rAF parses only the dirty delta block (64 bytes).
    this.lastFrameWorkCost = 64;
    this.activeSessions.delete(sid);
    this.drafts.delete(sid); // cascade side-map cleanup!
  }

  drainToQuiescence(): void {}

  observeIndependentState(cycleIndex: number): QuiescentSnapshot {
    let orphans = 0;
    for (const k of this.drafts.keys()) {
      if (!this.activeSessions.has(k)) orphans += 1;
    }
    return {
      cycle: cycleIndex,
      heldHandles: orphans,
      activeWork: 0,
      pooledSlots: this.domNodes.length,
      retainedBytes: this.lastFrameWorkCost + this.domNodes.length * 256,
      queueDepth: 0,
      retriesPending: 0,
    };
  }
}

describe('Marlin + MyGo + WebView UI End-to-End Steady-State Soak & Slope Oracle', () => {
  test('Layer 1 (Host BridgeState + Session Table): bad state locks out & grows O(N); bounded eviction stays flat with 0 lockouts', () => {
    const policy: SlopeOraclePolicy = {
      warmupCycles: 32,
      soakCycles: 48,
      sampleEvery: 4,
      maxQuiescentRetainedBytes: 64 * 1024,
      maxAllowedByteSlopePerCycle: 16,
      maxQuiescentQueueDepth: 0,
      maxAllowedRetriesPending: 0,
    };
    const bad = new BadMarlinHostSubject();
    const badVerdict = evaluateSteadyStateSlope(bad, policy);
    expect(bad.lockouts).toBeGreaterThan(40);
    expect(badVerdict.kind).toBe('Refuted');

    const good = new DeterministicMarlinHostSubject();
    const goodVerdict = evaluateSteadyStateSlope(good, policy);
    expect(good.lockouts).toBe(0);
    expect(good.evictions).toBeGreaterThan(40);
    expect(good.orphanedSideKeys()).toBe(0);
    expect(goodVerdict.kind).toBe('Proven');
    expect(goodVerdict.retainedByteSlope).toBeLessThanOrEqual(0);
  });

  test('Layer 2 (Broadcast Lag Resync & Coalesced Store): eliminates silent lag disconnect and >10x write amplification', () => {
    const bad = simulateBadBroadcastAndPerTokenStore(160, 2);
    expect(bad.streamAlive).toBe(false);
    expect(bad.clientGen).toBeLessThan(bad.serverGen);
    expect(bad.flushWrites).toBe(160);

    const steady = simulateSteadyLagResyncAndCoalescedStore(160, 2, 16);
    expect(steady.streamAlive).toBe(true);
    expect(steady.clientGen).toBe(steady.serverGen);
    expect(steady.resyncCount).toBeGreaterThan(0);
    expect(steady.flushWrites).toBe(10);
    expect(steady.totalRewrittenBytes * 10).toBeLessThan(bad.totalRewrittenBytes);
  });

  test('Layer 3 (WebView SM7 DOM Window + Incremental Render): Slope Oracle refutes O(N^2) innerHTML & certifies bounded viewport', () => {
    const policy: SlopeOraclePolicy = {
      warmupCycles: 24,
      soakCycles: 48,
      sampleEvery: 4,
      maxQuiescentRetainedBytes: 16 * 1024,
      maxAllowedByteSlopePerCycle: 4,
      maxQuiescentQueueDepth: 0,
      maxAllowedRetriesPending: 0,
    };
    const badUi = new BadWebViewUiSubject();
    const badVerdict = evaluateSteadyStateSlope(badUi, policy);
    expect(badVerdict.kind).toBe('Refuted');

    const goodUi = new DeterministicWebViewUiSubject();
    const goodVerdict = evaluateSteadyStateSlope(goodUi, policy);
    expect(goodUi.domNodes.length).toBeLessThanOrEqual(24);
    expect(goodUi.drafts.size).toBe(0);
    expect(goodVerdict.kind).toBe('Proven');
    expect(goodVerdict.retainedByteSlope).toBeLessThanOrEqual(0);
  });

  test('Layer 4 (Closed-Loop Marlin/MyGo AI Governance): emits SM3/SM4/SM5/SM7 C2 repair packet + SARIF 2.1.0 and converges on Attempt 1', () => {
    const badFiles: Record<string, string> = {
      'ui_grpc.rs': `
fn upload_artifact(st: &mut BridgeState, id: String, buf: Vec<u8>) {
  st.artifacts.insert(id, buf);
}
async fn watch_workbench(tx: tokio::sync::broadcast::Sender<Snap>) {
  let mut rx = tx.subscribe();
  while let Ok(snap) = rx.recv().await { forward(snap); }
}`,
      'bridge.go': `
func followTurn(ctx context.Context, emit func(string) error) error {
  events := make(chan string, 16)
  followErr := make(chan error, 1)
  go func() { defer close(events); followErr <- stream(ctx, events) }()
  for ev := range events {
    if err := emit(ev); err != nil { return err }
  }
  return <-followErr
}`,
      'main.ts': `
const drafts = new Map<string, string>();
export function saveDraft(id: string, text: string) { drafts.set(id, text); }
export async function removeChat(id: string) { await ChatService.deleteSession(id); }
export function flushMarkdown(row: { raw: string; text: HTMLElement }, delta: string) {
  row.raw += delta;
  row.text.innerHTML = renderMarkdown(row.raw);
}
export function addRow(messages: HTMLElement) {
  messages.appendChild(document.createElement('div'));
}`,
    };

    const fixedFiles: Record<string, string> = {
      'ui_grpc.rs': `
fn upload_artifact(st: &mut BridgeState, id: String, buf: Vec<u8>) {
  if st.artifacts.len() >= MAX_ARTIFACTS { st.artifacts.pop_first(); }
  st.artifacts.insert(id, buf);
}
async fn watch_workbench(tx: tokio::sync::broadcast::Sender<Snap>) {
  let mut rx = tx.subscribe();
  loop {
    match rx.recv().await {
      Ok(snap) => forward(snap),
      Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => resync_snapshot(),
      Err(_) => break,
    }
  }
}`,
      'bridge.go': `
func followTurn(ctx context.Context, emit func(string) error) error {
  events := make(chan string, 16)
  followCtx, cancel := context.WithCancel(ctx)
  followErr := make(chan error, 1)
  go func() { defer close(events); followErr <- stream(followCtx, events) }()
  defer func() { cancel(); <-followErr }()
  for ev := range events {
    if err := emit(ev); err != nil { return err }
  }
  return nil
}`,
      'main.ts': `
const drafts = new Map<string, string>();
export function saveDraft(id: string, text: string) { drafts.set(id, text); }
export async function removeChat(id: string) { drafts.delete(id); await ChatService.deleteSession(id); }
export function appendIncremental(messages: HTMLElement, blockHtml: string, maxVisibleNodes: number) {
  const node = document.createElement('div');
  node.innerHTML = renderDeltaBlock(blockHtml);
  messages.appendChild(node);
  while (messages.children.length > maxVisibleNodes) { messages.firstElementChild?.remove(); }
}`,
    };

    const uiPolicy: SlopeOraclePolicy = {
      warmupCycles: 24,
      soakCycles: 32,
      sampleEvery: 4,
      maxQuiescentRetainedBytes: 16 * 1024,
      maxAllowedByteSlopePerCycle: 4,
      maxQuiescentQueueDepth: 0,
      maxAllowedRetriesPending: 0,
    };

    const result = runGovernedAgingRepairLoop({
      maxAttempts: 3,
      proposeAttempt: (attempt): AgingPatchProposal =>
        attempt === 0
          ? {files: badFiles, proseClaim: 'Marlin/MyGo initial draft looks fast!'}
          : {files: fixedFiles, proseClaim: 'Applied bounded eviction, lag resync, structured join, and SM7 windowing.'},
      runSlopeOracle: (proposal) =>
        proposal.files['main.ts']?.includes('renderDeltaBlock')
          ? evaluateSteadyStateSlope(new DeterministicWebViewUiSubject(), uiPolicy)
          : evaluateSteadyStateSlope(new BadWebViewUiSubject(), uiPolicy),
    });

    expect(result.finalDecision).toBe('ADMIT');
    expect(result.attemptsUsed).toBe(2);
    const attempt0Findings = result.receipts[0]!.repairPacket.findings;
    const mechanisms = new Set(attempt0Findings.map((f) => f.mechanism));
    expect(mechanisms.has('SM3-watermark-ratchet')).toBe(true);
    expect(mechanisms.has('SM4-orphan-concurrency')).toBe(true);
    expect(mechanisms.has('SM5-metastable-overload')).toBe(true);
    expect(mechanisms.has('SM7-ui-render-aging')).toBe(true);

    // Verify SARIF 2.1.0 includes all cross-layer findings cleanly.
    const reports = Object.entries(badFiles)
      .map(([name, src]) => auditFileForAging(name, src))
      .filter((r): r is NonNullable<typeof r> => r !== null);
    const sarif = formatAgingSarif(reports) as {version: string; runs: Array<{results: unknown[]}>};
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results.length).toBeGreaterThanOrEqual(6);
  });
});
