// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Live Quint --mbt ITF Trace Refinement Tests for the 3 Software Aging / Steady-State Models:
 *   1. QuiescenceResourceDrain.qnt    (SM2/SM4)
 *   2. BufferRatchetReclamation.qnt   (SM3)
 *   3. MetastableRetryCollapse.qnt    (SM5)
 *
 * Generates live --mbt ITF traces from each formal model, dispatches every `mbt::actionTaken`
 * onto stateful TypeScript SUTs, asserts step-by-step field isomorphism, and verifies that
 * defective aging SUTs are immediately rejected by the exact same formal traces.
 */

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {auditMbtCoverage} from '../../../../packages/quint-modules-resolver/src/mbt.ts';

interface ItfState {
  'mbt::actionTaken'?: string;
  h?: Record<string, unknown>;
  [k: string]: unknown;
}

interface ItfDoc {
  states: ItfState[];
}

function asInt(v: unknown): number {
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'number') return Math.trunc(v);
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number(BigInt(String((v as {'#bigint': string})['#bigint'])));
  }
  throw new Error(`Expected int-like ITF value, got ${JSON.stringify(v)}`);
}

function getH(state: ItfState): Record<string, unknown> {
  if (state.h && typeof state.h === 'object') return state.h;
  for (const [k, v] of Object.entries(state)) {
    if (k.endsWith('::h') && v && typeof v === 'object') {
      return v as Record<string, unknown>;
    }
  }
  throw new Error(`Could not locate state variable h in ITF state ${JSON.stringify(Object.keys(state))}`);
}

const REPO_ROOT = resolve(import.meta.dir, '../../../..');

function replayTraces<T extends Record<string, unknown>>(
  relQntPath: string,
  makeSut: () => {apply(action: string): void; snapshot(): T},
  normalize: (h: Record<string, unknown>) => T,
): {traceCount: number; stepCount: number; coverage: number} {
  const qntPath = resolve(REPO_ROOT, relQntPath);
  const tmpDir = mkdtempSync(join(tmpdir(), 'de-mbt-stability-'));
  try {
    const audit = auditMbtCoverage(qntPath, {
      nTraces: 12,
      seed: '7',
      minCoverage: 1.0,
      outDir: tmpDir,
    });
    expect(audit.passed).toBe(true);
    expect(audit.actionCoverage).toBe(1.0);
    const files = audit.traceFiles ?? [];
    expect(files.length).toBeGreaterThan(0);

    let totalSteps = 0;
    for (const itfFile of files) {
      const doc = JSON.parse(readFileSync(itfFile, 'utf8')) as ItfDoc;
      const sut = makeSut();
      expect(sut.snapshot()).toEqual(normalize(getH(doc.states[0]!)));
      for (let i = 1; i < doc.states.length; i++) {
        const st = doc.states[i]!;
        const action = st['mbt::actionTaken'];
        if (!action || action === 'init') continue;
        sut.apply(action);
        expect(sut.snapshot()).toEqual(normalize(getH(st)));
        totalSteps += 1;
      }
    }
    return {traceCount: files.length, stepCount: totalSteps, coverage: audit.actionCoverage};
  } finally {
    rmSync(tmpDir, {recursive: true, force: true});
  }
}

// ── SUT 1: QuiescenceResourceDrain ──
class QuiescenceDrainSUT {
  activeWork = 0;
  heldHandles = 0;
  pendingError = false;
  pendingCancel = false;
  cyclesCompleted = 0;

  apply(action: string): void {
    switch (action) {
      case 'acquireWork':
        if (this.activeWork < 2 && this.heldHandles < 2 && this.cyclesCompleted < 4) {
          this.activeWork += 1;
          this.heldHandles += 1;
        }
        break;
      case 'completeNormal':
        if (this.activeWork > 0 && !this.pendingError && !this.pendingCancel) {
          this.activeWork -= 1;
          this.heldHandles -= 1;
          this.cyclesCompleted += 1;
        }
        break;
      case 'injectError':
        if (this.activeWork > 0 && !this.pendingError && !this.pendingCancel) {
          this.pendingError = true;
        }
        break;
      case 'finishWithError':
        if (this.activeWork > 0 && this.pendingError) {
          this.activeWork -= 1;
          this.pendingError = false;
          this.heldHandles -= 1;
          this.cyclesCompleted += 1;
        }
        break;
      case 'injectCancel':
        if (this.activeWork > 0 && !this.pendingCancel && !this.pendingError) {
          this.pendingCancel = true;
        }
        break;
      case 'finishWithCancel':
        if (this.activeWork > 0 && this.pendingCancel) {
          this.activeWork -= 1;
          this.pendingCancel = false;
          this.heldHandles -= 1;
          this.cyclesCompleted += 1;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      activeWork: this.activeWork,
      heldHandles: this.heldHandles,
      pendingError: this.pendingError,
      pendingCancel: this.pendingCancel,
      cyclesCompleted: this.cyclesCompleted,
    };
  }
}

class BadErrorLeakDrainSUT extends QuiescenceDrainSUT {
  override apply(action: string): void {
    if (action === 'finishWithError' && this.activeWork > 0 && this.pendingError) {
      this.activeWork -= 1;
      this.pendingError = false;
      // Bug: omits releasing heldHandles on error path!
      this.cyclesCompleted += 1;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 2: BufferRatchetReclamation ──
class BufferRatchetSUT {
  activeSmall = 0;
  activeSpike = 0;
  pooledSlots = 0;
  pooledBytes = 0;

  apply(action: string): void {
    switch (action) {
      case 'acquireSmallFresh':
        if (this.activeSmall < 2) this.activeSmall += 1;
        break;
      case 'acquireSmallFromPool':
        if (this.activeSmall < 2 && this.pooledSlots > 0) {
          this.activeSmall += 1;
          this.pooledSlots -= 1;
          this.pooledBytes -= 1;
        }
        break;
      case 'releaseSmall':
        if (this.activeSmall > 0 && this.pooledSlots < 1) {
          this.activeSmall -= 1;
          this.pooledSlots += 1;
          this.pooledBytes += 1;
        } else if (this.activeSmall > 0) {
          this.activeSmall -= 1;
        }
        break;
      case 'acquireSpike':
        if (this.activeSpike === 0) this.activeSpike = 1;
        break;
      case 'releaseSpike':
        if (this.activeSpike > 0) {
          // Safe retain ceiling drops spike buffer instead of poisoning pool.
          this.activeSpike -= 1;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      activeSmall: this.activeSmall,
      activeSpike: this.activeSpike,
      pooledSlots: this.pooledSlots,
      pooledBytes: this.pooledBytes,
    };
  }
}

class BadSpikePoisonSUT extends BufferRatchetSUT {
  override apply(action: string): void {
    if (action === 'releaseSpike' && this.activeSpike > 0) {
      // Bug: returns 4-unit spike buffer into reusable pool!
      this.activeSpike -= 1;
      this.pooledSlots += 1;
      this.pooledBytes += 4;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 3: MetastableRetryCollapse ──
class MetastableRetrySUT {
  congested = false;
  triggerCleared = false;
  queueDepth = 0;
  retriesPending = 0;
  shedCount = 0;

  apply(action: string): void {
    switch (action) {
      case 'admitFresh':
        if (this.queueDepth < 3 && this.shedCount < 3 && !this.congested && this.queueDepth < 2) {
          this.queueDepth += 1;
        } else if (this.queueDepth < 3 && this.shedCount < 3) {
          this.shedCount += 1;
        }
        break;
      case 'triggerCongestion':
        if (!this.congested) {
          this.congested = true;
          this.triggerCleared = false;
        }
        break;
      case 'timeoutAndRetry':
        if (
          this.congested &&
          this.queueDepth > 0 &&
          this.queueDepth < 4 &&
          this.shedCount < 3 &&
          this.retriesPending < 1 &&
          this.queueDepth < 2
        ) {
          this.queueDepth += 1;
          this.retriesPending += 1;
        } else if (this.congested && this.queueDepth > 0 && this.shedCount < 3) {
          this.shedCount += 1;
        }
        break;
      case 'clearTrigger':
        if (this.congested && !this.triggerCleared) {
          this.triggerCleared = true;
        }
        break;
      case 'drainNormal':
        if (this.queueDepth > 0 && (!this.congested || this.triggerCleared)) {
          const wasLast = this.queueDepth === 1;
          this.queueDepth -= 1;
          if (this.retriesPending > 0) this.retriesPending -= 1;
          if (wasLast) this.congested = false;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      congested: this.congested,
      triggerCleared: this.triggerCleared,
      queueDepth: this.queueDepth,
      retriesPending: this.retriesPending,
      shedCount: this.shedCount,
    };
  }
}

class BadUnboundedRetrySUT extends MetastableRetrySUT {
  override apply(action: string): void {
    if (action === 'timeoutAndRetry' && this.congested && this.queueDepth > 0) {
      // Bug: ignores retry budget and amplifies queueDepth!
      this.queueDepth += 1;
      this.retriesPending += 1;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 4: GcPacingThrashGuard (SM3b) ──
class GcPacingThrashSUT {
  liveHeap = 0;
  gcCyclesInWindow = 0;
  shedRequests = 0;
  completedWork = 0;

  apply(action: string): void {
    switch (action) {
      case 'admitAlloc':
        if (this.liveHeap < 4 && this.shedRequests < 3 && this.completedWork < 4 && this.liveHeap < 3) {
          this.liveHeap += 1;
        } else if (this.shedRequests < 3 && this.completedWork < 4) {
          this.shedRequests += 1;
        }
        break;
      case 'runGcCycle':
        if (this.liveHeap > 0 && this.gcCyclesInWindow < 2 && this.gcCyclesInWindow < 1) {
          this.liveHeap -= 1;
          this.gcCyclesInWindow += 1;
        }
        break;
      case 'finishMutatorWindow':
        if (this.gcCyclesInWindow > 0 && this.completedWork < 4) {
          this.gcCyclesInWindow = 0;
          this.completedWork += 1;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      liveHeap: this.liveHeap,
      gcCyclesInWindow: this.gcCyclesInWindow,
      shedRequests: this.shedRequests,
      completedWork: this.completedWork,
    };
  }
}

class BadZeroHeadroomGcSUT extends GcPacingThrashSUT {
  override apply(action: string): void {
    if (action === 'admitAlloc' && this.liveHeap < 4 && this.shedRequests < 3 && this.completedWork < 4) {
      // Bug: ignores headroom floor and pushes liveHeap all the way to softMemLimit=4!
      this.liveHeap += 1;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 5: SlowConsumerEviction (SM4b / SM5b) ──
class SlowConsumerEvictionSUT {
  slowConnected = true;
  slowBuf = 0;
  fastDelivered = 0;
  orphanedBuf = 0;

  apply(action: string): void {
    switch (action) {
      case 'publishFrame':
        if (this.fastDelivered < 4 && !this.slowConnected) {
          this.fastDelivered += 1;
        } else if (this.fastDelivered < 4 && this.slowConnected && this.slowBuf < 3 && this.slowBuf < 2) {
          this.slowBuf += 1;
          this.fastDelivered += 1;
        }
        break;
      case 'slowConsumeOne':
        if (this.slowConnected && this.slowBuf > 0) {
          this.slowBuf -= 1;
        }
        break;
      case 'evictSlowConsumer':
        if (this.slowConnected && this.slowBuf >= 2) {
          this.slowConnected = false;
          this.slowBuf = 0;
          this.orphanedBuf = 0;
        }
        break;
      case 'reconnectSlow':
        if (!this.slowConnected && this.orphanedBuf === 0 && this.fastDelivered < 4) {
          this.slowConnected = true;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      slowConnected: this.slowConnected,
      slowBuf: this.slowBuf,
      fastDelivered: this.fastDelivered,
      orphanedBuf: this.orphanedBuf,
    };
  }
}

class BadEvictedLeakSUT extends SlowConsumerEvictionSUT {
  override apply(action: string): void {
    if (action === 'evictSlowConsumer' && this.slowConnected && this.slowBuf >= 2) {
      // Bug: evicts connection without draining retained slow frames!
      this.orphanedBuf = this.slowBuf;
      this.slowConnected = false;
      this.slowBuf = 0;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 6: BoundedProjectionEviction (SM3c — Marlin ui_grpc / marlin_mygo_host / WebView side maps) ──
class BoundedProjectionEvictionSUT {
  entries = 0;
  activeCount = 0;
  orphanedSideMap = 0;
  evictions = 0;

  apply(action: string): void {
    switch (action) {
      case 'admitEntry':
        if (this.entries < 3 && this.entries < 2) {
          this.entries += 1;
          this.activeCount += 1;
        }
        break;
      case 'deactivateEntry':
        if (this.activeCount > 0) {
          this.activeCount -= 1;
        }
        break;
      case 'evictIdleEntry':
        if (this.entries > this.activeCount) {
          this.entries -= 1;
          this.evictions += 1;
          this.orphanedSideMap = 0;
        }
        break;
      case 'admitWithIdleEviction':
        if (this.entries === 2 && this.activeCount < this.entries) {
          this.activeCount += 1;
          this.evictions += 1;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      entries: this.entries,
      activeCount: this.activeCount,
      orphanedSideMap: this.orphanedSideMap,
      evictions: this.evictions,
    };
  }
}

class BadOrphanSideMapSUT extends BoundedProjectionEvictionSUT {
  override apply(action: string): void {
    if (action === 'evictIdleEntry' && this.entries > this.activeCount) {
      this.entries -= 1;
      this.evictions += 1;
      // Bug: forgets to cascade-delete auxiliary drafts/queues/metadata side-map key!
      this.orphanedSideMap += 1;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 7: StreamLagResyncCoalescing (SM5c — ui_grpc broadcast lag resync & MyGo coalesced flush) ──
class StreamLagResyncSUT {
  serverGen = 0;
  clientGen = 0;
  lagged = false;
  streamAlive = true;
  dirtyBatch = 0;
  flushedBatches = 0;
  uncoalescedFlushes = 0;

  apply(action: string): void {
    switch (action) {
      case 'emitDelta':
        if (this.serverGen < 6 && this.dirtyBatch < 2) {
          const nextGen = this.serverGen + 1;
          this.serverGen = nextGen;
          this.dirtyBatch += 1;
          this.lagged = this.lagged || nextGen - this.clientGen > 2;
        }
        break;
      case 'consumeDelta':
        if (this.streamAlive && !this.lagged && this.clientGen < this.serverGen) {
          this.clientGen += 1;
        }
        break;
      case 'resyncOnLag':
        if (this.streamAlive && this.lagged) {
          this.clientGen = this.serverGen;
          this.lagged = false;
          this.streamAlive = true;
        }
        break;
      case 'flushCheckpoint':
        if (this.dirtyBatch > 0 && this.dirtyBatch >= 2) {
          if (this.dirtyBatch < 2) this.uncoalescedFlushes += 1;
          this.dirtyBatch = 0;
          this.flushedBatches += 1;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      serverGen: this.serverGen,
      clientGen: this.clientGen,
      lagged: this.lagged,
      streamAlive: this.streamAlive,
      dirtyBatch: this.dirtyBatch,
      flushedBatches: this.flushedBatches,
      uncoalescedFlushes: this.uncoalescedFlushes,
    };
  }
}

class BadSilentLagDisconnectSUT extends StreamLagResyncSUT {
  override apply(action: string): void {
    if (action === 'resyncOnLag' && this.streamAlive && this.lagged) {
      // Bug: silently terminates stream on RecvError::Lagged instead of resyncing!
      this.clientGen = this.serverGen;
      this.lagged = false;
      this.streamAlive = false;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 8: UiRenderWindowBudget (SM7 — WebView bounded DOM viewport & O(1) incremental render) ──
class UiRenderWindowBudgetSUT {
  totalTurns = 0;
  mountedNodes = 0;
  pendingRafs = 0;
  frameWorkUnits = 0;

  apply(action: string): void {
    switch (action) {
      case 'appendTurnDelta':
        if (this.totalTurns < 6) {
          this.totalTurns += 1;
          if (this.mountedNodes < 3) this.mountedNodes += 1;
          this.pendingRafs = 1;
        }
        break;
      case 'flushFrame':
        if (this.pendingRafs > 0) {
          this.pendingRafs = 0;
          this.frameWorkUnits = 1;
        }
        break;
      case 'switchSessionReset':
        if (this.totalTurns > 0 && this.pendingRafs === 0) {
          this.mountedNodes = this.totalTurns > 3 ? 3 : this.totalTurns;
          this.pendingRafs = 1;
          this.frameWorkUnits = 0;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      totalTurns: this.totalTurns,
      mountedNodes: this.mountedNodes,
      pendingRafs: this.pendingRafs,
      frameWorkUnits: this.frameWorkUnits,
    };
  }
}

class BadFullReparseUiSUT extends UiRenderWindowBudgetSUT {
  override apply(action: string): void {
    if (action === 'flushFrame' && this.pendingRafs > 0) {
      this.pendingRafs = 0;
      // Bug: re-parses entire accumulated transcript on every frame!
      this.frameWorkUnits = this.totalTurns;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 9: SearchQueryGenerationFencing (SM8) ──
class SearchQueryGenerationFencingSUT {
  activeGen = 1;
  displayedGen = 0;
  visibleCount = 0;
  markedCount = 0;
  staleDrops = 0;
  selectedAnchored = true;
  generationInversion = false;
  staleApplied = false;

  apply(action: string): void {
    switch (action) {
      case 'beginQuery':
        if (this.activeGen < 3) {
          this.activeGen += 1;
          this.visibleCount = 0;
          this.markedCount = 0;
          this.selectedAnchored = true;
        }
        break;
      case 'dispatchDelayedOlderQuery':
        if (this.activeGen > 1 && this.staleDrops < 3) {
          this.staleDrops += 1;
          this.generationInversion = false;
        }
        break;
      case 'applyFreshBatch':
        if (this.visibleCount < 2) {
          this.displayedGen = this.activeGen;
          this.visibleCount += 1;
          this.selectedAnchored = true;
        }
        break;
      case 'applyStaleBatch':
        if (this.activeGen > 1 && this.staleDrops < 3) {
          this.staleDrops += 1;
          this.staleApplied = false;
        }
        break;
      case 'toggleMark':
        if (this.visibleCount > 0 && this.markedCount < this.visibleCount) {
          this.markedCount += 1;
        }
        break;
      case 'filterSource':
        if (this.visibleCount > 0) {
          this.visibleCount -= 1;
          if (this.markedCount > this.visibleCount) {
            this.markedCount = this.visibleCount;
          }
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      activeGen: this.activeGen,
      displayedGen: this.displayedGen,
      visibleCount: this.visibleCount,
      markedCount: this.markedCount,
      staleDrops: this.staleDrops,
      selectedAnchored: this.selectedAnchored,
      generationInversion: this.generationInversion,
      staleApplied: this.staleApplied,
    };
  }
}

class BadSelectionJumpSearchSUT extends SearchQueryGenerationFencingSUT {
  override apply(action: string): void {
    if (action === 'applyFreshBatch' && this.visibleCount > 0 && this.visibleCount < 2) {
      this.displayedGen = this.activeGen;
      this.visibleCount += 1;
      // Bug: higher-priority batch shifts integer cursor index without re-anchoring candidate ID!
      this.selectedAnchored = false;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 10: SingleFlightCancellationSafety (SM9) ──
class SingleFlightCancellationSUT {
  inFlight = false;
  leaderActive = false;
  armedWaiters = 0;
  stuckWaiters = 0;
  completedSyncs = 0;

  apply(action: string): void {
    switch (action) {
      case 'acquireLeader':
        if (!this.inFlight && this.completedSyncs < 3) {
          this.inFlight = true;
          this.leaderActive = true;
        }
        break;
      case 'coalesceWaiter':
        if (this.inFlight && this.armedWaiters < 2) {
          this.armedWaiters += 1;
          this.stuckWaiters = 0;
        }
        break;
      case 'completeLeader':
        if (this.leaderActive) {
          this.inFlight = false;
          this.leaderActive = false;
          this.armedWaiters = 0;
          this.completedSyncs += 1;
        }
        break;
      case 'cancelLeader':
        if (this.leaderActive) {
          this.leaderActive = false;
          this.inFlight = false;
          this.armedWaiters = 0;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      inFlight: this.inFlight,
      leaderActive: this.leaderActive,
      armedWaiters: this.armedWaiters,
      stuckWaiters: this.stuckWaiters,
      completedSyncs: this.completedSyncs,
    };
  }
}

class BadNoDropGuardSingleFlightSUT extends SingleFlightCancellationSUT {
  override apply(action: string): void {
    if (action === 'cancelLeader' && this.leaderActive) {
      // Bug: future dropped mid-await without Drop guard -> inFlight stays true forever!
      this.leaderActive = false;
      return;
    }
    super.apply(action);
  }
}

// ── SUT 11: SearchQueryMetamorphicAlgebra (SM10) ──
class SearchQueryMetamorphicSUT {
  hasQualifier = false;
  hasNegation = false;
  activeScopeEpoch = 0;
  effectiveScopeEpoch = 0;
  matchedCount = 2;
  clippedClicksIgnored = 0;
  qualifierLeaked = false;
  phantomTabHit = false;

  apply(action: string): void {
    switch (action) {
      case 'applyQualifier':
        if (!this.hasQualifier) {
          this.hasQualifier = true;
          this.qualifierLeaked = false;
        }
        break;
      case 'applyScopeReplace':
        if (this.activeScopeEpoch < 2) {
          this.activeScopeEpoch += 1;
          this.effectiveScopeEpoch = this.activeScopeEpoch;
        }
        break;
      case 'addNegationFilter':
        if (!this.hasNegation && this.matchedCount > 0) {
          this.hasNegation = true;
          this.matchedCount -= 1;
        }
        break;
      case 'clickClippedTab':
        if (this.clippedClicksIgnored < 2) {
          this.clippedClicksIgnored += 1;
          this.phantomTabHit = false;
        }
        break;
      case 'resetQuery':
        if (this.hasQualifier || this.hasNegation || this.activeScopeEpoch > 0) {
          this.hasQualifier = false;
          this.hasNegation = false;
          this.activeScopeEpoch = 0;
          this.effectiveScopeEpoch = 0;
          this.matchedCount = 2;
        }
        break;
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  snapshot() {
    return {
      hasQualifier: this.hasQualifier,
      hasNegation: this.hasNegation,
      activeScopeEpoch: this.activeScopeEpoch,
      effectiveScopeEpoch: this.effectiveScopeEpoch,
      matchedCount: this.matchedCount,
      clippedClicksIgnored: this.clippedClicksIgnored,
      qualifierLeaked: this.qualifierLeaked,
      phantomTabHit: this.phantomTabHit,
    };
  }
}

class BadQualifierLeakSearchSUT extends SearchQueryMetamorphicSUT {
  override apply(action: string): void {
    if (action === 'applyQualifier' && !this.hasQualifier) {
      this.hasQualifier = true;
      this.qualifierLeaked = true;
      this.matchedCount = 0;
      return;
    }
    super.apply(action);
  }
}

describe('Quint --mbt ITF Trace Refinement for Steady-State Stability Models', () => {
  test('QuiescenceResourceDrain: valid SUT refines 100% of ITF traces and error-leak SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      activeWork: asInt(h.activeWork),
      heldHandles: asInt(h.heldHandles),
      pendingError: Boolean(h.pendingError),
      pendingCancel: Boolean(h.pendingCancel),
      cyclesCompleted: asInt(h.cyclesCompleted),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/quiescence-resource-drain/QuiescenceResourceDrain.qnt',
      () => new QuiescenceDrainSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/quiescence-resource-drain/QuiescenceResourceDrain.qnt',
        () => new BadErrorLeakDrainSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('BufferRatchetReclamation: valid SUT refines 100% of ITF traces and spike-poison SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      activeSmall: asInt(h.activeSmall),
      activeSpike: asInt(h.activeSpike),
      pooledSlots: asInt(h.pooledSlots),
      pooledBytes: asInt(h.pooledBytes),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/buffer-ratchet-reclamation/BufferRatchetReclamation.qnt',
      () => new BufferRatchetSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/buffer-ratchet-reclamation/BufferRatchetReclamation.qnt',
        () => new BadSpikePoisonSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('MetastableRetryCollapse: valid SUT refines 100% of ITF traces and unbounded-retry SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      congested: Boolean(h.congested),
      triggerCleared: Boolean(h.triggerCleared),
      queueDepth: asInt(h.queueDepth),
      retriesPending: asInt(h.retriesPending),
      shedCount: asInt(h.shedCount),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/metastable-retry-collapse/MetastableRetryCollapse.qnt',
      () => new MetastableRetrySUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/metastable-retry-collapse/MetastableRetryCollapse.qnt',
        () => new BadUnboundedRetrySUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('GcPacingThrashGuard: valid SUT refines 100% of ITF traces and zero-headroom SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      liveHeap: asInt(h.liveHeap),
      gcCyclesInWindow: asInt(h.gcCyclesInWindow),
      shedRequests: asInt(h.shedRequests),
      completedWork: asInt(h.completedWork),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/gc/gc-pacing-thrash-guard/GcPacingThrashGuard.qnt',
      () => new GcPacingThrashSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/gc/gc-pacing-thrash-guard/GcPacingThrashGuard.qnt',
        () => new BadZeroHeadroomGcSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('SlowConsumerEviction: valid SUT refines 100% of ITF traces and evicted-leak SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      slowConnected: Boolean(h.slowConnected),
      slowBuf: asInt(h.slowBuf),
      fastDelivered: asInt(h.fastDelivered),
      orphanedBuf: asInt(h.orphanedBuf),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/slow-consumer-eviction/SlowConsumerEviction.qnt',
      () => new SlowConsumerEvictionSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/slow-consumer-eviction/SlowConsumerEviction.qnt',
        () => new BadEvictedLeakSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('BoundedProjectionEviction: valid SUT refines 100% of ITF traces and orphan-sidemap SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      entries: asInt(h.entries),
      activeCount: asInt(h.activeCount),
      orphanedSideMap: asInt(h.orphanedSideMap),
      evictions: asInt(h.evictions),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/bounded-projection-eviction/BoundedProjectionEviction.qnt',
      () => new BoundedProjectionEvictionSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/bounded-projection-eviction/BoundedProjectionEviction.qnt',
        () => new BadOrphanSideMapSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('StreamLagResyncCoalescing: valid SUT refines 100% of ITF traces and silent-lag-drop SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      serverGen: asInt(h.serverGen),
      clientGen: asInt(h.clientGen),
      lagged: Boolean(h.lagged),
      streamAlive: Boolean(h.streamAlive),
      dirtyBatch: asInt(h.dirtyBatch),
      flushedBatches: asInt(h.flushedBatches),
      uncoalescedFlushes: asInt(h.uncoalescedFlushes),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/stream-lag-resync-coalescing/StreamLagResyncCoalescing.qnt',
      () => new StreamLagResyncSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/stream-lag-resync-coalescing/StreamLagResyncCoalescing.qnt',
        () => new BadSilentLagDisconnectSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('UiRenderWindowBudget: valid SUT refines 100% of ITF traces and full-reparse SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      totalTurns: asInt(h.totalTurns),
      mountedNodes: asInt(h.mountedNodes),
      pendingRafs: asInt(h.pendingRafs),
      frameWorkUnits: asInt(h.frameWorkUnits),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/ui-render-window-budget/UiRenderWindowBudget.qnt',
      () => new UiRenderWindowBudgetSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/ui-render-window-budget/UiRenderWindowBudget.qnt',
        () => new BadFullReparseUiSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('SearchQueryGenerationFencing: valid SUT refines 100% of ITF traces and selection-jump SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      activeGen: asInt(h.activeGen),
      displayedGen: asInt(h.displayedGen),
      visibleCount: asInt(h.visibleCount),
      markedCount: asInt(h.markedCount),
      staleDrops: asInt(h.staleDrops),
      selectedAnchored: Boolean(h.selectedAnchored),
      generationInversion: Boolean(h.generationInversion),
      staleApplied: Boolean(h.staleApplied),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/search-query-generation-fencing/SearchQueryGenerationFencing.qnt',
      () => new SearchQueryGenerationFencingSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/search-query-generation-fencing/SearchQueryGenerationFencing.qnt',
        () => new BadSelectionJumpSearchSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('SingleFlightCancellationSafety: valid SUT refines 100% of ITF traces and no-drop-guard SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      inFlight: Boolean(h.inFlight),
      leaderActive: Boolean(h.leaderActive),
      armedWaiters: asInt(h.armedWaiters),
      stuckWaiters: asInt(h.stuckWaiters),
      completedSyncs: asInt(h.completedSyncs),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/singleflight-cancellation-safety/SingleFlightCancellationSafety.qnt',
      () => new SingleFlightCancellationSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/singleflight-cancellation-safety/SingleFlightCancellationSafety.qnt',
        () => new BadNoDropGuardSingleFlightSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('SearchQueryMetamorphicAlgebra: valid SUT refines 100% of ITF traces and qualifier-leak SUT fails', () => {
    const normalize = (h: Record<string, unknown>) => ({
      hasQualifier: Boolean(h.hasQualifier),
      hasNegation: Boolean(h.hasNegation),
      activeScopeEpoch: asInt(h.activeScopeEpoch),
      effectiveScopeEpoch: asInt(h.effectiveScopeEpoch),
      matchedCount: asInt(h.matchedCount),
      clippedClicksIgnored: asInt(h.clippedClicksIgnored),
      qualifierLeaked: Boolean(h.qualifierLeaked),
      phantomTabHit: Boolean(h.phantomTabHit),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/search-query-metamorphic-algebra/SearchQueryMetamorphicAlgebra.qnt',
      () => new SearchQueryMetamorphicSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/search-query-metamorphic-algebra/SearchQueryMetamorphicAlgebra.qnt',
        () => new BadQualifierLeakSearchSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);

  test('PriorityIsolatedBoundedMailbox: valid SUT refines 100% of ITF traces and shared-channel starvation SUT fails', () => {
    class PriorityMailboxSUT {
      hiQueue = 0;
      loQueue = 0;
      zombieLo = 0;
      hiBurst = 0;
      hiStarved = false;
      progressSlots = 0;
      producedWater = 0;
      observedWater = 0;
      shedLoCount = 0;

      apply(action: string): void {
        switch (action) {
          case 'submitHi':
            if (this.hiQueue < 2) this.hiQueue += 1;
            break;
          case 'submitLo':
            if (this.loQueue < 2) this.loQueue += 1;
            else this.shedLoCount += 1;
            break;
          case 'cancelLo':
            if (this.loQueue > 0) this.loQueue -= 1;
            break;
          case 'drainOne':
            if (this.loQueue > 0 && (this.hiQueue === 0 || this.hiBurst >= 2)) {
              this.loQueue -= 1;
              this.hiBurst = 0;
            } else if (this.hiQueue > 0) {
              this.hiQueue -= 1;
              this.hiBurst += 1;
            }
            break;
          case 'publishProgress':
            if (this.producedWater < 3) {
              this.producedWater += 1;
              this.progressSlots = 1;
            }
            break;
          case 'pollProgress':
            if (this.progressSlots > 0) {
              this.observedWater = this.producedWater;
              this.progressSlots = 0;
            }
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
      }

      snapshot() {
        return {
          hiQueue: this.hiQueue,
          loQueue: this.loQueue,
          zombieLo: this.zombieLo,
          hiBurst: this.hiBurst,
          hiStarved: this.hiStarved,
          progressSlots: this.progressSlots,
          producedWater: this.producedWater,
          observedWater: this.observedWater,
          shedLoCount: this.shedLoCount,
        };
      }
    }

    class BadZombieLeakMailboxSUT extends PriorityMailboxSUT {
      override apply(action: string): void {
        if (action === 'cancelLo' && this.loQueue > 0) {
          this.zombieLo += 1;
          return;
        }
        if (action === 'submitHi' && this.hiQueue < 2 && this.loQueue >= 2) {
          this.hiStarved = true;
          return;
        }
        super.apply(action);
      }
    }

    const normalize = (h: Record<string, unknown>) => ({
      hiQueue: asInt(h.hiQueue),
      loQueue: asInt(h.loQueue),
      zombieLo: asInt(h.zombieLo),
      hiBurst: asInt(h.hiBurst),
      hiStarved: Boolean(h.hiStarved),
      progressSlots: asInt(h.progressSlots),
      producedWater: asInt(h.producedWater),
      observedWater: asInt(h.observedWater),
      shedLoCount: asInt(h.shedLoCount),
    });
    const res = replayTraces(
      'packages/quint-models/engineering/concurrency/priority-isolated-bounded-mailbox/PriorityIsolatedBoundedMailbox.qnt',
      () => new PriorityMailboxSUT(),
      normalize,
    );
    expect(res.coverage).toBe(1.0);
    expect(res.stepCount).toBeGreaterThan(20);
    expect(() =>
      replayTraces(
        'packages/quint-models/engineering/concurrency/priority-isolated-bounded-mailbox/PriorityIsolatedBoundedMailbox.qnt',
        () => new BadZombieLeakMailboxSUT(),
        normalize,
      ),
    ).toThrow();
  }, 30000);
});
