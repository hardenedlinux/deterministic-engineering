// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Paired long-running stability contrast evaluated by the Independent Slope Oracle (SM6).
 * Proves that compressed chaotic pulse cycles catch all 3 aging failure classes
 * (ARB handle leak, buffer watermark ratchet, metastable retry collapse) in milliseconds
 * while certifying deterministic steady-state implementations with exact zero drift.
 */

import {describe, expect, test} from 'bun:test';
import {BadBufferPool, BadHandleManager, BadRetryController, type CycleOutcome} from './bad_aging.ts';
import {
  DeterministicBufferPool,
  DeterministicHandleManager,
  DeterministicRetryController,
} from './deterministic_steady.ts';
import {
  evaluateSteadyStateSlope,
  type QuiescentSnapshot,
  type SlopeOraclePolicy,
  type SoakHarnessSubject,
} from './slope-oracle.ts';

const NORMAL_BUF_BYTES = 1024;
const SPIKE_BUF_BYTES = 65536;
const POOL_SLOT_CAP = 4;
const QUEUE_CAP = 4;
const RETRY_BUDGET = 1;

const STRICT_SOAK_POLICY: SlopeOraclePolicy = {
  warmupCycles: 5,
  soakCycles: 120,
  sampleEvery: 10,
  maxQuiescentRetainedBytes: POOL_SLOT_CAP * NORMAL_BUF_BYTES,
  maxAllowedByteSlopePerCycle: 0.01,
  maxQuiescentQueueDepth: 0,
  maxAllowedRetriesPending: RETRY_BUDGET,
};

function outcomeForCycle(c: number): CycleOutcome {
  if (c % 7 === 0) return 'error';
  if (c % 11 === 0) return 'cancel';
  return 'ok';
}

function makeBadSubject(): SoakHarnessSubject {
  const handles = new BadHandleManager();
  const pool = new BadBufferPool();
  const retry = new BadRetryController();
  return {
    runPulseCycle(c: number): void {
      handles.runOperation(outcomeForCycle(c));
      const size = c % 15 === 0 ? SPIKE_BUF_BYTES : NORMAL_BUF_BYTES;
      const b1 = pool.acquire(size);
      const b2 = pool.acquire(NORMAL_BUF_BYTES);
      pool.release(b1);
      pool.release(b2);
      retry.admitFresh();
      if (c % 5 === 0) {
        retry.triggerCongestion();
        retry.admitFresh();
        retry.onTimeoutRetry();
        retry.onTimeoutRetry();
        retry.onTimeoutRetry();
      }
    },
    drainToQuiescence(): void {
      // Fixed per-cycle service capacity (QUEUE_CAP): healthy bounded queues drain to 0,
      // while metastable unbounded retry queues accumulate unrecovered backlog.
      retry.drainStep(QUEUE_CAP);
    },
    observeIndependentState(cycle: number): QuiescentSnapshot {
      return {
        cycle,
        heldHandles: handles.heldHandleCount(),
        activeWork: handles.activeWork,
        pooledSlots: pool.pooledSlots(),
        retainedBytes: pool.retainedBytes(),
        queueDepth: retry.queueDepth,
        retriesPending: retry.retriesPending,
      };
    },
  };
}

function makeDeterministicSubject(): SoakHarnessSubject {
  const handles = new DeterministicHandleManager(16);
  const pool = new DeterministicBufferPool(POOL_SLOT_CAP, NORMAL_BUF_BYTES);
  const retry = new DeterministicRetryController(QUEUE_CAP, RETRY_BUDGET);
  return {
    runPulseCycle(c: number): void {
      handles.runOperation(outcomeForCycle(c));
      const size = c % 15 === 0 ? SPIKE_BUF_BYTES : NORMAL_BUF_BYTES;
      const b1 = pool.acquire(size);
      const b2 = pool.acquire(NORMAL_BUF_BYTES);
      pool.release(b1);
      pool.release(b2);
      retry.admitFresh();
      if (c % 5 === 0) {
        retry.triggerCongestion();
        retry.admitFresh();
        retry.onTimeoutRetry();
        retry.onTimeoutRetry();
        retry.onTimeoutRetry();
      }
    },
    drainToQuiescence(): void {
      retry.drainStep(QUEUE_CAP);
    },
    observeIndependentState(cycle: number): QuiescentSnapshot {
      return {
        cycle,
        heldHandles: handles.heldHandleCount(),
        activeWork: handles.activeWork,
        pooledSlots: pool.pooledSlots(),
        retainedBytes: pool.retainedBytes(),
        queueDepth: retry.queueDepth,
        retriesPending: retry.retriesPending,
      };
    },
  };
}

describe('SM2/SM3/SM4/SM5/SM6 TypeScript aging contrast & Independent Slope Oracle', () => {
  test('Slope Oracle refutes bad aging implementation across all three failure classes', () => {
    const verdict = evaluateSteadyStateSlope(makeBadSubject(), STRICT_SOAK_POLICY);
    expect(verdict.kind).toBe('Refuted');
    expect(verdict.handleDelta).toBeGreaterThan(0);
    expect(verdict.retainedByteSlope).toBeGreaterThan(100);
    expect(verdict.peakQuiescentBytes).toBeGreaterThan(STRICT_SOAK_POLICY.maxQuiescentRetainedBytes);
    expect(verdict.peakQuiescentQueue).toBeGreaterThan(0);
    expect(verdict.reasons.some((r) => r.startsWith('discrete-handle-drift:'))).toBe(true);
    expect(verdict.reasons.some((r) => r.startsWith('quiescent-bytes-exceeded:'))).toBe(true);
    expect(verdict.reasons.some((r) => r.startsWith('positive-memory-slope:'))).toBe(true);
    expect(verdict.reasons.some((r) => r.startsWith('metastable-quiescent-queue:'))).toBe(true);
  });

  test('Slope Oracle certifies deterministic steady-state implementation with exact zero drift', () => {
    const verdict = evaluateSteadyStateSlope(makeDeterministicSubject(), STRICT_SOAK_POLICY);
    expect(verdict.kind).toBe('Proven');
    expect(verdict.reasons).toEqual([]);
    expect(verdict.handleDelta).toBe(0);
    expect(verdict.finalSnapshot.heldHandles).toBe(0);
    expect(verdict.finalSnapshot.activeWork).toBe(0);
    expect(verdict.finalSnapshot.queueDepth).toBe(0);
    expect(verdict.finalSnapshot.retriesPending).toBe(0);
    expect(verdict.peakQuiescentBytes).toBeLessThanOrEqual(STRICT_SOAK_POLICY.maxQuiescentRetainedBytes);
    expect(verdict.retainedByteSlope).toBeLessThanOrEqual(STRICT_SOAK_POLICY.maxAllowedByteSlopePerCycle);
  });
});
