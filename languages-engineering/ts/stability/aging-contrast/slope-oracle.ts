// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * SM6 Independent Steady-State Slope Oracle (Time-Compressed Software Aging Detector).
 *
 * Grounded in:
 * - Gil Tene (Coordinated Omission): open-loop schedule checkpoints independent of SUT stalls.
 * - Yuan et al. (OSDI 2014) & Lu et al. (ASPLOS 2008): small-scale / tightened-budget reproducibility.
 * - Cotroneo, Grottke, Natella, Trivedi (ISSRE 2013): Aging-Related Bug (ARB) monotonic trend detection.
 *
 * Evaluates a System Under Test across:
 *   1. Warmup cycles to reach initial steady state;
 *   2. Baseline quiescent snapshot;
 *   3. N open-loop chaotic pulse cycles (normal, error, cancel, spike, congestion) with periodic quiescent drains;
 *   4. Independent assertions on exact discrete zero-drift (delta == 0), quiescent byte ceiling, and OLS slope.
 */

export interface QuiescentSnapshot {
  cycle: number;
  heldHandles: number;
  activeWork: number;
  pooledSlots: number;
  retainedBytes: number;
  queueDepth: number;
  retriesPending: number;
}

export interface SlopeOraclePolicy {
  warmupCycles: number;
  soakCycles: number;
  sampleEvery: number;
  maxQuiescentRetainedBytes: number;
  maxAllowedByteSlopePerCycle: number;
  maxQuiescentQueueDepth: number;
  maxAllowedRetriesPending: number;
}

export interface SlopeOracleVerdict {
  kind: 'Proven' | 'Refuted';
  reasons: string[];
  baseline: QuiescentSnapshot;
  finalSnapshot: QuiescentSnapshot;
  samples: QuiescentSnapshot[];
  handleDelta: number;
  retainedByteSlope: number;
  peakQuiescentBytes: number;
  peakQuiescentQueue: number;
}

/** Ordinary Least Squares slope of y over x (returns 0 when fewer than 2 distinct x points). */
export function computeLinearSlope(xs: readonly number[], ys: readonly number[]): number {
  const n = Math.min(xs.length, ys.length);
  if (n < 2) return 0;
  let sumX = 0;
  let sumY = 0;
  for (let i = 0; i < n; i++) {
    sumX += xs[i]!;
    sumY += ys[i]!;
  }
  const meanX = sumX / n;
  const meanY = sumY / n;
  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i]! - meanX;
    num += dx * (ys[i]! - meanY);
    den += dx * dx;
  }
  return den === 0 ? 0 : num / den;
}

export interface SoakHarnessSubject {
  runPulseCycle(cycleIndex: number): void;
  drainToQuiescence(): void;
  observeIndependentState(cycleIndex: number): QuiescentSnapshot;
}

export function evaluateSteadyStateSlope(
  subject: SoakHarnessSubject,
  policy: SlopeOraclePolicy,
): SlopeOracleVerdict {
  for (let i = 0; i < policy.warmupCycles; i++) {
    subject.runPulseCycle(i);
    subject.drainToQuiescence();
  }
  const baseline = subject.observeIndependentState(0);
  const samples: QuiescentSnapshot[] = [baseline];

  for (let c = 1; c <= policy.soakCycles; c++) {
    subject.runPulseCycle(policy.warmupCycles + c);
    subject.drainToQuiescence();
    if (c % policy.sampleEvery === 0 || c === policy.soakCycles) {
      samples.push(subject.observeIndependentState(c));
    }
  }

  const finalSnapshot = samples[samples.length - 1]!;
  const xs = samples.map((s) => s.cycle);
  const ys = samples.map((s) => s.retainedBytes);
  const retainedByteSlope = computeLinearSlope(xs, ys);
  const handleDelta = finalSnapshot.heldHandles - baseline.heldHandles;
  const peakQuiescentBytes = Math.max(...samples.map((s) => s.retainedBytes));
  const peakQuiescentQueue = Math.max(...samples.map((s) => s.queueDepth));
  const peakRetries = Math.max(...samples.map((s) => s.retriesPending));

  const reasons: string[] = [];
  if (finalSnapshot.activeWork !== 0) {
    reasons.push(`non-quiescent-active-work:${finalSnapshot.activeWork}`);
  }
  if (finalSnapshot.heldHandles !== 0 || handleDelta !== 0) {
    reasons.push(`discrete-handle-drift:baseline=${baseline.heldHandles},final=${finalSnapshot.heldHandles}`);
  }
  if (peakQuiescentBytes > policy.maxQuiescentRetainedBytes) {
    reasons.push(
      `quiescent-bytes-exceeded:peak=${peakQuiescentBytes},cap=${policy.maxQuiescentRetainedBytes}`,
    );
  }
  if (retainedByteSlope > policy.maxAllowedByteSlopePerCycle) {
    reasons.push(
      `positive-memory-slope:${retainedByteSlope.toFixed(4)}>${policy.maxAllowedByteSlopePerCycle}`,
    );
  }
  if (peakQuiescentQueue > policy.maxQuiescentQueueDepth) {
    reasons.push(
      `metastable-quiescent-queue:peak=${peakQuiescentQueue},cap=${policy.maxQuiescentQueueDepth}`,
    );
  }
  if (peakRetries > policy.maxAllowedRetriesPending) {
    reasons.push(
      `retry-amplification-exceeded:peak=${peakRetries},cap=${policy.maxAllowedRetriesPending}`,
    );
  }

  return {
    kind: reasons.length === 0 ? 'Proven' : 'Refuted',
    reasons,
    baseline,
    finalSnapshot,
    samples,
    handleDelta,
    retainedByteSlope,
    peakQuiescentBytes,
    peakQuiescentQueue,
  };
}
