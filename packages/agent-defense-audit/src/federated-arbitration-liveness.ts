// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 37 (B13, 10.185): Federated Multi-Agent Arbitration, Deadlock Preemption,
 * Bounded Retry Termination & Non-Blocking Escalation Engine.
 *
 * Runtime implementation paired with `FederatedArbitrationLiveness.lean`:
 *   1. Pinned M1 Rollback Cut Prerequisite: refuses to start arbitration without a
 *      verified pinned historical rollback cut in `ContentAddressedKvStore`.
 *   2. Deterministic Circular-Wait Deadlock Detection: detects wait-for cycles across
 *      arbitrary multi-agent graphs via DFS and immediately preempts auto-retries.
 *   3. Bounded Retry Termination: guarantees finite exit to `EscalatedToHuman`
 *      (when an escalation route is configured) or fail-closed `SafelyAborted`
 *      (when unrouted) — NEVER stalls indefinitely or silently flips to `Admitted`.
 *   4. Absorbing Terminal Phases: once `EscalatedToHuman`, `SafelyAborted`, or
 *      `Admitted`, all further mutation attempts are refused (no zombie re-activation).
 */

import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';

export type ArbitrationPhase = 'Active' | 'EscalatedToHuman' | 'SafelyAborted' | 'Admitted';

export interface WaitEdge {
  waitingAgent: string;
  blockingAgent: string;
}

export interface ArbitrationSessionState {
  sessionId: string;
  phase: ArbitrationPhase;
  attemptsUsed: number;
  maxAttempts: number;
  rollbackCutHash: string;
  humanEscalationTarget: string | null;
  deadlockCycle: string[] | null;
  terminalReceiptHash: string | null;
}

export type ArbitrationStartVerdict =
  | {kind: 'Started'; session: ArbitrationSessionState}
  | {kind: 'Refuted'; reason: 'missing-pinned-rollback-cut' | 'invalid-retry-budget'};

export type ArbitrationStepVerdict =
  | {
      kind: 'RetryPermitted';
      session: ArbitrationSessionState;
    }
  | {
      kind: 'EscalatedToHuman';
      reason: 'retry-budget-exhausted' | 'deadlock-cycle-detected';
      escalationTarget: string;
      rollbackCutHash: string;
      forensicReceiptHash: string;
      deadlockCycle?: string[];
    }
  | {
      kind: 'SafelyAborted';
      reason: 'unrouted-retry-exhaustion' | 'unrouted-deadlock-cycle';
      rollbackCutHash: string;
      forensicReceiptHash: string;
      deadlockCycle?: string[];
    }
  | {
      kind: 'Admitted';
      resolutionReceiptHash: string;
    }
  | {
      kind: 'Refuted';
      reason: 'unknown-session' | 'terminal-phase-absorbing';
      currentPhase?: ArbitrationPhase;
    };

/**
 * Deterministic DFS wait-for cycle detector over arbitrary multi-agent wait graphs.
 * Returns the detected cycle path `[a, ..., a]` or `null` if acyclic.
 */
export function detectWaitCycle(edges: readonly WaitEdge[]): string[] | null {
  const adj = new Map<string, string[]>();
  const nodes = new Set<string>();
  for (const e of edges) {
    nodes.add(e.waitingAgent);
    nodes.add(e.blockingAgent);
    const list = adj.get(e.waitingAgent) ?? [];
    list.push(e.blockingAgent);
    adj.set(e.waitingAgent, list);
  }
  const color = new Map<string, 0 | 1 | 2>(); // 0=unvisited, 1=visiting, 2=done
  const stack: string[] = [];

  const dfs = (u: string): string[] | null => {
    color.set(u, 1);
    stack.push(u);
    const neighbors = [...(adj.get(u) ?? [])].sort();
    for (const v of neighbors) {
      const c = color.get(v) ?? 0;
      if (c === 1) {
        const idx = stack.indexOf(v);
        return [...stack.slice(idx), v];
      }
      if (c === 0) {
        const found = dfs(v);
        if (found) return found;
      }
    }
    stack.pop();
    color.set(u, 2);
    return null;
  };

  for (const n of [...nodes].sort()) {
    if ((color.get(n) ?? 0) === 0) {
      const found = dfs(n);
      if (found) return found;
    }
  }
  return null;
}

export class FederatedSwarmArbitrator {
  private readonly sessions = new Map<string, ArbitrationSessionState>();

  constructor(private readonly kv: ContentAddressedKvStore) {}

  startSession(params: {
    sessionId: string;
    maxAttempts: number;
    rollbackCutHash: string;
    humanEscalationTarget?: string | null;
  }): ArbitrationStartVerdict {
    if (!params.rollbackCutHash || !this.kv.hasBlob(params.rollbackCutHash)) {
      return {kind: 'Refuted', reason: 'missing-pinned-rollback-cut'};
    }
    if (!Number.isInteger(params.maxAttempts) || params.maxAttempts < 1) {
      return {kind: 'Refuted', reason: 'invalid-retry-budget'};
    }
    const session: ArbitrationSessionState = {
      sessionId: params.sessionId,
      phase: 'Active',
      attemptsUsed: 0,
      maxAttempts: params.maxAttempts,
      rollbackCutHash: params.rollbackCutHash,
      humanEscalationTarget: params.humanEscalationTarget ?? null,
      deadlockCycle: null,
      terminalReceiptHash: null,
    };
    this.sessions.set(params.sessionId, session);
    return {kind: 'Started', session: {...session}};
  }

  getSession(sessionId: string): ArbitrationSessionState | null {
    const s = this.sessions.get(sessionId);
    return s ? {...s} : null;
  }

  recordConflictAttempt(params: {
    sessionId: string;
    conflictReason: string;
    waitGraph?: readonly WaitEdge[];
  }): ArbitrationStepVerdict {
    const s = this.sessions.get(params.sessionId);
    if (!s) return {kind: 'Refuted', reason: 'unknown-session'};
    if (s.phase !== 'Active') {
      return {kind: 'Refuted', reason: 'terminal-phase-absorbing', currentPhase: s.phase};
    }

    const cycle = params.waitGraph ? detectWaitCycle(params.waitGraph) : null;
    if (cycle) {
      s.deadlockCycle = cycle;
      return this.terminateNonBlocking(s, 'deadlock-cycle-detected', params.conflictReason);
    }

    s.attemptsUsed += 1;
    if (s.attemptsUsed >= s.maxAttempts) {
      return this.terminateNonBlocking(s, 'retry-budget-exhausted', params.conflictReason);
    }

    return {kind: 'RetryPermitted', session: {...s}};
  }

  admitCleanResolution(params: {
    sessionId: string;
    resolutionEvidenceDigest: string;
  }): ArbitrationStepVerdict {
    const s = this.sessions.get(params.sessionId);
    if (!s) return {kind: 'Refuted', reason: 'unknown-session'};
    if (s.phase !== 'Active') {
      return {kind: 'Refuted', reason: 'terminal-phase-absorbing', currentPhase: s.phase};
    }

    s.phase = 'Admitted';
    const resolutionReceiptHash = this.kv.putBlob(
      'federated-arbitration-admitted',
      {
        sessionId: s.sessionId,
        attemptsUsed: s.attemptsUsed,
        rollbackCutHash: s.rollbackCutHash,
        resolutionEvidenceDigest: params.resolutionEvidenceDigest,
      },
      [s.rollbackCutHash],
    );
    this.kv.pinHistoricalCut(resolutionReceiptHash);
    s.terminalReceiptHash = resolutionReceiptHash;
    return {kind: 'Admitted', resolutionReceiptHash};
  }

  private terminateNonBlocking(
    s: ArbitrationSessionState,
    cause: 'retry-budget-exhausted' | 'deadlock-cycle-detected',
    conflictReason: string,
  ): ArbitrationStepVerdict {
    if (s.humanEscalationTarget) {
      s.phase = 'EscalatedToHuman';
      const forensicReceiptHash = this.kv.putBlob(
        'federated-arbitration-escalation',
        {
          sessionId: s.sessionId,
          cause,
          conflictReason,
          attemptsUsed: s.attemptsUsed,
          maxAttempts: s.maxAttempts,
          escalationTarget: s.humanEscalationTarget,
          rollbackCutHash: s.rollbackCutHash,
          deadlockCycle: s.deadlockCycle,
          digest: sha256Digest({sessionId: s.sessionId, cause, conflictReason}),
        },
        [s.rollbackCutHash],
      );
      this.kv.pinHistoricalCut(forensicReceiptHash);
      s.terminalReceiptHash = forensicReceiptHash;
      return {
        kind: 'EscalatedToHuman',
        reason: cause,
        escalationTarget: s.humanEscalationTarget,
        rollbackCutHash: s.rollbackCutHash,
        forensicReceiptHash,
        deadlockCycle: s.deadlockCycle ?? undefined,
      };
    }

    s.phase = 'SafelyAborted';
    const abortReason =
      cause === 'deadlock-cycle-detected' ? 'unrouted-deadlock-cycle' : 'unrouted-retry-exhaustion';
    const forensicReceiptHash = this.kv.putBlob(
      'federated-arbitration-safe-abort',
      {
        sessionId: s.sessionId,
        abortReason,
        conflictReason,
        attemptsUsed: s.attemptsUsed,
        maxAttempts: s.maxAttempts,
        rollbackCutHash: s.rollbackCutHash,
        deadlockCycle: s.deadlockCycle,
      },
      [s.rollbackCutHash],
    );
    this.kv.pinHistoricalCut(forensicReceiptHash);
    s.terminalReceiptHash = forensicReceiptHash;
    return {
      kind: 'SafelyAborted',
      reason: abortReason,
      rollbackCutHash: s.rollbackCutHash,
      forensicReceiptHash,
      deadlockCycle: s.deadlockCycle ?? undefined,
    };
  }
}
