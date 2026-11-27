// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 15 (Business Extension B6, 10.163):
 * Durable Compensable Multi-Agent Sagas, Pivot Boundaries, PendingUnknownEffect
 * Fencing, and Linear Compute/Cost Resource Budget Conservation.
 *
 * Grounded in:
 *   - H. Garcia-Molina & K. Salem (ACM SIGMOD 1987) — Sagas & Pivot Transactions
 *   - P. Helland (CIDR 2007) — Idempotent Forward & Compensating External Actions
 *   - KeyKOS / Linear Types — Strict Conservation Law across Sub-Agent Delegation
 *
 * Guarantees:
 *   1. Linear Budget Conservation (`LinearBudgetTree`): splitting a coordinator's
 *      budget across sub-agents atomically transfers units so
 *      `sum(remaining) + sum(spent) === rootBudget` at every point in time;
 *      exhaustion triggers `BudgetExhaustedHalt` without losing committed M1 work.
 *   2. Write-Ahead Compensation Log (`DurableAgentSagaEngine`): every `Compensable`
 *      step must durably register its M1 compensation spec & idempotency key BEFORE
 *      executing forward; pre-pivot failures trigger strict reverse-order idempotent
 *      compensations.
 *   3. At-Most-One Irreversible Pivot: crossing a `PivotIrreversible` step forbids
 *      backward compensation (`rollback-forbidden-past-pivot`) and enforces durable
 *      roll-forward recovery.
 *   4. `PendingUnknownEffect` Fence: mid-step timeout blocks both blind retry and
 *      blind compensation until explicit external reconciliation (`Committed` | `NotApplied`).
 */

import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

// ── Part 1: Linear Resource / Cost Budget Conservation Tree (M3 Live Account) ──

export interface BudgetLedgerEntry {
  agentId: string;
  costUnits: number;
  reason: string;
  m1EvidenceHash: string;
}

export type BudgetSplitVerdict =
  | {kind: 'Allocated'; childId: string; allocatedUnits: number; parentRemaining: number}
  | {kind: 'Refuted'; reason: 'invalid-amount' | 'unknown-parent' | 'duplicate-child' | 'insufficient-parent-budget'};

export type BudgetConsumeVerdict =
  | {kind: 'Consumed'; agentId: string; spentUnits: number; remainingUnits: number}
  | {kind: 'BudgetExhaustedHalt'; agentId: string; requestedUnits: number; remainingUnits: number};

/**
 * Non-serializable live M3 linear budget tree (R3 branded so mutable budget accounts
 * can never be duplicated via accidental M1 serialization!).
 */
export class LinearBudgetTree {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;

  private readonly remainingByAgent = new Map<string, number>();
  private readonly spentByAgent = new Map<string, number>();
  private readonly ledger: BudgetLedgerEntry[] = [];

  constructor(
    readonly rootAgentId: string,
    readonly rootBudgetUnits: number,
  ) {
    if (!Number.isInteger(rootBudgetUnits) || rootBudgetUnits < 0) {
      throw new Error(`rootBudgetUnits must be a non-negative integer, got ${rootBudgetUnits}`);
    }
    this.capabilityId = `linear-budget-tree:${rootAgentId}`;
    this.remainingByAgent.set(rootAgentId, rootBudgetUnits);
    this.spentByAgent.set(rootAgentId, 0);
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: LinearBudgetTree '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }

  getRemaining(agentId: string): number {
    return this.remainingByAgent.get(agentId) ?? 0;
  }

  getSpent(agentId: string): number {
    return this.spentByAgent.get(agentId) ?? 0;
  }

  /**
   * Atomically splits `units` from `parentId` to a new `childId` (linear transfer).
   * Conserves total budget: parent loses `units`, child receives `units`.
   */
  splitSubBudget(parentId: string, childId: string, units: number): BudgetSplitVerdict {
    if (!Number.isInteger(units) || units <= 0) {
      return {kind: 'Refuted', reason: 'invalid-amount'};
    }
    const parentRem = this.remainingByAgent.get(parentId);
    if (parentRem === undefined) {
      return {kind: 'Refuted', reason: 'unknown-parent'};
    }
    if (this.remainingByAgent.has(childId)) {
      return {kind: 'Refuted', reason: 'duplicate-child'};
    }
    if (parentRem < units) {
      return {kind: 'Refuted', reason: 'insufficient-parent-budget'};
    }
    this.remainingByAgent.set(parentId, parentRem - units);
    this.remainingByAgent.set(childId, units);
    this.spentByAgent.set(childId, 0);
    return {
      kind: 'Allocated',
      childId,
      allocatedUnits: units,
      parentRemaining: parentRem - units,
    };
  }

  consume(agentId: string, costUnits: number, reason: string, m1EvidenceHash: string): BudgetConsumeVerdict {
    if (!Number.isInteger(costUnits) || costUnits <= 0) {
      return {
        kind: 'BudgetExhaustedHalt',
        agentId,
        requestedUnits: costUnits,
        remainingUnits: this.getRemaining(agentId),
      };
    }
    const rem = this.remainingByAgent.get(agentId) ?? 0;
    if (rem < costUnits) {
      return {
        kind: 'BudgetExhaustedHalt',
        agentId,
        requestedUnits: costUnits,
        remainingUnits: rem,
      };
    }
    this.remainingByAgent.set(agentId, rem - costUnits);
    this.spentByAgent.set(agentId, (this.spentByAgent.get(agentId) ?? 0) + costUnits);
    this.ledger.push({agentId, costUnits, reason, m1EvidenceHash});
    return {
      kind: 'Consumed',
      agentId,
      spentUnits: costUnits,
      remainingUnits: rem - costUnits,
    };
  }

  /**
   * Verifies the linear conservation law across the entire delegation tree:
   *   sum(remaining) + sum(spent) === rootBudgetUnits
   */
  conservationAudit(): {
    rootBudgetUnits: number;
    totalRemaining: number;
    totalSpent: number;
    conserved: boolean;
  } {
    let totalRemaining = 0;
    let totalSpent = 0;
    for (const r of this.remainingByAgent.values()) totalRemaining += r;
    for (const s of this.spentByAgent.values()) totalSpent += s;
    return {
      rootBudgetUnits: this.rootBudgetUnits,
      totalRemaining,
      totalSpent,
      conserved: totalRemaining + totalSpent === this.rootBudgetUnits,
    };
  }

  getLedger(): readonly BudgetLedgerEntry[] {
    return this.ledger;
  }
}

// ── Part 2: Durable Compensable Multi-Agent Saga Engine ──

export type EffectReversibilityClass =
  | 'ReadOnlyIdempotent'
  | 'Compensable'
  | 'PivotIrreversible';

export type ExternalCallOutcome =
  | {kind: 'Committed'; externalReceiptId: string}
  | {kind: 'FailedCleanly'; errorCode: string}
  | {kind: 'UnknownTimeout'; intentDigest: string};

export interface SagaStepSpec {
  stepId: string;
  agentId: string;
  reversibility: EffectReversibilityClass;
  costUnits: number;
  /** Required for `Compensable` steps: describes the write-ahead compensator action */
  compensatorActionName?: string;
  executeForward: (idempotencyKey: string) => ExternalCallOutcome;
  executeCompensate?: (compensationIdempotencyKey: string) => {compensated: boolean};
}

export interface SagaCompensationReceipt {
  stepId: string;
  compensationIdempotencyKey: string;
  receiptMerkleHash: string;
}

export type SagaRegistrationVerdict =
  | {kind: 'Registered'; sagaId: string; sagaPlanMerkleHash: string}
  | {
      kind: 'Refuted';
      reason:
        | 'empty-saga'
        | 'multiple-pivots-forbidden'
        | 'missing-write-ahead-compensator'
        | 'compensable-step-after-pivot-forbidden';
    };

export type SagaRunVerdict =
  | {
      kind: 'Completed';
      sagaId: string;
      completedSteps: string[];
      pivotCrossed: boolean;
      finalReceiptHash: string;
    }
  | {
      kind: 'CompensatedRollback';
      sagaId: string;
      failedAtStepId: string;
      failureReason: string;
      compensatedStepsInOrder: string[];
      compensationReceipts: SagaCompensationReceipt[];
    }
  | {
      kind: 'PendingUnknownEffect';
      sagaId: string;
      unknownStepId: string;
      idempotencyKey: string;
      pivotCrossed: boolean;
    }
  | {
      kind: 'RollForwardRequired';
      sagaId: string;
      failedPostPivotStepId: string;
      failureReason: string;
      pivotStepId: string;
    };

interface SagaRuntimeState {
  sagaId: string;
  steps: SagaStepSpec[];
  completedStepIds: string[];
  compensatedStepIds: string[];
  unknownStep: {stepId: string; idempotencyKey: string; index: number} | null;
  pivotStepId: string | null;
  pivotCrossed: boolean;
  nextIndex: number;
}

export class DurableAgentSagaEngine {
  private readonly sagas = new Map<string, SagaRuntimeState>();

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly budget: LinearBudgetTree,
  ) {}

  /**
   * Registers a Saga plan and validates Garcia-Molina/Salem structural invariants:
   *  1. At most ONE `PivotIrreversible` step.
   *  2. No `Compensable` steps after the Pivot (post-pivot steps must be retriable/roll-forward).
   *  3. Every `Compensable` step MUST declare its write-ahead compensator spec & callback.
   */
  registerSaga(sagaId: string, steps: SagaStepSpec[]): SagaRegistrationVerdict {
    if (steps.length === 0) {
      return {kind: 'Refuted', reason: 'empty-saga'};
    }
    let pivotIdx = -1;
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i]!;
      if (s.reversibility === 'PivotIrreversible') {
        if (pivotIdx !== -1) {
          return {kind: 'Refuted', reason: 'multiple-pivots-forbidden'};
        }
        pivotIdx = i;
      } else if (s.reversibility === 'Compensable') {
        if (pivotIdx !== -1) {
          return {kind: 'Refuted', reason: 'compensable-step-after-pivot-forbidden'};
        }
        if (!s.compensatorActionName || !s.executeCompensate) {
          return {kind: 'Refuted', reason: 'missing-write-ahead-compensator'};
        }
      }
    }

    const sagaPlanMerkleHash = this.kv.putBlob(
      'saga-write-ahead-plan',
      {
        sagaId,
        steps: steps.map(s => ({
          stepId: s.stepId,
          agentId: s.agentId,
          reversibility: s.reversibility,
          costUnits: s.costUnits,
          compensatorActionName: s.compensatorActionName ?? null,
        })),
      },
      [],
    );
    this.kv.pinHistoricalCut(sagaPlanMerkleHash);

    this.sagas.set(sagaId, {
      sagaId,
      steps,
      completedStepIds: [],
      compensatedStepIds: [],
      unknownStep: null,
      pivotStepId: pivotIdx >= 0 ? steps[pivotIdx]!.stepId : null,
      pivotCrossed: false,
      nextIndex: 0,
    });
    return {kind: 'Registered', sagaId, sagaPlanMerkleHash};
  }

  /**
   * Attempts explicit backward compensation (e.g. operator/recovery trigger).
   * Strictly refuses if Pivot has been crossed OR if any step is PendingUnknownEffect!
   */
  attemptBackwardRollback(
    sagaId: string,
    reason: string,
  ):
    | {kind: 'Compensated'; compensatedStepsInOrder: string[]; receipts: SagaCompensationReceipt[]}
    | {kind: 'Refuted'; reason: 'unknown-saga' | 'rollback-forbidden-past-pivot' | 'pending-unknown-effect-must-reconcile'} {
    const st = this.sagas.get(sagaId);
    if (!st) return {kind: 'Refuted', reason: 'unknown-saga'};
    if (st.pivotCrossed) {
      return {kind: 'Refuted', reason: 'rollback-forbidden-past-pivot'};
    }
    if (st.unknownStep) {
      return {kind: 'Refuted', reason: 'pending-unknown-effect-must-reconcile'};
    }
    const receipts = this.compensateCompletedInReverse(st, reason);
    return {
      kind: 'Compensated',
      compensatedStepsInOrder: receipts.map(r => r.stepId),
      receipts,
    };
  }

  /**
   * Reconciles a fenced `PendingUnknownEffect` after checking the external system:
   *  - `'Committed'`: records the step as completed (advances `nextIndex`) and marks pivot if applicable.
   *  - `'NotApplied'`: clears the fence so the Saga can compensate prior steps cleanly.
   */
  reconcileUnknownEffect(
    sagaId: string,
    resolution: 'Committed' | 'NotApplied',
    externalProofDigest: string,
  ):
    | {kind: 'Reconciled'; stepId: string; resolution: 'Committed' | 'NotApplied'}
    | {kind: 'Refuted'; reason: 'unknown-saga' | 'no-unknown-effect-pending'} {
    const st = this.sagas.get(sagaId);
    if (!st) return {kind: 'Refuted', reason: 'unknown-saga'};
    if (!st.unknownStep) return {kind: 'Refuted', reason: 'no-unknown-effect-pending'};

    const {stepId, index} = st.unknownStep;
    const step = st.steps[index]!;
    this.kv.putBlob(
      'saga-unknown-reconciliation',
      {sagaId, stepId, resolution, externalProofDigest},
      [],
    );

    st.unknownStep = null;
    if (resolution === 'Committed') {
      st.completedStepIds.push(stepId);
      if (step.reversibility === 'PivotIrreversible') {
        st.pivotCrossed = true;
      }
      st.nextIndex = index + 1;
    }
    return {kind: 'Reconciled', stepId, resolution};
  }

  /**
   * Advances Saga execution from `nextIndex` under strict linear budget enforcement.
   */
  runSaga(sagaId: string): SagaRunVerdict {
    const st = this.sagas.get(sagaId);
    if (!st) {
      throw new Error(`Unknown sagaId '${sagaId}'`);
    }
    if (st.unknownStep) {
      return {
        kind: 'PendingUnknownEffect',
        sagaId,
        unknownStepId: st.unknownStep.stepId,
        idempotencyKey: st.unknownStep.idempotencyKey,
        pivotCrossed: st.pivotCrossed,
      };
    }

    while (st.nextIndex < st.steps.length) {
      const idx = st.nextIndex;
      const step = st.steps[idx]!;
      const idempotencyKey = `saga:${sagaId}:step:${step.stepId}:fwd`;

      // 1. Write-ahead M1 intent record BEFORE consuming budget or calling external world:
      const intentHash = this.kv.putBlob(
        'saga-step-intent',
        {
          sagaId,
          stepId: step.stepId,
          agentId: step.agentId,
          reversibility: step.reversibility,
          idempotencyKey,
          compensatorActionName: step.compensatorActionName ?? null,
        },
        [],
      );

      // 2. Linear Budget Conservation gate:
      const spend = this.budget.consume(
        step.agentId,
        step.costUnits,
        `saga:${sagaId}:${step.stepId}`,
        intentHash,
      );
      if (spend.kind === 'BudgetExhaustedHalt') {
        if (st.pivotCrossed) {
          return {
            kind: 'RollForwardRequired',
            sagaId,
            failedPostPivotStepId: step.stepId,
            failureReason: 'budget-exhausted-halt',
            pivotStepId: st.pivotStepId!,
          };
        }
        const receipts = this.compensateCompletedInReverse(st, 'budget-exhausted-halt');
        return {
          kind: 'CompensatedRollback',
          sagaId,
          failedAtStepId: step.stepId,
          failureReason: 'budget-exhausted-halt',
          compensatedStepsInOrder: receipts.map(r => r.stepId),
          compensationReceipts: receipts,
        };
      }

      // 3. Execute external forward step:
      const outcome = step.executeForward(idempotencyKey);
      if (outcome.kind === 'Committed') {
        const commitHash = this.kv.putBlob(
          'saga-step-committed',
          {
            sagaId,
            stepId: step.stepId,
            externalReceiptId: outcome.externalReceiptId,
            reversibility: step.reversibility,
          },
          [intentHash],
        );
        this.kv.pinHistoricalCut(commitHash);
        st.completedStepIds.push(step.stepId);
        if (step.reversibility === 'PivotIrreversible') {
          st.pivotCrossed = true;
        }
        st.nextIndex = idx + 1;
        continue;
      }

      if (outcome.kind === 'UnknownTimeout') {
        st.unknownStep = {stepId: step.stepId, idempotencyKey, index: idx};
        return {
          kind: 'PendingUnknownEffect',
          sagaId,
          unknownStepId: step.stepId,
          idempotencyKey,
          pivotCrossed: st.pivotCrossed,
        };
      }

      // FailedCleanly:
      if (st.pivotCrossed) {
        return {
          kind: 'RollForwardRequired',
          sagaId,
          failedPostPivotStepId: step.stepId,
          failureReason: outcome.errorCode,
          pivotStepId: st.pivotStepId!,
        };
      }
      const receipts = this.compensateCompletedInReverse(st, outcome.errorCode);
      return {
        kind: 'CompensatedRollback',
        sagaId,
        failedAtStepId: step.stepId,
        failureReason: outcome.errorCode,
        compensatedStepsInOrder: receipts.map(r => r.stepId),
        compensationReceipts: receipts,
      };
    }

    const finalReceiptHash = this.kv.putBlob(
      'saga-completed-receipt',
      {
        sagaId,
        completedSteps: st.completedStepIds,
        pivotCrossed: st.pivotCrossed,
        digest: sha256Digest(st.completedStepIds),
      },
      [],
    );
    this.kv.pinHistoricalCut(finalReceiptHash);

    return {
      kind: 'Completed',
      sagaId,
      completedSteps: [...st.completedStepIds],
      pivotCrossed: st.pivotCrossed,
      finalReceiptHash,
    };
  }

  private compensateCompletedInReverse(
    st: SagaRuntimeState,
    reason: string,
  ): SagaCompensationReceipt[] {
    const receipts: SagaCompensationReceipt[] = [];
    for (let i = st.completedStepIds.length - 1; i >= 0; i--) {
      const stepId = st.completedStepIds[i]!;
      if (st.compensatedStepIds.includes(stepId)) continue;
      const spec = st.steps.find(s => s.stepId === stepId);
      if (!spec || spec.reversibility !== 'Compensable' || !spec.executeCompensate) continue;

      const compKey = `saga:${st.sagaId}:step:${stepId}:comp`;
      const res = spec.executeCompensate(compKey);
      if (res.compensated) {
        const receiptMerkleHash = this.kv.putBlob(
          'saga-compensation-receipt',
          {
            sagaId: st.sagaId,
            stepId,
            compensatorActionName: spec.compensatorActionName,
            compensationIdempotencyKey: compKey,
            reason,
          },
          [],
        );
        this.kv.pinHistoricalCut(receiptMerkleHash);
        st.compensatedStepIds.push(stepId);
        receipts.push({
          stepId,
          compensationIdempotencyKey: compKey,
          receiptMerkleHash,
        });
      }
    }
    return receipts;
  }
}
