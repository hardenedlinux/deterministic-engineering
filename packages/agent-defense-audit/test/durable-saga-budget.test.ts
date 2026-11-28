// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from '../src/durable-merkle-store.ts';
import {
  DurableAgentSagaEngine,
  LinearBudgetTree,
} from '../src/durable-saga-budget.ts';

describe('Phase 15 Durable Compensable Multi-Agent Sagas & Linear Budget Conservation (10.163 / 30.05 AG81-AG85)', () => {
  test('AG81: Write-ahead compensation executes deterministic reverse-order rollback on pre-pivot failure', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 100);
    const engine = new DurableAgentSagaEngine(kv, budget);

    // Rejects a compensable step lacking a write-ahead compensator spec!
    expect(
      engine.registerSaga('bad-no-comp', [
        {
          stepId: 's1',
          agentId: 'coordinator',
          reversibility: 'Compensable',
          costUnits: 10,
          executeForward: () => ({kind: 'Committed', externalReceiptId: 'r1'}),
        },
      ]),
    ).toEqual({kind: 'Refuted', reason: 'missing-write-ahead-compensator'});

    const compLog: string[] = [];
    const reg = engine.registerSaga('saga-cloud-deploy', [
      {
        stepId: 'provision-iam',
        agentId: 'coordinator',
        reversibility: 'Compensable',
        costUnits: 10,
        compensatorActionName: 'destroy-iam',
        executeForward: key => ({kind: 'Committed', externalReceiptId: `iam:${key}`}),
        executeCompensate: key => {
          compLog.push(`destroy-iam:${key}`);
          return {compensated: true};
        },
      },
      {
        stepId: 'reserve-gpu',
        agentId: 'coordinator',
        reversibility: 'Compensable',
        costUnits: 15,
        compensatorActionName: 'release-gpu',
        executeForward: key => ({kind: 'Committed', externalReceiptId: `gpu:${key}`}),
        executeCompensate: key => {
          compLog.push(`release-gpu:${key}`);
          return {compensated: true};
        },
      },
      {
        stepId: 'wire-settlement-pivot',
        agentId: 'coordinator',
        reversibility: 'PivotIrreversible',
        costUnits: 20,
        executeForward: () => ({kind: 'FailedCleanly', errorCode: 'bank-gateway-503'}),
      },
    ]);
    expect(reg.kind).toBe('Registered');

    const res = engine.runSaga('saga-cloud-deploy');
    expect(res.kind).toBe('CompensatedRollback');
    if (res.kind === 'CompensatedRollback') {
      expect(res.failedAtStepId).toBe('wire-settlement-pivot');
      // Strict reverse order: reserve-gpu compensated BEFORE provision-iam!
      expect(res.compensatedStepsInOrder).toEqual(['reserve-gpu', 'provision-iam']);
      expect(compLog).toEqual([
        'release-gpu:saga:saga-cloud-deploy:step:reserve-gpu:comp',
        'destroy-iam:saga:saga-cloud-deploy:step:provision-iam:comp',
      ]);
      for (const r of res.compensationReceipts) {
        expect(kv.hasBlob(r.receiptMerkleHash)).toBe(true);
      }
    }
    expect(budget.conservationAudit().conserved).toBe(true);
  });

  test('AG82: Pivot point-of-no-return enforces at-most-one pivot, forbids backward rollback past pivot, and completes via roll-forward', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 100);
    const engine = new DurableAgentSagaEngine(kv, budget);

    // At-most-one pivot enforced structurally:
    expect(
      engine.registerSaga('two-pivots', [
        {
          stepId: 'p1',
          agentId: 'coordinator',
          reversibility: 'PivotIrreversible',
          costUnits: 10,
          executeForward: () => ({kind: 'Committed', externalReceiptId: 'ok1'}),
        },
        {
          stepId: 'p2',
          agentId: 'coordinator',
          reversibility: 'PivotIrreversible',
          costUnits: 10,
          executeForward: () => ({kind: 'Committed', externalReceiptId: 'ok2'}),
        },
      ]),
    ).toEqual({kind: 'Refuted', reason: 'multiple-pivots-forbidden'});

    let notifyAttempts = 0;
    engine.registerSaga('saga-wire-transfer', [
      {
        stepId: 'hold-funds',
        agentId: 'coordinator',
        reversibility: 'Compensable',
        costUnits: 10,
        compensatorActionName: 'release-hold',
        executeForward: () => ({kind: 'Committed', externalReceiptId: 'hold-1'}),
        executeCompensate: () => ({compensated: true}),
      },
      {
        stepId: 'broadcast-wire',
        agentId: 'coordinator',
        reversibility: 'PivotIrreversible',
        costUnits: 10,
        executeForward: () => ({kind: 'Committed', externalReceiptId: 'wire-tx-999'}),
      },
      {
        stepId: 'send-receipt-webhook',
        agentId: 'coordinator',
        reversibility: 'ReadOnlyIdempotent',
        costUnits: 5,
        executeForward: () => {
          notifyAttempts++;
          if (notifyAttempts === 1) {
            return {kind: 'FailedCleanly', errorCode: 'webhook-transient-502'};
          }
          return {kind: 'Committed', externalReceiptId: 'webhook-ok'};
        },
      },
    ]);

    // Post-pivot failure MUST return RollForwardRequired (NEVER backward rollback!):
    const firstRun = engine.runSaga('saga-wire-transfer');
    expect(firstRun).toEqual({
      kind: 'RollForwardRequired',
      sagaId: 'saga-wire-transfer',
      failedPostPivotStepId: 'send-receipt-webhook',
      failureReason: 'webhook-transient-502',
      pivotStepId: 'broadcast-wire',
    });

    // Explicit backward rollback attempt past crossed pivot MUST be refuted!
    expect(engine.attemptBackwardRollback('saga-wire-transfer', 'operator-panic')).toEqual({
      kind: 'Refuted',
      reason: 'rollback-forbidden-past-pivot',
    });

    // Durable roll-forward retries ONLY the post-pivot idempotent step and finishes!
    const secondRun = engine.runSaga('saga-wire-transfer');
    expect(secondRun.kind).toBe('Completed');
    if (secondRun.kind === 'Completed') {
      expect(secondRun.pivotCrossed).toBe(true);
      expect(secondRun.completedSteps).toEqual([
        'hold-funds',
        'broadcast-wire',
        'send-receipt-webhook',
      ]);
    }
  });

  test('AG83: PendingUnknownEffect crash fence blocks both blind retry and premature compensation until external reconciliation', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 100);
    const engine = new DurableAgentSagaEngine(kv, budget);

    let step1Calls = 0;
    const compCalls: string[] = [];

    engine.registerSaga('saga-timeout-fence', [
      {
        stepId: 'reserve-seat',
        agentId: 'coordinator',
        reversibility: 'Compensable',
        costUnits: 10,
        compensatorActionName: 'cancel-seat',
        executeForward: key => {
          step1Calls++;
          return {kind: 'UnknownTimeout', intentDigest: key};
        },
        executeCompensate: key => {
          compCalls.push(key);
          return {compensated: true};
        },
      },
      {
        stepId: 'issue-ticket',
        agentId: 'coordinator',
        reversibility: 'PivotIrreversible',
        costUnits: 10,
        executeForward: () => ({kind: 'FailedCleanly', errorCode: 'price-changed'}),
      },
    ]);

    const r1 = engine.runSaga('saga-timeout-fence');
    expect(r1.kind).toBe('PendingUnknownEffect');
    expect(step1Calls).toBe(1);

    // Blind retry MUST NOT re-invoke `executeForward`!
    const r2 = engine.runSaga('saga-timeout-fence');
    expect(r2.kind).toBe('PendingUnknownEffect');
    expect(step1Calls).toBe(1);

    // Premature rollback while step outcome is Unknown MUST be refused!
    expect(engine.attemptBackwardRollback('saga-timeout-fence', 'blind-cancel')).toEqual({
      kind: 'Refuted',
      reason: 'pending-unknown-effect-must-reconcile',
    });
    expect(compCalls.length).toBe(0);

    // Reconcile as 'Committed' -> Saga resumes, step 2 fails cleanly -> step 1 compensated cleanly!
    expect(engine.reconcileUnknownEffect('saga-timeout-fence', 'Committed', 'ext-proof-ok')).toEqual({
      kind: 'Reconciled',
      stepId: 'reserve-seat',
      resolution: 'Committed',
    });
    const r3 = engine.runSaga('saga-timeout-fence');
    expect(r3.kind).toBe('CompensatedRollback');
    expect(compCalls).toEqual(['saga:saga-timeout-fence:step:reserve-seat:comp']);
  });

  test('AG84: Linear resource budget strictly conserves root budget across multi-agent delegation and blocks R3 serialization', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 100);

    // R3: Non-serializable live M3 budget tree cannot leak into M1 storage!
    expect(() => kv.putBlob('budget-leak', {budget}, [])).toThrow(/R3 ReachabilityLeakError/);

    expect(budget.splitSubBudget('coordinator', 'sub-agent-a', 40)).toEqual({
      kind: 'Allocated',
      childId: 'sub-agent-a',
      allocatedUnits: 40,
      parentRemaining: 60,
    });
    expect(budget.splitSubBudget('coordinator', 'sub-agent-b', 35)).toEqual({
      kind: 'Allocated',
      childId: 'sub-agent-b',
      allocatedUnits: 35,
      parentRemaining: 25,
    });
    // Over-allocation (30 > 25 remaining) deterministically refused:
    expect(budget.splitSubBudget('coordinator', 'sub-agent-c', 30)).toEqual({
      kind: 'Refuted',
      reason: 'insufficient-parent-budget',
    });

    // Sub-agent-a spends 25, then tries to spend 20 (only 15 left) -> BudgetExhaustedHalt!
    const m1WorkHash = kv.putBlob('sub-a-partial-work', {progress: 'step-1-done'}, []);
    kv.pinHistoricalCut(m1WorkHash);
    expect(budget.consume('sub-agent-a', 25, 'llm-step-1', m1WorkHash).kind).toBe('Consumed');
    expect(budget.consume('sub-agent-a', 20, 'runaway-loop', m1WorkHash)).toEqual({
      kind: 'BudgetExhaustedHalt',
      agentId: 'sub-agent-a',
      requestedUnits: 20,
      remainingUnits: 15,
    });

    // Exact linear conservation law: totalRemaining (25 + 15 + 35 = 75) + totalSpent (25) === 100!
    const audit = budget.conservationAudit();
    expect(audit).toEqual({
      rootBudgetUnits: 100,
      totalRemaining: 75,
      totalSpent: 25,
      conserved: true,
    });
    // Committed M1 partial progress survives halt & GC!
    kv.gcUnreferenced();
    expect(kv.hasBlob(m1WorkHash)).toBe(true);
  });

  test('AG85: Budget exhaustion mid-saga triggers clean reverse compensation while preserving linear budget conservation', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 25);
    budget.splitSubBudget('coordinator', 'worker-a', 15);
    budget.splitSubBudget('coordinator', 'worker-b', 10);

    const engine = new DurableAgentSagaEngine(kv, budget);
    const compensated: string[] = [];

    engine.registerSaga('saga-budget-halt', [
      {
        stepId: 'alloc-storage',
        agentId: 'worker-a',
        reversibility: 'Compensable',
        costUnits: 15,
        compensatorActionName: 'free-storage',
        executeForward: () => ({kind: 'Committed', externalReceiptId: 'vol-1'}),
        executeCompensate: () => {
          compensated.push('alloc-storage');
          return {compensated: true};
        },
      },
      {
        stepId: 'expensive-gpu-train',
        agentId: 'worker-b',
        reversibility: 'PivotIrreversible',
        costUnits: 20, // Exceeds worker-b's 10-unit linear sub-budget!
        executeForward: () => ({kind: 'Committed', externalReceiptId: 'should-never-run'}),
      },
    ]);

    const res = engine.runSaga('saga-budget-halt');
    expect(res.kind).toBe('CompensatedRollback');
    if (res.kind === 'CompensatedRollback') {
      expect(res.failureReason).toBe('budget-exhausted-halt');
      expect(res.compensatedStepsInOrder).toEqual(['alloc-storage']);
    }
    expect(compensated).toEqual(['alloc-storage']);
    expect(budget.conservationAudit()).toEqual({
      rootBudgetUnits: 25,
      totalRemaining: 10,
      totalSpent: 15,
      conserved: true,
    });
  });
});
