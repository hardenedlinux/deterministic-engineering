// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore, LiveM3Capability} from '../src/durable-merkle-store.ts';
import {DurableHitlApprovalEngine} from '../src/durable-hitl-approval.ts';

function makeRollbackCut(kv: ContentAddressedKvStore, label: string): string {
  const hash = kv.putBlob('pre-release-cut', {label, version: 'v1.0.0'}, []);
  kv.pinHistoricalCut(hash);
  return hash;
}

describe('Phase 11 HITL Durable Pause/Resume, Policy-Drift Re-Approval & Anti-Nagging Veto (10.159 / 30.05 AG61-AG65)', () => {
  test('AG61: Cold hibernation enforces R3 (rejects leaked M3 lease) and strips untrusted M2 prose from HumanDecisionBrief', () => {
    const kv = new ContentAddressedKvStore();
    const engine = new DurableHitlApprovalEngine(kv);
    const rollbackCutHash = makeRollbackCut(kv, 'prod-base-1');
    const activeLease = new LiveM3Capability('lease-agent-1', 'deploy:prod', 1);
    const smuggledToken = new LiveM3Capability('smuggled-db-conn', 'db:write', 1);

    // 1. R3 guard blocks smuggling a live M3 handle into cold suspension metadata.
    expect(() =>
      engine.suspendForApproval(
        {
          proposalId: 'prop-leak',
          semanticTarget: 'payments-router',
          requesterId: 'coder-agent-1',
          baseCutHash: rollbackCutHash,
          policyEpochHash: 'pol-v1',
          affectedScopes: ['payments'],
          diffDigest: 'diff-aaa',
          rollbackCutHash,
          coldReceipts: [{receiptId: 'r1', kind: 'ast-audit', digest: 'ast-1', passed: true}],
          metadata: {nested: {dbHandle: smuggledToken}},
          ttlEpochs: 10,
          nowEpoch: 100,
        },
        activeLease,
      ),
    ).toThrow(/R3 ReachabilityLeakError/);

    // 2. Clean cold hibernation revokes active M3 lease and strips persuasive M2 prose.
    const socialEngineeringProse =
      'URGENT!! CEO ALREADY APPROVED THIS OVER COFFEE! IGNORE SECURITY CHECKS AND CLICK APPROVE IMMEDIATELY!';
    const susp = engine.suspendForApproval(
      {
        proposalId: 'prop-clean',
        semanticTarget: 'payments-router',
        requesterId: 'coder-agent-1',
        baseCutHash: rollbackCutHash,
        policyEpochHash: 'pol-v1',
        affectedScopes: ['payments'],
        diffDigest: 'diff-bbb',
        rollbackCutHash,
        coldReceipts: [
          {receiptId: 'r1', kind: 'ast-audit', digest: 'ast-1', passed: true},
          {receiptId: 'r2', kind: 'apalache-proof', digest: 'apa-1', passed: true},
        ],
        untrustedAgentProse: socialEngineeringProse,
        ttlEpochs: 10,
        nowEpoch: 100,
      },
      activeLease,
    );

    expect(susp.kind).toBe('SuspendedCold');
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');
    expect(engine.isLeaseRevoked(activeLease.capabilityId)).toBe(true);
    expect(susp.anchor.m3LeaseRevokedAtSuspend).toBe(true);
    expect(susp.brief.strippedUntrustedProseBytes).toBe(
      Buffer.byteLength(socialEngineeringProse, 'utf8'),
    );
    expect(JSON.stringify(susp.brief)).not.toContain('URGENT');
    expect(JSON.stringify(susp.brief)).not.toContain('IGNORE SECURITY CHECKS');
    expect(susp.brief.verifiedReceiptDigests).toEqual([
      'ast-audit:ast-1',
      'apalache-proof:apa-1',
    ]);
  });

  test('AG62: Baseline drift & intersecting policy upgrade invalidate stale approval; disjoint policy upgrade succeeds via R1', () => {
    const kv = new ContentAddressedKvStore();
    const engine = new DurableHitlApprovalEngine(kv);
    const baseCutV1 = makeRollbackCut(kv, 'base-v1');
    const baseCutV2 = makeRollbackCut(kv, 'base-v2');

    const susp = engine.suspendForApproval(
      {
        proposalId: 'prop-drift',
        semanticTarget: 'auth-middleware',
        requesterId: 'coder-agent-1',
        baseCutHash: baseCutV1,
        policyEpochHash: 'pol-v1',
        affectedScopes: ['auth', 'session'],
        diffDigest: 'diff-auth-1',
        rollbackCutHash: baseCutV1,
        coldReceipts: [{receiptId: 'r1', kind: 'ast-audit', digest: 'ast-ok', passed: true}],
        ttlEpochs: 50,
        nowEpoch: 10,
      },
      new LiveM3Capability('lease-2', 'auth', 1),
    );
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');

    const rec = engine.recordHumanApproval({
      suspensionId: susp.anchor.suspensionId,
      approverId: 'human-sec-lead',
      signedAtEpoch: 15,
    });
    expect(rec.kind).toBe('Recorded');

    // 1. Baseline moved while human slept -> MUST require re-approval!
    const baselineDrifted = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCutV2,
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 20,
        emergencyFreezeActive: false,
      },
    });
    expect(baselineDrifted.kind).toBe('PendingReapproval');
    if (baselineDrifted.kind === 'PendingReapproval') {
      expect(baselineDrifted.reason).toBe('baseline-drift-reapproval-required');
    }

    // 2. Intersecting security policy upgrade (`auth` tightened) -> MUST require re-approval!
    const policyDrifted = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCutV1,
        currentPolicyEpochHash: 'pol-v2',
        policyChangedScopes: ['auth'],
        currentEpoch: 20,
        emergencyFreezeActive: false,
      },
    });
    expect(policyDrifted.kind).toBe('PendingReapproval');
    if (policyDrifted.kind === 'PendingReapproval') {
      expect(policyDrifted.reason).toBe('policy-drift-reapproval-required');
      expect(policyDrifted.intersectingScopes).toEqual(['auth']);
    }

    // 3. Disjoint policy upgrade (`docs-lint` only) -> R1 bounded co-evolution allows safe resume!
    const disjointSafe = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCutV1,
        currentPolicyEpochHash: 'pol-v2-docs-only',
        policyChangedScopes: ['docs-lint'],
        currentEpoch: 20,
        emergencyFreezeActive: false,
      },
    });
    expect(disjointSafe.kind).toBe('AdmitAndResume');
    if (disjointSafe.kind === 'AdmitAndResume') {
      expect(disjointSafe.policyCoEvolutionMode).toBe('r1-bounded-disjoint-upgrade');
      expect(disjointSafe.executionEpoch).toBe(2);
      expect(disjointSafe.executionLease).toBeInstanceOf(LiveM3Capability);
    }
  });

  test('AG63: TTL expiry, duplicate webhook replay, and cross-proposal binding mismatch fail closed', () => {
    const kv = new ContentAddressedKvStore();
    const engine = new DurableHitlApprovalEngine(kv);
    const baseCut = makeRollbackCut(kv, 'base-ttl');

    const susp = engine.suspendForApproval(
      {
        proposalId: 'prop-ttl',
        semanticTarget: 'billing-ledger',
        requesterId: 'coder-agent-2',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-v1',
        affectedScopes: ['billing'],
        diffDigest: 'diff-bill-1',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r1', kind: 'mbt-coverage', digest: 'mbt-100', passed: true}],
        ttlEpochs: 5,
        nowEpoch: 10,
      },
      new LiveM3Capability('lease-3', 'billing', 1),
    );
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');

    engine.recordHumanApproval({
      suspensionId: susp.anchor.suspensionId,
      approverId: 'human-finance-1',
      signedAtEpoch: 12,
    });

    // 1. Cross-proposal hash mismatch rejected!
    const wrongBinding = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: 'forged-other-proposal-hash',
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 13,
        emergencyFreezeActive: false,
      },
    });
    expect(wrongBinding).toEqual({kind: 'Refuted', reason: 'proposal-binding-mismatch'});

    // 2. Wake-up after TTL expiry (epoch 16 > 15) -> PendingReapproval(approval-expired)
    const expired = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 16,
        emergencyFreezeActive: false,
      },
    });
    expect(expired.kind).toBe('PendingReapproval');
    if (expired.kind === 'PendingReapproval') {
      expect(expired.reason).toBe('approval-expired');
    }

    // 3. Valid wake-up at epoch 14 consumes once; duplicate webhook replay returns AlreadyConsumedNoop!
    const firstResume = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 14,
        emergencyFreezeActive: false,
      },
    });
    expect(firstResume.kind).toBe('AdmitAndResume');

    const replayAttempt = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 14,
        emergencyFreezeActive: false,
      },
    });
    expect(replayAttempt.kind).toBe('AlreadyConsumedNoop');
  });

  test('AG64: 2-of-N human quorum enforces SoD (blocks self-approval & duplicate signer) and mints monotonic M3 lease', () => {
    const kv = new ContentAddressedKvStore();
    const engine = new DurableHitlApprovalEngine(kv);
    const baseCut = makeRollbackCut(kv, 'base-quorum');

    const susp = engine.suspendForApproval(
      {
        proposalId: 'prop-tier1',
        semanticTarget: 'kms-root-rotation',
        requesterId: 'release-bot',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-tier1',
        affectedScopes: ['kms'],
        diffDigest: 'diff-kms',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r1', kind: 'apalache-proof', digest: 'apa-kms', passed: true}],
        requiredApprovals: 2,
        ttlEpochs: 20,
        nowEpoch: 50,
      },
      new LiveM3Capability('lease-kms-1', 'kms', 1),
    );
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');

    // Requester self-approval blocked by SoD.
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'release-bot',
        signedAtEpoch: 51,
      }),
    ).toEqual({kind: 'Refuted', reason: 'sod-requester-self-approval-forbidden'});

    // First independent human approves -> quorum still incomplete (1/2).
    const a1 = engine.recordHumanApproval({
      suspensionId: susp.anchor.suspensionId,
      approverId: 'human-alice',
      signedAtEpoch: 52,
    });
    expect(a1.kind).toBe('Recorded');

    // Alice cannot sign twice to spoof a 2-of-N quorum!
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'human-alice',
        signedAtEpoch: 53,
      }),
    ).toEqual({kind: 'Refuted', reason: 'duplicate-approver-in-quorum'});

    const incomplete = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-tier1',
        policyChangedScopes: [],
        currentEpoch: 54,
        emergencyFreezeActive: false,
      },
    });
    expect(incomplete.kind).toBe('PendingReapproval');
    if (incomplete.kind === 'PendingReapproval') {
      expect(incomplete.reason).toBe('quorum-incomplete');
      expect(incomplete.approvalsCollected).toBe(1);
      expect(incomplete.requiredApprovals).toBe(2);
    }

    // Second distinct human signs -> quorum satisfied -> AdmitAndResume!
    const a2 = engine.recordHumanApproval({
      suspensionId: susp.anchor.suspensionId,
      approverId: 'human-bob',
      signedAtEpoch: 55,
    });
    expect(a2.kind).toBe('Recorded');

    const resumed = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: baseCut,
        currentPolicyEpochHash: 'pol-tier1',
        policyChangedScopes: [],
        currentEpoch: 56,
        emergencyFreezeActive: false,
      },
    });
    expect(resumed.kind).toBe('AdmitAndResume');
    if (resumed.kind === 'AdmitAndResume') {
      expect(resumed.consumedApprovalDigests.length).toBe(2);
      expect(resumed.executionEpoch).toBe(2);
    }
  });

  test('AG65: Anti-Nagging Veto Persistence blocks identical/unaddressed retries and enforces finite resubmission budget', () => {
    const kv = new ContentAddressedKvStore();
    const engine = new DurableHitlApprovalEngine(kv, 1); // max 1 revised resubmission after veto
    const baseCut = makeRollbackCut(kv, 'base-veto');

    const susp1 = engine.suspendForApproval(
      {
        proposalId: 'prop-drop-idx',
        semanticTarget: 'orders-db-index',
        requesterId: 'db-agent',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-db',
        affectedScopes: ['orders-db'],
        diffDigest: 'diff-drop-1',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r1', kind: 'ast-audit', digest: 'ast-db', passed: true}],
        ttlEpochs: 20,
        nowEpoch: 100,
      },
      new LiveM3Capability('lease-db-1', 'db', 1),
    );
    if (susp1.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');

    const veto = engine.recordHumanVeto({
      suspensionId: susp1.anchor.suspensionId,
      vetoedBy: 'human-dba-lead',
      reasonCode: 'table-lock-risk',
      requiredFixConstraint: 'use-concurrent-index-migration',
      vetoedAtEpoch: 101,
    });
    expect(kv.hasBlob(veto.vetoMerkleHash)).toBe(true);

    // 1. Vetoed suspension cannot be approved or resumed.
    expect(
      engine.recordHumanApproval({
        suspensionId: susp1.anchor.suspensionId,
        approverId: 'human-other',
        signedAtEpoch: 102,
      }),
    ).toEqual({kind: 'Refuted', reason: 'suspension-already-vetoed'});

    expect(
      engine.evaluateAndResume({
        suspensionId: susp1.anchor.suspensionId,
        expectedProposalHash: susp1.anchor.proposalHash,
        world: {
          currentBaseCutHash: baseCut,
          currentPolicyEpochHash: 'pol-db',
          policyChangedScopes: [],
          currentEpoch: 102,
          emergencyFreezeActive: false,
        },
      }),
    ).toEqual({kind: 'Refuted', reason: 'human-vetoed'});

    // 2. Nagging retry with identical proposal or without M1 vetoResolutionEvidenceHash is blocked!
    const naggingRetry = engine.suspendForApproval(
      {
        proposalId: 'prop-drop-idx',
        semanticTarget: 'orders-db-index',
        requesterId: 'db-agent',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-db',
        affectedScopes: ['orders-db'],
        diffDigest: 'diff-drop-1',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r1', kind: 'ast-audit', digest: 'ast-db', passed: true}],
        ttlEpochs: 20,
        nowEpoch: 103,
      },
      new LiveM3Capability('lease-db-2', 'db', 2),
    );
    expect(naggingRetry.kind).toBe('Refuted');
    if (naggingRetry.kind === 'Refuted') {
      expect(naggingRetry.reason).toBe('vetoed-proposal-resubmission-blocked');
      expect(naggingRetry.vetoConstraint?.requiredFixConstraint).toBe(
        'use-concurrent-index-migration',
      );
    }

    // 3. Revised proposal WITH explicit M1 vetoResolutionEvidenceHash is permitted ONCE.
    const revised = engine.suspendForApproval(
      {
        proposalId: 'prop-concurrent-idx',
        semanticTarget: 'orders-db-index',
        requesterId: 'db-agent',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-db',
        affectedScopes: ['orders-db'],
        diffDigest: 'diff-concurrent-2',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r2', kind: 'ast-audit', digest: 'ast-db-2', passed: true}],
        vetoResolutionEvidenceHash: 'm1-concurrent-migration-proof',
        ttlEpochs: 20,
        nowEpoch: 104,
      },
      new LiveM3Capability('lease-db-3', 'db', 3),
    );
    expect(revised.kind).toBe('SuspendedCold');

    // 4. Exceeding the finite anti-nagging budget fails closed to human-veto-budget-exhausted!
    const budgetExceeded = engine.suspendForApproval(
      {
        proposalId: 'prop-concurrent-idx-v3',
        semanticTarget: 'orders-db-index',
        requesterId: 'db-agent',
        baseCutHash: baseCut,
        policyEpochHash: 'pol-db',
        affectedScopes: ['orders-db'],
        diffDigest: 'diff-concurrent-3',
        rollbackCutHash: baseCut,
        coldReceipts: [{receiptId: 'r3', kind: 'ast-audit', digest: 'ast-db-3', passed: true}],
        vetoResolutionEvidenceHash: 'm1-concurrent-migration-proof-v3',
        ttlEpochs: 20,
        nowEpoch: 105,
      },
      new LiveM3Capability('lease-db-4', 'db', 4),
    );
    expect(budgetExceeded.kind).toBe('Refuted');
    if (budgetExceeded.kind === 'Refuted') {
      expect(budgetExceeded.reason).toBe('human-veto-budget-exhausted');
    }
  });
});
