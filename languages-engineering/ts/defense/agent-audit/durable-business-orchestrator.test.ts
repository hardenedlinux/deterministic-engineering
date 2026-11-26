// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {
  AeadPartitionKey,
  CapabilityPartitionedAeadStore,
  ContentAddressedKvStore,
} from './durable-merkle-store.ts';
import {runGovernedAgentRepairLoop} from './governance-harness.ts';
import {
  AutonomousReleaseOrchestrator,
  RegulatedMultiTenantDecisionEngine,
} from './durable-business-orchestrator.ts';

function admittedReleaseTranscript() {
  return runGovernedAgentRepairLoop({
    patchId: 'rel-hotfix-101',
    baseFiles: {'src/rate-limit.ts': 'export const max = 100;\n'},
    scopePolicy: {allowedPaths: ['src/**']},
    maxRepairAttempts: 2,
    proposeAttempt: () => ({
      proseClaim: 'Adjusted bounded rate limit.',
      files: {'src/rate-limit.ts': 'export const max = 80;\n'},
    }),
    runIndependentOracle: () => ({passed: true, detail: 'unit & property checks pass'}),
  });
}

describe('Phase 10 Durable AI Business Extensions: SoD Release & Regulated Multi-Tenant Replay (10.158 / 30.05 AG56-AG60)', () => {
  test('AG56-AG58 (B1): SoD blocks self-approval, freeze/unpinned gates fail closed, and canary breach rolls back with forensic preservation', () => {
    const kv = new ContentAddressedKvStore();
    const orch = new AutonomousReleaseOrchestrator(kv);
    const transcript = admittedReleaseTranscript();
    const preCut = orch.pinPreReleaseCut('rel-101', {service: 'gateway', version: 'v1.4.2'});

    // AG56a: Author self-approval MUST be refused (Separation of Duties)
    const selfApprove = orch.promoteToProduction({
      releaseId: 'rel-101',
      authorId: 'coder-agent-1',
      approverId: 'coder-agent-1',
      workerEpoch: 1,
      transcript,
      preReleaseCutHash: preCut,
      canarySloStatus: 'Healthy',
      emergencyFreezeActive: false,
      artifactDigest: 'sha256-rel-101',
    });
    expect(selfApprove).toEqual({kind: 'Refuted', reason: 'sod-self-approval-forbidden'});

    // AG57a: Unpinned release refused
    const unpinned = orch.promoteToProduction({
      releaseId: 'rel-101',
      authorId: 'coder-agent-1',
      approverId: 'human-release-mgr',
      workerEpoch: 1,
      transcript,
      preReleaseCutHash: null,
      canarySloStatus: 'Healthy',
      emergencyFreezeActive: false,
      artifactDigest: 'sha256-rel-101',
    });
    expect(unpinned).toEqual({kind: 'Refuted', reason: 'missing-pinned-rollback-cut'});

    // AG57b: Emergency freeze refused & PendingScope canary stays pending (never silently promoted)
    expect(
      orch.promoteToProduction({
        releaseId: 'rel-101',
        authorId: 'coder-agent-1',
        approverId: 'human-release-mgr',
        workerEpoch: 1,
        transcript,
        preReleaseCutHash: preCut,
        canarySloStatus: 'Healthy',
        emergencyFreezeActive: true,
        artifactDigest: 'sha256-rel-101',
      }),
    ).toEqual({kind: 'Refuted', reason: 'emergency-freeze-active'});
    expect(
      orch.promoteToProduction({
        releaseId: 'rel-101',
        authorId: 'coder-agent-1',
        approverId: 'human-release-mgr',
        workerEpoch: 1,
        transcript,
        preReleaseCutHash: preCut,
        canarySloStatus: 'PendingScope',
        emergencyFreezeActive: false,
        artifactDigest: 'sha256-rel-101',
      }),
    ).toEqual({kind: 'PendingScope', reason: 'canary-slo-pending'});

    // AG56b: Valid SoD + pinned cut + healthy canary promotes cleanly
    const promoted = orch.promoteToProduction({
      releaseId: 'rel-101',
      authorId: 'coder-agent-1',
      approverId: 'human-release-mgr',
      workerEpoch: 1,
      transcript,
      preReleaseCutHash: preCut,
      canarySloStatus: 'Healthy',
      emergencyFreezeActive: false,
      artifactDigest: 'sha256-rel-101',
    });
    expect(promoted.kind).toBe('Proven');
    if (promoted.kind !== 'Proven') throw new Error('expected Proven');

    // AG58: Canary SLO breach triggers deterministic rollback to pinned M1 cut, bumps fencing epoch,
    // fences stalled epoch-1 workers, and preserves forensic evidence across GC!
    const scratch = kv.putBlob('ephemeral-rollout-scratch', {tmp: true});
    const rb = orch.rollbackToPinnedCut('rel-101', 'p99-latency-slo-breach');
    expect(rb.restoredPreReleaseCutHash).toBe(preCut);
    expect(rb.failedReleaseForensicHash).toBe(promoted.releaseRootHash);
    expect(rb.newFencingEpoch).toBe(2);
    expect(orch.getActiveProdCutHash()).toBe(preCut);

    // Stalled worker from epoch 1 is fenced out:
    expect(
      orch.promoteToProduction({
        releaseId: 'rel-101',
        authorId: 'coder-agent-1',
        approverId: 'human-release-mgr',
        workerEpoch: 1,
        transcript,
        preReleaseCutHash: preCut,
        canarySloStatus: 'Healthy',
        emergencyFreezeActive: false,
        artifactDigest: 'sha256-rel-101',
      }),
    ).toEqual({kind: 'Refuted', reason: 'fenced-stale-release-epoch'});

    // GC sweeps scratch while keeping 100% of pre-release cut & failed rollout forensics intact:
    const gc = kv.gcUnreferenced();
    expect(gc.removed).toBe(1);
    expect(kv.hasBlob(scratch)).toBe(false);
    expect(kv.hasBlob(preCut)).toBe(true);
    expect(kv.hasBlob(promoted.releaseRootHash)).toBe(true);
  });

  test('AG59-AG60 (B2): Multi-tenant AEAD isolation blocks cross-tenant reads & pinned cuts enable deterministic regulatory replay after GC', () => {
    const kv = new ContentAddressedKvStore();
    const aead = new CapabilityPartitionedAeadStore();
    const engine = new RegulatedMultiTenantDecisionEngine(kv, aead);

    const alphaKey = new AeadPartitionKey('tenant-alpha');
    const betaKey = new AeadPartitionKey('tenant-beta');

    const decisionRoot = engine.recordRegulatedDecision(
      alphaKey,
      'claim-4921',
      {applicantId: 'acct-8821', amountUsd: 125000, riskScore: 0.18},
      'underwriting-policy-2026-v3',
      'gemini-pro-pinned',
      'Approved',
      'Passed solvency and sanctions oracle checks',
    );
    const scratch = kv.putBlob('transient-chat-scratch', {raw: 'discarded-after-compaction'});

    // AG59: Tenant Beta CANNOT decrypt or replay Tenant Alpha's regulated decision!
    expect(engine.replayDecisionAudit(betaKey, decisionRoot)).toEqual({
      kind: 'Refuted',
      reason: 'unauthorized-partition-key',
    });

    // AG60: After GC sweeps transient scratch & chat history is gone, Tenant Alpha reproduces
    // the exact input, policy version, model ID, and verdict with cryptographic integrity!
    const gc = kv.gcUnreferenced();
    expect(gc.removed).toBe(1);
    expect(kv.hasBlob(scratch)).toBe(false);

    const replay = engine.replayDecisionAudit<{applicantId: string; amountUsd: number; riskScore: number}>(
      alphaKey,
      decisionRoot,
    );
    expect(replay.kind).toBe('Proven');
    if (replay.kind === 'Proven') {
      expect(replay.integrityVerified).toBe(true);
      expect(replay.proof.policyDigest).toBe('underwriting-policy-2026-v3');
      expect(replay.proof.verdict).toBe('Approved');
      expect(replay.decryptedInput).toEqual({applicantId: 'acct-8821', amountUsd: 125000, riskScore: 0.18});
    }
  });
});
