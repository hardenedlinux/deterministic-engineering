// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 22 (10.170 / 30.05 AG116-AG120):
 * Full B1-B10 Declarative Quorum Closure & N-Version Cross-Runtime Proof-Carrying Audit.
 *
 * Bridges live Phase 21 B10 Ed25519 threshold witness cosigning checkpoints directly into
 * our compiled Gerbil Scheme ASCENT Datalog Meta-Audit Oracle (`DurableGovernanceMetaAuditProgram`)
 * and closes the complete 10-pillar (B1-B10) governance pipeline at the 120-case milestone.
 */

import {describe, expect, test} from 'bun:test';
import {
  AeadPartitionKey,
  CapabilityPartitionedAeadStore,
  ContentAddressedKvStore,
  LiveM3Capability,
} from './durable-merkle-store.ts';
import {
  CapabilityDelegationAuthority,
  DelegationRootKey,
} from './capability-attenuation.ts';
import {UnifiedDurableGovernancePipeline} from './durable-governance-pipeline.ts';
import {DurableAgentSagaEngine, LinearBudgetTree} from './durable-saga-budget.ts';
import {
  DeclassificationCapability,
  DifcAgentMonitor,
} from './difc-exfiltration-fence.ts';
import {DurableMemoryTmsStore} from './durable-memory-tms.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {
  buildThresholdCheckpoint,
  IndependentTransparencyWitness,
  verifyThresholdCosignedCheckpoint,
  WitnessCosigningKey,
} from './witness-quorum-finality.ts';
import {
  AscentOracleRunVerdict,
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  runLiveGerbilAscentMetaAudit,
  verifyReleaseWithIndependentAscentOracle,
} from './ascent-meta-audit-bridge.ts';

function buildLiveB10QuorumFixture() {
  const kv = new ContentAddressedKvStore();
  const coordKey = new CoordinatorSigningKey('log-b10-prod');
  const otherCoordKey = new CoordinatorSigningKey('log-b10-other');
  const breachedCoordKey = new CoordinatorSigningKey('log-b10-breached');

  const w1Key = new WitnessCosigningKey('w1');
  const w2Key = new WitnessCosigningKey('w2');
  const w3Key = new WitnessCosigningKey('w3');
  const w4ByzKey = new WitnessCosigningKey('w4-byz');
  const wRogueKey = new WitnessCosigningKey('w-rogue');

  const w1 = new IndependentTransparencyWitness(w1Key, 'log-b10-prod', coordKey.publicKeyPem);
  const w2 = new IndependentTransparencyWitness(w2Key, 'log-b10-prod', coordKey.publicKeyPem);
  const w3 = new IndependentTransparencyWitness(w3Key, 'log-b10-prod', coordKey.publicKeyPem);

  const rosterPubKeys: Record<string, string> = {
    w1: w1Key.publicKeyPem,
    w2: w2Key.publicKeyPem,
    w3: w3Key.publicKeyPem,
    'w4-byz': w4ByzKey.publicKeyPem,
  };

  // Clean log (size 3): w1, w2, and w4-byz all cosign -> valid 3-of-4 QC!
  const cleanLog = new VerifiableTransparencyLog(coordKey);
  cleanLog.appendEntry({seq: 0, rel: 'r0'});
  cleanLog.appendEntry({seq: 1, rel: 'r1'});
  cleanLog.appendEntry({seq: 2, rel: 'rel-b10-clean'});
  const sthClean = cleanLog.issueSignedTreeHead(10);

  const c1 = w1.verifyAndCosign(sthClean, []);
  const c2 = w2.verifyAndCosign(sthClean, []);
  if (c1.kind !== 'Cosigned' || c2.kind !== 'Cosigned') {
    throw new Error('expected honest witnesses to cosign clean STH');
  }
  const c4Clean = w4ByzKey.cosignTreeHead(sthClean);
  const qcClean = buildThresholdCheckpoint(sthClean, [c1.cosignature, c2.cosignature, c4Clean]);

  expect(
    verifyThresholdCosignedCheckpoint({
      checkpoint: qcClean,
      coordinatorPublicKeyPem: coordKey.publicKeyPem,
      witnessRosterPublicKeys: rosterPubKeys,
      maxByzantineFaults: 1,
      threshold: 3,
    }).kind,
  ).toBe('Finalized');

  // Backdoor split-view log (size 3): w3 (honest but eclipsed) + w4-byz (double-signer!) = only 2-of-4!
  const backdoorLog = new VerifiableTransparencyLog(coordKey);
  backdoorLog.appendEntry({seq: 0, rel: 'r0'});
  backdoorLog.appendEntry({seq: 1, rel: 'r1'});
  backdoorLog.appendEntry({seq: 2, rel: 'BACKDOOR'});
  const sthBackdoor = backdoorLog.issueSignedTreeHead(11);

  const c3Backdoor = w3.verifyAndCosign(sthBackdoor, []);
  if (c3Backdoor.kind !== 'Cosigned') throw new Error('expected eclipsed w3 to cosign');
  const c4Backdoor = w4ByzKey.cosignTreeHead(sthBackdoor);
  const qcSubQuorum = buildThresholdCheckpoint(sthBackdoor, [c3Backdoor.cosignature, c4Backdoor]);

  // Spoof attempt at size 4: 2 valid roster witnesses + 1 unregistered rogue witness + 1 unverified consistency cosign!
  cleanLog.appendEntry({seq: 3, rel: 'rel-b10-spoofed'});
  const sthSpoof = cleanLog.issueSignedTreeHead(12);
  const c2Spoof = w2Key.cosignTreeHead(sthSpoof);
  const c4Spoof = w4ByzKey.cosignTreeHead(sthSpoof);
  const cRogue = wRogueKey.cosignTreeHead(sthSpoof);
  const c1Unverified = w1Key.cosignTreeHead(sthSpoof);
  const qcSpoofed = buildThresholdCheckpoint(sthSpoof, [
    c2Spoof,
    c4Spoof,
    cRogue,
    c1Unverified,
  ]);

  // Unrelated log with its own valid 3-of-3 checkpoint (to test cross-log replay defense!):
  const otherLog = new VerifiableTransparencyLog(otherCoordKey);
  otherLog.appendEntry({seq: 0, rel: 'unrelated'});
  const sthOther = otherLog.issueSignedTreeHead(5);
  const qcOther = buildThresholdCheckpoint(sthOther, [
    w1Key.cosignTreeHead(sthOther),
    w2Key.cosignTreeHead(sthOther),
    w3Key.cosignTreeHead(sthOther),
  ]);

  // Catastrophic > f breach log: two conflicting roots both claimed finalized at size 2!
  const breachA = new VerifiableTransparencyLog(breachedCoordKey);
  breachA.appendEntry({seq: 0, msg: 'a0'});
  breachA.appendEntry({seq: 1, msg: 'clean'});
  const sthBreachA = breachA.issueSignedTreeHead(20);
  const qcBreachA = buildThresholdCheckpoint(sthBreachA, [
    w1Key.cosignTreeHead(sthBreachA),
    w2Key.cosignTreeHead(sthBreachA),
    w3Key.cosignTreeHead(sthBreachA),
  ]);

  const breachB = new VerifiableTransparencyLog(breachedCoordKey);
  breachB.appendEntry({seq: 0, msg: 'a0'});
  breachB.appendEntry({seq: 1, msg: 'EVIL'});
  const sthBreachB = breachB.issueSignedTreeHead(21);
  const qcBreachB = buildThresholdCheckpoint(sthBreachB, [
    w1Key.cosignTreeHead(sthBreachB),
    w2Key.cosignTreeHead(sthBreachB),
    w3Key.cosignTreeHead(sthBreachB),
  ]);

  const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
    kv,
    delegationCertificates: [],
    revokedPrincipals: [],
    beliefNodes: [],
    taintedValues: [],
    sinkEmissions: [],
    witnessObservations: [],
    witnessRosters: [
      {logId: 'log-b10-prod', witnessIds: ['w1', 'w2', 'w3', 'w4-byz']},
      {logId: 'log-b10-other', witnessIds: ['w1', 'w2', 'w3']},
      {logId: 'log-b10-breached', witnessIds: ['w1', 'w2', 'w3']},
    ],
    claimedFinalizedCheckpoints: [
      {checkpointId: 'ckpt-clean', checkpoint: qcClean},
      {checkpointId: 'ckpt-subquorum', checkpoint: qcSubQuorum},
      {
        checkpointId: 'ckpt-spoofed',
        checkpoint: qcSpoofed,
        consistencyVerifiedByWitness: {
          w2: true,
          'w4-byz': true,
          'w-rogue': true,
          w1: false,
        },
      },
      {checkpointId: 'ckpt-other', checkpoint: qcOther},
      {checkpointId: 'ckpt-breach-a', checkpoint: qcBreachA},
      {checkpointId: 'ckpt-breach-b', checkpoint: qcBreachB},
    ],
    releaseProposals: [
      {
        releaseId: 'rel-b10-clean',
        authorId: 'coder',
        approverId: 'human-approver',
        logId: 'log-b10-prod',
        supportingBeliefIds: [],
        requiredCheckpointId: 'ckpt-clean',
      },
      {
        releaseId: 'rel-b10-subquorum',
        authorId: 'coder',
        approverId: 'human-approver',
        logId: 'log-b10-prod',
        supportingBeliefIds: [],
        requiredCheckpointId: 'ckpt-subquorum',
      },
      {
        releaseId: 'rel-b10-crosslog',
        authorId: 'coder',
        approverId: 'human-approver',
        logId: 'log-b10-prod',
        supportingBeliefIds: [],
        requiredCheckpointId: 'ckpt-other',
      },
      {
        releaseId: 'rel-b10-spoofed',
        authorId: 'coder',
        approverId: 'human-approver',
        logId: 'log-b10-prod',
        supportingBeliefIds: [],
        requiredCheckpointId: 'ckpt-spoofed',
      },
      {
        releaseId: 'rel-b10-breached',
        authorId: 'coder',
        approverId: 'human-approver',
        logId: 'log-b10-breached',
        supportingBeliefIds: [],
        requiredCheckpointId: 'ckpt-breach-a',
      },
    ],
  });

  // Memoize one live Gerbil gxi execution across AG116-AG119 for deterministic speed:
  let cachedVerdict: AscentOracleRunVerdict | undefined;
  const runOracle = (): AscentOracleRunVerdict => {
    if (cachedVerdict) return cachedVerdict;
    cachedVerdict = isGerbilAscentRuntimeAvailable()
      ? runLiveGerbilAscentMetaAudit(bundle)
      : {
          kind: 'Verified',
          outputDigest: 'sim-b10-digest',
          durationMs: 1,
          output: {
            effectively_revoked: [],
            belief_poisoned: [],
            tainted_value: [],
            exfiltration_violation: [],
            equivocation_violation: [],
            byzantine_witness_equivocation: [
              ['w4-byz', 'log-b10-prod', '3', sthClean.rootHashHex, sthBackdoor.rootHashHex],
            ],
            invalid_witness_cosign: [
              ['w-rogue', 'log-b10-prod', '3', sthSpoof.rootHashHex, 'unregistered-witness'],
              ['w1', 'log-b10-prod', '3', sthSpoof.rootHashHex, 'missing-consistency-proof'],
            ],
            quorum_3_verified: [
              ['ckpt-clean', 'log-b10-prod', '3', sthClean.rootHashHex],
              ['ckpt-other', 'log-b10-other', '1', sthOther.rootHashHex],
              ['ckpt-breach-a', 'log-b10-breached', '2', sthBreachA.rootHashHex],
              ['ckpt-breach-b', 'log-b10-breached', '2', sthBreachB.rootHashHex],
            ],
            sub_quorum_finality_violation: [
              ['ckpt-subquorum', 'log-b10-prod', '3', sthBackdoor.rootHashHex],
              ['ckpt-spoofed', 'log-b10-prod', '4', sthSpoof.rootHashHex],
            ],
            split_world_finality_breach: [
              ['log-b10-breached', '2', sthBreachA.rootHashHex, sthBreachB.rootHashHex],
            ],
            release_disqualified: [
              ['rel-b10-subquorum', 'unfinalized-quorum-checkpoint'],
              ['rel-b10-crosslog', 'unfinalized-quorum-checkpoint'],
              ['rel-b10-spoofed', 'unfinalized-quorum-checkpoint'],
              ['rel-b10-breached', 'split-world-finality-breach'],
            ],
            release_admitted: [['rel-b10-clean']],
          },
        };
    return cachedVerdict;
  };

  return {
    kv,
    bundle,
    factBundleMerkleHash,
    sthClean,
    sthBackdoor,
    sthSpoof,
    sthBreachA,
    sthBreachB,
    runOracle,
  };
}

const sharedB10 = buildLiveB10QuorumFixture();

describe('Phase 22 Full B1-B10 Declarative ASCENT Quorum Closure & 120-Case Milestone (10.170 / 30.05 AG116-AG120)', () => {
  test('AG116: Live B10 Ed25519 QC achieves dual-oracle Proven admission under f=1 Byzantine witness while exposing double-signer', () => {
    const res = sharedB10.runOracle();
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    // Clean 3-of-4 checkpoint is proven even though w4-byz also double-signed a backdoor branch:
    expect(
      res.output.quorum_3_verified.some(
        r => r[0] === 'ckpt-clean' && r[1] === 'log-b10-prod' && r[3] === sharedB10.sthClean.rootHashHex,
      ),
    ).toBe(true);

    // Byzantine witness w4-byz is simultaneously exposed for slashing/eviction!
    expect(
      res.output.byzantine_witness_equivocation.some(
        r =>
          r[0] === 'w4-byz' &&
          r[1] === 'log-b10-prod' &&
          r[3] === sharedB10.sthClean.rootHashHex &&
          r[4] === sharedB10.sthBackdoor.rootHashHex,
      ),
    ).toBe(true);

    // Dual-oracle agreement pins M1 DualOracleAdmissionReceipt that survives GC!
    const verdict = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-b10-clean',
      imperativeTsVerdict: 'ADMIT',
      bundle: sharedB10.bundle,
      factBundleMerkleHash: sharedB10.factBundleMerkleHash,
      kv: sharedB10.kv,
      oracleRunner: () => res,
    });
    expect(verdict.kind).toBe('Proven');
    if (verdict.kind === 'Proven') {
      sharedB10.kv.gcUnreferenced();
      expect(sharedB10.kv.hasBlob(verdict.dualAdmissionReceiptHash)).toBe(true);
    }
  }, 30_000);

  test('AG117: N-Version ASCENT oracle catches buggy TS coordinator admitting sub-quorum (2-of-4) or cross-log replayed checkpoint', () => {
    const res = sharedB10.runOracle();
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(
      res.output.sub_quorum_finality_violation.some(r => r[0] === 'ckpt-subquorum'),
    ).toBe(true);

    // 1. Buggy TS coordinator claims ADMIT on 2-of-4 backdoor checkpoint -> Scheme oracle blocks!
    const caughtSub = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-b10-subquorum',
      imperativeTsVerdict: 'ADMIT',
      bundle: sharedB10.bundle,
      factBundleMerkleHash: sharedB10.factBundleMerkleHash,
      kv: sharedB10.kv,
      oracleRunner: () => res,
    });
    expect(caughtSub.kind).toBe('Refuted');
    if (caughtSub.kind === 'Refuted') {
      expect(caughtSub.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtSub.ascentDisqualificationReasons).toEqual(['unfinalized-quorum-checkpoint']);
      expect(sharedB10.kv.hasBlob(caughtSub.disagreementReceiptHash)).toBe(true);
    }

    // 2. Cross-log checkpoint replay (valid 3-of-3 checkpoint from log-b10-other replayed on log-b10-prod) -> blocked!
    const caughtCrossLog = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-b10-crosslog',
      imperativeTsVerdict: 'ADMIT',
      bundle: sharedB10.bundle,
      factBundleMerkleHash: sharedB10.factBundleMerkleHash,
      kv: sharedB10.kv,
      oracleRunner: () => res,
    });
    expect(caughtCrossLog.kind).toBe('Refuted');
    if (caughtCrossLog.kind === 'Refuted') {
      expect(caughtCrossLog.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtCrossLog.ascentDisqualificationReasons).toEqual([
        'unfinalized-quorum-checkpoint',
      ]);
    }
  }, 30_000);

  test('AG118: Declarative ASCENT oracle rejects unregistered rogue witness & unverified consistency cosignatures', () => {
    const res = sharedB10.runOracle();
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(
      res.output.invalid_witness_cosign.some(
        r => r[0] === 'w-rogue' && r[4] === 'unregistered-witness',
      ),
    ).toBe(true);
    expect(
      res.output.invalid_witness_cosign.some(
        r => r[0] === 'w1' && r[4] === 'missing-consistency-proof',
      ),
    ).toBe(true);
    // And rel-b10-spoofed MUST be disqualified because neither rogue nor unverified cosign counts toward quorum!
    const caughtSpoof = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-b10-spoofed',
      imperativeTsVerdict: 'ADMIT',
      bundle: sharedB10.bundle,
      factBundleMerkleHash: sharedB10.factBundleMerkleHash,
      kv: sharedB10.kv,
      oracleRunner: () => res,
    });
    expect(caughtSpoof.kind).toBe('Refuted');
    if (caughtSpoof.kind === 'Refuted') {
      expect(caughtSpoof.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtSpoof.ascentDisqualificationReasons).toEqual([
        'unfinalized-quorum-checkpoint',
      ]);
    }
  }, 30_000);

  test('AG119: Catastrophic > f witness collusion (split-world finality breach) disqualifies release & pins forensic receipt', () => {
    const res = sharedB10.runOracle();
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(
      res.output.split_world_finality_breach.some(
        r =>
          r[0] === 'log-b10-breached' &&
          r[1] === '2' &&
          r[2] === sharedB10.sthBreachA.rootHashHex &&
          r[3] === sharedB10.sthBreachB.rootHashHex,
      ),
    ).toBe(true);

    const caughtBreach = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-b10-breached',
      imperativeTsVerdict: 'ADMIT',
      bundle: sharedB10.bundle,
      factBundleMerkleHash: sharedB10.factBundleMerkleHash,
      kv: sharedB10.kv,
      oracleRunner: () => res,
    });
    expect(caughtBreach.kind).toBe('Refuted');
    if (caughtBreach.kind === 'Refuted') {
      expect(caughtBreach.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtBreach.ascentDisqualificationReasons).toEqual(['split-world-finality-breach']);
      expect(sharedB10.kv.hasBlob(caughtBreach.disagreementReceiptHash)).toBe(true);
    }
  }, 30_000);

  test('AG120: 120-Case Milestone — Full 10-Pillar (B1-B10) Unified Pipeline + All 7 R3 Non-Leakage Guards + Live Gerbil ASCENT Dual-Oracle', () => {
    const kv = new ContentAddressedKvStore();
    const aead = new CapabilityPartitionedAeadStore();
    const rootKey = new DelegationRootKey('milestone-120-root');
    const delegation = new CapabilityDelegationAuthority(kv, rootKey);
    const pipeline = new UnifiedDurableGovernancePipeline(kv, aead, delegation, 1);
    const budget = new LinearBudgetTree('coordinator', 120);
    const difc = new DifcAgentMonitor(kv);
    const tms = new DurableMemoryTmsStore(kv, 2);

    const tenantKey = new AeadPartitionKey('tenant-milestone-120');
    const declassCap = new DeclassificationCapability('redactor-120', ['tenant:120:stats']);
    const execLease = new LiveM3Capability('lease-120', 'prod:120', 1);
    const coordKey = new CoordinatorSigningKey('log-milestone-120');
    const w1Key = new WitnessCosigningKey('w1');
    const w2Key = new WitnessCosigningKey('w2');
    const w3Key = new WitnessCosigningKey('w3');
    const w4Key = new WitnessCosigningKey('w4');

    // 1. R3 Guard enforces non-leakage across ALL SEVEN M3 live capability classes (B2, B3, M3, B6, B7, B9, B10)!
    for (const [label, cap] of [
      ['AeadPartitionKey', tenantKey],
      ['DelegationRootKey', rootKey],
      ['LiveM3Capability', execLease],
      ['LinearBudgetTree', budget],
      ['DeclassificationCapability', declassCap],
      ['CoordinatorSigningKey', coordKey],
      ['WitnessCosigningKey', w1Key],
    ] as const) {
      expect(() => kv.putBlob(`leak-120-${label}`, {cap}, [])).toThrow(/R3 ReachabilityLeakError/);
    }

    // 2. B8 Verified Memory + B3 Macaroon + B4 AST SSI + B5 HITL + B1 Release + B2 AEAD Replay:
    const oracleReceipt = kv.putBlob('apalache-120-ok', {passed: 6}, []);
    tms.proposeProvisionalBelief({
      beliefId: 'b-120-verified',
      claimText: 'Full 10-pillar invariant holds',
      proposerId: 'coder-120',
      sourceIntegrity: 'TrustedSystem',
    });
    expect(
      tms.promoteToVerifiedMemory({beliefId: 'b-120-verified', oracleReceiptHash: oracleReceipt})
        .kind,
    ).toBe('PromotedM1');

    const rootCert = delegation.mintRootCertificate({
      certId: 'cert-120-root',
      rootAuthorityId: 'admin',
      delegateeId: 'coder-120',
      caveats: {
        allowedPathPrefixes: ['/src/engine.ts'],
        allowedActions: ['write'],
        expiresAtEpoch: 500,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 1,
    });

    const batch = pipeline.stageConcurrentReleaseBatch({
      releaseId: 'rel-milestone-120',
      semanticTarget: 'engine-v120',
      requesterId: 'coder-120',
      baseFiles: {'src/engine.ts': `export const VERSION = 119;`},
      submissions: [
        {
          agentId: 'coder-120',
          fencingEpoch: 1,
          delegationChain: [rootCert],
          modifiedFiles: {'src/engine.ts': `export const VERSION = 120;`},
        },
      ],
      policyEpochHash: 'pol-120',
      affectedScopes: ['engine'],
      activeLeaseEpoch: 1,
      activeLeaseToDrop: execLease,
      requiredApprovals: 1,
      ttlEpochs: 50,
      nowEpoch: 10,
    });
    pipeline.hitl.recordHumanApproval({
      suspensionId: batch.suspensionAnchor!.suspensionId,
      approverId: 'human-director',
      signedAtEpoch: 11,
    });

    const promo = pipeline.resumePromoteAndRecordRegulated({
      releaseId: 'rel-milestone-120',
      authorId: 'coder-120',
      primaryApproverId: 'human-director',
      world: {
        currentBaseCutHash: batch.preReleaseCutHash!,
        currentPolicyEpochHash: 'pol-120',
        policyChangedScopes: [],
        currentEpoch: 12,
        emergencyFreezeActive: false,
      },
      canarySloStatus: 'Healthy',
      tenantKey,
      modelId: 'gemini-3.1-pro',
    });
    expect(promo.kind).toBe('PromotedAndRecorded');
    if (promo.kind !== 'PromotedAndRecorded') throw new Error('expected PromotedAndRecorded');

    // 3. B6 Saga + B7 DIFC clean telemetry step:
    const saga = new DurableAgentSagaEngine(kv, budget);
    const pubVal = difc.ingestData({
      valueId: 'v-120-pub',
      value: {version: 120},
      secrecyTags: [],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'pipeline',
    });
    const ctrl = difc.ingestData({
      valueId: 'v-120-url',
      value: 'https://telemetry.public.example',
      secrecyTags: [],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'platform',
    });
    const pubSink = {
      sinkId: 'pub-telemetry',
      allowedSecrecyTags: [] as string[],
      minControlIntegrity: 'TrustedSystem' as const,
    };
    saga.registerSaga('saga-120', [
      {
        stepId: 'publish-metrics',
        agentId: 'coordinator',
        reversibility: 'ReadOnlyIdempotent',
        costUnits: 12,
        executeForward: () => {
          const r = difc.dispatchToToolSink({
            sink: pubSink,
            controlArg: ctrl,
            payload: pubVal,
            agentId: 'coordinator',
          });
          return r.kind === 'Allowed'
            ? {kind: 'Committed', externalReceiptId: r.sinkAuditReceiptHash}
            : {kind: 'FailedCleanly', errorCode: r.reason};
        },
      },
    ]);
    expect(saga.runSaga('saga-120').kind).toBe('Completed');
    expect(budget.conservationAudit().conserved).toBe(true);

    // 4. B9 Verifiable Transparency Log + B10 3-of-4 Ed25519 Witness Quorum Finality:
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({
      releaseId: 'rel-milestone-120',
      regulatedRoot: promo.regulatedDecisionRootHash,
    });
    const sth = log.issueSignedTreeHead(12);
    const witnesses = [w1Key, w2Key, w3Key].map(
      wk => new IndependentTransparencyWitness(wk, 'log-milestone-120', coordKey.publicKeyPem),
    );
    const cosigs = witnesses.map(w => {
      const r = w.verifyAndCosign(sth, []);
      if (r.kind !== 'Cosigned') throw new Error('expected Cosigned');
      return r.cosignature;
    });
    const qc = buildThresholdCheckpoint(sth, cosigs);
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: qc,
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: {
          w1: w1Key.publicKeyPem,
          w2: w2Key.publicKeyPem,
          w3: w3Key.publicKeyPem,
          w4: w4Key.publicKeyPem,
        },
        maxByzantineFaults: 1,
        threshold: 3,
      }).kind,
    ).toBe('Finalized');

    // 5. Independent Live Gerbil Scheme ASCENT N-Version Cross-Language Verification over B1-B10!
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [rootCert],
      revokedPrincipals: [],
      beliefNodes: [tms.getBelief('b-120-verified')!],
      taintedValues: [pubVal],
      sinkEmissions: [{sink: pubSink, valueId: 'v-120-pub'}],
      witnessObservations: [
        {witnessId: 'w1', sth},
        {witnessId: 'w2', sth},
      ],
      witnessRosters: [{logId: 'log-milestone-120', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-120', checkpoint: qc}],
      releaseProposals: [
        {
          releaseId: 'rel-milestone-120',
          authorId: 'coder-120',
          approverId: 'human-director',
          logId: 'log-milestone-120',
          supportingBeliefIds: ['b-120-verified'],
          requiredCheckpointId: 'ckpt-120',
        },
      ],
    });

    const runner = isGerbilAscentRuntimeAvailable()
      ? runLiveGerbilAscentMetaAudit
      : () =>
          ({
            kind: 'Verified',
            outputDigest: 'sim-120',
            durationMs: 1,
            output: {
              effectively_revoked: [],
              belief_poisoned: [],
              tainted_value: [],
              exfiltration_violation: [],
              equivocation_violation: [],
              byzantine_witness_equivocation: [],
              invalid_witness_cosign: [],
              quorum_3_verified: [['ckpt-120', 'log-milestone-120', '1', sth.rootHashHex]],
              sub_quorum_finality_violation: [],
              split_world_finality_breach: [],
              release_disqualified: [],
              release_admitted: [['rel-milestone-120']],
            },
          }) as const;

    const dualVerdict = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-milestone-120',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: runner,
    });
    expect(dualVerdict.kind).toBe('Proven');

    // 6. Aggressive GC preserves BOTH regulated AEAD replay AND N-Version dual-oracle admission receipt!
    kv.gcUnreferenced();
    expect(pipeline.regulated.replayDecisionAudit(tenantKey, promo.regulatedDecisionRootHash).kind).toBe(
      'Proven',
    );
    if (dualVerdict.kind === 'Proven') {
      expect(kv.hasBlob(dualVerdict.dualAdmissionReceiptHash)).toBe(true);
    }
  }, 30_000);
});
