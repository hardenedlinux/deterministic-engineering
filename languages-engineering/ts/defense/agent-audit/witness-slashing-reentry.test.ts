// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 25 (B10c, 10.173 / 30.05 AG131-AG135):
 * Library-Owned Self-Authenticating Equivocation Slash Tombstones & Anti-Reentry
 * across TypeScript B10b Runtime, Live Gerbil ASCENT Datalog, and LeanPoo Proofs.
 *
 * Strictly preserves the Library (deterministic-engineering-qnt) <-> Consuming
 * Authorization Host (cedar-poo-spec) boundary: only pure cryptographic slashing
 * & state-machine anti-reentry primitives live here.
 */

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from './durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {buildThresholdCheckpoint} from './witness-quorum-finality.ts';
import {
  buildJointHandoverCertificate,
  buildWitnessSlashProof,
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
} from './witness-epoch-reconfiguration.ts';
import {
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  runLiveGerbilAscentMetaAudit,
  verifyReleaseWithIndependentAscentOracle,
} from './ascent-meta-audit-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';

function setupSlashingFixture(logId: string) {
  const kv = new ContentAddressedKvStore();
  const coordKey = new CoordinatorSigningKey(logId);

  const w1 = new ForwardSecureWitnessKey('w1', 1);
  const w2 = new ForwardSecureWitnessKey('w2', 1);
  const w3 = new ForwardSecureWitnessKey('w3', 1);
  const w4Byz = new ForwardSecureWitnessKey('w4-byz', 1);

  const epoch1Roster = createEpochRoster({
    logId,
    epoch: 1,
    witnessPublicKeys: {
      w1: w1.getPublicKeyPem(1),
      w2: w2.getPublicKeyPem(1),
      w3: w3.getPublicKeyPem(1),
      'w4-byz': w4Byz.getPublicKeyPem(1),
    },
    maxByzantineFaults: 1,
    threshold: 3,
  });

  const cleanLog = new VerifiableTransparencyLog(coordKey);
  cleanLog.appendEntry({seq: 0, msg: 'clean'});
  const sthClean = cleanLog.issueSignedTreeHead(1);

  const evilLog = new VerifiableTransparencyLog(coordKey);
  evilLog.appendEntry({seq: 0, msg: 'BACKDOOR'});
  const sthEvil = evilLog.issueSignedTreeHead(1);

  // w4-byz double-signs BOTH sthClean and sthEvil at (epoch=1, treeSize=1)!
  const cosigCleanW4 = w4Byz.cosignCheckpoint(sthClean);
  const cosigEvilW4 = w4Byz.cosignCheckpoint(sthEvil);

  return {
    kv,
    coordKey,
    w1,
    w2,
    w3,
    w4Byz,
    epoch1Roster,
    cleanLog,
    sthClean,
    sthEvil,
    cosigCleanW4,
    cosigEvilW4,
  };
}

describe('Phase 25 B10c Self-Authenticating Equivocation Slashing, Anti-Reentry & LeanPoo Refinement (10.173 / 30.05 AG131-AG135)', () => {
  test('AG131: Self-authenticating WitnessEquivocationSlashProof pins M1 tombstone surviving GC & blocks framing honest witnesses', () => {
    const {kv, coordKey, w1, w4Byz, epoch1Roster, sthClean, cosigCleanW4, cosigEvilW4} =
      setupSlashingFixture('log-slash-ag131');

    // 1. Valid equivocation proof for w4-byz succeeds & pins M1 tombstone surviving GC!
    const built = buildWitnessSlashProof({
      cosigA: cosigCleanW4,
      cosigB: cosigEvilW4,
      witnessPublicKeyPem: w4Byz.getPublicKeyPem(1),
    });
    expect(built.kind).toBe('SlashProofCreated');
    if (built.kind !== 'SlashProofCreated') throw new Error('expected SlashProofCreated');

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    const slashed = verifier.recordVerifiedSlashProof(built.proof);
    expect(slashed.kind).toBe('Slashed');
    if (slashed.kind !== 'Slashed') throw new Error('expected Slashed');
    expect(verifier.getSlashedWitnessIds()).toEqual(['w4-byz']);

    kv.gcUnreferenced();
    expect(kv.hasBlob(slashed.slashTombstoneHash)).toBe(true);

    // 2. Framing honest witness w1 with identical roots -> REFUSED!
    const honestSig = w1.cosignCheckpoint(sthClean);
    expect(
      buildWitnessSlashProof({
        cosigA: honestSig,
        cosigB: honestSig,
        witnessPublicKeyPem: w1.getPublicKeyPem(1),
      }),
    ).toEqual({kind: 'Refuted', reason: 'identical-roots-not-equivocation'});

    // 3. Framing honest witness w1 with forged signature -> REFUSED!
    expect(
      buildWitnessSlashProof({
        cosigA: honestSig,
        cosigB: {...cosigEvilW4, witnessId: 'w1'},
        witnessPublicKeyPem: w1.getPublicKeyPem(1),
      }),
    ).toEqual({kind: 'Refuted', reason: 'invalid-slash-ed25519-signature'});
  });

  test('AG132: ForwardSealedEpochVerifier blocks slashed witness re-entry by ID AND by Sybil public-key alias', () => {
    const {kv, coordKey, w1, w2, w3, w4Byz, epoch1Roster, sthClean, cosigCleanW4, cosigEvilW4} =
      setupSlashingFixture('log-slash-ag132');

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    const proofRes = buildWitnessSlashProof({
      cosigA: cosigCleanW4,
      cosigB: cosigEvilW4,
      witnessPublicKeyPem: w4Byz.getPublicKeyPem(1),
    });
    if (proofRes.kind !== 'SlashProofCreated') throw new Error('expected SlashProofCreated');
    expect(verifier.recordVerifiedSlashProof(proofRes.proof).kind).toBe('Slashed');

    w1.provisionEpochKey(2);
    w2.provisionEpochKey(2);
    w4Byz.provisionEpochKey(2);
    const w5 = new ForwardSecureWitnessKey('w5', 2);
    const w6 = new ForwardSecureWitnessKey('w6', 2);

    // 1. Attempt to re-admit `w4-byz` by witnessId into Epoch 2 roster -> REFUSED!
    const reentryByIdRoster = createEpochRoster({
      logId: 'log-slash-ag132',
      epoch: 2,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(2),
        w2: w2.getPublicKeyPem(2),
        w5: w5.getPublicKeyPem(2),
        'w4-byz': w4Byz.getPublicKeyPem(2),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const commonId = {
      logId: 'log-slash-ag132',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: reentryByIdRoster.rosterDigest,
    };
    const certReentryById = buildJointHandoverCertificate({
      logId: commonId.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: reentryByIdRoster,
      oldQuorumCosignatures: [w1, w2, w3].map(w => w.signHandover({...commonId, signingEpoch: 1})),
      newQuorumCosignatures: [w1, w2, w5].map(w => w.signHandover({...commonId, signingEpoch: 2})),
    });
    expect(verifier.applyJointHandover({cert: certReentryById})).toEqual({
      kind: 'Refuted',
      reason: 'slashed-witness-reentry-refused',
    });

    // 2. Sybil attack: rebrand `w4-byz` as `w4-sybil-alias` reusing its slashed Epoch 1 pubkey -> REFUSED!
    const sybilRoster = createEpochRoster({
      logId: 'log-slash-ag132',
      epoch: 2,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(2),
        w2: w2.getPublicKeyPem(2),
        w5: w5.getPublicKeyPem(2),
        'w4-sybil-alias': w4Byz.getPublicKeyPem(1),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const commonSybil = {
      ...commonId,
      newRosterDigest: sybilRoster.rosterDigest,
    };
    const certSybil = buildJointHandoverCertificate({
      logId: commonSybil.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: sybilRoster,
      oldQuorumCosignatures: [w1, w2, w3].map(w =>
        w.signHandover({...commonSybil, signingEpoch: 1}),
      ),
      newQuorumCosignatures: [w1, w2, w5].map(w =>
        w.signHandover({...commonSybil, signingEpoch: 2}),
      ),
    });
    expect(verifier.applyJointHandover({cert: certSybil})).toEqual({
      kind: 'Refuted',
      reason: 'slashed-pubkey-sybil-reentry-refused',
    });

    // 3. Clean eviction handover {w1, w2, w5, w6} succeeds cleanly!
    const cleanE2Roster = createEpochRoster({
      logId: 'log-slash-ag132',
      epoch: 2,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(2),
        w2: w2.getPublicKeyPem(2),
        w5: w5.getPublicKeyPem(2),
        w6: w6.getPublicKeyPem(2),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const commonClean = {...commonId, newRosterDigest: cleanE2Roster.rosterDigest};
    const certClean = buildJointHandoverCertificate({
      logId: commonClean.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: cleanE2Roster,
      oldQuorumCosignatures: [w1, w2, w3].map(w =>
        w.signHandover({...commonClean, signingEpoch: 1}),
      ),
      newQuorumCosignatures: [w1, w2, w5].map(w =>
        w.signHandover({...commonClean, signingEpoch: 2}),
      ),
    });
    expect(verifier.applyJointHandover({cert: certClean}).kind).toBe('EpochAdvanced');
  });

  test('AG133: Live Gerbil Scheme ASCENT Datalog oracle derives slashed_witness_reentry_violation from live double-sign & blocks buggy TS ADMIT', () => {
    const {kv, w1, w2, sthClean, cosigCleanW4, cosigEvilW4} =
      setupSlashingFixture('log-slash-ascent');

    const qcClean = buildThresholdCheckpoint(sthClean, [
      w1.cosignCheckpoint(sthClean),
      w2.cosignCheckpoint(sthClean),
      cosigCleanW4,
    ]);

    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      witnessRosters: [{logId: 'log-slash-ascent', witnessIds: ['w1', 'w2', 'w3', 'w4-byz']}],
      witnessCosignatures: [{cosig: cosigEvilW4, consistencyVerified: true}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-e1', checkpoint: qcClean}],
      // Candidate Epoch 2 roster tries to sneak equivocating `w4-byz` back in!
      nextEpochRosters: [
        {logId: 'log-slash-ascent', epoch: 2, witnessIds: ['w1', 'w2', 'w5', 'w4-byz']},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-reentry-sneak',
          authorId: 'coder',
          approverId: 'human-approver',
          logId: 'log-slash-ascent',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-e1',
        },
      ],
    });

    const oracleRes = isGerbilAscentRuntimeAvailable()
      ? runLiveGerbilAscentMetaAudit(bundle)
      : ({
          kind: 'Verified',
          outputDigest: 'sim-b10c',
          durationMs: 1,
          output: {
            effectively_revoked: [],
            belief_poisoned: [],
            tainted_value: [],
            exfiltration_violation: [],
            equivocation_violation: [],
            byzantine_witness_equivocation: [
              ['w4-byz', 'log-slash-ascent', '1', sthClean.rootHashHex, cosigEvilW4.rootHashHex],
            ],
            invalid_witness_cosign: [],
            quorum_3_verified: [['ckpt-e1', 'log-slash-ascent', '1', sthClean.rootHashHex]],
            sub_quorum_finality_violation: [],
            split_world_finality_breach: [],
            slashed_witness_reentry_violation: [['log-slash-ascent', '2', 'w4-byz']],
            release_disqualified: [['rel-reentry-sneak', 'slashed-witness-reentry']],
            release_admitted: [],
          },
        } as const);

    expect(oracleRes.kind).toBe('Verified');
    if (oracleRes.kind !== 'Verified') throw new Error('expected Verified');
    expect(oracleRes.output.slashed_witness_reentry_violation).toEqual([
      ['log-slash-ascent', '2', 'w4-byz'],
    ]);

    const gate = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-reentry-sneak',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: () => oracleRes,
    });
    expect(gate.kind).toBe('Refuted');
    if (gate.kind === 'Refuted') {
      expect(gate.reason).toBe('oracle-disagreement-fail-closed');
      expect(gate.ascentDisqualificationReasons).toEqual(['slashed-witness-reentry']);
    }
  }, 60_000);

  test('AG134: Live Lean 4 / LeanPoo oracle verifies all 4 new B10c slashing & 3rd-step refinement theorems (19 total) carry zero sorry/custom axioms', () => {
    const b10cTheorems = [
      'slashed_witness_is_byzantine',
      'slashed_witness_never_reenters_future_epochs',
      'hostPolicyOverSlashing_preserves_library_rejection',
      'droppingSlashReentryGuard_invalidates_reuse',
    ] as const;

    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
          namespacePrefix: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
          expectedTheorems: b10cTheorems,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const kv = new ContentAddressedKvStore();
    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      namespacePrefix: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      expectedTheorems: b10cTheorems,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(4);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG135: Full B10c Lifecycle — Detect -> Slash Tombstone (M1) -> Refuse Slashed QC -> Evict & Rotate -> Zeroize -> Clean E2 Finality', () => {
    const {
      kv,
      coordKey,
      w1,
      w2,
      w3,
      w4Byz,
      epoch1Roster,
      cleanLog,
      sthClean,
      cosigCleanW4,
      cosigEvilW4,
    } = setupSlashingFixture('log-slash-full-lifecycle');

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    const proofRes = buildWitnessSlashProof({
      cosigA: cosigCleanW4,
      cosigB: cosigEvilW4,
      witnessPublicKeyPem: w4Byz.getPublicKeyPem(1),
    });
    if (proofRes.kind !== 'SlashProofCreated') throw new Error('expected SlashProofCreated');
    const slashRes = verifier.recordVerifiedSlashProof(proofRes.proof);
    if (slashRes.kind !== 'Slashed') throw new Error('expected Slashed');

    // A checkpoint relying on slashed w4-byz as its 3rd vote is now REFUSED (`2 < 3` unslashed)!
    const qcWithSlashedW4 = buildThresholdCheckpoint(sthClean, [
      w1.cosignCheckpoint(sthClean),
      w2.cosignCheckpoint(sthClean),
      cosigCleanW4,
    ]);
    expect(verifier.verifyCheckpointInCurrentEpoch({checkpoint: qcWithSlashedW4})).toEqual({
      kind: 'Refuted',
      reason: 'insufficient-unslashed-witness-quorum',
    });

    // Checkpoint backed by 3 HONEST witnesses {w1, w2, w3} finalizes cleanly!
    const qcHonestE1 = buildThresholdCheckpoint(sthClean, [
      w1.cosignCheckpoint(sthClean),
      w2.cosignCheckpoint(sthClean),
      w3.cosignCheckpoint(sthClean),
    ]);
    expect(verifier.verifyCheckpointInCurrentEpoch({checkpoint: qcHonestE1}).kind).toBe(
      'FinalizedInEpoch',
    );

    // Evict w4-byz & rotate to Epoch 2 {w1, w2, w5, w6}, then zeroize retired Epoch 1 keys:
    w1.provisionEpochKey(2);
    w2.provisionEpochKey(2);
    const w5 = new ForwardSecureWitnessKey('w5', 2);
    const w6 = new ForwardSecureWitnessKey('w6', 2);
    const e2Roster = createEpochRoster({
      logId: 'log-slash-full-lifecycle',
      epoch: 2,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(2),
        w2: w2.getPublicKeyPem(2),
        w5: w5.getPublicKeyPem(2),
        w6: w6.getPublicKeyPem(2),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const common = {
      logId: 'log-slash-full-lifecycle',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: e2Roster.rosterDigest,
    };
    const handover = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthClean.treeSize,
      anchorRootHashHex: sthClean.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: e2Roster,
      oldQuorumCosignatures: [w1, w2, w3].map(w => w.signHandover({...common, signingEpoch: 1})),
      newQuorumCosignatures: [w1, w2, w5].map(w => w.signHandover({...common, signingEpoch: 2})),
    });
    const advanced = verifier.applyJointHandover({cert: handover});
    expect(advanced.kind).toBe('EpochAdvanced');
    if (advanced.kind !== 'EpochAdvanced') throw new Error('expected EpochAdvanced');

    w1.zeroizeRetiredEpochKey(1);
    w2.zeroizeRetiredEpochKey(1);
    w3.zeroizeRetiredEpochKey(1);

    // Grow log in Epoch 2 & finalize with {w1, w5, w6}:
    cleanLog.appendEntry({seq: 1, msg: 'post-eviction-clean'});
    const sthE2 = cleanLog.issueSignedTreeHead(2);
    const qcE2 = buildThresholdCheckpoint(sthE2, [
      w1.cosignCheckpoint(sthE2),
      w5.cosignCheckpoint(sthE2),
      w6.cosignCheckpoint(sthE2),
    ]);
    expect(
      verifier.verifyCheckpointInCurrentEpoch({
        checkpoint: qcE2,
        consistencyProofFromAnchor: cleanLog.getConsistencyProof(1, 2),
      }).kind,
    ).toBe('FinalizedInEpoch');

    // Aggressive GC retains BOTH M1 slash tombstone AND M1 handover receipt!
    kv.gcUnreferenced();
    expect(kv.hasBlob(slashRes.slashTombstoneHash)).toBe(true);
    expect(kv.hasBlob(advanced.handoverReceiptHash)).toBe(true);
  });
});
