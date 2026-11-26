// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from './durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {buildThresholdCheckpoint} from './witness-quorum-finality.ts';
import {
  buildJointHandoverCertificate,
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
  verifyJointHandoverCertificate,
} from './witness-epoch-reconfiguration.ts';

function setupDynamicCommitteeFixture(logId: string) {
  const kv = new ContentAddressedKvStore();
  const coordKey = new CoordinatorSigningKey(logId);

  // Epoch 1 Committee: {w1, w2, w3, w4-byz} (N=4, f=1, t=3)
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

  // Epoch 2 Committee: evict w3 & w4-byz, rotate w1 & w2 keys to fresh Epoch 2 keys, onboard w5 & w6!
  const w5 = new ForwardSecureWitnessKey('w5', 2);
  const w6 = new ForwardSecureWitnessKey('w6', 2);
  w1.provisionEpochKey(2);
  w2.provisionEpochKey(2);

  const epoch2Roster = createEpochRoster({
    logId,
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

  return {kv, coordKey, w1, w2, w3, w4Byz, w5, w6, epoch1Roster, epoch2Roster};
}

describe('Phase 23 Dynamic Witness Roster Reconfiguration, Dual-Quorum Handover & Forward-Secure Epoch Sealing (10.171 / 30.05 AG121-AG125)', () => {
  test('AG121: Clean Joint-Consensus Handover (Epoch 1 -> Epoch 2) pins M1 receipt, preserves RFC 6962 continuity (3 -> 6) & survives GC', () => {
    const {kv, coordKey, w1, w2, w3, w5, w6, epoch1Roster, epoch2Roster} =
      setupDynamicCommitteeFixture('log-reconfig-clean');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, rel: 'e1-r0'});
    log.appendEntry({seq: 1, rel: 'e1-r1'});
    log.appendEntry({seq: 2, rel: 'e1-r2'});
    const sthE1 = log.issueSignedTreeHead(1);

    const qcE1 = buildThresholdCheckpoint(sthE1, [
      w1.cosignCheckpoint(sthE1),
      w2.cosignCheckpoint(sthE1),
      w3.cosignCheckpoint(sthE1),
    ]);

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    expect(verifier.verifyCheckpointInCurrentEpoch({checkpoint: qcE1}).kind).toBe(
      'FinalizedInEpoch',
    );

    // Build Joint-Consensus Handover Certificate signed by BOTH Q_old {w1, w2, w3} AND Q_new {w1, w2, w5}:
    const common = {
      logId: 'log-reconfig-clean',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: epoch2Roster.rosterDigest,
    };
    const handoverCert = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch2Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 1}),
        w2.signHandover({...common, signingEpoch: 1}),
        w3.signHandover({...common, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 2}),
        w2.signHandover({...common, signingEpoch: 2}),
        w5.signHandover({...common, signingEpoch: 2}),
      ],
    });

    const applied = verifier.applyJointHandover({cert: handoverCert});
    expect(applied.kind).toBe('EpochAdvanced');
    if (applied.kind !== 'EpochAdvanced') throw new Error('expected EpochAdvanced');
    expect(applied.newEpoch).toBe(2);
    expect(verifier.getPinnedEpoch()).toBe(2);

    // Grow log to size 6 under Epoch 2 committee {w1, w5, w6} with RFC 6962 consistency proof (3 -> 6)!
    log.appendEntry({seq: 3, rel: 'e2-r3'});
    log.appendEntry({seq: 4, rel: 'e2-r4'});
    log.appendEntry({seq: 5, rel: 'e2-r5'});
    const sthE2 = log.issueSignedTreeHead(2);
    const consProof = log.getConsistencyProof(3, 6);

    const qcE2 = buildThresholdCheckpoint(sthE2, [
      w1.cosignCheckpoint(sthE2),
      w5.cosignCheckpoint(sthE2),
      w6.cosignCheckpoint(sthE2),
    ]);
    const e2Verdict = verifier.verifyCheckpointInCurrentEpoch({
      checkpoint: qcE2,
      consistencyProofFromAnchor: consProof,
    });
    expect(e2Verdict.kind).toBe('FinalizedInEpoch');
    if (e2Verdict.kind === 'FinalizedInEpoch') {
      expect(e2Verdict.epoch).toBe(2);
      expect(e2Verdict.verifiedWitnessIds).toEqual(['w1', 'w5', 'w6']);
    }

    // Aggressive GC preserves pinned M1 handover receipt!
    kv.gcUnreferenced();
    expect(kv.hasBlob(applied.handoverReceiptHash)).toBe(true);
  });

  test('AG122: Unilateral single-quorum handover (old-only or new-only) is deterministically refused', () => {
    const {coordKey, w1, w2, w3, w5, epoch1Roster, epoch2Roster} =
      setupDynamicCommitteeFixture('log-reconfig-unilateral');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, rel: 'e1-r0'});
    const sthE1 = log.issueSignedTreeHead(1);

    const common = {
      logId: 'log-reconfig-unilateral',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: epoch2Roster.rosterDigest,
    };

    // 1. Old-quorum-only handover (only 2 new signatures < 3) -> REFUSED!
    const oldOnlyCert = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch2Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 1}),
        w2.signHandover({...common, signingEpoch: 1}),
        w3.signHandover({...common, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 2}),
        w2.signHandover({...common, signingEpoch: 2}),
      ],
    });
    expect(verifyJointHandoverCertificate({cert: oldOnlyCert, oldRoster: epoch1Roster})).toEqual({
      kind: 'Refuted',
      reason: 'new-quorum-failed:insufficient-handover-quorum',
    });

    // 2. New-quorum-only handover (only 2 old signatures < 3) -> REFUSED!
    const newOnlyCert = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch2Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 1}),
        w2.signHandover({...common, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 2}),
        w2.signHandover({...common, signingEpoch: 2}),
        w5.signHandover({...common, signingEpoch: 2}),
      ],
    });
    expect(verifyJointHandoverCertificate({cert: newOnlyCert, oldRoster: epoch1Roster})).toEqual({
      kind: 'Refuted',
      reason: 'old-quorum-failed:insufficient-handover-quorum',
    });
  });

  test('AG123: Forward-secure retired key zeroization & monotonic weak-subjectivity pin defeat Long-Range posterior-corruption attack', () => {
    const {kv, coordKey, w1, w2, w3, w4Byz, w5, epoch1Roster, epoch2Roster} =
      setupDynamicCommitteeFixture('log-reconfig-longrange');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, rel: 'clean'});
    const sthE1 = log.issueSignedTreeHead(1);

    const common = {
      logId: 'log-reconfig-longrange',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: epoch2Roster.rosterDigest,
    };
    const handoverCert = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch2Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 1}),
        w2.signHandover({...common, signingEpoch: 1}),
        w3.signHandover({...common, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 2}),
        w2.signHandover({...common, signingEpoch: 2}),
        w5.signHandover({...common, signingEpoch: 2}),
      ],
    });

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    expect(verifier.applyJointHandover({cert: handoverCert}).kind).toBe('EpochAdvanced');

    // Layer 1 Defense: Honest witness w1 permanently zeroizes its retired Epoch 1 signing key!
    w1.zeroizeRetiredEpochKey(1);
    expect(w1.isEpochZeroized(1)).toBe(true);
    expect(() => w1.cosignCheckpoint(sthE1)).toThrow(/ForwardSecureKeyZeroizedError/);
    expect(() => w1.provisionEpochKey(1)).toThrow(/ForwardSecureKeyZeroizedError/);
    // Meanwhile w1's active Epoch 2 key continues working cleanly!
    expect(w1.cosignCheckpoint({...sthE1, epoch: 2}).epoch).toBe(2);

    // Layer 2 Defense: Even if adversary compromises ALL remaining un-zeroized Epoch 1 keys {w2, w3, w4-byz}
    // (3-of-4 retired C_old quorum!) and forges a backdoor Epoch 1 checkpoint + fake HandoverQC' to C_evil:
    const evilLog = new VerifiableTransparencyLog(coordKey);
    evilLog.appendEntry({seq: 0, rel: 'LONG-RANGE-BACKDOOR'});
    const sthEvilE1 = evilLog.issueSignedTreeHead(1);
    const qcEvilE1 = buildThresholdCheckpoint(sthEvilE1, [
      w2.cosignCheckpoint(sthEvilE1),
      w3.cosignCheckpoint(sthEvilE1),
      w4Byz.cosignCheckpoint(sthEvilE1),
    ]);

    expect(verifier.verifyCheckpointInCurrentEpoch({checkpoint: qcEvilE1})).toEqual({
      kind: 'Refuted',
      reason: 'long-range-retired-epoch-refused',
    });

    const evilW1 = new ForwardSecureWitnessKey('evil-1', 2);
    const evilW2 = new ForwardSecureWitnessKey('evil-2', 2);
    const evilW3 = new ForwardSecureWitnessKey('evil-3', 2);
    const evilW4 = new ForwardSecureWitnessKey('evil-4', 2);
    const evilRoster = createEpochRoster({
      logId: 'log-reconfig-longrange',
      epoch: 2,
      witnessPublicKeys: {
        'evil-1': evilW1.getPublicKeyPem(2),
        'evil-2': evilW2.getPublicKeyPem(2),
        'evil-3': evilW3.getPublicKeyPem(2),
        'evil-4': evilW4.getPublicKeyPem(2),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const evilCommon = {
      logId: 'log-reconfig-longrange',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthEvilE1.treeSize,
      anchorRootHashHex: sthEvilE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: evilRoster.rosterDigest,
    };
    const fakeHandover = buildJointHandoverCertificate({
      logId: evilCommon.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthEvilE1.treeSize,
      anchorRootHashHex: sthEvilE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: evilRoster,
      oldQuorumCosignatures: [
        w2.signHandover({...evilCommon, signingEpoch: 1}),
        w3.signHandover({...evilCommon, signingEpoch: 1}),
        w4Byz.signHandover({...evilCommon, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        evilW1.signHandover({...evilCommon, signingEpoch: 2}),
        evilW2.signHandover({...evilCommon, signingEpoch: 2}),
        evilW3.signHandover({...evilCommon, signingEpoch: 2}),
      ],
    });
    expect(verifier.applyJointHandover({cert: fakeHandover})).toEqual({
      kind: 'Refuted',
      reason: 'stale-handover-from-retired-epoch',
    });
  });

  test('AG124: Spliced/rewritten Epoch 2 tree failing RFC 6962 consistency from handover anchor is deterministically refused', () => {
    const {kv, coordKey, w1, w2, w3, w5, w6, epoch1Roster, epoch2Roster} =
      setupDynamicCommitteeFixture('log-reconfig-splice');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, rel: 'clean-0'});
    log.appendEntry({seq: 1, rel: 'clean-1'});
    const sthE1 = log.issueSignedTreeHead(1);

    const common = {
      logId: 'log-reconfig-splice',
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: epoch2Roster.rosterDigest,
    };
    const handoverCert = buildJointHandoverCertificate({
      logId: common.logId,
      fromEpoch: 1,
      toEpoch: 2,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch2Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 1}),
        w2.signHandover({...common, signingEpoch: 1}),
        w3.signHandover({...common, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...common, signingEpoch: 2}),
        w2.signHandover({...common, signingEpoch: 2}),
        w5.signHandover({...common, signingEpoch: 2}),
      ],
    });

    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, epoch1Roster);
    expect(verifier.applyJointHandover({cert: handoverCert}).kind).toBe('EpochAdvanced');

    // Adversary builds a SPLICED log at Epoch 2 that rewrote leaf #1 (`clean-1` -> `TAMPERED-1`)!
    const splicedLog = new VerifiableTransparencyLog(coordKey);
    splicedLog.appendEntry({seq: 0, rel: 'clean-0'});
    splicedLog.appendEntry({seq: 1, rel: 'TAMPERED-1'});
    splicedLog.appendEntry({seq: 2, rel: 'e2-entry'});
    const sthSplicedE2 = splicedLog.issueSignedTreeHead(2);
    const badProof = splicedLog.getConsistencyProof(2, 3);
    const qcSplicedE2 = buildThresholdCheckpoint(sthSplicedE2, [
      w1.cosignCheckpoint(sthSplicedE2),
      w5.cosignCheckpoint(sthSplicedE2),
      w6.cosignCheckpoint(sthSplicedE2),
    ]);

    expect(
      verifier.verifyCheckpointInCurrentEpoch({
        checkpoint: qcSplicedE2,
        consistencyProofFromAnchor: badProof,
      }),
    ).toEqual({
      kind: 'Refuted',
      reason: 'epoch-anchor-consistency-failed',
    });
  });

  test('AG125: R3 blocks ForwardSecureWitnessKey leakage into M1 store & refuses non-monotonic Epoch 1 -> Epoch 3 skip', () => {
    const {kv, coordKey, w1, w2, w3, w5, epoch1Roster} =
      setupDynamicCommitteeFixture('log-reconfig-r3');

    // 1. R3 Guard prevents ForwardSecureWitnessKey from entering M1 store or JSON serialization:
    expect(() => kv.putBlob('leak-fs-witness-key', {key: w1}, [])).toThrow(
      /R3 ReachabilityLeakError/,
    );
    expect(() => JSON.stringify({key: w1})).toThrow(/R3 ReachabilityLeakError/);

    // 2. Non-monotonic epoch skip (Epoch 1 -> Epoch 3) is deterministically refused:
    w1.provisionEpochKey(3);
    w2.provisionEpochKey(3);
    w5.provisionEpochKey(3);
    const w7 = new ForwardSecureWitnessKey('w7', 3);
    const epoch3Roster = createEpochRoster({
      logId: 'log-reconfig-r3',
      epoch: 3,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(3),
        w2: w2.getPublicKeyPem(3),
        w5: w5.getPublicKeyPem(3),
        w7: w7.getPublicKeyPem(3),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, rel: 'r0'});
    const sthE1 = log.issueSignedTreeHead(1);
    const skipCommon = {
      logId: 'log-reconfig-r3',
      fromEpoch: 1,
      toEpoch: 3,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRosterDigest: epoch1Roster.rosterDigest,
      newRosterDigest: epoch3Roster.rosterDigest,
    };
    const skipCert = buildJointHandoverCertificate({
      logId: skipCommon.logId,
      fromEpoch: 1,
      toEpoch: 3,
      anchorTreeSize: sthE1.treeSize,
      anchorRootHashHex: sthE1.rootHashHex,
      oldRoster: epoch1Roster,
      newRoster: epoch3Roster,
      oldQuorumCosignatures: [
        w1.signHandover({...skipCommon, signingEpoch: 1}),
        w2.signHandover({...skipCommon, signingEpoch: 1}),
        w3.signHandover({...skipCommon, signingEpoch: 1}),
      ],
      newQuorumCosignatures: [
        w1.signHandover({...skipCommon, signingEpoch: 3}),
        w2.signHandover({...skipCommon, signingEpoch: 3}),
        w5.signHandover({...skipCommon, signingEpoch: 3}),
      ],
    });
    expect(verifyJointHandoverCertificate({cert: skipCert, oldRoster: epoch1Roster})).toEqual({
      kind: 'Refuted',
      reason: 'non-monotonic-epoch-transition',
    });
  });
});
