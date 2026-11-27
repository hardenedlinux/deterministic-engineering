// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from '../src/durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from '../src/transparency-log-equivocation.ts';
import {
  buildThresholdCheckpoint,
  IndependentTransparencyWitness,
  validateBftQuorumParameters,
  verifyThresholdCosignedCheckpoint,
  WitnessCosigningKey,
} from '../src/witness-quorum-finality.ts';

function setupFourWitnessFleet(logId: string) {
  const coordKey = new CoordinatorSigningKey(logId);
  const w1Key = new WitnessCosigningKey('witness-1');
  const w2Key = new WitnessCosigningKey('witness-2');
  const w3Key = new WitnessCosigningKey('witness-3');
  const w4ByzKey = new WitnessCosigningKey('witness-4-byz');

  const w1 = new IndependentTransparencyWitness(w1Key, logId, coordKey.publicKeyPem);
  const w2 = new IndependentTransparencyWitness(w2Key, logId, coordKey.publicKeyPem);
  const w3 = new IndependentTransparencyWitness(w3Key, logId, coordKey.publicKeyPem);

  const roster: Record<string, string> = {
    'witness-1': w1Key.publicKeyPem,
    'witness-2': w2Key.publicKeyPem,
    'witness-3': w3Key.publicKeyPem,
    'witness-4-byz': w4ByzKey.publicKeyPem,
  };

  return {coordKey, w1, w2, w3, w4ByzKey, roster};
}

describe('Phase 21 Proactive Threshold Witness Cosigning (2f+1 of 3f+1) & Quorum Intersection Finality (10.169 / 30.05 AG111-AG115)', () => {
  test('AG111: 3-of-4 Ed25519 Quorum Certificate verifies RFC 6962 growth (2 -> 5) and finalizes offline with zero gossip', () => {
    const {coordKey, w1, w2, w3, roster} = setupFourWitnessFleet('log-bft-prod');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0, release: 'r0'});
    log.appendEntry({seq: 1, release: 'r1'});
    const sth2 = log.issueSignedTreeHead(10);

    // Epoch 10 (size 2): 3 honest witnesses cosign
    const c2 = [w1, w2, w3].map(w => {
      const r = w.verifyAndCosign(sth2, []);
      if (r.kind !== 'Cosigned') throw new Error('expected Cosigned');
      return r.cosignature;
    });
    const qc2 = buildThresholdCheckpoint(sth2, c2);
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: qc2,
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }).kind,
    ).toBe('Finalized');

    // Grow log to size 5; witnesses verify RFC 6962 consistency proof before cosigning!
    log.appendEntry({seq: 2, release: 'r2'});
    log.appendEntry({seq: 3, release: 'r3'});
    log.appendEntry({seq: 4, release: 'r4'});
    const sth5 = log.issueSignedTreeHead(20);
    const consProof = log.getConsistencyProof(2, 5);

    const c5 = [w1, w2, w3].map(w => {
      const r = w.verifyAndCosign(sth5, consProof);
      if (r.kind !== 'Cosigned') throw new Error('expected Cosigned');
      return r.cosignature;
    });
    const qc5 = buildThresholdCheckpoint(sth5, c5);

    // Completely offline air-gapped verifier confirms finality!
    const finalVerdict = verifyThresholdCosignedCheckpoint({
      checkpoint: qc5,
      coordinatorPublicKeyPem: coordKey.publicKeyPem,
      witnessRosterPublicKeys: roster,
      maxByzantineFaults: 1,
      threshold: 3,
    });
    expect(finalVerdict).toEqual({
      kind: 'Finalized',
      checkpointDigest: qc5.checkpointDigest,
      verifiedWitnessIds: ['witness-1', 'witness-2', 'witness-3'],
      quorumThreshold: 3,
    });
  });

  test('AG112: Byzantine Quorum Intersection (N=4, f=1, t=3) proactively blocks split-view backdoor even under total network eclipse', () => {
    const {coordKey, w1, w2, w3, w4ByzKey, roster} = setupFourWitnessFleet('log-eclipse-test');

    // Compromised coordinator prepares Clean View (size 3) for Regulator:
    const cleanLog = new VerifiableTransparencyLog(coordKey);
    cleanLog.appendEntry({seq: 0, msg: 'ok'});
    cleanLog.appendEntry({seq: 1, msg: 'ok'});
    cleanLog.appendEntry({seq: 2, msg: 'ok'});
    const sthClean = cleanLog.issueSignedTreeHead(10);

    // Clean View achieves 3-of-4 QC via honest w1, honest w2, and Byzantine w4:
    const w1Clean = w1.verifyAndCosign(sthClean);
    const w2Clean = w2.verifyAndCosign(sthClean);
    if (w1Clean.kind !== 'Cosigned' || w2Clean.kind !== 'Cosigned') {
      throw new Error('expected Cosigned');
    }
    const w4Clean = w4ByzKey.cosignTreeHead(sthClean);
    const qcClean = buildThresholdCheckpoint(sthClean, [
      w1Clean.cosignature,
      w2Clean.cosignature,
      w4Clean,
    ]);
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: qcClean,
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }).kind,
    ).toBe('Finalized');

    // Now compromised coordinator tries to finalize Backdoor View (size 3) for an eclipsed prod worker!
    const backdoorLog = new VerifiableTransparencyLog(coordKey);
    backdoorLog.appendEntry({seq: 0, msg: 'ok'});
    backdoorLog.appendEntry({seq: 1, msg: 'BACKDOOR'});
    backdoorLog.appendEntry({seq: 2, msg: 'ok'});
    const sthBackdoor = backdoorLog.issueSignedTreeHead(11);

    // Honest w3 (who hasn't seen Clean View yet) signs Backdoor, and Byzantine w4 double-signs Backdoor...
    const w3Backdoor = w3.verifyAndCosign(sthBackdoor);
    if (w3Backdoor.kind !== 'Cosigned') throw new Error('expected Cosigned');
    const w4Backdoor = w4ByzKey.cosignTreeHead(sthBackdoor);

    // ...but honest w1 and w2 BOTH refuse Backdoor and emit cryptographic Fraud Proofs!
    const w1Refusal = w1.verifyAndCosign(sthBackdoor);
    expect(w1Refusal.kind).toBe('RefusedEquivocation');
    const w2Refusal = w2.verifyAndCosign(sthBackdoor);
    expect(w2Refusal.kind).toBe('RefusedEquivocation');

    // Therefore Backdoor caps at 2 < 3 signatures and is PROACTIVELY BLOCKED offline!
    const qcBackdoorAttempt = buildThresholdCheckpoint(sthBackdoor, [
      w3Backdoor.cosignature,
      w4Backdoor,
    ]);
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: qcBackdoorAttempt,
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }),
    ).toEqual({
      kind: 'Refuted',
      reason: 'insufficient-witness-quorum',
      detail: 'collected=2 required=3',
    });
  });

  test('AG113: Duplicate witness spoofing, rogue unregistered witness, and forged cosignature are rejected', () => {
    const {coordKey, w1, w2, roster} = setupFourWitnessFleet('log-spoof');
    const log = new VerifiableTransparencyLog(coordKey);
    log.appendEntry({seq: 0});
    const sth = log.issueSignedTreeHead(1);

    const c1 = w1.verifyAndCosign(sth);
    const c2 = w2.verifyAndCosign(sth);
    if (c1.kind !== 'Cosigned' || c2.kind !== 'Cosigned') throw new Error('expected Cosigned');

    // 1. Duplicate witness-1 cosignature to spoof 3-of-4 -> refused!
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: buildThresholdCheckpoint(sth, [c1.cosignature, c1.cosignature, c2.cosignature]),
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }).reason,
    ).toBe('duplicate-witness-cosignature');

    // 2. Unregistered rogue witness -> refused!
    const rogueKey = new WitnessCosigningKey('rogue-witness-99');
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: buildThresholdCheckpoint(sth, [
          c1.cosignature,
          c2.cosignature,
          rogueKey.cosignTreeHead(sth),
        ]),
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }).reason,
    ).toBe('unregistered-witness');

    // 3. Tampered signature bytes on registered witness-3 -> refused!
    const forgedW3 = {
      ...c1.cosignature,
      witnessId: 'witness-3',
    };
    expect(
      verifyThresholdCosignedCheckpoint({
        checkpoint: buildThresholdCheckpoint(sth, [c1.cosignature, c2.cosignature, forgedW3]),
        coordinatorPublicKeyPem: coordKey.publicKeyPem,
        witnessRosterPublicKeys: roster,
        maxByzantineFaults: 1,
        threshold: 3,
      }).reason,
    ).toBe('invalid-witness-signature');
  });

  test('AG114: Retroactive history rewrite is refused by honest witnesses BEFORE cosigning', () => {
    const {coordKey, w1} = setupFourWitnessFleet('log-rewrite-cosign');
    const log1 = new VerifiableTransparencyLog(coordKey);
    log1.appendEntry({seq: 0, v: 'original'});
    log1.appendEntry({seq: 1, v: 'original'});
    const sth2 = log1.issueSignedTreeHead(1);
    expect(w1.verifyAndCosign(sth2).kind).toBe('Cosigned');

    // Coordinator rewrites leaf 0 and grows to size 3:
    const evilLog = new VerifiableTransparencyLog(coordKey);
    evilLog.appendEntry({seq: 0, v: 'REWRITTEN'});
    evilLog.appendEntry({seq: 1, v: 'original'});
    evilLog.appendEntry({seq: 2, v: 'new'});
    const sthEvil3 = evilLog.issueSignedTreeHead(2);
    const fakeProof = evilLog.getConsistencyProof(2, 3);

    const res = w1.verifyAndCosign(sthEvil3, fakeProof);
    expect(res.kind).toBe('RefusedEquivocation');
    if (res.kind === 'RefusedEquivocation') {
      expect(res.fraudProof.fraudKind).toBe('history-rewrite-inconsistent-prefix');
    }
  });

  test('AG115: R3 blocks WitnessCosigningKey from leaking into M1 store & rejects unsafe non-intersecting BFT quorum parameters', () => {
    const kv = new ContentAddressedKvStore();
    const wKey = new WitnessCosigningKey('witness-secret');

    expect(() => kv.putBlob('leak', {nested: {wKey}}, [])).toThrow(/R3 ReachabilityLeakError/);
    expect(() => JSON.stringify(wKey)).toThrow(/R3 ReachabilityLeakError/);

    // N=4, f=1, threshold=2 -> overlap = 2*2 - 4 = 0 < f+1 = 2 -> UNSAFE!
    expect(
      validateBftQuorumParameters({totalWitnesses: 4, maxByzantineFaults: 1, threshold: 2}),
    ).toEqual({kind: 'Refuted', reason: 'unsafe-non-intersecting-quorum'});

    // N=4, f=1, threshold=3 -> overlap = 6 - 4 = 2 >= f+1 -> VALID (minHonestIntersection = 1)!
    expect(
      validateBftQuorumParameters({totalWitnesses: 4, maxByzantineFaults: 1, threshold: 3}),
    ).toEqual({kind: 'Valid', minHonestIntersection: 1});
  });
});
