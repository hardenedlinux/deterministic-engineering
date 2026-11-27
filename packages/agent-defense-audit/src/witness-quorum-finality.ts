// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 21 (Business Extension B10, 10.169):
 * Proactive Threshold Witness Cosigning (t = 2f + 1 of N = 3f + 1),
 * Byzantine Quorum Intersection Finality, and Eclipse-Resistant Offline Verification.
 *
 * Closes the residual network-eclipse limitation of reactive gossip (10.166 / B9):
 *   1. Non-Serializable M3 `WitnessCosigningKey` (real `node:crypto` Ed25519 keypair,
 *      branded with R3 `M3_NON_SERIALIZABLE_CAPABILITY`).
 *   2. `IndependentTransparencyWitness`: maintains monotonic per-log state and verifies
 *      BOTH Coordinator Ed25519 signature AND exact RFC 6962 append-only consistency
 *      before cosigning. Refuses split-view & emits `EquivocationFraudProof`.
 *   3. `validateBftQuorumParameters(n, f, threshold)`: mathematically enforces Byzantine
 *      Quorum Intersection (`2 * threshold > n + f`, i.e., any two quorums intersect in
 *      at least `f + 1` witnesses, guaranteeing >= 1 honest witness in the intersection!).
 *   4. `verifyThresholdCosignedCheckpoint`: completely offline, air-gap-safe verifier
 *      requiring >= `threshold` distinct registered witness Ed25519 cosignatures —
 *      preventing a compromised Coordinator + `f` Byzantine witnesses from finalizing
 *      conflicting checkpoints even under total network eclipse!
 */

import {
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {M3_NON_SERIALIZABLE_CAPABILITY, sha256Digest} from './durable-merkle-store.ts';
import {
  EquivocationFraudProof,
  SignedTreeHead,
  verifySignedTreeHead,
  WitnessEquivocationMonitor,
} from './transparency-log-equivocation.ts';

export interface WitnessCosignature {
  witnessId: string;
  logId: string;
  treeSize: number;
  rootHashHex: string;
  epoch: number;
  cosignatureBase64: string;
}

export interface ThresholdCosignedCheckpoint {
  sth: SignedTreeHead;
  cosignatures: WitnessCosignature[];
  checkpointDigest: string;
}

function canonicalCosignMessage(params: {
  witnessId: string;
  logId: string;
  treeSize: number;
  rootHashHex: string;
  epoch: number;
}): Buffer {
  return Buffer.from(
    `COSIGN-STH|${params.witnessId}|${params.logId}|${params.treeSize}|${params.rootHashHex}|${params.epoch}`,
    'utf8',
  );
}

/**
 * R3 Non-Serializable M3 Ed25519 Cosigning Key owned by an independent external Witness.
 */
export class WitnessCosigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly witnessId: string) {
    this.capabilityId = `ed25519-witness-key:${witnessId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  cosignTreeHead(sth: SignedTreeHead): WitnessCosignature {
    const msg = canonicalCosignMessage({
      witnessId: this.witnessId,
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHashHex: sth.rootHashHex,
      epoch: sth.epoch,
    });
    const sig = cryptoSign(null, msg, this.privateKey);
    return {
      witnessId: this.witnessId,
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHashHex: sth.rootHashHex,
      epoch: sth.epoch,
      cosignatureBase64: sig.toString('base64'),
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: WitnessCosigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export function verifyWitnessCosignature(
  cosig: WitnessCosignature,
  sth: SignedTreeHead,
  witnessPublicKeyPem: string,
): boolean {
  if (
    cosig.logId !== sth.logId ||
    cosig.treeSize !== sth.treeSize ||
    cosig.rootHashHex !== sth.rootHashHex ||
    cosig.epoch !== sth.epoch
  ) {
    return false;
  }
  const pubKey = createPublicKey(witnessPublicKeyPem);
  const sig = Buffer.from(cosig.cosignatureBase64, 'base64');
  const msg = canonicalCosignMessage({
    witnessId: cosig.witnessId,
    logId: sth.logId,
    treeSize: sth.treeSize,
    rootHashHex: sth.rootHashHex,
    epoch: sth.epoch,
  });
  return cryptoVerify(null, msg, pubKey, sig);
}

export type WitnessCosignVerdict =
  | {kind: 'Cosigned'; cosignature: WitnessCosignature}
  | {kind: 'Refuted'; reason: 'invalid-ed25519-signature' | 'log-id-mismatch'}
  | {kind: 'RefusedEquivocation'; fraudProof: EquivocationFraudProof};

/**
 * Honest Independent Transparency Witness:
 * Never cosigns without verifying Coordinator Ed25519 signature + RFC 6962 append-only
 * consistency against its own monotonic state; emits `EquivocationFraudProof` on any
 * split-view, rollback, or retroactive rewrite.
 */
export class IndependentTransparencyWitness {
  private readonly monitor: WitnessEquivocationMonitor;

  constructor(
    private readonly witnessKey: WitnessCosigningKey,
    logId: string,
    coordinatorPublicKeyPem: string,
  ) {
    this.monitor = new WitnessEquivocationMonitor(logId, coordinatorPublicKeyPem);
  }

  get witnessId(): string {
    return this.witnessKey.witnessId;
  }

  get publicKeyPem(): string {
    return this.witnessKey.publicKeyPem;
  }

  verifyAndCosign(
    sth: SignedTreeHead,
    consistencyProofFromLast: readonly string[] = [],
  ): WitnessCosignVerdict {
    const obs = this.monitor.observeSignedTreeHead(sth, consistencyProofFromLast);
    if (obs.kind === 'Refuted') return obs;
    if (obs.kind === 'EquivocationDetected') {
      return {kind: 'RefusedEquivocation', fraudProof: obs.fraudProof};
    }
    return {kind: 'Cosigned', cosignature: this.witnessKey.cosignTreeHead(sth)};
  }
}

export function validateBftQuorumParameters(params: {
  totalWitnesses: number;
  maxByzantineFaults: number;
  threshold: number;
}):
  | {kind: 'Valid'; minHonestIntersection: number}
  | {kind: 'Refuted'; reason: 'invalid-parameters' | 'unsafe-non-intersecting-quorum'} {
  const {totalWitnesses: n, maxByzantineFaults: f, threshold: t} = params;
  if (!Number.isInteger(n) || !Number.isInteger(f) || !Number.isInteger(t) || n <= 0 || f < 0 || t <= 0 || t > n) {
    return {kind: 'Refuted', reason: 'invalid-parameters'};
  }
  // Quorum Intersection Theorem: two quorums of size t in N witnesses intersect in at least (2t - n).
  // For Byzantine safety against f equivocating witnesses, we need (2t - n) >= f + 1!
  const overlap = 2 * t - n;
  const minHonestIntersection = overlap - f;
  if (minHonestIntersection < 1) {
    return {kind: 'Refuted', reason: 'unsafe-non-intersecting-quorum'};
  }
  return {kind: 'Valid', minHonestIntersection};
}

export function buildThresholdCheckpoint(
  sth: SignedTreeHead,
  cosignatures: readonly WitnessCosignature[],
): ThresholdCosignedCheckpoint {
  const sorted = [...cosignatures].sort((a, b) => a.witnessId.localeCompare(b.witnessId));
  return {
    sth,
    cosignatures: sorted,
    checkpointDigest: sha256Digest({sth, cosignatures: sorted}),
  };
}

export type CheckpointFinalityVerdict =
  | {
      kind: 'Finalized';
      checkpointDigest: string;
      verifiedWitnessIds: string[];
      quorumThreshold: number;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'unsafe-quorum-parameters'
        | 'invalid-coordinator-signature'
        | 'duplicate-witness-cosignature'
        | 'unregistered-witness'
        | 'invalid-witness-signature'
        | 'insufficient-witness-quorum';
      detail?: string;
    };

/**
 * Offline, Air-Gap-Safe Checkpoint Finality Verifier:
 * Requires zero network connectivity to other witnesses — verifies Coordinator Ed25519 STH
 * plus >= `threshold` distinct, registered Witness Ed25519 cosignatures under a proven
 * BFT quorum-intersection policy (`2t - N >= f + 1`).
 */
export function verifyThresholdCosignedCheckpoint(params: {
  checkpoint: ThresholdCosignedCheckpoint;
  coordinatorPublicKeyPem: string;
  witnessRosterPublicKeys: Record<string, string>;
  maxByzantineFaults: number;
  threshold: number;
}): CheckpointFinalityVerdict {
  const rosterIds = Object.keys(params.witnessRosterPublicKeys);
  const paramCheck = validateBftQuorumParameters({
    totalWitnesses: rosterIds.length,
    maxByzantineFaults: params.maxByzantineFaults,
    threshold: params.threshold,
  });
  if (paramCheck.kind !== 'Valid') {
    return {kind: 'Refuted', reason: 'unsafe-quorum-parameters'};
  }

  if (!verifySignedTreeHead(params.checkpoint.sth, params.coordinatorPublicKeyPem)) {
    return {kind: 'Refuted', reason: 'invalid-coordinator-signature'};
  }

  const seenWitnesses = new Set<string>();
  const verifiedWitnessIds: string[] = [];

  for (const cosig of params.checkpoint.cosignatures) {
    if (seenWitnesses.has(cosig.witnessId)) {
      return {
        kind: 'Refuted',
        reason: 'duplicate-witness-cosignature',
        detail: cosig.witnessId,
      };
    }
    seenWitnesses.add(cosig.witnessId);

    const pubPem = params.witnessRosterPublicKeys[cosig.witnessId];
    if (!pubPem) {
      return {
        kind: 'Refuted',
        reason: 'unregistered-witness',
        detail: cosig.witnessId,
      };
    }
    if (!verifyWitnessCosignature(cosig, params.checkpoint.sth, pubPem)) {
      return {
        kind: 'Refuted',
        reason: 'invalid-witness-signature',
        detail: cosig.witnessId,
      };
    }
    verifiedWitnessIds.push(cosig.witnessId);
  }

  if (verifiedWitnessIds.length < params.threshold) {
    return {
      kind: 'Refuted',
      reason: 'insufficient-witness-quorum',
      detail: `collected=${verifiedWitnessIds.length} required=${params.threshold}`,
    };
  }

  return {
    kind: 'Finalized',
    checkpointDigest: params.checkpoint.checkpointDigest,
    verifiedWitnessIds: verifiedWitnessIds.sort(),
    quorumThreshold: params.threshold,
  };
}
