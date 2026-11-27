// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 23 (Business Extension B10b, 10.171):
 * Dynamic Witness Roster Reconfiguration, Joint-Consensus Dual-Quorum Handover
 * (Q_old ∩ Q_new), and Forward-Secure Epoch Sealing Against Long-Range Attacks.
 *
 * Closes the static-committee residual limit of B10 (10.169 / 10.170):
 *   1. `ForwardSecureWitnessKey` (R3 non-serializable M3 capability): maintains
 *      per-epoch Ed25519 private signing keys and supports irreversible
 *      `zeroizeRetiredEpochKey(epoch)` upon epoch retirement (Bellare & Miner
 *      CRYPTO 1999 forward security) so posterior host compromise cannot forge
 *      historical checkpoints.
 *   2. `JointHandoverCertificate` & `verifyJointHandoverCertificate`: enforces
 *      Raft/BFT Joint-Consensus dual-quorum handover (Ongaro & Ousterhout USENIX
 *      ATC 2014 §6) requiring BOTH >= t_old distinct Ed25519 signatures from
 *      C_old AND >= t_new distinct Ed25519 signatures from C_new, binding exact
 *      RFC 6962 `(anchorTreeSize, anchorRootHashHex)` and monotonic `epoch -> epoch+1`.
 *   3. `ForwardSealedEpochVerifier`: offline weak-subjectivity monotonic trust-anchor
 *      verifier that refuses retired-epoch checkpoints and alternative handovers
 *      even under total posterior compromise of retired C_old keys, and enforces
 *      exact RFC 6962 append-only consistency across epoch boundaries.
 */

import {
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';
import {verifyConsistencyProof} from './transparency-log-equivocation.ts';
import {
  ThresholdCosignedCheckpoint,
  validateBftQuorumParameters,
  verifyThresholdCosignedCheckpoint,
  WitnessCosignature,
} from './witness-quorum-finality.ts';

export interface EpochRoster {
  logId: string;
  epoch: number;
  witnessPublicKeys: Record<string, string>;
  maxByzantineFaults: number;
  threshold: number;
  rosterDigest: string;
}

export interface EpochHandoverCosignature {
  witnessId: string;
  logId: string;
  fromEpoch: number;
  toEpoch: number;
  anchorTreeSize: number;
  anchorRootHashHex: string;
  oldRosterDigest: string;
  newRosterDigest: string;
  signatureBase64: string;
}

export interface JointHandoverCertificate {
  logId: string;
  fromEpoch: number;
  toEpoch: number;
  anchorTreeSize: number;
  anchorRootHashHex: string;
  oldRosterDigest: string;
  newRosterDigest: string;
  newRoster: EpochRoster;
  oldQuorumCosignatures: EpochHandoverCosignature[];
  newQuorumCosignatures: EpochHandoverCosignature[];
  handoverDigest: string;
}

export function computeRosterDigest(params: {
  logId: string;
  epoch: number;
  witnessPublicKeys: Record<string, string>;
  maxByzantineFaults: number;
  threshold: number;
}): string {
  const sortedKeys = Object.keys(params.witnessPublicKeys)
    .sort()
    .map(id => [id, params.witnessPublicKeys[id]]);
  return sha256Digest({
    logId: params.logId,
    epoch: params.epoch,
    maxByzantineFaults: params.maxByzantineFaults,
    threshold: params.threshold,
    witnesses: sortedKeys,
  });
}

export function createEpochRoster(params: {
  logId: string;
  epoch: number;
  witnessPublicKeys: Record<string, string>;
  maxByzantineFaults: number;
  threshold: number;
}): EpochRoster {
  const n = Object.keys(params.witnessPublicKeys).length;
  const check = validateBftQuorumParameters({
    totalWitnesses: n,
    maxByzantineFaults: params.maxByzantineFaults,
    threshold: params.threshold,
  });
  if (check.kind !== 'Valid') {
    throw new Error(`Invalid BFT roster parameters for epoch ${params.epoch}: ${check.reason}`);
  }
  return {
    logId: params.logId,
    epoch: params.epoch,
    witnessPublicKeys: {...params.witnessPublicKeys},
    maxByzantineFaults: params.maxByzantineFaults,
    threshold: params.threshold,
    rosterDigest: computeRosterDigest(params),
  };
}

function canonicalHandoverMessage(params: {
  witnessId: string;
  logId: string;
  fromEpoch: number;
  toEpoch: number;
  anchorTreeSize: number;
  anchorRootHashHex: string;
  oldRosterDigest: string;
  newRosterDigest: string;
}): Buffer {
  return Buffer.from(
    `HANDOVER|${params.witnessId}|${params.logId}|${params.fromEpoch}->${params.toEpoch}|${params.anchorTreeSize}|${params.anchorRootHashHex}|${params.oldRosterDigest}|${params.newRosterDigest}`,
    'utf8',
  );
}

function canonicalCheckpointCosignMessage(params: {
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
 * R3 Non-Serializable Forward-Secure M3 Witness Signing Key.
 * Generates an independent Ed25519 keypair per epoch and supports permanent
 * irreversible zeroization of retired epoch private keys.
 */
export class ForwardSecureWitnessKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  private readonly epochPrivateKeys = new Map<number, KeyObject>();
  private readonly epochPublicPems = new Map<number, string>();
  private readonly zeroizedEpochs = new Set<number>();

  constructor(
    readonly witnessId: string,
    initialEpoch: number,
  ) {
    this.capabilityId = `forward-secure-ed25519-witness:${witnessId}`;
    this.provisionEpochKey(initialEpoch);
  }

  provisionEpochKey(epoch: number): string {
    if (this.zeroizedEpochs.has(epoch)) {
      throw new Error(
        `ForwardSecureKeyZeroizedError: epoch ${epoch} key for '${this.witnessId}' was permanently zeroized and cannot be re-provisioned`,
      );
    }
    const existing = this.epochPublicPems.get(epoch);
    if (existing) return existing;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    const pem = publicKey.export({type: 'spki', format: 'pem'}).toString();
    this.epochPrivateKeys.set(epoch, privateKey);
    this.epochPublicPems.set(epoch, pem);
    return pem;
  }

  getPublicKeyPem(epoch: number): string {
    const pem = this.epochPublicPems.get(epoch);
    if (!pem) throw new Error(`No public key registered for witness '${this.witnessId}' at epoch ${epoch}`);
    return pem;
  }

  isEpochZeroized(epoch: number): boolean {
    return this.zeroizedEpochs.has(epoch);
  }

  zeroizeRetiredEpochKey(epoch: number): void {
    this.epochPrivateKeys.delete(epoch);
    this.zeroizedEpochs.add(epoch);
  }

  private requireActivePrivateKey(epoch: number): KeyObject {
    if (this.zeroizedEpochs.has(epoch)) {
      throw new Error(
        `ForwardSecureKeyZeroizedError: private key for witness '${this.witnessId}' epoch ${epoch} has been zeroized`,
      );
    }
    const key = this.epochPrivateKeys.get(epoch);
    if (!key) {
      throw new Error(`No active private key for witness '${this.witnessId}' at epoch ${epoch}`);
    }
    return key;
  }

  cosignCheckpoint(params: {
    logId: string;
    treeSize: number;
    rootHashHex: string;
    epoch: number;
  }): WitnessCosignature {
    const priv = this.requireActivePrivateKey(params.epoch);
    const msg = canonicalCheckpointCosignMessage({
      witnessId: this.witnessId,
      logId: params.logId,
      treeSize: params.treeSize,
      rootHashHex: params.rootHashHex,
      epoch: params.epoch,
    });
    return {
      witnessId: this.witnessId,
      logId: params.logId,
      treeSize: params.treeSize,
      rootHashHex: params.rootHashHex,
      epoch: params.epoch,
      cosignatureBase64: cryptoSign(null, msg, priv).toString('base64'),
    };
  }

  signHandover(params: {
    signingEpoch: number;
    logId: string;
    fromEpoch: number;
    toEpoch: number;
    anchorTreeSize: number;
    anchorRootHashHex: string;
    oldRosterDigest: string;
    newRosterDigest: string;
  }): EpochHandoverCosignature {
    const priv = this.requireActivePrivateKey(params.signingEpoch);
    const msg = canonicalHandoverMessage({
      witnessId: this.witnessId,
      logId: params.logId,
      fromEpoch: params.fromEpoch,
      toEpoch: params.toEpoch,
      anchorTreeSize: params.anchorTreeSize,
      anchorRootHashHex: params.anchorRootHashHex,
      oldRosterDigest: params.oldRosterDigest,
      newRosterDigest: params.newRosterDigest,
    });
    return {
      witnessId: this.witnessId,
      logId: params.logId,
      fromEpoch: params.fromEpoch,
      toEpoch: params.toEpoch,
      anchorTreeSize: params.anchorTreeSize,
      anchorRootHashHex: params.anchorRootHashHex,
      oldRosterDigest: params.oldRosterDigest,
      newRosterDigest: params.newRosterDigest,
      signatureBase64: cryptoSign(null, msg, priv).toString('base64'),
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: ForwardSecureWitnessKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export function buildJointHandoverCertificate(params: {
  logId: string;
  fromEpoch: number;
  toEpoch: number;
  anchorTreeSize: number;
  anchorRootHashHex: string;
  oldRoster: EpochRoster;
  newRoster: EpochRoster;
  oldQuorumCosignatures: EpochHandoverCosignature[];
  newQuorumCosignatures: EpochHandoverCosignature[];
}): JointHandoverCertificate {
  const payload = {
    logId: params.logId,
    fromEpoch: params.fromEpoch,
    toEpoch: params.toEpoch,
    anchorTreeSize: params.anchorTreeSize,
    anchorRootHashHex: params.anchorRootHashHex,
    oldRosterDigest: params.oldRoster.rosterDigest,
    newRosterDigest: params.newRoster.rosterDigest,
    newRoster: params.newRoster,
    oldQuorumCosignatures: params.oldQuorumCosignatures,
    newQuorumCosignatures: params.newQuorumCosignatures,
  };
  return {
    ...payload,
    handoverDigest: sha256Digest(payload),
  };
}

function verifyHandoverQuorumSignatures(
  cert: JointHandoverCertificate,
  roster: EpochRoster,
  cosigs: readonly EpochHandoverCosignature[],
): {ok: true; signers: string[]} | {ok: false; reason: string} {
  const bftCheck = validateBftQuorumParameters({
    totalWitnesses: Object.keys(roster.witnessPublicKeys).length,
    maxByzantineFaults: roster.maxByzantineFaults,
    threshold: roster.threshold,
  });
  if (bftCheck.kind !== 'Valid') return {ok: false, reason: bftCheck.reason};

  const verified = new Set<string>();
  for (const sig of cosigs) {
    if (
      sig.logId !== cert.logId ||
      sig.fromEpoch !== cert.fromEpoch ||
      sig.toEpoch !== cert.toEpoch ||
      sig.anchorTreeSize !== cert.anchorTreeSize ||
      sig.anchorRootHashHex !== cert.anchorRootHashHex ||
      sig.oldRosterDigest !== cert.oldRosterDigest ||
      sig.newRosterDigest !== cert.newRosterDigest
    ) {
      return {ok: false, reason: 'handover-signature-payload-mismatch'};
    }
    const pubPem = roster.witnessPublicKeys[sig.witnessId];
    if (!pubPem) return {ok: false, reason: 'unregistered-handover-witness'};
    if (verified.has(sig.witnessId)) return {ok: false, reason: 'duplicate-handover-witness'};

    const msg = canonicalHandoverMessage(sig);
    const sigBytes = Buffer.from(sig.signatureBase64, 'base64');
    const valid = cryptoVerify(null, msg, createPublicKey(pubPem), sigBytes);
    if (!valid) return {ok: false, reason: 'invalid-handover-ed25519-signature'};
    verified.add(sig.witnessId);
  }

  if (verified.size < roster.threshold) {
    return {ok: false, reason: 'insufficient-handover-quorum'};
  }
  return {ok: true, signers: [...verified].sort()};
}

export type HandoverVerificationVerdict =
  | {
      kind: 'HandoverVerified';
      handoverDigest: string;
      oldSigners: string[];
      newSigners: string[];
    }
  | {kind: 'Refuted'; reason: string};

/**
 * Offline cryptographic verifier for Joint-Consensus Dual-Quorum Handover (Q_old ∩ Q_new).
 */
export function verifyJointHandoverCertificate(params: {
  cert: JointHandoverCertificate;
  oldRoster: EpochRoster;
}): HandoverVerificationVerdict {
  const {cert, oldRoster} = params;
  if (cert.logId !== oldRoster.logId || cert.newRoster.logId !== oldRoster.logId) {
    return {kind: 'Refuted', reason: 'handover-log-id-mismatch'};
  }
  if (cert.fromEpoch !== oldRoster.epoch || cert.toEpoch !== oldRoster.epoch + 1) {
    return {kind: 'Refuted', reason: 'non-monotonic-epoch-transition'};
  }
  if (cert.newRoster.epoch !== cert.toEpoch) {
    return {kind: 'Refuted', reason: 'new-roster-epoch-mismatch'};
  }
  if (cert.oldRosterDigest !== oldRoster.rosterDigest) {
    return {kind: 'Refuted', reason: 'old-roster-digest-mismatch'};
  }
  const recomputedNewDigest = computeRosterDigest(cert.newRoster);
  if (
    cert.newRosterDigest !== recomputedNewDigest ||
    cert.newRoster.rosterDigest !== recomputedNewDigest
  ) {
    return {kind: 'Refuted', reason: 'new-roster-digest-mismatch'};
  }

  const oldCheck = verifyHandoverQuorumSignatures(cert, oldRoster, cert.oldQuorumCosignatures);
  if (!oldCheck.ok) {
    return {kind: 'Refuted', reason: `old-quorum-failed:${oldCheck.reason}`};
  }
  const newCheck = verifyHandoverQuorumSignatures(cert, cert.newRoster, cert.newQuorumCosignatures);
  if (!newCheck.ok) {
    return {kind: 'Refuted', reason: `new-quorum-failed:${newCheck.reason}`};
  }

  return {
    kind: 'HandoverVerified',
    handoverDigest: cert.handoverDigest,
    oldSigners: oldCheck.signers,
    newSigners: newCheck.signers,
  };
}

export type EpochCheckpointVerdict =
  | {
      kind: 'FinalizedInEpoch';
      epoch: number;
      treeSize: number;
      rootHashHex: string;
      checkpointDigest: string;
      verifiedWitnessIds: string[];
    }
  | {kind: 'Refuted'; reason: string};

export type EpochHandoverApplyVerdict =
  | {
      kind: 'EpochAdvanced';
      newEpoch: number;
      handoverReceiptHash: string;
      oldSigners: string[];
      newSigners: string[];
    }
  | {kind: 'Refuted'; reason: string};

/**
 * Phase 25 (B10c, 10.173): Self-Authenticating Cryptographic Equivocation Slash Proof.
 * Pure library primitive: any offline node can verify that `witnessId` signed two
 * distinct roots at the same `(logId, epoch, treeSize)` under `witnessPublicKeyPem`.
 */
export interface WitnessEquivocationSlashProof {
  witnessId: string;
  witnessPublicKeyPem: string;
  witnessPublicKeyDigest: string;
  logId: string;
  epoch: number;
  treeSize: number;
  cosigA: WitnessCosignature;
  cosigB: WitnessCosignature;
  slashProofDigest: string;
}

export type SlashProofBuildVerdict =
  | {kind: 'SlashProofCreated'; proof: WitnessEquivocationSlashProof}
  | {kind: 'Refuted'; reason: string};

export function verifyWitnessSlashProof(
  proof: WitnessEquivocationSlashProof,
): {kind: 'Valid'} | {kind: 'Refuted'; reason: string} {
  const {cosigA, cosigB} = proof;
  if (
    cosigA.witnessId !== proof.witnessId ||
    cosigB.witnessId !== proof.witnessId ||
    cosigA.logId !== proof.logId ||
    cosigB.logId !== proof.logId ||
    cosigA.epoch !== proof.epoch ||
    cosigB.epoch !== proof.epoch ||
    cosigA.treeSize !== proof.treeSize ||
    cosigB.treeSize !== proof.treeSize
  ) {
    return {kind: 'Refuted', reason: 'slash-proof-metadata-mismatch'};
  }
  if (cosigA.rootHashHex === cosigB.rootHashHex) {
    return {kind: 'Refuted', reason: 'identical-roots-not-equivocation'};
  }
  if (sha256Digest(proof.witnessPublicKeyPem) !== proof.witnessPublicKeyDigest) {
    return {kind: 'Refuted', reason: 'pubkey-digest-mismatch'};
  }
  const pubKey = createPublicKey(proof.witnessPublicKeyPem);
  const okA = cryptoVerify(
    null,
    canonicalCheckpointCosignMessage(cosigA),
    pubKey,
    Buffer.from(cosigA.cosignatureBase64, 'base64'),
  );
  const okB = cryptoVerify(
    null,
    canonicalCheckpointCosignMessage(cosigB),
    pubKey,
    Buffer.from(cosigB.cosignatureBase64, 'base64'),
  );
  if (!okA || !okB) {
    return {kind: 'Refuted', reason: 'invalid-slash-ed25519-signature'};
  }
  return {kind: 'Valid'};
}

export function buildWitnessSlashProof(params: {
  cosigA: WitnessCosignature;
  cosigB: WitnessCosignature;
  witnessPublicKeyPem: string;
}): SlashProofBuildVerdict {
  const {cosigA, cosigB, witnessPublicKeyPem} = params;
  const witnessPublicKeyDigest = sha256Digest(witnessPublicKeyPem);
  const draft: WitnessEquivocationSlashProof = {
    witnessId: cosigA.witnessId,
    witnessPublicKeyPem,
    witnessPublicKeyDigest,
    logId: cosigA.logId,
    epoch: cosigA.epoch,
    treeSize: cosigA.treeSize,
    cosigA,
    cosigB,
    slashProofDigest: sha256Digest({
      witnessId: cosigA.witnessId,
      witnessPublicKeyDigest,
      logId: cosigA.logId,
      epoch: cosigA.epoch,
      treeSize: cosigA.treeSize,
      roots: [cosigA.rootHashHex, cosigB.rootHashHex].sort(),
    }),
  };
  const check = verifyWitnessSlashProof(draft);
  if (check.kind !== 'Valid') return check;
  return {kind: 'SlashProofCreated', proof: draft};
}

/**
 * Offline Weak-Subjectivity Monotonic Epoch Trust-Anchor Verifier.
 * Pins the highest completed handover epoch and monotonic M1 slash tombstones, refusing:
 *   - Retired-epoch checkpoints or alternative handovers (defeats posterior corruption),
 *   - Future-epoch checkpoints without verified Joint-Consensus handover,
 *   - Spliced post-handover trees failing RFC 6962 consistency from the epoch anchor,
 *   - Re-entry of cryptographically slashed witnesses by ID OR Sybil public-key reuse (B10c).
 */
export class ForwardSealedEpochVerifier {
  private activeRoster: EpochRoster;
  private anchorTreeSize = 0;
  private anchorRootHashHex = '';
  private lastFinalizedSize = 0;
  private lastFinalizedRootHex = '';
  private readonly slashedWitnessIds = new Set<string>();
  private readonly slashedPublicKeyDigests = new Set<string>();

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly coordinatorPublicKeyPem: string,
    genesisRoster: EpochRoster,
  ) {
    this.activeRoster = genesisRoster;
  }

  getPinnedEpoch(): number {
    return this.activeRoster.epoch;
  }

  getActiveRoster(): EpochRoster {
    return this.activeRoster;
  }

  getSlashedWitnessIds(): string[] {
    return [...this.slashedWitnessIds].sort();
  }

  /**
   * Verifies a self-authenticating `WitnessEquivocationSlashProof` offline and pins an
   * immutable M1 slash tombstone (blocking future re-entry by ID or Sybil pubkey reuse).
   */
  recordVerifiedSlashProof(
    proof: WitnessEquivocationSlashProof,
  ): {kind: 'Slashed'; slashTombstoneHash: string; witnessId: string} | {kind: 'Refuted'; reason: string} {
    if (proof.logId !== this.activeRoster.logId) {
      return {kind: 'Refuted', reason: 'slash-log-id-mismatch'};
    }
    const check = verifyWitnessSlashProof(proof);
    if (check.kind !== 'Valid') return check;

    this.slashedWitnessIds.add(proof.witnessId);
    this.slashedPublicKeyDigests.add(proof.witnessPublicKeyDigest);

    const slashTombstoneHash = this.kv.putBlob(
      'witness-equivocation-slash-tombstone',
      {
        logId: proof.logId,
        witnessId: proof.witnessId,
        witnessPublicKeyDigest: proof.witnessPublicKeyDigest,
        epoch: proof.epoch,
        treeSize: proof.treeSize,
        slashProofDigest: proof.slashProofDigest,
      },
      [],
    );
    this.kv.pinHistoricalCut(slashTombstoneHash);

    return {kind: 'Slashed', slashTombstoneHash, witnessId: proof.witnessId};
  }

  verifyCheckpointInCurrentEpoch(params: {
    checkpoint: ThresholdCosignedCheckpoint;
    consistencyProofFromAnchor?: string[];
  }): EpochCheckpointVerdict {
    const sth = params.checkpoint.sth;
    if (sth.logId !== this.activeRoster.logId) {
      return {kind: 'Refuted', reason: 'log-id-mismatch'};
    }
    if (sth.epoch < this.activeRoster.epoch) {
      return {kind: 'Refuted', reason: 'long-range-retired-epoch-refused'};
    }
    if (sth.epoch > this.activeRoster.epoch) {
      return {kind: 'Refuted', reason: 'future-epoch-without-handover-refused'};
    }

    // Filter out any cosignatures from cryptographically slashed witnesses before quorum check:
    const unslashedCosigs = params.checkpoint.cosignatures.filter(c => {
      if (this.slashedWitnessIds.has(c.witnessId)) return false;
      const pem = this.activeRoster.witnessPublicKeys[c.witnessId];
      if (pem && this.slashedPublicKeyDigests.has(sha256Digest(pem))) return false;
      return true;
    });
    if (unslashedCosigs.length < this.activeRoster.threshold) {
      return {kind: 'Refuted', reason: 'insufficient-unslashed-witness-quorum'};
    }
    const filteredCheckpoint: ThresholdCosignedCheckpoint = {
      ...params.checkpoint,
      cosignatures: unslashedCosigs,
    };

    // Enforce RFC 6962 append-only continuity from the pinned epoch anchor:
    if (this.anchorTreeSize > 0) {
      if (sth.treeSize < this.anchorTreeSize) {
        return {kind: 'Refuted', reason: 'tree-size-below-epoch-anchor'};
      }
      if (sth.treeSize === this.anchorTreeSize) {
        if (sth.rootHashHex !== this.anchorRootHashHex) {
          return {kind: 'Refuted', reason: 'epoch-anchor-root-mismatch'};
        }
      } else {
        const ok = verifyConsistencyProof({
          firstSize: this.anchorTreeSize,
          secondSize: sth.treeSize,
          firstRootHex: this.anchorRootHashHex,
          secondRootHex: sth.rootHashHex,
          proofHex: params.consistencyProofFromAnchor ?? [],
        });
        if (!ok) {
          return {kind: 'Refuted', reason: 'epoch-anchor-consistency-failed'};
        }
      }
    }

    const qcVerdict = verifyThresholdCosignedCheckpoint({
      checkpoint: filteredCheckpoint,
      coordinatorPublicKeyPem: this.coordinatorPublicKeyPem,
      witnessRosterPublicKeys: this.activeRoster.witnessPublicKeys,
      maxByzantineFaults: this.activeRoster.maxByzantineFaults,
      threshold: this.activeRoster.threshold,
    });
    if (qcVerdict.kind !== 'Finalized') {
      return {kind: 'Refuted', reason: qcVerdict.reason};
    }

    if (sth.treeSize > this.lastFinalizedSize) {
      this.lastFinalizedSize = sth.treeSize;
      this.lastFinalizedRootHex = sth.rootHashHex;
    }

    return {
      kind: 'FinalizedInEpoch',
      epoch: sth.epoch,
      treeSize: sth.treeSize,
      rootHashHex: sth.rootHashHex,
      checkpointDigest: qcVerdict.checkpointDigest,
      verifiedWitnessIds: qcVerdict.verifiedWitnessIds,
    };
  }

  applyJointHandover(params: {
    cert: JointHandoverCertificate;
    consistencyProofFromLastFinalized?: string[];
  }): EpochHandoverApplyVerdict {
    const {cert} = params;
    if (cert.fromEpoch < this.activeRoster.epoch) {
      return {kind: 'Refuted', reason: 'stale-handover-from-retired-epoch'};
    }
    if (cert.fromEpoch !== this.activeRoster.epoch) {
      return {kind: 'Refuted', reason: 'non-monotonic-epoch-transition'};
    }

    // B10c Anti-Reentry Gate: forbid any slashed witness ID OR Sybil pubkey reuse in newRoster!
    for (const [wid, pem] of Object.entries(cert.newRoster.witnessPublicKeys)) {
      if (this.slashedWitnessIds.has(wid)) {
        return {kind: 'Refuted', reason: 'slashed-witness-reentry-refused'};
      }
      if (this.slashedPublicKeyDigests.has(sha256Digest(pem))) {
        return {kind: 'Refuted', reason: 'slashed-pubkey-sybil-reentry-refused'};
      }
    }

    const verifyRes = verifyJointHandoverCertificate({cert, oldRoster: this.activeRoster});
    if (verifyRes.kind !== 'HandoverVerified') {
      return verifyRes;
    }

    // Verify RFC 6962 history continuity from our last finalized checkpoint to the handover anchor:
    if (this.lastFinalizedSize > 0) {
      if (cert.anchorTreeSize < this.lastFinalizedSize) {
        return {kind: 'Refuted', reason: 'handover-anchor-rollback-refused'};
      }
      if (cert.anchorTreeSize === this.lastFinalizedSize) {
        if (cert.anchorRootHashHex !== this.lastFinalizedRootHex) {
          return {kind: 'Refuted', reason: 'handover-anchor-equivocation-refused'};
        }
      } else {
        const ok = verifyConsistencyProof({
          firstSize: this.lastFinalizedSize,
          secondSize: cert.anchorTreeSize,
          firstRootHex: this.lastFinalizedRootHex,
          secondRootHex: cert.anchorRootHashHex,
          proofHex: params.consistencyProofFromLastFinalized ?? [],
        });
        if (!ok) {
          return {kind: 'Refuted', reason: 'handover-anchor-consistency-failed'};
        }
      }
    }

    // Monotonically advance trust anchor and pin immutable M1 handover receipt:
    this.activeRoster = cert.newRoster;
    this.anchorTreeSize = cert.anchorTreeSize;
    this.anchorRootHashHex = cert.anchorRootHashHex;
    this.lastFinalizedSize = cert.anchorTreeSize;
    this.lastFinalizedRootHex = cert.anchorRootHashHex;

    const handoverReceiptHash = this.kv.putBlob(
      'witness-epoch-handover-receipt',
      {
        logId: cert.logId,
        fromEpoch: cert.fromEpoch,
        toEpoch: cert.toEpoch,
        anchorTreeSize: cert.anchorTreeSize,
        anchorRootHashHex: cert.anchorRootHashHex,
        oldRosterDigest: cert.oldRosterDigest,
        newRosterDigest: cert.newRosterDigest,
        handoverDigest: cert.handoverDigest,
        oldSigners: verifyRes.oldSigners,
        newSigners: verifyRes.newSigners,
      },
      [],
    );
    this.kv.pinHistoricalCut(handoverReceiptHash);

    return {
      kind: 'EpochAdvanced',
      newEpoch: cert.toEpoch,
      handoverReceiptHash,
      oldSigners: verifyRes.oldSigners,
      newSigners: verifyRes.newSigners,
    };
  }
}
