// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 18 (Business Extension B9, 10.166):
 * Verifiable Append-Only Transparency Log (RFC 6962), Asymmetric Ed25519 Signed
 * Tree Heads (STH), and Independent Witness Split-View Equivocation Fraud Proofs.
 *
 * Removes the final centralized trust assumption of B1-B8 ("honest Coordinator /
 * honest storage operator"):
 *   1. Exact RFC 6962 Section 2.1 Domain-Separated Merkle Tree:
 *        - Leaf hash:  SHA-256(0x00 || payload)
 *        - Inner hash: SHA-256(0x01 || left || right)
 *        - O(log N) Inclusion Proofs (`generateInclusionProof` / `verifyInclusionProof`)
 *        - O(log N) Append-Only Consistency Proofs (`generateConsistencyProof` /
 *          `verifyConsistencyProof`) proving `newTree` strictly extends `oldTree`.
 *   2. Real Asymmetric Ed25519 Signing (`CoordinatorSigningKey`, branded with R3
 *      `M3_NON_SERIALIZABLE_CAPABILITY`) so ANY external regulator or witness can
 *      verify Signed Tree Heads using ONLY the public key (zero shared secret!).
 *   3. Witness Gossip Equivocation Detector (`WitnessEquivocationMonitor`):
 *        - Catches same-size divergent roots (Split-View Equivocation),
 *        - Catches monotonic size rollbacks (`newSize < oldSize`),
 *        - Catches retroactive leaf tampering (failed RFC 6962 consistency proof),
 *        - Emits a self-authenticating cryptographic `EquivocationFraudProof` containing
 *          BOTH coordinator-signed STHs proving misbehavior to any third party.
 */

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from 'node:crypto';
import {M3_NON_SERIALIZABLE_CAPABILITY} from './durable-merkle-store.ts';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export function rfc6962HashLeaf(data: Buffer): Buffer {
  return createHash('sha256').update(LEAF_PREFIX).update(data).digest();
}

export function rfc6962HashNode(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(NODE_PREFIX).update(left).update(right).digest();
}

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function computeRfc6962Root(leaves: readonly Buffer[]): Buffer {
  const n = leaves.length;
  if (n === 0) return createHash('sha256').update(Buffer.alloc(0)).digest();
  if (n === 1) return rfc6962HashLeaf(leaves[0]!);
  const k = largestPowerOfTwoLessThan(n);
  return rfc6962HashNode(
    computeRfc6962Root(leaves.slice(0, k)),
    computeRfc6962Root(leaves.slice(k)),
  );
}

/** RFC 6962 Section 2.1.1 Inclusion Proof PATH(m, D[n]) */
export function generateInclusionProof(index: number, leaves: readonly Buffer[]): string[] {
  const n = leaves.length;
  if (index < 0 || index >= n) {
    throw new Error(`Leaf index ${index} out of bounds for tree size ${n}`);
  }
  const recurse = (m: number, sub: readonly Buffer[]): Buffer[] => {
    const len = sub.length;
    if (len === 1) return [];
    const k = largestPowerOfTwoLessThan(len);
    if (m < k) {
      return [...recurse(m, sub.slice(0, k)), computeRfc6962Root(sub.slice(k))];
    }
    return [...recurse(m - k, sub.slice(k)), computeRfc6962Root(sub.slice(0, k))];
  };
  return recurse(index, leaves).map(b => b.toString('hex'));
}

export function verifyInclusionProof(params: {
  leafBytes: Buffer;
  index: number;
  treeSize: number;
  proofHex: readonly string[];
  expectedRootHex: string;
}): boolean {
  const {leafBytes, index, treeSize, proofHex, expectedRootHex} = params;
  if (treeSize <= 0 || index < 0 || index >= treeSize) return false;
  const expectedRoot = Buffer.from(expectedRootHex, 'hex');
  if (expectedRoot.length !== 32) return false;

  let fn = index;
  let sn = treeSize - 1;
  let r = rfc6962HashLeaf(leafBytes);

  for (const hex of proofHex) {
    if (sn === 0) return false;
    const p = Buffer.from(hex, 'hex');
    if (p.length !== 32) return false;

    if ((fn & 1) === 1 || fn === sn) {
      r = rfc6962HashNode(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = rfc6962HashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }

  return sn === 0 && timingSafeEqual(r, expectedRoot);
}

/** RFC 6962 Section 2.1.2 Append-Only Consistency Proof SUBPROOF(m, D[n], b) */
export function generateConsistencyProof(
  firstSize: number,
  secondSize: number,
  leaves: readonly Buffer[],
): string[] {
  if (firstSize < 0 || secondSize < firstSize || secondSize > leaves.length) {
    throw new Error(
      `Invalid consistency bounds: first=${firstSize}, second=${secondSize}, len=${leaves.length}`,
    );
  }
  if (firstSize === 0 || firstSize === secondSize) return [];

  const subproof = (m: number, sub: readonly Buffer[], b: boolean): Buffer[] => {
    const n = sub.length;
    if (m === n) {
      return b ? [] : [computeRfc6962Root(sub)];
    }
    const k = largestPowerOfTwoLessThan(n);
    if (m <= k) {
      return [...subproof(m, sub.slice(0, k), b), computeRfc6962Root(sub.slice(k))];
    }
    return [...subproof(m - k, sub.slice(k), false), computeRfc6962Root(sub.slice(0, k))];
  };

  return subproof(firstSize, leaves.slice(0, secondSize), true).map(b => b.toString('hex'));
}

export function verifyConsistencyProof(params: {
  firstSize: number;
  secondSize: number;
  firstRootHex: string;
  secondRootHex: string;
  proofHex: readonly string[];
}): boolean {
  const {firstSize, secondSize, firstRootHex, secondRootHex, proofHex} = params;
  if (firstSize < 0 || secondSize < firstSize) return false;
  const firstRoot = Buffer.from(firstRootHex, 'hex');
  const secondRoot = Buffer.from(secondRootHex, 'hex');
  if (firstRoot.length !== 32 || secondRoot.length !== 32) return false;

  if (firstSize === 0) return proofHex.length === 0;
  if (firstSize === secondSize) {
    return proofHex.length === 0 && timingSafeEqual(firstRoot, secondRoot);
  }
  if (proofHex.length === 0) return false;

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }

  let fr: Buffer;
  let sr: Buffer;
  let idx = 0;
  if (fn === 0) {
    fr = firstRoot;
    sr = firstRoot;
  } else {
    const firstNode = Buffer.from(proofHex[0]!, 'hex');
    if (firstNode.length !== 32) return false;
    fr = firstNode;
    sr = firstNode;
    idx = 1;
  }

  for (let i = idx; i < proofHex.length; i++) {
    if (sn === 0) return false;
    const p = Buffer.from(proofHex[i]!, 'hex');
    if (p.length !== 32) return false;

    if ((fn & 1) === 1 || fn === sn) {
      fr = rfc6962HashNode(p, fr);
      sr = rfc6962HashNode(p, sr);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = rfc6962HashNode(sr, p);
    }
    fn >>= 1;
    sn >>= 1;
  }

  return sn === 0 && timingSafeEqual(fr, firstRoot) && timingSafeEqual(sr, secondRoot);
}

// ── Asymmetric Ed25519 Signed Tree Heads (Non-Serializable M3 Private Key) ──

export interface SignedTreeHead {
  logId: string;
  treeSize: number;
  rootHashHex: string;
  epoch: number;
  signatureBase64: string;
}

function canonicalSthMessage(sth: Omit<SignedTreeHead, 'signatureBase64'>): Buffer {
  return Buffer.from(
    `RFC6962-STH|${sth.logId}|${sth.treeSize}|${sth.rootHashHex}|${sth.epoch}`,
    'utf8',
  );
}

/**
 * R3 Non-Serializable M3 Ed25519 Signing Key for the Transparency Log Coordinator.
 * Public key PEM can be freely shared with external regulators & witnesses;
 * private key is mechanically blocked from entering M1 Merkle persistence!
 */
export class CoordinatorSigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly logId: string) {
    this.capabilityId = `ed25519-log-signing-key:${logId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  signTreeHead(treeSize: number, rootHashHex: string, epoch: number): SignedTreeHead {
    const unsigned = {logId: this.logId, treeSize, rootHashHex, epoch};
    const sig = cryptoSign(null, canonicalSthMessage(unsigned), this.privateKey);
    return {...unsigned, signatureBase64: sig.toString('base64')};
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: CoordinatorSigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export function verifySignedTreeHead(sth: SignedTreeHead, publicKeyPem: string): boolean {
  const pubKey = createPublicKey(publicKeyPem);
  const sig = Buffer.from(sth.signatureBase64, 'base64');
  return cryptoVerify(
    null,
    canonicalSthMessage({
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHashHex: sth.rootHashHex,
      epoch: sth.epoch,
    }),
    pubKey,
    sig,
  );
}

export class VerifiableTransparencyLog {
  private readonly leaves: Buffer[] = [];

  constructor(private readonly signingKey: CoordinatorSigningKey) {}

  get publicKeyPem(): string {
    return this.signingKey.publicKeyPem;
  }

  get size(): number {
    return this.leaves.length;
  }

  appendEntry(payload: unknown): {leafIndex: number; leafBytes: Buffer} {
    const leafBytes = Buffer.from(JSON.stringify(payload), 'utf8');
    const leafIndex = this.leaves.length;
    this.leaves.push(leafBytes);
    return {leafIndex, leafBytes};
  }

  issueSignedTreeHead(epoch: number): SignedTreeHead {
    const rootHex = computeRfc6962Root(this.leaves).toString('hex');
    return this.signingKey.signTreeHead(this.leaves.length, rootHex, epoch);
  }

  getInclusionProof(index: number): string[] {
    return generateInclusionProof(index, this.leaves);
  }

  getConsistencyProof(oldSize: number, newSize = this.leaves.length): string[] {
    return generateConsistencyProof(oldSize, newSize, this.leaves);
  }
}

// ── Independent Witness Gossip & Cryptographic Split-View Equivocation Detector ──

export interface EquivocationFraudProof {
  fraudKind:
    | 'split-view-same-size-divergent-root'
    | 'monotonic-tree-size-rollback'
    | 'history-rewrite-inconsistent-prefix';
  sthEarlierOrPeer: SignedTreeHead;
  sthConflicting: SignedTreeHead;
  publicKeyPem: string;
}

export type WitnessObserveVerdict =
  | {kind: 'AcceptedConsistent'; latestSth: SignedTreeHead}
  | {kind: 'Refuted'; reason: 'invalid-ed25519-signature' | 'log-id-mismatch'}
  | {kind: 'EquivocationDetected'; fraudProof: EquivocationFraudProof};

export class WitnessEquivocationMonitor {
  private latestSth: SignedTreeHead | null = null;
  private readonly observedBySize = new Map<number, SignedTreeHead>();

  constructor(
    readonly logId: string,
    readonly publicKeyPem: string,
  ) {}

  getLatestSth(): SignedTreeHead | null {
    return this.latestSth;
  }

  /**
   * Observes a new STH (from Coordinator or gossiped from another Witness/Regulator)
   * together with an RFC 6962 consistency proof from `latestSth`.
   * Emits a self-authenticating `EquivocationFraudProof` on any split-view, rollback,
   * or retroactive history rewrite!
   */
  observeSignedTreeHead(
    candidateSth: SignedTreeHead,
    consistencyProofFromLatest: readonly string[] = [],
  ): WitnessObserveVerdict {
    if (candidateSth.logId !== this.logId) {
      return {kind: 'Refuted', reason: 'log-id-mismatch'};
    }
    if (!verifySignedTreeHead(candidateSth, this.publicKeyPem)) {
      return {kind: 'Refuted', reason: 'invalid-ed25519-signature'};
    }

    // Check same-size split-view against EVERY historically observed size!
    const priorSameSize = this.observedBySize.get(candidateSth.treeSize);
    if (priorSameSize && priorSameSize.rootHashHex !== candidateSth.rootHashHex) {
      return {
        kind: 'EquivocationDetected',
        fraudProof: {
          fraudKind: 'split-view-same-size-divergent-root',
          sthEarlierOrPeer: priorSameSize,
          sthConflicting: candidateSth,
          publicKeyPem: this.publicKeyPem,
        },
      };
    }

    if (!this.latestSth) {
      this.latestSth = candidateSth;
      this.observedBySize.set(candidateSth.treeSize, candidateSth);
      return {kind: 'AcceptedConsistent', latestSth: candidateSth};
    }

    if (candidateSth.treeSize < this.latestSth.treeSize) {
      return {
        kind: 'EquivocationDetected',
        fraudProof: {
          fraudKind: 'monotonic-tree-size-rollback',
          sthEarlierOrPeer: this.latestSth,
          sthConflicting: candidateSth,
          publicKeyPem: this.publicKeyPem,
        },
      };
    }

    if (candidateSth.treeSize === this.latestSth.treeSize) {
      // Same size & same root (divergent root already caught above!)
      return {kind: 'AcceptedConsistent', latestSth: this.latestSth};
    }

    // Strict append-only RFC 6962 consistency proof verification!
    const ok = verifyConsistencyProof({
      firstSize: this.latestSth.treeSize,
      secondSize: candidateSth.treeSize,
      firstRootHex: this.latestSth.rootHashHex,
      secondRootHex: candidateSth.rootHashHex,
      proofHex: consistencyProofFromLatest,
    });
    if (!ok) {
      return {
        kind: 'EquivocationDetected',
        fraudProof: {
          fraudKind: 'history-rewrite-inconsistent-prefix',
          sthEarlierOrPeer: this.latestSth,
          sthConflicting: candidateSth,
          publicKeyPem: this.publicKeyPem,
        },
      };
    }

    this.latestSth = candidateSth;
    this.observedBySize.set(candidateSth.treeSize, candidateSth);
    return {kind: 'AcceptedConsistent', latestSth: candidateSth};
  }
}
