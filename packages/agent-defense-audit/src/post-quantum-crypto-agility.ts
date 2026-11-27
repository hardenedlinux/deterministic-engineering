// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 45 (10.193): Business Extension B17 — Post-Quantum Hybrid Cryptographic
 * Agility & Anti-Algorithm-Downgrade Gate (Dual-AND Ed25519 + Stateful SHA-256
 * Lamport-Diffie Hash-Based One-Time Signature Merkle Tree).
 *
 * Defends long-lived `M1` Merkle governance artifacts against "Harvest Now, Forge Later"
 * quantum adversaries (CRQC) with ZERO external dependencies:
 *   1. Real SHA-256 Lamport-Diffie OTS (256 bit-pairs = 512 random 32-byte secrets per leaf)
 *      anchored under a Merkle public-key root (NIST SP 800-208 / RFC 8391 foundation).
 *   2. Strict single-use OTS leaf statefulness + immediate physical `Buffer.fill(0)`
 *      zeroization of spent preimage leaves after signing.
 *   3. `HybridPqSigningKey`: 14th R3 non-leakable M3 capability class combining Ed25519
 *      AND stateful SHA-256 Lamport OTS Merkle tree.
 *   4. `verifyHybridPqSignatureOffline`: 100% air-gapped Dual-AND verifier enforcing
 *      anti-downgrade suite floor, non-deprecated suite, domain separation, OTS leaf
 *      non-reuse, Lamport preimage + Merkle leaf authentication, AND Ed25519 signature.
 */

import {createHash, generateKeyPairSync, randomBytes, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export type CryptoSuiteId =
  | 'legacy-sha1'
  | 'classical-ed25519-only'
  | 'hybrid-ed25519-lamport-sha256-v1';

export const SUITE_SECURITY_LEVELS: Readonly<Record<CryptoSuiteId, number>> = {
  'legacy-sha1': 0,
  'classical-ed25519-only': 1,
  'hybrid-ed25519-lamport-sha256-v1': 2,
};

function sha256Buf(buf: Buffer): Buffer {
  return createHash('sha256').update(buf).digest();
}

function hashLeafPub(pubHashes0: readonly string[], pubHashes1: readonly string[]): string {
  return sha256Digest({
    domain: 'b17-lamport-leaf-pk-v1',
    h0: pubHashes0,
    h1: pubHashes1,
  });
}

function computePqMerkleRoot(leafHashesHex: readonly string[]): string {
  if (leafHashesHex.length === 0) throw new Error('Empty PQ OTS leaf pool');
  let level = [...leafHashesHex];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(sha256Digest({domain: 'b17-pq-node-v1', left, right}));
    }
    level = next;
  }
  return level[0]!;
}

function buildPqMerkleAuthPath(
  leafHashesHex: readonly string[],
  leafIndex: number,
): Array<{side: 'left' | 'right'; siblingHex: string}> {
  const path: Array<{side: 'left' | 'right'; siblingHex: string}> = [];
  let idx = leafIndex;
  let level = [...leafHashesHex];
  while (level.length > 1) {
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : Math.min(idx + 1, level.length - 1);
    path.push({
      side: isRight ? 'left' : 'right',
      siblingHex: level[siblingIdx]!,
    });
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(sha256Digest({domain: 'b17-pq-node-v1', left, right}));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return path;
}

function verifyPqMerkleAuthPath(
  leafHashHex: string,
  authPath: ReadonlyArray<{side: 'left' | 'right'; siblingHex: string}>,
  expectedRootHex: string,
): boolean {
  let acc = leafHashHex;
  for (const step of authPath) {
    const left = step.side === 'left' ? step.siblingHex : acc;
    const right = step.side === 'left' ? acc : step.siblingHex;
    acc = sha256Digest({domain: 'b17-pq-node-v1', left, right});
  }
  return acc === expectedRootHex;
}

interface LamportLeafSecret {
  sk0: Buffer[];
  sk1: Buffer[];
  pk0Hex: string[];
  pk1Hex: string[];
  spent: boolean;
}

export interface HybridPqPublicBundle {
  readonly signerId: string;
  readonly suiteId: CryptoSuiteId;
  readonly classicalPublicKeyPem: string;
  readonly pqMerkleRootHex: string;
  readonly otsPoolSize: number;
}

export interface SignedHybridPqEnvelope {
  readonly signerId: string;
  readonly suiteId: CryptoSuiteId;
  readonly domainTag: string;
  readonly payloadDigestHex: string;
  readonly otsLeafIndex: number;
  readonly classicalSignatureHex: string;
  readonly pqRevealedPreimagesHex: readonly string[];
  readonly pqLeafPk0Hex: readonly string[];
  readonly pqLeafPk1Hex: readonly string[];
  readonly pqMerkleAuthPath: ReadonlyArray<{side: 'left' | 'right'; siblingHex: string}>;
}

export interface HybridPqVerificationPolicy {
  readonly minRequiredSuiteLevel: number;
  readonly expectedDomainTag: string;
  readonly deprecatedSuites: readonly CryptoSuiteId[];
  readonly trustedSigners: Readonly<Record<string, HybridPqPublicBundle>>;
  readonly usedOtsLeafIndicesBySigner?: Readonly<Record<string, readonly number[]>>;
}

export type HybridPqVerificationVerdict =
  | {
      kind: 'Proven';
      signerId: string;
      suiteId: CryptoSuiteId;
      otsLeafIndex: number;
      payloadDigestHex: string;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'algorithm-downgrade-refused'
        | 'deprecated-suite-refused'
        | 'domain-separation-mismatch'
        | 'unregistered-signer'
        | 'ots-leaf-reuse-detected'
        | 'classical-ed25519-signature-invalid'
        | 'pq-lamport-signature-invalid'
        | 'pq-merkle-auth-path-invalid';
      detail: string;
    };

function computeDomainBoundDigest(domainTag: string, payloadDigestHex: string): Buffer {
  return createHash('sha256')
    .update(`b17-hybrid-v1::${domainTag}::${payloadDigestHex}`, 'utf8')
    .digest();
}

/**
 * 14th R3 non-leakable M3 capability class: Hybrid Post-Quantum Signing Key
 * (Ed25519 + Stateful SHA-256 Lamport-Diffie OTS Merkle Tree).
 * Mechanically blocked from entering M1 persistence via `M3_NON_SERIALIZABLE_CAPABILITY`.
 */
export class HybridPqSigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly suiteId: CryptoSuiteId = 'hybrid-ed25519-lamport-sha256-v1';
  readonly classicalPublicKeyPem: string;
  readonly pqMerkleRootHex: string;
  readonly otsPoolSize: number;

  private readonly classicalPrivateKey: KeyObject;
  private readonly leaves: LamportLeafSecret[] = [];
  private readonly leafHashesHex: string[] = [];
  private nextLeafIndex = 0;

  constructor(readonly signerId: string, otsPoolSize = 4) {
    if (!Number.isInteger(otsPoolSize) || otsPoolSize < 1 || otsPoolSize > 64) {
      throw new Error(`Invalid OTS pool size: ${otsPoolSize}`);
    }
    this.capabilityId = `hybrid-pq-ed25519-lamport:${signerId}`;
    this.otsPoolSize = otsPoolSize;

    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.classicalPrivateKey = privateKey;
    this.classicalPublicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();

    for (let i = 0; i < otsPoolSize; i++) {
      const sk0: Buffer[] = [];
      const sk1: Buffer[] = [];
      const pk0Hex: string[] = [];
      const pk1Hex: string[] = [];
      for (let bit = 0; bit < 256; bit++) {
        const s0 = randomBytes(32);
        const s1 = randomBytes(32);
        sk0.push(s0);
        sk1.push(s1);
        pk0Hex.push(sha256Buf(s0).toString('hex'));
        pk1Hex.push(sha256Buf(s1).toString('hex'));
      }
      this.leaves.push({sk0, sk1, pk0Hex, pk1Hex, spent: false});
      this.leafHashesHex.push(hashLeafPub(pk0Hex, pk1Hex));
    }
    this.pqMerkleRootHex = computePqMerkleRoot(this.leafHashesHex);
  }

  exportPublicBundle(): HybridPqPublicBundle {
    return {
      signerId: this.signerId,
      suiteId: this.suiteId,
      classicalPublicKeyPem: this.classicalPublicKeyPem,
      pqMerkleRootHex: this.pqMerkleRootHex,
      otsPoolSize: this.otsPoolSize,
    };
  }

  get remainingOtsLeaves(): number {
    return this.otsPoolSize - this.nextLeafIndex;
  }

  signHybridDigest(params: {domainTag: string; payloadDigestHex: string}): SignedHybridPqEnvelope {
    if (this.nextLeafIndex >= this.otsPoolSize) {
      throw new Error(
        `B17 OTS pool exhausted for signer '${this.signerId}': rotate HybridPqSigningKey before signing`,
      );
    }
    const leafIdx = this.nextLeafIndex;
    const leaf = this.leaves[leafIdx]!;
    if (leaf.spent) {
      throw new Error(`B17 fatal: OTS leaf ${leafIdx} already spent`);
    }
    this.nextLeafIndex += 1;
    leaf.spent = true;

    const boundDigest = computeDomainBoundDigest(params.domainTag, params.payloadDigestHex);
    const classicalSignatureHex = sign(null, boundDigest, this.classicalPrivateKey).toString('hex');

    // Lamport-Diffie 256-bit signature: reveal sk0[bit] if bit==0 else sk1[bit], then physically zeroize BOTH!
    const revealed: string[] = [];
    for (let bit = 0; bit < 256; bit++) {
      const byteVal = boundDigest[Math.floor(bit / 8)]!;
      const bitVal = (byteVal >> (7 - (bit % 8))) & 1;
      const chosen = bitVal === 0 ? leaf.sk0[bit]! : leaf.sk1[bit]!;
      revealed.push(chosen.toString('hex'));
      leaf.sk0[bit]!.fill(0);
      leaf.sk1[bit]!.fill(0);
    }

    return {
      signerId: this.signerId,
      suiteId: this.suiteId,
      domainTag: params.domainTag,
      payloadDigestHex: params.payloadDigestHex,
      otsLeafIndex: leafIdx,
      classicalSignatureHex,
      pqRevealedPreimagesHex: revealed,
      pqLeafPk0Hex: [...leaf.pk0Hex],
      pqLeafPk1Hex: [...leaf.pk1Hex],
      pqMerkleAuthPath: buildPqMerkleAuthPath(this.leafHashesHex, leafIdx),
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: HybridPqSigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

/**
 * 100% Air-Gapped Offline Dual-AND Hybrid Verifier (Ed25519 AND SHA-256 Lamport-Diffie PQ).
 */
export function verifyHybridPqSignatureOffline(params: {
  envelope: SignedHybridPqEnvelope;
  policy: HybridPqVerificationPolicy;
  kv?: ContentAddressedKvStore;
}): HybridPqVerificationVerdict {
  const {envelope, policy} = params;

  // 1. Deprecated suite & anti-algorithm-downgrade floor:
  if (policy.deprecatedSuites.includes(envelope.suiteId)) {
    return {
      kind: 'Refuted',
      reason: 'deprecated-suite-refused',
      detail: `Suite '${envelope.suiteId}' is deprecated`,
    };
  }
  const offeredLevel = SUITE_SECURITY_LEVELS[envelope.suiteId] ?? -1;
  if (offeredLevel < policy.minRequiredSuiteLevel) {
    return {
      kind: 'Refuted',
      reason: 'algorithm-downgrade-refused',
      detail: `Offered suite '${envelope.suiteId}' (level ${offeredLevel}) < minimum floor ${policy.minRequiredSuiteLevel}`,
    };
  }

  // 2. Domain separation:
  if (envelope.domainTag !== policy.expectedDomainTag) {
    return {
      kind: 'Refuted',
      reason: 'domain-separation-mismatch',
      detail: `Signed domain '${envelope.domainTag}' != expected '${policy.expectedDomainTag}'`,
    };
  }

  // 3. Signer registration & OTS leaf non-reuse:
  const pub = policy.trustedSigners[envelope.signerId];
  if (!pub) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-signer',
      detail: `Signer '${envelope.signerId}' not in trustedSigners`,
    };
  }
  const usedIndices = policy.usedOtsLeafIndicesBySigner?.[envelope.signerId] ?? [];
  if (usedIndices.includes(envelope.otsLeafIndex)) {
    return {
      kind: 'Refuted',
      reason: 'ots-leaf-reuse-detected',
      detail: `OTS leaf index ${envelope.otsLeafIndex} already consumed for signer '${envelope.signerId}'`,
    };
  }

  const boundDigest = computeDomainBoundDigest(envelope.domainTag, envelope.payloadDigestHex);

  // 4. Classical Leg (Ed25519):
  let classicalOk = false;
  let classicalErr = '';
  try {
    classicalOk = verify(
      null,
      boundDigest,
      pub.classicalPublicKeyPem,
      Buffer.from(envelope.classicalSignatureHex, 'hex'),
    );
  } catch (err) {
    classicalOk = false;
    classicalErr = err instanceof Error ? err.message : String(err);
  }
  if (!classicalOk) {
    return {
      kind: 'Refuted',
      reason: 'classical-ed25519-signature-invalid',
      detail: `Classical Ed25519 verification failed${classicalErr ? `: ${classicalErr}` : ''}`,
    };
  }

  // 5. Post-Quantum Leg (SHA-256 Lamport-Diffie OTS + Merkle Auth Path):
  if (
    envelope.pqRevealedPreimagesHex.length !== 256 ||
    envelope.pqLeafPk0Hex.length !== 256 ||
    envelope.pqLeafPk1Hex.length !== 256
  ) {
    return {
      kind: 'Refuted',
      reason: 'pq-lamport-signature-invalid',
      detail: 'Lamport-Diffie signature vectors must each contain 256 entries',
    };
  }
  const leafHash = hashLeafPub(envelope.pqLeafPk0Hex, envelope.pqLeafPk1Hex);
  if (!verifyPqMerkleAuthPath(leafHash, envelope.pqMerkleAuthPath, pub.pqMerkleRootHex)) {
    return {
      kind: 'Refuted',
      reason: 'pq-merkle-auth-path-invalid',
      detail: 'OTS leaf public key does not authenticate to pinned pqMerkleRootHex',
    };
  }
  for (let bit = 0; bit < 256; bit++) {
    const byteVal = boundDigest[Math.floor(bit / 8)]!;
    const bitVal = (byteVal >> (7 - (bit % 8))) & 1;
    const expectedHash = bitVal === 0 ? envelope.pqLeafPk0Hex[bit]! : envelope.pqLeafPk1Hex[bit]!;
    const actualHash = sha256Buf(Buffer.from(envelope.pqRevealedPreimagesHex[bit]!, 'hex')).toString('hex');
    if (actualHash !== expectedHash) {
      return {
        kind: 'Refuted',
        reason: 'pq-lamport-signature-invalid',
        detail: `Lamport preimage hash mismatch at bit ${bit}`,
      };
    }
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b17-hybrid-pq-verification-receipt',
      {
        signerId: envelope.signerId,
        suiteId: envelope.suiteId,
        domainTag: envelope.domainTag,
        payloadDigestHex: envelope.payloadDigestHex,
        otsLeafIndex: envelope.otsLeafIndex,
        pqMerkleRootHex: pub.pqMerkleRootHex,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    signerId: envelope.signerId,
    suiteId: envelope.suiteId,
    otsLeafIndex: envelope.otsLeafIndex,
    payloadDigestHex: envelope.payloadDigestHex,
    pinnedReceiptHash,
  };
}
