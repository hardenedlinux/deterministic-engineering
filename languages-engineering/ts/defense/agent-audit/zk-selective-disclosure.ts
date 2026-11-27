// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 47 (10.195): Business Extension B18 — Verifiable Zero-Knowledge Selective-Disclosure
 * Compliance Proofs (Non-Interactive Fiat-Shamir Schnorr Sigma Protocol over RFC 3526
 * 2048-bit MODP Group 14 + Salted Merkle Attribute Commitment Tree).
 *
 * Enables an agent or tenant operator to prove regulatory compliance to an external auditor
 * or downstream `cedar-poo-spec` host WITHOUT disclosing confidential attributes, PII, or
 * private witness scalars:
 *   1. Real BigInt modular exponentiation over RFC 3526 2048-bit safe prime `p = 2q + 1`
 *      (`g = 2`, order `q = (p - 1)/2` via `g^2 mod p` subgroup generator `G = 4`) — ZERO
 *      external dependencies.
 *   2. Non-Interactive Fiat-Shamir Schnorr Sigma Protocol proving knowledge of private
 *      witness `w` satisfying `Y = G^w mod p` bound to `(commitmentRootHex, verifierNonce,
 *      policyDigestHex, domainTag, nullifierHex)` without leaking `w`.
 *   3. Salted Merkle Selective Disclosure Tree: reveals ONLY requested non-confidential
 *      compliance predicates with per-leaf authentication paths, while mechanically blocking
 *      over-disclosure of confidential/PII fields.
 *   4. `ZkProverWitnessKey`: 15th R3 non-leakable M3 capability class holding raw witness
 *      scalar `w` and all blinding salts; mechanically refused by `ContentAddressedKvStore`.
 */

import {createHash, randomBytes} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

// RFC 3526 Section 3: 2048-bit MODP Safe Prime p = 2q + 1 (exact standard hex constant).
const RFC3526_MODP_2048_P = BigInt(
  '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
);
const RFC3526_MODP_2048_Q = (RFC3526_MODP_2048_P - 1n) / 2n;
// Subgroup generator G = 2^2 = 4 has exact prime order Q modulo P.
const SUBGROUP_G = 4n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function randomScalarModQ(): bigint {
  const raw = BigInt('0x' + randomBytes(32).toString('hex'));
  return (raw % (RFC3526_MODP_2048_Q - 2n)) + 2n;
}

function hashToScalarModQ(domain: string, fields: Record<string, unknown>): bigint {
  const h = createHash('sha256')
    .update(domain)
    .update(':')
    .update(JSON.stringify(fields))
    .digest('hex');
  return (BigInt('0x' + h) % (RFC3526_MODP_2048_Q - 1n)) + 1n;
}

export interface ComplianceAttributeSpec {
  readonly fieldId: string;
  readonly value: string | number | boolean;
  readonly confidential: boolean;
}

export interface SaltedAttributeOpening {
  readonly fieldId: string;
  readonly value: string | number | boolean;
  readonly saltHex: string;
  readonly leafIndex: number;
  readonly authPath: ReadonlyArray<{side: 'left' | 'right'; siblingHex: string}>;
}

export interface ZkComplianceCommitmentPublicBundle {
  readonly proverId: string;
  readonly publicKeyYHex: string;
  readonly commitmentRootHex: string;
  readonly attributeCount: number;
}

export interface ZkSelectiveDisclosureProof {
  readonly proverId: string;
  readonly domainTag: string;
  readonly verifierNonce: string;
  readonly policyDigestHex: string;
  readonly commitmentRootHex: string;
  readonly nullifierHex: string;
  readonly disclosedOpenings: readonly SaltedAttributeOpening[];
  readonly sigmaCommitmentRHex: string;
  readonly sigmaResponseSHex: string;
}

export interface ZkComplianceVerificationPolicy {
  readonly expectedDomainTag: string;
  readonly expectedVerifierNonce: string;
  readonly expectedPolicyDigestHex: string;
  readonly trustedProvers: Readonly<Record<string, ZkComplianceCommitmentPublicBundle>>;
  readonly forbiddenSecretFieldIds: readonly string[];
  readonly requiredPublicFieldIds: readonly string[];
  readonly spentNullifiers: readonly string[];
}

export type ZkComplianceVerificationVerdict =
  | {
      kind: 'Proven';
      proverId: string;
      nullifierHex: string;
      disclosedFieldIds: string[];
      disclosedValues: Record<string, string | number | boolean>;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'unregistered-prover'
        | 'commitment-root-mismatch'
        | 'domain-or-nonce-or-policy-mismatch'
        | 'nullifier-replay-detected'
        | 'over-disclosure-of-secret-field'
        | 'missing-required-public-field'
        | 'merkle-opening-invalid'
        | 'zk-sigma-proof-invalid';
      detail: string;
    };

function hashSaltedAttributeLeaf(
  fieldId: string,
  value: string | number | boolean,
  saltHex: string,
): string {
  return sha256Digest({
    domain: 'b18-salted-attr-leaf-v1',
    fieldId,
    value,
    saltHex,
  });
}

function computeAttrMerkleRoot(leafHashes: readonly string[]): string {
  if (leafHashes.length === 0) throw new Error('Empty attribute set');
  let level = [...leafHashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(sha256Digest({domain: 'b18-attr-node-v1', left, right}));
    }
    level = next;
  }
  return level[0]!;
}

function buildAttrMerkleAuthPath(
  leafHashes: readonly string[],
  leafIndex: number,
): Array<{side: 'left' | 'right'; siblingHex: string}> {
  const path: Array<{side: 'left' | 'right'; siblingHex: string}> = [];
  let idx = leafIndex;
  let level = [...leafHashes];
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
      next.push(sha256Digest({domain: 'b18-attr-node-v1', left, right}));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return path;
}

function verifyAttrMerkleAuthPath(
  leafHash: string,
  authPath: ReadonlyArray<{side: 'left' | 'right'; siblingHex: string}>,
  expectedRoot: string,
): boolean {
  let acc = leafHash;
  for (const step of authPath) {
    const left = step.side === 'left' ? step.siblingHex : acc;
    const right = step.side === 'left' ? acc : step.siblingHex;
    acc = sha256Digest({domain: 'b18-attr-node-v1', left, right});
  }
  return acc === expectedRoot;
}

function computeFiatShamirChallenge(params: {
  proverId: string;
  domainTag: string;
  verifierNonce: string;
  policyDigestHex: string;
  commitmentRootHex: string;
  nullifierHex: string;
  publicKeyYHex: string;
  sigmaCommitmentRHex: string;
  disclosedFieldIds: readonly string[];
}): bigint {
  return hashToScalarModQ('b18-fiat-shamir-schnorr-v1', params);
}

/**
 * 15th R3 non-leakable M3 capability class: Zero-Knowledge Prover Witness Key.
 * Holds the private Schnorr discrete-log witness `w` and all per-attribute blinding salts.
 * Mechanically blocked from entering M1 persistence via `M3_NON_SERIALIZABLE_CAPABILITY`.
 */
export class ZkProverWitnessKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyYHex: string;
  readonly commitmentRootHex: string;

  private readonly witnessScalarW: bigint;
  private readonly attributes: Array<{
    fieldId: string;
    value: string | number | boolean;
    confidential: boolean;
    saltHex: string;
    leafHash: string;
  }>;

  constructor(
    readonly proverId: string,
    attributes: readonly ComplianceAttributeSpec[],
  ) {
    if (attributes.length === 0) throw new Error('ZkProverWitnessKey requires at least 1 attribute');
    this.capabilityId = `zk-prover-witness:${proverId}`;
    this.witnessScalarW = randomScalarModQ();
    this.publicKeyYHex = modPow(SUBGROUP_G, this.witnessScalarW, RFC3526_MODP_2048_P).toString(16);
    this.attributes = attributes.map(attr => {
      const saltHex = randomBytes(32).toString('hex');
      const leafHash = hashSaltedAttributeLeaf(attr.fieldId, attr.value, saltHex);
      return {...attr, saltHex, leafHash};
    });
    this.commitmentRootHex = computeAttrMerkleRoot(this.attributes.map(a => a.leafHash));
  }

  exportPublicBundle(): ZkComplianceCommitmentPublicBundle {
    return {
      proverId: this.proverId,
      publicKeyYHex: this.publicKeyYHex,
      commitmentRootHex: this.commitmentRootHex,
      attributeCount: this.attributes.length,
    };
  }

  /**
   * Generates a non-interactive Zero-Knowledge Selective-Disclosure Compliance Proof.
   * Refuses by default to disclose any attribute marked `confidential: true` unless
   * `allowUnsafeOverDisclosureForNegativeTest` is explicitly passed for adversarial testing.
   */
  generateSelectiveDisclosureProof(params: {
    domainTag: string;
    verifierNonce: string;
    policyDigestHex: string;
    discloseFieldIds: readonly string[];
    allowUnsafeOverDisclosureForNegativeTest?: boolean;
  }): ZkSelectiveDisclosureProof {
    const leafHashes = this.attributes.map(a => a.leafHash);
    const disclosedOpenings: SaltedAttributeOpening[] = [];
    for (const fid of params.discloseFieldIds) {
      const idx = this.attributes.findIndex(a => a.fieldId === fid);
      if (idx === -1) {
        throw new Error(`Unknown compliance attribute '${fid}'`);
      }
      const attr = this.attributes[idx]!;
      if (attr.confidential && !params.allowUnsafeOverDisclosureForNegativeTest) {
        throw new Error(
          `B18 Prover Fence: refusing to disclose confidential attribute '${fid}' in plaintext`,
        );
      }
      disclosedOpenings.push({
        fieldId: attr.fieldId,
        value: attr.value,
        saltHex: attr.saltHex,
        leafIndex: idx,
        authPath: buildAttrMerkleAuthPath(leafHashes, idx),
      });
    }

    // Deterministic domain-bound nullifier derived from secret witness w + audit nonce (prevents replay without leaking w):
    const nullifierHex = sha256Digest({
      domain: 'b18-zk-nullifier-v1',
      witnessBinding: sha256Digest({w: this.witnessScalarW.toString(16), id: this.proverId}),
      verifierNonce: params.verifierNonce,
      policyDigestHex: params.policyDigestHex,
    });

    // Real Schnorr Sigma Protocol (RFC 3526 MODP-2048 subgroup):
    //   1. Sample fresh ephemeral k in [2, q-1], R = G^k mod p
    //   2. Fiat-Shamir challenge c = H(transcript || R) mod q
    //   3. Response s = (k + c * w) mod q
    const k = randomScalarModQ();
    const bigR = modPow(SUBGROUP_G, k, RFC3526_MODP_2048_P);
    const sigmaCommitmentRHex = bigR.toString(16);
    const challengeC = computeFiatShamirChallenge({
      proverId: this.proverId,
      domainTag: params.domainTag,
      verifierNonce: params.verifierNonce,
      policyDigestHex: params.policyDigestHex,
      commitmentRootHex: this.commitmentRootHex,
      nullifierHex,
      publicKeyYHex: this.publicKeyYHex,
      sigmaCommitmentRHex,
      disclosedFieldIds: disclosedOpenings.map(o => o.fieldId),
    });
    const responseS = (k + challengeC * this.witnessScalarW) % RFC3526_MODP_2048_Q;

    return {
      proverId: this.proverId,
      domainTag: params.domainTag,
      verifierNonce: params.verifierNonce,
      policyDigestHex: params.policyDigestHex,
      commitmentRootHex: this.commitmentRootHex,
      nullifierHex,
      disclosedOpenings,
      sigmaCommitmentRHex,
      sigmaResponseSHex: responseS.toString(16),
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: ZkProverWitnessKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

/**
 * 100% Air-Gapped Offline Verifier for B18 Zero-Knowledge Selective-Disclosure Compliance Proofs.
 * Learns ZERO confidential attribute values, ZERO salts of hidden fields, and ZERO witness scalar `w`.
 */
export function verifyZkComplianceDisclosureOffline(params: {
  proof: ZkSelectiveDisclosureProof;
  policy: ZkComplianceVerificationPolicy;
  kv?: ContentAddressedKvStore;
}): ZkComplianceVerificationVerdict {
  const {proof, policy} = params;

  // 1. Trusted prover registration & pinned commitment root:
  const pub = policy.trustedProvers[proof.proverId];
  if (!pub) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-prover',
      detail: `Prover '${proof.proverId}' not registered in trustedProvers`,
    };
  }
  if (proof.commitmentRootHex !== pub.commitmentRootHex) {
    return {
      kind: 'Refuted',
      reason: 'commitment-root-mismatch',
      detail: 'Proof commitmentRootHex does not match pinned prover commitment root',
    };
  }

  // 2. Domain separation, verifier challenge nonce & policy digest binding:
  if (
    proof.domainTag !== policy.expectedDomainTag ||
    proof.verifierNonce !== policy.expectedVerifierNonce ||
    proof.policyDigestHex !== policy.expectedPolicyDigestHex
  ) {
    return {
      kind: 'Refuted',
      reason: 'domain-or-nonce-or-policy-mismatch',
      detail: 'Proof transcript domainTag, verifierNonce, or policyDigestHex mismatch',
    };
  }

  // 3. Single-use nullifier anti-replay:
  if (policy.spentNullifiers.includes(proof.nullifierHex)) {
    return {
      kind: 'Refuted',
      reason: 'nullifier-replay-detected',
      detail: `Nullifier '${proof.nullifierHex}' was already consumed`,
    };
  }

  // 4. Anti-over-disclosure fence & required public predicate check:
  const disclosedFieldIds = proof.disclosedOpenings.map(o => o.fieldId);
  for (const fid of disclosedFieldIds) {
    if (policy.forbiddenSecretFieldIds.includes(fid)) {
      return {
        kind: 'Refuted',
        reason: 'over-disclosure-of-secret-field',
        detail: `Confidential field '${fid}' leaked in plaintext selective disclosure`,
      };
    }
  }
  for (const req of policy.requiredPublicFieldIds) {
    if (!disclosedFieldIds.includes(req)) {
      return {
        kind: 'Refuted',
        reason: 'missing-required-public-field',
        detail: `Mandatory compliance field '${req}' missing from selective disclosure`,
      };
    }
  }

  // 5. Salted Merkle Selective Opening verification:
  const disclosedValues: Record<string, string | number | boolean> = {};
  for (const op of proof.disclosedOpenings) {
    const leafHash = hashSaltedAttributeLeaf(op.fieldId, op.value, op.saltHex);
    if (!verifyAttrMerkleAuthPath(leafHash, op.authPath, pub.commitmentRootHex)) {
      return {
        kind: 'Refuted',
        reason: 'merkle-opening-invalid',
        detail: `Salted Merkle opening failed for attribute '${op.fieldId}'`,
      };
    }
    disclosedValues[op.fieldId] = op.value;
  }

  // 6. Real Fiat-Shamir Schnorr Sigma Verification: check G^s == R * Y^c (mod p)
  let bigR: bigint;
  let responseS: bigint;
  let bigY: bigint;
  try {
    bigR = BigInt('0x' + proof.sigmaCommitmentRHex);
    responseS = BigInt('0x' + proof.sigmaResponseSHex);
    bigY = BigInt('0x' + pub.publicKeyYHex);
  } catch (err) {
    return {
      kind: 'Refuted',
      reason: 'zk-sigma-proof-invalid',
      detail: `Malformed hex in Sigma proof: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (
    bigR <= 1n ||
    bigR >= RFC3526_MODP_2048_P ||
    bigY <= 1n ||
    bigY >= RFC3526_MODP_2048_P ||
    responseS <= 0n ||
    responseS >= RFC3526_MODP_2048_Q
  ) {
    return {
      kind: 'Refuted',
      reason: 'zk-sigma-proof-invalid',
      detail: 'Sigma group elements or scalar out of valid subgroup range',
    };
  }

  const challengeC = computeFiatShamirChallenge({
    proverId: proof.proverId,
    domainTag: proof.domainTag,
    verifierNonce: proof.verifierNonce,
    policyDigestHex: proof.policyDigestHex,
    commitmentRootHex: proof.commitmentRootHex,
    nullifierHex: proof.nullifierHex,
    publicKeyYHex: pub.publicKeyYHex,
    sigmaCommitmentRHex: proof.sigmaCommitmentRHex,
    disclosedFieldIds,
  });
  const lhs = modPow(SUBGROUP_G, responseS, RFC3526_MODP_2048_P);
  const rhs = (bigR * modPow(bigY, challengeC, RFC3526_MODP_2048_P)) % RFC3526_MODP_2048_P;
  if (lhs !== rhs) {
    return {
      kind: 'Refuted',
      reason: 'zk-sigma-proof-invalid',
      detail: 'Schnorr Sigma verification equation G^s == R * Y^c (mod p) failed',
    };
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b18-zk-selective-disclosure-receipt',
      {
        proverId: proof.proverId,
        domainTag: proof.domainTag,
        verifierNonce: proof.verifierNonce,
        policyDigestHex: proof.policyDigestHex,
        commitmentRootHex: proof.commitmentRootHex,
        nullifierHex: proof.nullifierHex,
        disclosedFieldIds,
        disclosedValues,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    proverId: proof.proverId,
    nullifierHex: proof.nullifierHex,
    disclosedFieldIds,
    disclosedValues,
    pinnedReceiptHash,
  };
}
