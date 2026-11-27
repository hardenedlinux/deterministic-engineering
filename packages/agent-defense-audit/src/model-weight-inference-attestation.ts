// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 53 (10.202): Business Extension B21 — Deterministic Model-Weight Pinning &
 * Reproducible Inference Sampling Attestation (Weight Shard Merkle Root, LoRA/PEFT
 * Adapter Allowlisting, Deterministic Temperature/Seed/Kernel Binding).
 *
 * Defends regulated AI inference pipelines against silent model substitution, stealth
 * LoRA backdoor injection, and non-deterministic sampling drift:
 *   1. `computeModelWeightMerkleRoot`: domain-separated SHA-256 Merkle root over
 *      ordered tensor shard digests (safetensors/GGUF).
 *   2. `ModelWeightAttestationKey`: 18th R3 non-leakable M3 capability class holding
 *      an Ed25519 signing key for a model-serving host.
 *   3. `verifyModelInferenceAttestationOffline`: 100% air-gapped verifier enforcing
 *      non-revoked model ID, pinned base-weight Merkle root, allowlisted LoRA adapters,
 *      deterministic sampling envelope (`temperatureBps <= maxAllowedTempBps`, explicit
 *      seed, pinned runtime kernel), and valid Ed25519 serving signature.
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export function computeModelWeightMerkleRoot(shardDigestsHex: readonly string[]): string {
  if (shardDigestsHex.length === 0) {
    throw new Error('Model weight shard list must be non-empty');
  }
  let level = shardDigestsHex.map((d, idx) =>
    sha256Digest({domain: 'b21-weight-shard-leaf-v1', index: idx, shardDigest: d}),
  );
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(sha256Digest({domain: 'b21-weight-node-v1', left, right}));
    }
    level = next;
  }
  return level[0]!;
}

export interface ModelInferenceTraceAttestation {
  readonly servingKeyId: string;
  readonly modelId: string;
  readonly weightMerkleRootHex: string;
  readonly attachedAdapterDigests: readonly string[];
  readonly runtimeKernelDigestHex: string;
  readonly temperatureBps: number;
  readonly rngSeed: number | null;
  readonly promptDigestHex: string;
  readonly outputDigestHex: string;
  readonly signatureHex: string;
}

export interface ModelGovernanceVerificationPolicy {
  readonly trustedServingPublicKeys: Readonly<Record<string, string>>;
  readonly pinnedWeightRootsByModel: Readonly<Record<string, string>>;
  readonly approvedAdapterDigests: readonly string[];
  readonly pinnedKernelDigestHex: string;
  readonly maxAllowedTempBps: number;
  readonly revokedModelIds: readonly string[];
}

export type ModelInferenceVerificationVerdict =
  | {
      kind: 'Proven';
      modelId: string;
      weightMerkleRootHex: string;
      outputDigestHex: string;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'revoked-or-unpinned-model'
        | 'weight-merkle-root-mismatch'
        | 'unauthorized-lora-adapter'
        | 'non-deterministic-sampling-config'
        | 'unregistered-serving-key'
        | 'inference-attestation-signature-invalid';
      detail: string;
    };

function inferenceSigningDigest(
  att: Omit<ModelInferenceTraceAttestation, 'signatureHex'>,
): string {
  return sha256Digest({
    domain: 'b21-model-inference-attestation-v1',
    servingKeyId: att.servingKeyId,
    modelId: att.modelId,
    weightMerkleRootHex: att.weightMerkleRootHex,
    attachedAdapterDigests: att.attachedAdapterDigests,
    runtimeKernelDigestHex: att.runtimeKernelDigestHex,
    temperatureBps: att.temperatureBps,
    rngSeed: att.rngSeed,
    promptDigestHex: att.promptDigestHex,
    outputDigestHex: att.outputDigestHex,
  });
}

function verifyServingEd25519(
  pubPem: string,
  digestHex: string,
  sigHex: string,
): {kind: 'Proven'} | {kind: 'Refuted'; detail: string} {
  try {
    const ok = verify(null, Buffer.from(digestHex, 'hex'), pubPem, Buffer.from(sigHex, 'hex'));
    return ok
      ? {kind: 'Proven'}
      : {kind: 'Refuted', detail: 'Ed25519 signature mismatch on ModelInferenceTraceAttestation'};
  } catch (err) {
    return {
      kind: 'Refuted',
      detail: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * 18th R3 non-leakable M3 capability class: Model Weight & Inference Attestation Signing Key.
 * Mechanically refused by `ContentAddressedKvStore` and `JSON.stringify`.
 */
export class ModelWeightAttestationKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly servingKeyId: string) {
    this.capabilityId = `model-weight-attestation-key:${servingKeyId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  attestInferenceTrace(params: {
    modelId: string;
    weightMerkleRootHex: string;
    attachedAdapterDigests: readonly string[];
    runtimeKernelDigestHex: string;
    temperatureBps: number;
    rngSeed: number | null;
    promptDigestHex: string;
    outputDigestHex: string;
  }): ModelInferenceTraceAttestation {
    const body = {
      servingKeyId: this.servingKeyId,
      modelId: params.modelId,
      weightMerkleRootHex: params.weightMerkleRootHex,
      attachedAdapterDigests: [...params.attachedAdapterDigests],
      runtimeKernelDigestHex: params.runtimeKernelDigestHex,
      temperatureBps: params.temperatureBps,
      rngSeed: params.rngSeed,
      promptDigestHex: params.promptDigestHex,
      outputDigestHex: params.outputDigestHex,
    };
    const digest = inferenceSigningDigest(body);
    const signatureHex = sign(null, Buffer.from(digest, 'hex'), this.privateKey).toString('hex');
    return {...body, signatureHex};
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: ModelWeightAttestationKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

/**
 * 100% Air-Gapped Offline Verifier for B21 Deterministic Model-Weight & Inference Attestations.
 */
export function verifyModelInferenceAttestationOffline(params: {
  attestation: ModelInferenceTraceAttestation;
  policy: ModelGovernanceVerificationPolicy;
  kv?: ContentAddressedKvStore;
}): ModelInferenceVerificationVerdict {
  const {attestation, policy} = params;

  // 1. Non-revoked model & pinned base-weight Merkle root:
  const pinnedRoot = policy.pinnedWeightRootsByModel[attestation.modelId];
  if (!pinnedRoot || policy.revokedModelIds.includes(attestation.modelId)) {
    return {
      kind: 'Refuted',
      reason: 'revoked-or-unpinned-model',
      detail: `Model '${attestation.modelId}' is revoked or has no pinned weight Merkle root`,
    };
  }
  if (attestation.weightMerkleRootHex !== pinnedRoot) {
    return {
      kind: 'Refuted',
      reason: 'weight-merkle-root-mismatch',
      detail: `Observed weight root does not match pinned Merkle root for '${attestation.modelId}'`,
    };
  }

  // 2. LoRA / PEFT adapter allowlist (empty list passes cleanly without P4 bloat):
  for (const adapter of attestation.attachedAdapterDigests) {
    if (!policy.approvedAdapterDigests.includes(adapter)) {
      return {
        kind: 'Refuted',
        reason: 'unauthorized-lora-adapter',
        detail: `Attached LoRA/PEFT adapter '${adapter}' is not in approvedAdapterDigests`,
      };
    }
  }

  // 3. Deterministic sampling envelope (kernel digest + temperature cap + explicit integer seed):
  if (
    attestation.runtimeKernelDigestHex !== policy.pinnedKernelDigestHex ||
    attestation.temperatureBps < 0 ||
    attestation.temperatureBps > policy.maxAllowedTempBps ||
    attestation.rngSeed === null ||
    !Number.isInteger(attestation.rngSeed)
  ) {
    return {
      kind: 'Refuted',
      reason: 'non-deterministic-sampling-config',
      detail: 'Runtime kernel mismatch, temperature above deterministic cap, or missing PRNG seed',
    };
  }

  // 4. Registered serving key & Ed25519 signature verification:
  const pubPem = policy.trustedServingPublicKeys[attestation.servingKeyId];
  if (!pubPem) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-serving-key',
      detail: `Serving key '${attestation.servingKeyId}' not registered in trustedServingPublicKeys`,
    };
  }
  const {signatureHex, ...body} = attestation;
  const sigRes = verifyServingEd25519(pubPem, inferenceSigningDigest(body), signatureHex);
  if (sigRes.kind !== 'Proven') {
    return {
      kind: 'Refuted',
      reason: 'inference-attestation-signature-invalid',
      detail: sigRes.detail,
    };
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b21-model-inference-attestation-receipt',
      {
        servingKeyId: attestation.servingKeyId,
        modelId: attestation.modelId,
        weightMerkleRootHex: attestation.weightMerkleRootHex,
        attachedAdapterDigests: attestation.attachedAdapterDigests,
        runtimeKernelDigestHex: attestation.runtimeKernelDigestHex,
        temperatureBps: attestation.temperatureBps,
        rngSeed: attestation.rngSeed,
        promptDigestHex: attestation.promptDigestHex,
        outputDigestHex: attestation.outputDigestHex,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    modelId: attestation.modelId,
    weightMerkleRootHex: attestation.weightMerkleRootHex,
    outputDigestHex: attestation.outputDigestHex,
    pinnedReceiptHash,
  };
}
