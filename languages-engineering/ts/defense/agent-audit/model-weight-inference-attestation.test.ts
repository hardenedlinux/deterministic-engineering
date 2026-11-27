// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  AeadPartitionKey,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {DelegationRootKey} from './capability-attenuation.ts';
import {LinearBudgetTree} from './durable-saga-budget.ts';
import {DeclassificationCapability} from './difc-exfiltration-fence.ts';
import {CoordinatorSigningKey} from './transparency-log-equivocation.ts';
import {WitnessCosigningKey} from './witness-quorum-finality.ts';
import {ForwardSecureWitnessKey} from './witness-epoch-reconfiguration.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';
import {ToolSandboxCapability} from './tool-sandbox-rpc-boundary.ts';
import {BuilderAttestationSigningKey} from './supply-chain-provenance.ts';
import {EnclaveRootAttestationKey} from './confidential-enclave-attestation.ts';
import {RotatableTenantAeadKeyRing} from './key-rotation-crypto-shredding.ts';
import {HybridPqSigningKey} from './post-quantum-crypto-agility.ts';
import {ZkProverWitnessKey} from './zk-selective-disclosure.ts';
import {GeoResidencySigningKey} from './geo-residency-sovereignty.ts';
import {FederatedOrgSigningKey} from './federated-org-reciprocity.ts';
import {
  computeModelWeightMerkleRoot,
  ModelWeightAttestationKey,
  verifyModelInferenceAttestationOffline,
  type ModelGovernanceVerificationPolicy,
} from './model-weight-inference-attestation.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';

const MODEL_WEIGHT_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
)!.theorems;

describe('Phase 53 — B21 Deterministic Model-Weight Pinning & Reproducible Inference Attestation + 20-Module / 216-Theorem LeanPoo Library (10.202 / 30.05 AG276-AG280)', () => {
  test('AG276: Live Lean 4 / LeanPoo verifies all 10 ModelWeightAndInferenceAttestation theorems + single-shot 216/216-theorem 20-module fleet attestation', () => {
    expect(MODEL_WEIGHT_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(20);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(216);
    expect(
      LEANPOO_LIBRARY_EXPORT_MANIFEST.some(
        m => m.moduleName === LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
      ),
    ).toBe(true);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
          namespacePrefix: LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
          expectedTheorems: MODEL_WEIGHT_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
      namespacePrefix: LEANPOO_MODEL_WEIGHT_FACADE_MODULE,
      expectedTheorems: MODEL_WEIGHT_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(fleet.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG277: Tensor shard Merkle root pinning admits clean zero-adapter & allowlisted-LoRA greedy inference while rejecting single-shard weight swap', () => {
    const kv = new ContentAddressedKvStore();
    const shards = ['shard-0-clean', 'shard-1-clean', 'shard-2-clean', 'shard-3-clean'].map(s =>
      sha256Digest({safetensor: s}),
    );
    const pinnedRoot = computeModelWeightMerkleRoot(shards);
    const tamperedRoot = computeModelWeightMerkleRoot([
      shards[0]!,
      sha256Digest({safetensor: 'shard-1-backdoored'}),
      shards[2]!,
      shards[3]!,
    ]);
    expect(tamperedRoot).not.toBe(pinnedRoot);

    const servingKey = new ModelWeightAttestationKey('vllm-enclave-277');
    const kernelDigest = sha256Digest({cuda: '12.4-det', cublas: 'deterministic'});
    const approvedLora = sha256Digest({lora: 'compliance-redaction-v1'});
    const policy: ModelGovernanceVerificationPolicy = {
      trustedServingPublicKeys: {[servingKey.servingKeyId]: servingKey.publicKeyPem},
      pinnedWeightRootsByModel: {'model-reg-70b': pinnedRoot},
      approvedAdapterDigests: [approvedLora],
      pinnedKernelDigestHex: kernelDigest,
      maxAllowedTempBps: 0,
      revokedModelIds: [],
    };

    // 1. Clean base model (zero LoRA adapters, temp=0, seed=42) -> admitted & pinned across GC:
    const baseAtt = servingKey.attestInferenceTrace({
      modelId: 'model-reg-70b',
      weightMerkleRootHex: pinnedRoot,
      attachedAdapterDigests: [],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 42,
      promptDigestHex: sha256Digest({prompt: 'underwrite-277'}),
      outputDigestHex: sha256Digest({verdict: 'APPROVE'}),
    });
    const baseRes = verifyModelInferenceAttestationOffline({
      attestation: JSON.parse(JSON.stringify(baseAtt)),
      policy,
      kv,
    });
    expect(baseRes.kind).toBe('Proven');
    if (baseRes.kind !== 'Proven') throw new Error('expected Proven');

    // 2. Allowlisted LoRA adapter -> admitted:
    const loraAtt = servingKey.attestInferenceTrace({
      modelId: 'model-reg-70b',
      weightMerkleRootHex: pinnedRoot,
      attachedAdapterDigests: [approvedLora],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 42,
      promptDigestHex: sha256Digest({prompt: 'underwrite-277-lora'}),
      outputDigestHex: sha256Digest({verdict: 'APPROVE-REDACTED'}),
    });
    expect(verifyModelInferenceAttestationOffline({attestation: loraAtt, policy}).kind).toBe(
      'Proven',
    );

    // 3. Single weight shard swapped -> refused:
    const swapAtt = servingKey.attestInferenceTrace({
      modelId: 'model-reg-70b',
      weightMerkleRootHex: tamperedRoot,
      attachedAdapterDigests: [],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 42,
      promptDigestHex: sha256Digest({prompt: 'underwrite-277'}),
      outputDigestHex: sha256Digest({verdict: 'APPROVE'}),
    });
    expect(verifyModelInferenceAttestationOffline({attestation: swapAtt, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'weight-merkle-root-mismatch',
    });

    kv.gcUnreferenced();
    expect(kv.hasBlob(baseRes.pinnedReceiptHash!)).toBe(true);
  });

  test('AG278: Verifier refuses all 6 inference-integrity attacks (stealth LoRA, non-zero temp, missing seed, kernel drift, revoked model, forged sig)', () => {
    const servingKey = new ModelWeightAttestationKey('vllm-enclave-278');
    const pinnedRoot = computeModelWeightMerkleRoot([sha256Digest({w: 'base-278'})]);
    const kernelDigest = sha256Digest({kernel: 'det-278'});
    const policy: ModelGovernanceVerificationPolicy = {
      trustedServingPublicKeys: {[servingKey.servingKeyId]: servingKey.publicKeyPem},
      pinnedWeightRootsByModel: {'model-278': pinnedRoot},
      approvedAdapterDigests: [sha256Digest({lora: 'approved-278'})],
      pinnedKernelDigestHex: kernelDigest,
      maxAllowedTempBps: 0,
      revokedModelIds: [],
    };
    const baseArgs = {
      modelId: 'model-278',
      weightMerkleRootHex: pinnedRoot,
      attachedAdapterDigests: [] as string[],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 7 as number | null,
      promptDigestHex: sha256Digest({p: 278}),
      outputDigestHex: sha256Digest({o: 278}),
    };

    // 1. Stealth unapproved LoRA adapter refused:
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: servingKey.attestInferenceTrace({
          ...baseArgs,
          attachedAdapterDigests: [sha256Digest({lora: 'trojan-lora'})],
        }),
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unauthorized-lora-adapter'});

    // 2. Non-deterministic temperature (temp=70 bps > 0) refused:
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: servingKey.attestInferenceTrace({...baseArgs, temperatureBps: 70}),
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'non-deterministic-sampling-config'});

    // 3. Missing PRNG seed (null) refused:
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: servingKey.attestInferenceTrace({...baseArgs, rngSeed: null}),
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'non-deterministic-sampling-config'});

    // 4. Runtime kernel drift refused:
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: servingKey.attestInferenceTrace({
          ...baseArgs,
          runtimeKernelDigestHex: sha256Digest({kernel: 'nondet-flash'}),
        }),
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'non-deterministic-sampling-config'});

    // 5. Revoked model ID refused:
    const cleanAtt = servingKey.attestInferenceTrace(baseArgs);
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: cleanAtt,
        policy: {...policy, revokedModelIds: ['model-278']},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'revoked-or-unpinned-model'});

    // 6. Forged signature refused:
    const badSig =
      (cleanAtt.signatureHex.startsWith('a') ? 'b' : 'a') + cleanAtt.signatureHex.slice(1);
    expect(
      verifyModelInferenceAttestationOffline({
        attestation: {...cleanAtt, signatureHex: badSig},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'inference-attestation-signature-invalid'});
  });

  test('AG279: All 18/18 R3 Non-Leakable M3 Capability Classes (including ModelWeightAttestationKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all18R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-279', 'scope:279', 1),
      new AeadPartitionKey('tenant-279'),
      new DelegationRootKey('root-279'),
      new LinearBudgetTree('agent-279', 279),
      new DeclassificationCapability('declass-279', ['tenant:279']),
      new CoordinatorSigningKey('log-279'),
      new WitnessCosigningKey('w-279'),
      new ForwardSecureWitnessKey('fw-279', 1),
      new LibraryReleaseSigningKey('pub-279'),
      new ToolSandboxCapability('agent-279', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-279'),
      new EnclaveRootAttestationKey('tee-node-279'),
      new RotatableTenantAeadKeyRing('tenant-ring-279', 1),
      new HybridPqSigningKey('pq-signer-279', 2),
      new ZkProverWitnessKey('zk-prover-279', [{fieldId: 'ok', value: true, confidential: false}]),
      new GeoResidencySigningKey('geo-auth-279', 'eu-central-1'),
      new FederatedOrgSigningKey('fed-org-279'),
      new ModelWeightAttestationKey('serving-host-279'),
    ];
    expect(all18R3Caps.length).toBe(18);
    for (const cap of all18R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-279', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG280: 280-Case & 20-Module / 216-Theorem Milestone — 29 Quint x 56x30 ASCENT x 216-Thm CLI + Model Weight Pinning -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    if (isLeanToolchainAvailable()) {
      const cliPath = resolve(import.meta.dir, 'leanpoo-fleet-audit.ts');
      const proc = spawnSync('bun', [cliPath, '--json'], {
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
      });
      expect(proc.status).toBe(0);
      const out = JSON.parse(proc.stdout) as {
        verdict: string;
        facadeModule: string;
        quintModelCount: number;
        ascentRulesPresent: boolean;
        multiLangHarnessCount: number;
        moduleCount: number;
        verifiedTheoremCount: number;
        zeroMathlib: boolean;
        zeroCedar: boolean;
      };
      expect(out.verdict).toBe('Proven');
      expect(out.facadeModule).toBe(LEANPOO_TOP_FACADE_MODULE);
      expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
      expect(out.ascentRulesPresent).toBe(true);
      expect(out.multiLangHarnessCount).toBe(8);
      expect(out.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
      expect(out.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
      expect(out.zeroMathlib).toBe(true);
      expect(out.zeroCedar).toBe(true);
    }

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 280, quint: 29, modules: 20, theorems: 216});

    // B21 Deterministic Model-Weight & Inference Attestation bound to attDigest:
    const servingKey = new ModelWeightAttestationKey('vllm-sovereign-280');
    const pinnedRoot = computeModelWeightMerkleRoot([sha256Digest({shard: 'v53-model-a'})]);
    const kernelDigest = sha256Digest({kernel: 'v53-det'});
    const infAtt = servingKey.attestInferenceTrace({
      modelId: 'sovereign-audit-llm-v53',
      weightMerkleRootHex: pinnedRoot,
      attachedAdapterDigests: [],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 280,
      promptDigestHex: attDigest,
      outputDigestHex: sha256Digest({admitted: true, attDigest}),
    });
    const infVerified = verifyModelInferenceAttestationOffline({
      attestation: JSON.parse(JSON.stringify(infAtt)),
      policy: {
        trustedServingPublicKeys: {[servingKey.servingKeyId]: servingKey.publicKeyPem},
        pinnedWeightRootsByModel: {'sovereign-audit-llm-v53': pinnedRoot},
        approvedAdapterDigests: [],
        pinnedKernelDigestHex: kernelDigest,
        maxAllowedTempBps: 0,
        revokedModelIds: [],
      },
      kv,
    });
    expect(infVerified.kind).toBe('Proven');
    if (infVerified.kind !== 'Proven') throw new Error('expected Proven');

    const publisher = new LibraryReleaseSigningKey('pub-280');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v53-20mod-216thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 53,
        moduleCount: LEANPOO_EXPECTED_MODULE_COUNT,
        verifiedTheoremCount: LEANPOO_EXPECTED_THEOREM_COUNT,
        quintModelCount: EXPECTED_QUINT_DEFENSE_MODELS.length,
        zeroMathlib: true,
        zeroCedar: true,
      },
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });

    const offline = verifyLibraryReleaseCertificateOffline({
      cert: JSON.parse(JSON.stringify(cert)),
      policy: {
        expectedAttestationDigest: attDigest,
        trustedPublisherPublicKeyPem: publisher.publicKeyPem,
        registeredWitnessPublicKeys: Object.fromEntries(
          witnesses.map(w => [w.publisherId, w.publicKeyPem]),
        ),
        minWitnessThreshold: 3,
        minRequiredTheorems: LEANPOO_EXPECTED_THEOREM_COUNT,
        minAllowedEpoch: 53,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-280', 'release:b21-model-weights', 53);
    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: offline.releaseEpoch,
        treeSize: 1,
        rootHashHex: offline.attestationDigest,
        checkpointDigest: offline.pinnedOfflineReceiptHash!,
        verifiedWitnessIds: offline.verifiedWitnessIds,
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: offline.attestationDigest,
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v53-model-weights'}),
        policyAffectedScopes: ['release:b21-model-weights'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v53-model-weights'}),
      activeLeaseEpoch: 53,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(infVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
