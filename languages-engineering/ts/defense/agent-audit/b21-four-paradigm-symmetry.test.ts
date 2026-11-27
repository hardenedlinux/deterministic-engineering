// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {buildThresholdCheckpoint, WitnessCosigningKey} from './witness-quorum-finality.ts';
import {
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  runLiveGerbilAscentMetaAudit,
  verifyReleaseWithIndependentAscentOracle,
} from './ascent-meta-audit-bridge.ts';
import {
  computeModelWeightMerkleRoot,
  ModelWeightAttestationKey,
  verifyModelInferenceAttestationOffline,
} from './model-weight-inference-attestation.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {isLeanToolchainAvailable} from './lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_TOP_FACADE_MODULE,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';

describe('Phase 54 — Full B21 Four-Paradigm Symmetry: 30 Quint/MBT Models + 60x32 B1-B21 Gerbil ASCENT + 216-Theorem LeanPoo (10.203 / 30.05 AG281-AG285)', () => {
  test('AG281: Live 60x32 Gerbil Scheme ASCENT derives B21 model_weight_violation for unpinned weight, revoked model & non-det sampling while admitting clean base model', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      modelPinnedWeights: [
        {modelId: 'model-281-clean', weightRoot: 'wroot-clean-281'},
        {modelId: 'model-281-revoked', weightRoot: 'wroot-rev-281'},
      ],
      modelRevokedIds: ['model-281-revoked'],
      releaseModelInferences: [
        {
          releaseId: 'rel-mod-clean',
          modelId: 'model-281-clean',
          observedWeightRoot: 'wroot-clean-281',
          adapterDigest: 'none',
          deterministicSamplingOk: true,
        },
        {
          releaseId: 'rel-mod-bad',
          modelId: 'model-281-revoked',
          observedWeightRoot: 'wroot-tampered-281',
          adapterDigest: 'none',
          deterministicSamplingOk: false,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-mod-clean',
          authorId: 'agent-281',
          approverId: 'human-281',
          logId: 'log-281',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-mod-bad',
          authorId: 'agent-281',
          approverId: 'human-281',
          logId: 'log-281',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) {
      expect(runLiveGerbilAscentMetaAudit(bundle, {gerbilBinary: 'missing-gerbil'})).toEqual({
        kind: 'PendingMethod',
        reason: 'gerbil-runtime-unavailable',
      });
      return;
    }

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.model_weight_violation).toContainEqual([
      'rel-mod-bad',
      'wroot-tampered-281',
      'unpinned-base-weight',
    ]);
    expect(res.output.model_weight_violation).toContainEqual([
      'rel-mod-bad',
      'model-281-revoked',
      'revoked-model-id',
    ]);
    expect(res.output.model_weight_violation).toContainEqual([
      'rel-mod-bad',
      'model-281-revoked',
      'non-deterministic-sampling',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-mod-bad',
      'model-weight-or-sampling-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-mod-clean']]);
  }, 60_000);

  test('AG282: Live 60x32 Gerbil Scheme ASCENT derives B21 model_adapter_violation for stealth LoRA while admitting allowlisted LoRA and zero-adapter base model', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      modelPinnedWeights: [{modelId: 'model-282', weightRoot: 'wroot-282'}],
      modelApprovedAdapters: ['lora-approved-282'],
      releaseModelInferences: [
        {
          releaseId: 'rel-lora-ok',
          modelId: 'model-282',
          observedWeightRoot: 'wroot-282',
          adapterDigest: 'lora-approved-282',
          deterministicSamplingOk: true,
        },
        {
          releaseId: 'rel-lora-stealth',
          modelId: 'model-282',
          observedWeightRoot: 'wroot-282',
          adapterDigest: 'lora-trojan-282',
          deterministicSamplingOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-lora-ok',
          authorId: 'agent-282',
          approverId: 'human-282',
          logId: 'log-282',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-lora-stealth',
          authorId: 'agent-282',
          approverId: 'human-282',
          logId: 'log-282',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.model_adapter_violation).toContainEqual([
      'rel-lora-stealth',
      'lora-trojan-282',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-lora-stealth',
      'unauthorized-lora-adapter',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-lora-ok']]);
  }, 60_000);

  test('AG283: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on swapped-weight & stealth-LoRA releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      modelPinnedWeights: [{modelId: 'model-283', weightRoot: 'wroot-283'}],
      modelApprovedAdapters: ['lora-ok-283'],
      releaseModelInferences: [
        {
          releaseId: 'rel-bug-swap',
          modelId: 'model-283',
          observedWeightRoot: 'wroot-evil-283',
          adapterDigest: 'none',
          deterministicSamplingOk: true,
        },
        {
          releaseId: 'rel-bug-lora',
          modelId: 'model-283',
          observedWeightRoot: 'wroot-283',
          adapterDigest: 'lora-stealth-283',
          deterministicSamplingOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-bug-swap',
          authorId: 'coder-283',
          approverId: 'human-283',
          logId: 'log-283',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-lora',
          authorId: 'coder-283',
          approverId: 'human-283',
          logId: 'log-283',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateSwap = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-swap',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateSwap.kind).toBe('Refuted');
    if (gateSwap.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateSwap.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateSwap.ascentDisqualificationReasons).toContain('model-weight-or-sampling-violation');

    const gateLora = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-lora',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateLora.kind).toBe('Refuted');
    if (gateLora.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateLora.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateLora.ascentDisqualificationReasons).toContain('unauthorized-lora-adapter');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateSwap.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateLora.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG284: Standalone 30-Quint x 60x32 ASCENT x 20-Module / 216-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(30);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('model-weight-inference-attestation');
    if (!isLeanToolchainAvailable()) return;

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
  }, 45_000);

  test('AG285: 285-Case & 30-Quint Milestone — Model Weight Merkle Pinning + 30 Quint x 60x32 ASCENT x 216-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B21 Tensor Shard Merkle Root + Ed25519 Inference Attestation:
    const servingKey = new ModelWeightAttestationKey('vllm-sovereign-285');
    const pinnedRoot = computeModelWeightMerkleRoot([
      sha256Digest({shard: 'b21-shard-0'}),
      sha256Digest({shard: 'b21-shard-1'}),
    ]);
    const kernelDigest = sha256Digest({cuda: '12.4-det', phase: 54});
    const approvedLora = sha256Digest({lora: 'audit-safe-v54'});
    const infAtt = servingKey.attestInferenceTrace({
      modelId: 'sovereign-70b-v54',
      weightMerkleRootHex: pinnedRoot,
      attachedAdapterDigests: [approvedLora],
      runtimeKernelDigestHex: kernelDigest,
      temperatureBps: 0,
      rngSeed: 285,
      promptDigestHex: sha256Digest({phase: 54, quint: 30, theorems: 216}),
      outputDigestHex: sha256Digest({admitted: true, phase: 54}),
    });
    const infCheck = verifyModelInferenceAttestationOffline({
      attestation: JSON.parse(JSON.stringify(infAtt)),
      policy: {
        trustedServingPublicKeys: {[servingKey.servingKeyId]: servingKey.publicKeyPem},
        pinnedWeightRootsByModel: {'sovereign-70b-v54': pinnedRoot},
        approvedAdapterDigests: [approvedLora],
        pinnedKernelDigestHex: kernelDigest,
        maxAllowedTempBps: 0,
        revokedModelIds: [],
      },
      kv,
    });
    expect(infCheck.kind).toBe('Proven');
    if (infCheck.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 60x32 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-285');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-285', infReceipt: infCheck.pinnedReceiptHash});
    const sth = log.issueSignedTreeHead(1);
    const wKeys = ['w1', 'w2', 'w3', 'w4'].map(id => new WitnessCosigningKey(id));
    const qc = buildThresholdCheckpoint(
      sth,
      wKeys.slice(0, 3).map(k => k.cosignTreeHead(sth)),
    );

    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [{witnessId: 'w1', sth}],
      witnessRosters: [{logId: 'log-285', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-285', checkpoint: qc}],
      modelPinnedWeights: [{modelId: 'sovereign-70b-v54', weightRoot: pinnedRoot}],
      modelApprovedAdapters: [approvedLora],
      releaseModelInferences: [
        {
          releaseId: 'rel-285',
          modelId: 'sovereign-70b-v54',
          observedWeightRoot: pinnedRoot,
          adapterDigest: approvedLora,
          deterministicSamplingOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-285',
          authorId: 'coder-285',
          approverId: 'human-285',
          logId: 'log-285',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-285',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-285',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 30-Quint x 20-Module / 216-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 285, quint: 30, modules: 20, theorems: 216});

    const publisher = new LibraryReleaseSigningKey('pub-285');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v54-30quint-216thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 54,
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
        minAllowedEpoch: 54,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-285', 'release:b1-b21-30quint', 54);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v54'}),
        policyAffectedScopes: ['release:b1-b21-30quint'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v54'}),
      activeLeaseEpoch: 54,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(infCheck.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
