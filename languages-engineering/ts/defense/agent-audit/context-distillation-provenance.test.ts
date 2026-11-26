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
import {DifcAgentMonitor} from './difc-exfiltration-fence.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {EXPECTED_QUINT_DEFENSE_MODELS} from './leanpoo-fleet-audit.ts';
import {
  ControlledContextDistiller,
  type SourceContextItem,
} from './context-distillation-provenance.ts';

const DISTILLATION_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
)!.theorems;

describe('Phase 36 — B12 Controlled Context Distillation & Epistemic Provenance + 126-Theorem 11-Module LeanPoo Library (10.184 / 30.05 AG186-AG190)', () => {
  test('AG186: Live Lean 4 / LeanPoo verifies all 10 ContextDistillationAndProvenance theorems + single-shot 126/126-theorem 11-module fleet attestation', () => {
    expect(DISTILLATION_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(11);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(126);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
          namespacePrefix: LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
          expectedTheorems: DISTILLATION_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
      namespacePrefix: LEANPOO_CONTEXT_DISTILLATION_FACADE_MODULE,
      expectedTheorems: DISTILLATION_THEOREMS,
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

  test('AG187: Blocks pinned M1 veto/constraint amnesia & fabricated source citation hallucinations during context compaction', () => {
    const kv = new ContentAddressedKvStore();
    const distiller = new ControlledContextDistiller(kv);

    const vetoHash = sha256Digest({veto: 'no-prod-ddl-drop'});
    const diffHash = sha256Digest({diff: 'add-index-concurrently'});
    const sources: SourceContextItem[] = [
      {
        itemId: 'human-veto-1',
        itemHash: vetoHash,
        isPinnedM1Constraint: true,
        integrity: 'TrustedSystem',
        secrecyTags: [],
        summaryText: 'Human veto: never run DROP TABLE on prod',
      },
      {
        itemId: 'patch-diff-1',
        itemHash: diffHash,
        isPinnedM1Constraint: false,
        integrity: 'AgentDerived',
        secrecyTags: [],
        summaryText: 'Patch adds concurrent index',
      },
    ];

    // 1. Summarizer drops pinned human veto -> Refuted (amnesia blocked!):
    expect(
      distiller.admitDistillation({
        sources,
        candidate: {
          distilledText: 'Ready to run migration.',
          retainedPinnedHashes: [], // Dropped vetoHash!
          citedSourceHashes: [diffHash],
          claimedOutputIntegrity: 'AgentDerived',
          claimedSecrecyTags: [],
          tokenCount: 120,
        },
        maxTokens: 1000,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'pinned-m1-constraint-dropped'});

    // 2. Summarizer fabricates a non-existent M1 citation hash -> Refuted:
    expect(
      distiller.admitDistillation({
        sources,
        candidate: {
          distilledText: 'Approved by phantom audit.',
          retainedPinnedHashes: [vetoHash],
          citedSourceHashes: [vetoHash, 'deadbeef-hallucinated-receipt'],
          claimedOutputIntegrity: 'AgentDerived',
          claimedSecrecyTags: [],
          tokenCount: 120,
        },
        maxTokens: 1000,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'hallucinated-source-citation'});
  });

  test('AG188: Blocks secrecy-tag stripping via paraphrasing, untrusted->trusted integrity laundering & token-budget overflow', () => {
    const kv = new ContentAddressedKvStore();
    const distiller = new ControlledContextDistiller(kv);

    const secretHash = sha256Digest({secret: 'tenant-alpha-api-key'});
    const webHash = sha256Digest({web: 'untrusted-github-comment'});
    const sources: SourceContextItem[] = [
      {
        itemId: 'vault-secret',
        itemHash: secretHash,
        isPinnedM1Constraint: true,
        integrity: 'TrustedSystem',
        secrecyTags: ['tenant:alpha', 'secret:api-key'],
        summaryText: 'Vault secret metadata',
      },
      {
        itemId: 'web-comment',
        itemHash: webHash,
        isPinnedM1Constraint: false,
        integrity: 'UntrustedExternal',
        secrecyTags: [],
        summaryText: 'External PR comment',
      },
    ];

    // 1. Paraphrasing strips `secret:api-key` without M3 declassification -> Refuted:
    expect(
      distiller.admitDistillation({
        sources,
        candidate: {
          distilledText: 'Paraphrased secret info',
          retainedPinnedHashes: [secretHash],
          citedSourceHashes: [secretHash, webHash],
          claimedOutputIntegrity: 'UntrustedExternal',
          claimedSecrecyTags: ['tenant:alpha'], // Missing secret:api-key!
          tokenCount: 200,
        },
        maxTokens: 1000,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'secrecy-tag-stripped-by-summarizer'});

    // 2. Laundering UntrustedExternal input into TrustedSystem summary -> Refuted:
    expect(
      distiller.admitDistillation({
        sources,
        candidate: {
          distilledText: 'Clean trusted synthesis',
          retainedPinnedHashes: [secretHash],
          citedSourceHashes: [secretHash, webHash],
          claimedOutputIntegrity: 'TrustedSystem', // Elevated above UntrustedExternal!
          claimedSecrecyTags: ['tenant:alpha', 'secret:api-key'],
          tokenCount: 200,
        },
        maxTokens: 1000,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'integrity-laundering-elevated-above-inputs'});

    // 3. Token-budget overflow (1500 > 1000) -> Refuted:
    expect(
      distiller.admitDistillation({
        sources,
        candidate: {
          distilledText: 'Way too verbose summary',
          retainedPinnedHashes: [secretHash],
          citedSourceHashes: [secretHash, webHash],
          claimedOutputIntegrity: 'UntrustedExternal',
          claimedSecrecyTags: ['tenant:alpha', 'secret:api-key'],
          tokenCount: 1500,
        },
        maxTokens: 1000,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'distilled-context-exceeds-token-budget'});
  });

  test('AG189: Safe distillation computes monotonic integrity meet & secrecy union; B7 DIFC blocks distilled secret leaking to public sink', () => {
    const kv = new ContentAddressedKvStore();
    const distiller = new ControlledContextDistiller(kv);
    const difc = new DifcAgentMonitor(kv);

    const sources: SourceContextItem[] = [
      {
        itemId: 'pinned-policy',
        itemHash: sha256Digest({policy: 'v36'}),
        isPinnedM1Constraint: true,
        integrity: 'TrustedSystem',
        secrecyTags: ['tenant:alpha'],
        summaryText: 'Tenant alpha policy',
      },
      {
        itemId: 'external-issue',
        itemHash: sha256Digest({issue: 'ext-189'}),
        isPinnedM1Constraint: false,
        integrity: 'UntrustedExternal',
        secrecyTags: [],
        summaryText: 'External bug report',
      },
    ];

    const distilled = distiller.distillSafely({
      sources,
      distilledText: 'Compacted summary preserving tenant:alpha & pinned policy',
      tokenCount: 350,
      maxTokens: 1000,
    });
    expect(distilled.kind).toBe('Proven');
    if (distilled.kind !== 'Proven') throw new Error('expected Proven');
    expect(distilled.outputIntegrity).toBe('UntrustedExternal');
    expect(distilled.outputSecrecyTags).toEqual(['tenant:alpha']);
    expect(distilled.retainedPinnedHashes).toEqual([sources[0]!.itemHash]);

    // Feed distilled context into B7 DIFC: public sink MUST reject due to preserved `tenant:alpha`!
    const taintedSummary = difc.ingestData({
      valueId: 'distilled-summary-189',
      value: distilled.distilledText,
      secrecyTags: distilled.outputSecrecyTags,
      integrity: distilled.outputIntegrity,
      sourcePrincipal: 'context-distiller',
    });
    const trustedCtrl = difc.ingestData({
      valueId: 'public-wiki-url',
      value: 'https://docs.example.org/notes',
      secrecyTags: [],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'coordinator',
    });
    const exfil = difc.dispatchToToolSink({
      sink: {sinkId: 'public-wiki', allowedSecrecyTags: [], minControlIntegrity: 'TrustedSystem'},
      controlArg: trustedCtrl,
      payload: taintedSummary,
      agentId: 'summarizer',
    });
    expect(exfil).toMatchObject({kind: 'Refuted', reason: 'secret-exfiltration-blocked'});

    kv.gcUnreferenced();
    expect(kv.hasBlob(distilled.distillationMerkleHash)).toBe(true);
  });

  test('AG190: 190-Case Milestone — 20 Quint x 11 Modules / 126 Theorems CLI JSON & cedar-poo-spec Data-Disclosure Dual Gate', () => {
    const kv = new ContentAddressedKvStore();
    let opDigest = sha256Digest({milestone: 190, modules: 11, theorems: 126});

    if (isLeanToolchainAvailable()) {
      const cliPath = resolve(import.meta.dir, 'leanpoo-fleet-audit.ts');
      const proc = spawnSync('bun', [cliPath, '--json'], {
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
      });
      expect(proc.status).toBe(0);
      const out = JSON.parse(proc.stdout) as {
        verdict: string;
        quintModelCount: number;
        moduleCount: number;
        verifiedTheoremCount: number;
        zeroMathlib: boolean;
        zeroCedar: boolean;
        releaseAttestationDigest: string;
      };
      expect(out.verdict).toBe('Proven');
      expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
      expect(out.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
      expect(out.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
      expect(out.zeroMathlib).toBe(true);
      expect(out.zeroCedar).toBe(true);
      opDigest = out.releaseAttestationDigest;
    }

    const lease = new LiveM3Capability('lease-190-distill', 'data:disclosure', 36);
    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: 36,
        treeSize: 1,
        rootHashHex: opDigest,
        checkpointDigest: sha256Digest({b12Milestone: 190}),
        verifiedWitnessIds: ['w1', 'w2', 'w3'],
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: opDigest,
        policySnapshotDigest: sha256Digest({cedarDataProfile: 'v36'}),
        policyAffectedScopes: ['data:disclosure'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: sha256Digest({cedarDataProfile: 'v36'}),
      activeLeaseEpoch: 36,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
