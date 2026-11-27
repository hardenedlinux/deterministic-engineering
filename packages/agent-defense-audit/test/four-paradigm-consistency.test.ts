// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from '../src/durable-merkle-store.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from '../src/host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from '../src/lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
} from '../src/leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  evaluateFourParadigmReleaseGate,
  EXPECTED_MULTILANG_HARNESSES,
  EXPECTED_QUINT_DEFENSE_MODELS,
  type EpistemicVerdict,
} from '../src/leanpoo-fleet-audit.ts';

const FOUR_PARADIGM_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
)!.theorems;

describe('Phase 31 — Four-Paradigm Cross-Consistency & 86-Theorem LeanPoo CLI Release Gate (10.179 / 30.05 AG161-AG165)', () => {
  test('AG161: Live Lean 4 / LeanPoo oracle verifies all 10 FourParadigmConsistency theorems (zero sorry/custom axioms) & pins M1 cert', () => {
    expect(FOUR_PARADIGM_THEOREMS.length).toBe(10);
    const kv = new ContentAddressedKvStore();

    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
          namespacePrefix: LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
          expectedTheorems: FOUR_PARADIGM_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
      namespacePrefix: LEANPOO_FOUR_PARADIGM_FACADE_MODULE,
      expectedTheorems: FOUR_PARADIGM_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(10);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG162: Live Four-Paradigm Cross-Consistency Audit verifies 19 Quint models x ASCENT x 5-Lang/CBMC x 86/86 LeanPoo fleet & pins M1 attestation', () => {
    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      const rep = auditFourParadigmCrossConsistency({kv, lakeBinary: 'missing-lake-162'});
      expect(rep.verdict).toBe('PendingMethod');
      return;
    }

    const rep = auditFourParadigmCrossConsistency({kv});
    expect(rep.verdict).toBe('Proven');
    expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
    expect(rep.missingQuintModels).toEqual([]);
    expect(rep.ascentRulesPresent).toBe(true);
    expect(rep.multiLangHarnessCount).toBe(EXPECTED_MULTILANG_HARNESSES.length);
    expect(rep.missingHarnesses).toEqual([]);
    expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(rep.zeroMathlib).toBe(true);
    expect(rep.zeroCedar).toBe(true);
    expect(rep.leanPooFleetVerdict.kind).toBe('Proven');
    expect(rep.pinnedReceiptHash).toBeDefined();

    kv.gcUnreferenced();
    expect(kv.hasBlob(rep.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG163: Standalone CLI `leanpoo-fleet-audit.ts --json` exits 0 and emits valid 86-theorem JSON attestation for cedar-poo-spec CI', () => {
    if (!isLeanToolchainAvailable()) return;

    const cliPath = resolve(import.meta.dir, '../src/leanpoo-fleet-audit.ts');
    const proc = spawnSync('bun', [cliPath, '--json'], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    expect(proc.status).toBe(0);
    const parsed = JSON.parse(proc.stdout) as {
      verdict: string;
      facadeModule: string;
      quintModelCount: number;
      ascentRulesPresent: boolean;
      multiLangHarnessCount: number;
      moduleCount: number;
      verifiedTheoremCount: number;
      zeroMathlib: boolean;
      zeroCedar: boolean;
      releaseAttestationDigest: string;
      pinnedReceiptHash: string;
    };
    expect(parsed.verdict).toBe('Proven');
    expect(parsed.facadeModule).toBe(LEANPOO_TOP_FACADE_MODULE);
    expect(parsed.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
    expect(parsed.ascentRulesPresent).toBe(true);
    expect(parsed.multiLangHarnessCount).toBe(8);
    expect(parsed.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(parsed.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(parsed.zeroMathlib).toBe(true);
    expect(parsed.zeroCedar).toBe(true);
    expect(parsed.releaseAttestationDigest.length).toBe(64);
    expect(parsed.pinnedReceiptHash.length).toBe(64);
  }, 45_000);

  test('AG164: Four-Paradigm N-Version Fail-Closed Matrix blocks release whenever ANY single paradigm is Refuted, PendingMethod or SetupDefect', () => {
    const nonProvenStates: EpistemicVerdict[] = ['Refuted', 'PendingMethod', 'SetupDefect'];
    const libKeys = [
      'quintApalache',
      'gerbilAscent',
      'cbmcMultiLang',
      'leanPooUnbounded',
    ] as const;

    // 1. All 4 x 3 = 12 single-paradigm failure combinations block BOTH library & full release
    // even when cedar-poo-spec hostPolicyGate is Proven!
    for (const key of libKeys) {
      for (const bad of nonProvenStates) {
        const res = evaluateFourParadigmReleaseGate({
          quintApalache: 'Proven',
          gerbilAscent: 'Proven',
          cbmcMultiLang: 'Proven',
          leanPooUnbounded: 'Proven',
          hostPolicyGate: 'Proven',
          [key]: bad,
        });
        expect(res.libraryAdmitted).toBe(false);
        expect(res.fullReleaseAdmitted).toBe(false);
        expect(res.blockingParadigms).toContain(`${key}:${bad}`);
      }
    }

    // 2. 4/4 Library Proven + Host non-Proven still blocks fullReleaseAdmitted!
    for (const bad of nonProvenStates) {
      const res = evaluateFourParadigmReleaseGate({
        quintApalache: 'Proven',
        gerbilAscent: 'Proven',
        cbmcMultiLang: 'Proven',
        leanPooUnbounded: 'Proven',
        hostPolicyGate: bad,
      });
      expect(res.libraryAdmitted).toBe(true);
      expect(res.fullReleaseAdmitted).toBe(false);
      expect(res.blockingParadigms).toEqual([`hostPolicyGate:${bad}`]);
    }

    // 3. Only 5/5 Proven admits full release:
    expect(
      evaluateFourParadigmReleaseGate({
        quintApalache: 'Proven',
        gerbilAscent: 'Proven',
        cbmcMultiLang: 'Proven',
        leanPooUnbounded: 'Proven',
        hostPolicyGate: 'Proven',
      }),
    ).toEqual({
      libraryAdmitted: true,
      fullReleaseAdmitted: true,
      blockingParadigms: [],
    });
  });

  test('AG165: 165-Case End-to-End Custody — 4-Paradigm 86-Theorem Release Attestation verified by cedar-poo-spec Dual-Sovereign Gate across GC', () => {
    const kv = new ContentAddressedKvStore();
    const attestationDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({fallbackReleaseAttestation: 165});

    const polDigest = sha256Digest({cedarBundle: 'cedar-poo-spec-release-v31'});
    const lease = new LiveM3Capability('lease-release-165', 'library:release', 31);

    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: 1,
        treeSize: 1,
        rootHashHex: attestationDigest,
        checkpointDigest: sha256Digest({qc: attestationDigest}),
        verifiedWitnessIds: ['w1', 'w2', 'w3'],
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: attestationDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['library:release'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: attestationDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 31,
    });

    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
