// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  auditLeanPooLibraryBoundaries,
  LEANPOO_EXPORT_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';

const EXPORT_FACADE_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_EXPORT_FACADE_MODULE,
)!.theorems;

describe('Phase 30 — LeanPoo Unified Library Export Contract & 76-Theorem Fleet Manifest for cedar-poo-spec (10.178 / 30.05 AG156-AG160)', () => {
  test('AG156: Live Lean 4 / LeanPoo oracle verifies all 12 LibraryExportContract facade theorems (zero sorry/custom axioms) & pins M1 cert', () => {
    expect(EXPORT_FACADE_THEOREMS.length).toBe(12);
    const kv = new ContentAddressedKvStore();

    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_EXPORT_FACADE_MODULE,
          namespacePrefix: LEANPOO_EXPORT_FACADE_MODULE,
          expectedTheorems: EXPORT_FACADE_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_EXPORT_FACADE_MODULE,
      namespacePrefix: LEANPOO_EXPORT_FACADE_MODULE,
      expectedTheorems: EXPORT_FACADE_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(12);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG157: Static Library Boundary Audit enforces ZERO Mathlib, ZERO Cedar, 6/6 SPDX & zero anti-fabrication across all 6 LeanPoo modules', () => {
    const audit = auditLeanPooLibraryBoundaries();
    expect(audit.passed).toBe(true);
    expect(audit.moduleCount).toBe(6);
    expect(audit.theoremCount).toBe(76);
    expect(audit.violations).toEqual([]);

    // Verify 100% pillar coverage across manifest:
    const coveredPillars = new Set(LEANPOO_LIBRARY_EXPORT_MANIFEST.flatMap(m => m.pillars));
    for (const req of [
      'B1',
      'B2',
      'B3',
      'B4',
      'B5',
      'B6',
      'B7',
      'B8',
      'B9',
      'B10',
      'B10b',
      'B10c',
      'R1',
      'R2',
      'R3',
      'R4',
      'R5',
      'DualSovereignty',
      'LibraryExport',
    ]) {
      expect(coveredPillars.has(req)).toBe(true);
    }
  });

  test('AG158: Single-Shot Batched 76/76-Theorem LeanPoo Fleet Attestation via LibraryExportContract facade pins deterministic M1 receipt', () => {
    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(verifyLeanPooLibraryFleet({kv, lakeBinary: 'nonexistent-lake-bin'})).toEqual({
        kind: 'PendingMethod',
        reason: 'lean-toolchain-unavailable',
      });
      return;
    }

    const run1 = verifyLeanPooLibraryFleet({kv});
    expect(run1.kind).toBe('Proven');
    if (run1.kind !== 'Proven') throw new Error(`expected Proven, got ${JSON.stringify(run1)}`);
    expect(run1.moduleCount).toBe(6);
    expect(run1.verifiedTheoremCount).toBe(76);
    expect(run1.pinnedReceiptHash).toBeDefined();

    // Deterministic attestation digest parity across independent runs:
    const run2 = verifyLeanPooLibraryFleet();
    expect(run2.kind).toBe('Proven');
    if (run2.kind !== 'Proven') throw new Error('expected Proven');
    expect(run2.fleetAttestationDigest).toBe(run1.fleetAttestationDigest);

    // Pinned M1 fleet attestation survives aggressive GC:
    kv.gcUnreferenced();
    expect(kv.hasBlob(run1.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG159: cedar-poo-spec 3-Layer Consuming-Host Stack (Authorization -> Governance -> Admission) preserves every Library refusal monotonically', () => {
    const kv = new ContentAddressedKvStore();
    const opDigest = sha256Digest({op: 'deploy-prod-159', libraryExport: 'v30'});
    const polDigest = sha256Digest({cedarBundle: 'cedar-poo-spec-v30'});
    const lease = new LiveM3Capability('lease-159', 'deploy:prod', 30);

    // All 3 consuming-host layers (Authorization, Governance, Admission) grant Permit:
    const fullHostPermit = evaluateHostPolicySemantics({
      permitMatched: true,
      forbidMatched: false,
      contextReady: true,
    });
    expect(fullHostPermit).toBe('Permit');

    // Case A: Library Refuted (e.g. missing quorum/slashing/DIFC/Saga/HITL invariant)
    // MUST STILL FAIL CLOSED even when all 3 cedar-poo-spec layers emit Permit!
    const libRefused = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {kind: 'Refuted', reason: 'library-export-invariant-failed'},
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: fullHostPermit,
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['deploy:prod'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 30,
    });
    expect(libRefused.kind).toBe('Refuted');

    // Case B: Library Finalized + cedar-poo-spec Governance Veto (`Forbid`) MUST ALSO FAIL CLOSED!
    const hostVetoed = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: 1,
        treeSize: 1,
        rootHashHex: 'a'.repeat(64),
        checkpointDigest: 'b'.repeat(64),
        verifiedWitnessIds: ['w1', 'w2', 'w3'],
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: true, // CedarPooSpec.Governance.Veto Forbid!
          contextReady: true,
        }),
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['deploy:prod'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 30,
    });
    expect(hostVetoed.kind).toBe('Refuted');

    // Case C: Both Library Finalized AND cedar-poo-spec Permit with disjoint host policy bundle tag upgrade -> Proven!
    const admitted = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: 1,
        treeSize: 1,
        rootHashHex: 'a'.repeat(64),
        checkpointDigest: 'b'.repeat(64),
        verifiedWitnessIds: ['w1', 'w2', 'w3'],
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: fullHostPermit,
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['deploy:prod'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: sha256Digest({cedarBundle: 'cedar-poo-spec-v31-disjoint'}),
      policyChangedScopes: ['billing:invoicing'],
      activeLeaseEpoch: 30,
    });
    expect(admitted.kind).toBe('Proven');
    if (admitted.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(admitted.dualSovereignReceiptHash)).toBe(true);
  });

  test('AG160: 160-Case Library Release Gate fails closed on missing toolchain or nonexistent exported theorem', () => {
    // 1. Missing `lake` binary MUST fail closed as PendingMethod (never ok:true!):
    const noLake = verifyLeanPooLibraryFleet({lakeBinary: 'definitely-missing-lake-binary-160'});
    expect(noLake).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});

    // 2. Manifest claiming a nonexistent theorem MUST fail closed (never silently pass!):
    if (!isLeanToolchainAvailable()) return;
    const forgedManifest = [
      {
        moduleName: LEANPOO_EXPORT_FACADE_MODULE,
        relativeLeanPath: 'DeterministicEngineering/Engineering/LibraryExportContract.lean',
        pillars: ['LibraryExport'],
        theorems: ['unifiedLibraryContract_accepts_all_enabled', 'forged_nonexistent_theorem_160'],
      },
    ];
    const forged = verifyLeanPooLibraryFleet({manifest: forgedManifest});
    expect(forged.kind).not.toBe('Proven');
    expect(['SetupDefect', 'Refuted']).toContain(forged.kind);
  }, 30_000);
});
