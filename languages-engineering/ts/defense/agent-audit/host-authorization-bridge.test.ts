// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
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
import {buildThresholdCheckpoint} from './witness-quorum-finality.ts';
import {
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
} from './witness-epoch-reconfiguration.ts';
import {
  auditLeanSourceAntiFabrication,
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
  HostAuthorizationReceipt,
} from './host-authorization-bridge.ts';

const BRIDGE_LEAN_PATH = resolve(
  import.meta.dir,
  '../../../../packages/lean-models/DeterministicEngineering/Engineering/HostAuthorizationBridge.lean',
);

const BRIDGE_THEOREMS = [
  'forbid_always_overrides_permit',
  'default_deny_when_no_permit',
  'cedar_permit_cannot_bypass_library_refusal',
  'library_finalized_cannot_bypass_host_forbid',
  'library_finalized_cannot_bypass_host_pending',
  'cross_operation_permit_replay_blocked',
  'stale_policy_snapshot_permit_blocked',
  'revoked_use_time_authority_blocked',
  'dualSovereignBridge_preserves_library_rejection',
  'disjointHostPolicyEvolution_preserves_bridge_certificate',
  'weakeningBoundOperation_invalidates_reuse',
] as const;

function buildVerifiedLibraryCheckpoint(logId: string) {
  const kv = new ContentAddressedKvStore();
  const coordKey = new CoordinatorSigningKey(logId);
  const w1 = new ForwardSecureWitnessKey('w1', 1);
  const w2 = new ForwardSecureWitnessKey('w2', 1);
  const w3 = new ForwardSecureWitnessKey('w3', 1);
  const w4 = new ForwardSecureWitnessKey('w4', 1);
  const roster = createEpochRoster({
    logId,
    epoch: 1,
    witnessPublicKeys: {
      w1: w1.getPublicKeyPem(1),
      w2: w2.getPublicKeyPem(1),
      w3: w3.getPublicKeyPem(1),
      w4: w4.getPublicKeyPem(1),
    },
    maxByzantineFaults: 1,
    threshold: 3,
  });
  const log = new VerifiableTransparencyLog(coordKey);
  log.appendEntry({op: 'deploy-release-140'});
  const sth = log.issueSignedTreeHead(1);
  const qc = buildThresholdCheckpoint(sth, [
    w1.cosignCheckpoint(sth),
    w2.cosignCheckpoint(sth),
    w3.cosignCheckpoint(sth),
  ]);
  const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, roster);
  const libVerdict = verifier.verifyCheckpointInCurrentEpoch({checkpoint: qc});
  if (libVerdict.kind !== 'FinalizedInEpoch') throw new Error('expected FinalizedInEpoch');
  return {kv, libVerdict};
}

describe('Phase 26 LeanPoo Dual-Sovereignty Bridge for cedar-poo-spec (10.174 / 30.05 AG136-AG140)', () => {
  test('AG136: Live Lean 4 / LeanPoo oracle verifies all 11 HostAuthorizationBridge theorems carry zero sorry/custom axioms & pins M1 cert', () => {
    const src = readFileSync(BRIDGE_LEAN_PATH, 'utf8');
    expect(auditLeanSourceAntiFabrication(src)).toEqual({passed: true, findings: []});

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
          namespacePrefix: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
          expectedTheorems: BRIDGE_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
      namespacePrefix: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
      expectedTheorems: BRIDGE_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(BRIDGE_THEOREMS.length);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG137: Dual-sovereignty symmetric refusal — Cedar Permit cannot bypass Library Refuted & Library Finalized cannot bypass Cedar Forbid/Pending', () => {
    const {kv, libVerdict} = buildVerifiedLibraryCheckpoint('log-dual-ag137');
    const opDigest = sha256Digest({op: 'deploy-release-140'});
    const polDigest = sha256Digest({policy: 'cedar-v1'});

    // Canonical Cedar Forbid-overrides-Permit & default-deny semantics:
    expect(
      evaluateHostPolicySemantics({permitMatched: true, forbidMatched: true, contextReady: true}),
    ).toBe('Forbid');
    expect(
      evaluateHostPolicySemantics({permitMatched: false, forbidMatched: false, contextReady: true}),
    ).toBe('Forbid');
    expect(
      evaluateHostPolicySemantics({permitMatched: true, forbidMatched: false, contextReady: false}),
    ).toBe('Pending');

    const permitReceipt: HostAuthorizationReceipt = {
      hostSystem: 'cedar-poo-spec',
      decision: 'Permit',
      boundOperationDigest: opDigest,
      policySnapshotDigest: polDigest,
      policyAffectedScopes: ['prod:deploy'],
      authorityLiveAtUse: true,
    };

    // 1. Host Cedar Permit CANNOT bypass Library Refuted (e.g., sub-quorum / slashed witness)!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: {kind: 'Refuted', reason: 'insufficient-unslashed-witness-quorum'},
        hostReceipt: permitReceipt,
        expectedOperationDigest: opDigest,
        activePolicySnapshotDigest: polDigest,
      }),
    ).toEqual({
      kind: 'Refuted',
      reason: 'library-verdict-refused',
      detail: 'insufficient-unslashed-witness-quorum',
    });

    // 2. Library Finalized CANNOT bypass Host Cedar Forbid!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: {...permitReceipt, decision: 'Forbid'},
        expectedOperationDigest: opDigest,
        activePolicySnapshotDigest: polDigest,
      }),
    ).toEqual({kind: 'Refuted', reason: 'host-policy-forbid'});

    // 3. Library Finalized CANNOT bypass unresolved Host Pending!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: {...permitReceipt, decision: 'Pending'},
        expectedOperationDigest: opDigest,
        activePolicySnapshotDigest: polDigest,
      }),
    ).toEqual({kind: 'Refuted', reason: 'host-policy-pending'});
  });

  test('AG138: BoundOperation anti-replay & PolicySnapshot drift fence (blocking intersecting drift, permitting R1 disjoint policy upgrade)', () => {
    const {kv, libVerdict} = buildVerifiedLibraryCheckpoint('log-dual-ag138');
    const opA = sha256Digest({op: 'deploy-staging'});
    const opB = sha256Digest({op: 'deploy-prod'});
    const polV1 = sha256Digest({policy: 'cedar-v1'});
    const polV2 = sha256Digest({policy: 'cedar-v2'});

    const receiptForOpA: HostAuthorizationReceipt = {
      hostSystem: 'cedar-poo-spec',
      decision: 'Permit',
      boundOperationDigest: opA,
      policySnapshotDigest: polV1,
      policyAffectedScopes: ['deploy:prod'],
      authorityLiveAtUse: true,
    };

    // 1. Cross-operation Permit replay (`opA` Permit replayed on `opB`) -> REFUSED!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: receiptForOpA,
        expectedOperationDigest: opB,
        activePolicySnapshotDigest: polV1,
      }),
    ).toEqual({kind: 'Refuted', reason: 'bound-operation-digest-mismatch'});

    // 2. Stale PolicySnapshot on intersecting changed scope (`deploy:prod`) -> REFUSED!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: {...receiptForOpA, boundOperationDigest: opB},
        expectedOperationDigest: opB,
        activePolicySnapshotDigest: polV2,
        policyChangedScopes: ['deploy:prod'],
      }),
    ).toEqual({kind: 'Refuted', reason: 'stale-policy-snapshot-digest'});

    // 3. R1 Disjoint Policy Co-Evolution (only unrelated `billing:read` Cedar policy changed) -> PROVEN!
    const r1Disjoint = evaluateDualSovereignGate({
      kv,
      libraryVerdict: libVerdict,
      hostReceipt: {...receiptForOpA, boundOperationDigest: opB},
      expectedOperationDigest: opB,
      activePolicySnapshotDigest: polV2,
      policyChangedScopes: ['billing:read'],
    });
    expect(r1Disjoint.kind).toBe('Proven');
  });

  test('AG139: AuthorityConsumption use-time M3 lease revocation TOCTOU fence & R3 non-leakage on host receipts', () => {
    const {kv, libVerdict} = buildVerifiedLibraryCheckpoint('log-dual-ag139');
    const opDigest = sha256Digest({op: 'wire-transfer'});
    const polDigest = sha256Digest({policy: 'cedar-fin-v1'});
    const staleLease = new LiveM3Capability('lease-fin-e1', 'fin:wire', 1);

    // 1. Stale M3 lease epoch (lease epoch 1 < active epoch 2) -> REFUSED at consumption time!
    expect(
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: {
          hostSystem: 'cedar-poo-spec',
          decision: 'Permit',
          boundOperationDigest: opDigest,
          policySnapshotDigest: polDigest,
          policyAffectedScopes: ['fin:wire'],
          liveAuthorityLease: staleLease,
          authorityLiveAtUse: true,
        },
        expectedOperationDigest: opDigest,
        activePolicySnapshotDigest: polDigest,
        activeLeaseEpoch: 2,
      }),
    ).toEqual({kind: 'Refuted', reason: 'authority-revoked-at-consumption'});

    // 2. Accidental reachability leak: burying LiveM3Capability inside host extraMetadata -> R3 REFUSED!
    expect(() =>
      evaluateDualSovereignGate({
        kv,
        libraryVerdict: libVerdict,
        hostReceipt: {
          hostSystem: 'cedar-poo-spec',
          decision: 'Permit',
          boundOperationDigest: opDigest,
          policySnapshotDigest: polDigest,
          policyAffectedScopes: ['fin:wire'],
          authorityLiveAtUse: true,
          extraMetadata: {leakedLease: staleLease},
        },
        expectedOperationDigest: opDigest,
        activePolicySnapshotDigest: polDigest,
      }),
    ).toThrow(/R3 ReachabilityLeakError/);
  });

  test('AG140: 140-Case Milestone — Clean B10/B10b/B10c Quorum Finality x cedar-poo-spec Dual-Sovereign Admission survives GC', () => {
    const {kv, libVerdict} = buildVerifiedLibraryCheckpoint('log-dual-milestone-140');
    const opDigest = sha256Digest({op: 'release-140', target: 'core'});
    const polDigest = sha256Digest({policy: 'cedar-poo-spec-v140'});
    const freshLease = new LiveM3Capability('lease-140', 'core:release', 5);

    const decision = evaluateHostPolicySemantics({
      permitMatched: true,
      forbidMatched: false,
      contextReady: true,
    });
    expect(decision).toBe('Permit');

    const verdict = evaluateDualSovereignGate({
      kv,
      libraryVerdict: libVerdict,
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision,
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['core:release'],
        liveAuthorityLease: freshLease,
        authorityLiveAtUse: true,
        extraMetadata: {cedarEvaluationEpoch: 5},
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 5,
    });

    expect(verdict.kind).toBe('Proven');
    if (verdict.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(verdict.dualSovereignReceiptHash)).toBe(true);
  });
});
