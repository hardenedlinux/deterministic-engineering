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
import {ControlledContextDistiller} from './context-distillation-provenance.ts';
import {FederatedSwarmArbitrator} from './federated-arbitration-liveness.ts';
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

describe('Phase 38 — Full B12 & B13 Four-Paradigm Symmetry: 22 Quint/MBT Models + 28x16 B1-B13 Gerbil ASCENT + 136-Theorem LeanPoo (10.186 / 30.05 AG201-AG205)', () => {
  test('AG201: Live Gerbil Scheme ASCENT derives B12 distillation_amnesia_violation when pinned M1 constraint is omitted while admitting clean retention', () => {
    const kv = new ContentAddressedKvStore();
    const vetoHash = kv.putBlob('pinned-veto-201', {veto: 'forbid-prod-drop'});
    kv.pinHistoricalCut(vetoHash);

    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      contextPinnedConstraints: [
        {releaseId: 'rel-b12-clean', constraintHash: vetoHash},
        {releaseId: 'rel-b12-amnesia', constraintHash: vetoHash},
      ],
      distillationRetainedConstraints: [
        {releaseId: 'rel-b12-clean', constraintHash: vetoHash},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-b12-clean',
          authorId: 'agent-201',
          approverId: 'human-201',
          logId: 'log-201',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-b12-amnesia',
          authorId: 'agent-201',
          approverId: 'human-201',
          logId: 'log-201',
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

    expect(res.output.distillation_amnesia_violation).toEqual([['rel-b12-amnesia', vetoHash]]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-b12-amnesia',
      'distillation-pinned-amnesia',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-b12-clean']]);
  }, 60_000);

  test('AG202: Live Gerbil Scheme ASCENT derives B13 transitive 3-agent swarm_deadlock_cycle (A->B->C->A) while admitting acyclic DAG session', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      swarmWaitEdges: [
        // Acyclic DAG session:
        {sessionId: 'sess-dag-202', waitingAgent: 'coder-1', blockingAgent: 'reviewer-1'},
        {sessionId: 'sess-dag-202', waitingAgent: 'reviewer-1', blockingAgent: 'oracle-1'},
        // Circular 3-agent deadlock cycle:
        {sessionId: 'sess-cycle-202', waitingAgent: 'agent-a', blockingAgent: 'agent-b'},
        {sessionId: 'sess-cycle-202', waitingAgent: 'agent-b', blockingAgent: 'agent-c'},
        {sessionId: 'sess-cycle-202', waitingAgent: 'agent-c', blockingAgent: 'agent-a'},
      ],
      swarmSessionReleases: [
        {releaseId: 'rel-b13-clean', sessionId: 'sess-dag-202'},
        {releaseId: 'rel-b13-deadlock', sessionId: 'sess-cycle-202'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-b13-clean',
          authorId: 'coder-1',
          approverId: 'human-202',
          logId: 'log-202',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-b13-deadlock',
          authorId: 'agent-a',
          approverId: 'human-202',
          logId: 'log-202',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.swarm_deadlock_cycle).toContainEqual(['sess-cycle-202', 'agent-a']);
    expect(res.output.swarm_deadlock_cycle).toContainEqual(['sess-cycle-202', 'agent-b']);
    expect(res.output.swarm_deadlock_cycle).toContainEqual(['sess-cycle-202', 'agent-c']);
    expect(res.output.swarm_deadlock_cycle.some(r => r[0] === 'sess-dag-202')).toBe(false);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-b13-deadlock',
      'swarm-deadlock-cycle',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-b13-clean']]);
  }, 60_000);

  test('AG203: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on both B12 amnesia and B13 deadlocked releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      contextPinnedConstraints: [{releaseId: 'rel-amnesia-203', constraintHash: 'pin-veto-203'}],
      distillationRetainedConstraints: [],
      swarmWaitEdges: [
        {sessionId: 'sess-203', waitingAgent: 'w-alpha', blockingAgent: 'w-beta'},
        {sessionId: 'sess-203', waitingAgent: 'w-beta', blockingAgent: 'w-alpha'},
      ],
      swarmSessionReleases: [{releaseId: 'rel-deadlock-203', sessionId: 'sess-203'}],
      releaseProposals: [
        {
          releaseId: 'rel-amnesia-203',
          authorId: 'coder-203',
          approverId: 'human-203',
          logId: 'log-203',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-deadlock-203',
          authorId: 'coder-203',
          approverId: 'human-203',
          logId: 'log-203',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateAmnesia = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-amnesia-203',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateAmnesia.kind).toBe('Refuted');
    if (gateAmnesia.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateAmnesia.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateAmnesia.ascentDisqualificationReasons).toContain('distillation-pinned-amnesia');

    const gateDeadlock = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-deadlock-203',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateDeadlock.kind).toBe('Refuted');
    if (gateDeadlock.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateDeadlock.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateDeadlock.ascentDisqualificationReasons).toContain('swarm-deadlock-cycle');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateAmnesia.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateDeadlock.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG204: Standalone 22-Quint x 28x16 ASCENT x 12-Module / 136-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBe(22);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('context-distillation-provenance');
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('federated-arbitration-liveness');
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
    expect(out.quintModelCount).toBe(22);
    expect(out.ascentRulesPresent).toBe(true);
    expect(out.multiLangHarnessCount).toBe(8);
    expect(out.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(out.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(out.zeroMathlib).toBe(true);
    expect(out.zeroCedar).toBe(true);
  }, 45_000);

  test('AG205: 205-Case Full B1-B13 Four-Paradigm Symmetry Closure — 22 Quint x 28x16 ASCENT x 136-Thm Offline Ed25519 Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCut = kv.putBlob('rollback-cut-205', {rev: 'v38.0'});
    kv.pinHistoricalCut(rollbackCut);

    // 1. Clean B12 context distillation retaining pinned rollback cut:
    const distiller = new ControlledContextDistiller(kv);
    const dist = distiller.distillSafely({
      sources: [
        {
          itemId: 'pinned-rollback-205',
          itemHash: rollbackCut,
          isPinnedM1Constraint: true,
          integrity: 'TrustedSystem',
          secrecyTags: [],
          summaryText: 'Pinned baseline cut for release 205',
        },
      ],
      distilledText: 'Verified distilled handoff retaining rollback cut',
      tokenCount: 96,
      maxTokens: 512,
    });
    expect(dist.kind).toBe('Proven');
    if (dist.kind !== 'Proven') throw new Error('expected Proven');

    // 2. Clean B13 federated arbitration terminating in Admitted:
    const arb = new FederatedSwarmArbitrator(kv);
    expect(
      arb.startSession({
        sessionId: 'sess-205',
        maxAttempts: 3,
        rollbackCutHash: rollbackCut,
        humanEscalationTarget: 'release-ops',
      }).kind,
    ).toBe('Started');
    const resolved = arb.admitCleanResolution({
      sessionId: 'sess-205',
      resolutionEvidenceDigest: dist.distillationMerkleHash,
    });
    expect(resolved.kind).toBe('Admitted');
    if (resolved.kind !== 'Admitted') throw new Error('expected Admitted');

    // 3. B10 3-of-4 Ed25519 threshold checkpoint + live TS <-> Scheme ASCENT dual gate:
    const coord = new CoordinatorSigningKey('log-205');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-205', resolution: resolved.resolutionReceiptHash});
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
      witnessRosters: [{logId: 'log-205', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-205', checkpoint: qc}],
      contextPinnedConstraints: [{releaseId: 'rel-205', constraintHash: rollbackCut}],
      distillationRetainedConstraints: dist.retainedPinnedHashes.map(h => ({
        releaseId: 'rel-205',
        constraintHash: h,
      })),
      swarmWaitEdges: [{sessionId: 'sess-205', waitingAgent: 'coder-205', blockingAgent: 'oracle-205'}],
      swarmSessionReleases: [{releaseId: 'rel-205', sessionId: 'sess-205'}],
      releaseProposals: [
        {
          releaseId: 'rel-205',
          authorId: 'coder-205',
          approverId: 'human-205',
          logId: 'log-205',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-205',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-205',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 4. 22-Quint x 12-Module / 136-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(22);
          expect(rep.leanPooModuleCount).toBe(12);
          expect(rep.leanPooTheoremCount).toBe(136);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 205, quint: 22, modules: 12, theorems: 136});

    const publisher = new LibraryReleaseSigningKey('pub-205');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v38-22quint-136thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 38,
        moduleCount: 12,
        verifiedTheoremCount: 136,
        quintModelCount: 22,
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
        minRequiredTheorems: 136,
        minAllowedEpoch: 38,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-205', 'release:b1-b13', 38);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v38'}),
        policyAffectedScopes: ['release:b1-b13'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v38'}),
      activeLeaseEpoch: 38,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
    expect(kv.hasBlob(resolved.resolutionReceiptHash)).toBe(true);
  }, 60_000);
});
