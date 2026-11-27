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
  HybridPqSigningKey,
  verifyHybridPqSignatureOffline,
  type CryptoSuiteId,
} from './post-quantum-crypto-agility.ts';
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

const PQ_HYBRID_SUITE_ID: CryptoSuiteId = 'hybrid-ed25519-lamport-sha256-v1';

describe('Phase 46 — Full B17 Four-Paradigm Symmetry: 26 Quint/MBT Models + 44x24 B1-B17 Gerbil ASCENT + 176-Theorem LeanPoo (10.194 / 30.05 AG241-AG245)', () => {
  test('AG241: Live 44x24 Gerbil Scheme ASCENT derives B17 pq_agility_violation for downgrade, deprecated suite, single-leg failure & domain mismatch while admitting clean hybrid envelope', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      pqAllowedSuites: [PQ_HYBRID_SUITE_ID],
      pqDeprecatedSuites: ['legacy-sha1'],
      releasePqEnvelopes: [
        {
          releaseId: 'rel-pq-clean',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-pq-downgrade',
          suiteId: 'classical-ed25519',
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-pq-deprecated',
          suiteId: 'legacy-sha1',
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-pq-legs',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: false,
          pqOk: false,
          domainOk: false,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-pq-clean',
          authorId: 'agent-241',
          approverId: 'human-241',
          logId: 'log-241',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-pq-downgrade',
          authorId: 'agent-241',
          approverId: 'human-241',
          logId: 'log-241',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-pq-deprecated',
          authorId: 'agent-241',
          approverId: 'human-241',
          logId: 'log-241',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-pq-legs',
          authorId: 'agent-241',
          approverId: 'human-241',
          logId: 'log-241',
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

    expect(res.output.pq_agility_violation).toContainEqual([
      'rel-pq-downgrade',
      'classical-ed25519',
      'algorithm-downgrade-refused',
    ]);
    expect(res.output.pq_agility_violation).toContainEqual([
      'rel-pq-deprecated',
      'legacy-sha1',
      'deprecated-suite-refused',
    ]);
    expect(res.output.pq_agility_violation).toContainEqual([
      'rel-pq-legs',
      PQ_HYBRID_SUITE_ID,
      'classical-leg-failed',
    ]);
    expect(res.output.pq_agility_violation).toContainEqual([
      'rel-pq-legs',
      PQ_HYBRID_SUITE_ID,
      'pq-leg-failed',
    ]);
    expect(res.output.pq_agility_violation).toContainEqual([
      'rel-pq-legs',
      PQ_HYBRID_SUITE_ID,
      'domain-separation-mismatch',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-pq-downgrade',
      'pq-hybrid-agility-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-pq-deprecated',
      'pq-hybrid-agility-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-pq-legs',
      'pq-hybrid-agility-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-pq-clean']]);
  }, 60_000);

  test('AG242: Live 44x24 Gerbil Scheme ASCENT derives B17 pq_ots_reuse_violation across distinct releases sharing an OTS leaf while admitting fresh leaves', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      pqAllowedSuites: [PQ_HYBRID_SUITE_ID],
      releasePqEnvelopes: [
        {
          releaseId: 'rel-ots-clean',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-ots-dup-a',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-ots-dup-b',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
      ],
      pqOtsLeafUses: [
        {releaseId: 'rel-ots-clean', signerId: 'pq-signer-242', leafIndex: 0},
        {releaseId: 'rel-ots-dup-a', signerId: 'pq-signer-242', leafIndex: 5},
        {releaseId: 'rel-ots-dup-b', signerId: 'pq-signer-242', leafIndex: 5},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-ots-clean',
          authorId: 'agent-242',
          approverId: 'human-242',
          logId: 'log-242',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-ots-dup-a',
          authorId: 'agent-242',
          approverId: 'human-242',
          logId: 'log-242',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-ots-dup-b',
          authorId: 'agent-242',
          approverId: 'human-242',
          logId: 'log-242',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.pq_ots_reuse_violation).toContainEqual([
      'rel-ots-dup-a',
      'rel-ots-dup-b',
      'pq-signer-242',
      '5',
    ]);
    expect(res.output.release_disqualified).toContainEqual(['rel-ots-dup-a', 'pq-ots-leaf-reuse']);
    expect(res.output.release_disqualified).toContainEqual(['rel-ots-dup-b', 'pq-ots-leaf-reuse']);
    expect(res.output.release_admitted).toEqual([['rel-ots-clean']]);
  }, 60_000);

  test('AG243: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on PQ downgrade & OTS leaf reuse releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      pqAllowedSuites: [PQ_HYBRID_SUITE_ID],
      releasePqEnvelopes: [
        {
          releaseId: 'rel-bug-downgrade',
          suiteId: 'classical-ed25519',
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-bug-ots-1',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
        {
          releaseId: 'rel-bug-ots-2',
          suiteId: PQ_HYBRID_SUITE_ID,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
      ],
      pqOtsLeafUses: [
        {releaseId: 'rel-bug-ots-1', signerId: 'pq-signer-243', leafIndex: 3},
        {releaseId: 'rel-bug-ots-2', signerId: 'pq-signer-243', leafIndex: 3},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-bug-downgrade',
          authorId: 'coder-243',
          approverId: 'human-243',
          logId: 'log-243',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-ots-1',
          authorId: 'coder-243',
          approverId: 'human-243',
          logId: 'log-243',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-ots-2',
          authorId: 'coder-243',
          approverId: 'human-243',
          logId: 'log-243',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateDowngrade = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-downgrade',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateDowngrade.kind).toBe('Refuted');
    if (gateDowngrade.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateDowngrade.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateDowngrade.ascentDisqualificationReasons).toContain('pq-hybrid-agility-violation');

    const gateOts = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-ots-2',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateOts.kind).toBe('Refuted');
    if (gateOts.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateOts.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateOts.ascentDisqualificationReasons).toContain('pq-ots-leaf-reuse');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateDowngrade.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateOts.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG244: Standalone 26-Quint x 44x24 ASCENT x 16-Module / 176-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(26);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('post-quantum-crypto-agility');
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

  test('AG245: 245-Case Full B1-B17 Four-Paradigm Symmetry Closure — Dual-AND Ed25519+Lamport OTS + 26 Quint x 44x24 ASCENT x 176-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B17 Dual-AND Ed25519 + Lamport-Diffie OTS Merkle signing & offline verification:
    const pqKey = new HybridPqSigningKey('pq-pub-245', 4);
    const releasePayloadDigest = sha256Digest({
      releaseId: 'rel-245',
      phase: 46,
      quintModels: 26,
      theorems: 176,
    });
    const pqEnv = pqKey.signHybridDigest({
      domainTag: 'de-qnt:b17-symmetry:v46',
      payloadDigestHex: releasePayloadDigest,
    });
    const pqCheck = verifyHybridPqSignatureOffline({
      envelope: pqEnv,
      policy: {
        minRequiredSuiteLevel: 2,
        deprecatedSuites: ['legacy-sha1'],
        expectedDomainTag: 'de-qnt:b17-symmetry:v46',
        trustedSigners: {[pqKey.signerId]: pqKey.exportPublicBundle()},
        usedOtsLeafIndicesBySigner: {},
      },
      kv,
    });
    expect(pqCheck.kind).toBe('Proven');
    if (pqCheck.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 44x24 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-245');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-245', pqReceipt: pqCheck.pinnedReceiptHash});
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
      witnessRosters: [{logId: 'log-245', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-245', checkpoint: qc}],
      pqAllowedSuites: [PQ_HYBRID_SUITE_ID],
      pqDeprecatedSuites: ['legacy-sha1'],
      releasePqEnvelopes: [
        {
          releaseId: 'rel-245',
          suiteId: pqEnv.suiteId,
          classicalOk: true,
          pqOk: true,
          domainOk: true,
        },
      ],
      pqOtsLeafUses: [{releaseId: 'rel-245', signerId: pqEnv.signerId, leafIndex: pqEnv.otsLeafIndex}],
      releaseProposals: [
        {
          releaseId: 'rel-245',
          authorId: 'coder-245',
          approverId: 'human-245',
          logId: 'log-245',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-245',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-245',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 26-Quint x 16-Module / 176-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 245, quint: 26, modules: 16, theorems: 176});

    const publisher = new LibraryReleaseSigningKey('pub-245');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v46-26quint-176thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 46,
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
        minAllowedEpoch: 46,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-245', 'release:b1-b17-full', 46);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v46'}),
        policyAffectedScopes: ['release:b1-b17-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v46'}),
      activeLeaseEpoch: 46,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(pqCheck.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
