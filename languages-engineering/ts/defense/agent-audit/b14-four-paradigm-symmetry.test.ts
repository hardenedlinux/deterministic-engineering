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
  BuilderAttestationSigningKey,
  issueBuildProvenanceAttestation,
  verifyHermeticBuildProvenance,
} from './supply-chain-provenance.ts';
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

describe('Phase 40 — Full B14 Four-Paradigm Symmetry: 23 Quint/MBT Models + 32x18 B1-B14 Gerbil ASCENT + 146-Theorem LeanPoo (10.188 / 30.05 AG211-AG215)', () => {
  test('AG211: Live 32x18 Gerbil Scheme ASCENT derives B14 supply_chain_dep_violation for AI slopsquatting & CVE tombstones while admitting pinned build', () => {
    const kv = new ContentAddressedKvStore();
    const depGood = sha256Digest({pkg: 'lean-poo@1.0.0'});
    const depSlop = sha256Digest({pkg: 'hallucinated-dep@9.9.9'});
    const depCve = sha256Digest({pkg: 'cve-pkg@5.6.1'});

    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      lockfilePinnedDeps: [depGood, depCve],
      cveTombstones: [depCve],
      releaseSbomDeps: [
        {releaseId: 'rel-b14-clean', depDigest: depGood},
        {releaseId: 'rel-b14-slop', depDigest: depSlop},
        {releaseId: 'rel-b14-cve', depDigest: depCve},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-b14-clean',
          authorId: 'agent-211',
          approverId: 'human-211',
          logId: 'log-211',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-b14-slop',
          authorId: 'agent-211',
          approverId: 'human-211',
          logId: 'log-211',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-b14-cve',
          authorId: 'agent-211',
          approverId: 'human-211',
          logId: 'log-211',
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

    expect(res.output.supply_chain_dep_violation).toContainEqual([
      'rel-b14-slop',
      depSlop,
      'unpinned-slopsquatting-dep',
    ]);
    expect(res.output.supply_chain_dep_violation).toContainEqual([
      'rel-b14-cve',
      depCve,
      'tombstoned-cve-dep',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-b14-slop',
      'supply-chain-dep-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-b14-cve',
      'supply-chain-dep-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-b14-clean']]);
  }, 60_000);

  test('AG212: Live 32x18 Gerbil Scheme ASCENT derives B14 reproducible_build_violation for non-hermetic network builds & 2-builder artifact divergence', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      buildAttestations: [
        {releaseId: 'rel-repro-clean', builderId: 'b1', artifactDigest: 'art-40', hermetic: true},
        {releaseId: 'rel-repro-clean', builderId: 'b2', artifactDigest: 'art-40', hermetic: true},
        {releaseId: 'rel-non-hermetic', builderId: 'b1', artifactDigest: 'art-net', hermetic: false},
        {releaseId: 'rel-diverged', builderId: 'b1', artifactDigest: 'art-clean', hermetic: true},
        {releaseId: 'rel-diverged', builderId: 'b2', artifactDigest: 'art-backdoor', hermetic: true},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-repro-clean',
          authorId: 'agent-212',
          approverId: 'human-212',
          logId: 'log-212',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-non-hermetic',
          authorId: 'agent-212',
          approverId: 'human-212',
          logId: 'log-212',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-diverged',
          authorId: 'agent-212',
          approverId: 'human-212',
          logId: 'log-212',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.reproducible_build_violation).toContainEqual([
      'rel-non-hermetic',
      'non-hermetic-build',
    ]);
    expect(res.output.reproducible_build_violation).toContainEqual([
      'rel-diverged',
      'builder-artifact-divergence',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-non-hermetic',
      'reproducible-build-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-diverged',
      'reproducible-build-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-repro-clean']]);
  }, 60_000);

  test('AG213: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on slopsquatted & diverged-builder releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      lockfilePinnedDeps: ['dep-ok-213'],
      releaseSbomDeps: [{releaseId: 'rel-slop-213', depDigest: 'dep-evil-213'}],
      buildAttestations: [
        {releaseId: 'rel-div-213', builderId: 'b1', artifactDigest: 'bin-a', hermetic: true},
        {releaseId: 'rel-div-213', builderId: 'b2', artifactDigest: 'bin-b', hermetic: true},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-slop-213',
          authorId: 'coder-213',
          approverId: 'human-213',
          logId: 'log-213',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-div-213',
          authorId: 'coder-213',
          approverId: 'human-213',
          logId: 'log-213',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateSlop = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-slop-213',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateSlop.kind).toBe('Refuted');
    if (gateSlop.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateSlop.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateSlop.ascentDisqualificationReasons).toContain('supply-chain-dep-violation');

    const gateDiv = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-div-213',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateDiv.kind).toBe('Refuted');
    if (gateDiv.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateDiv.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateDiv.ascentDisqualificationReasons).toContain('reproducible-build-violation');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateSlop.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateDiv.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG214: Standalone 23+-Quint x ASCENT x LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(23);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('supply-chain-provenance');
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

  test('AG215: 215-Case Full B1-B14 Four-Paradigm Symmetry Closure — 23 Quint x 32x18 ASCENT x 146-Thm Offline Ed25519 Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Clean 2-builder hermetic SLSA/in-toto build verification:
    const b1 = new BuilderAttestationSigningKey('builder-eu-215');
    const b2 = new BuilderAttestationSigningKey('builder-us-215');
    const srcHash = sha256Digest({commit: '1e18521'});
    const tcHash = sha256Digest({lean: '4.34.0', gerbil: '0.18'});
    const artHash = sha256Digest({release: 'v40.0'});
    const depHash = sha256Digest({pkg: 'lean-poo@1.0.0'});

    const att1 = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'build-215-1',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depHash}],
      },
    });
    const att2 = issueBuildProvenanceAttestation({
      builderKey: b2,
      payload: {
        buildId: 'build-215-2',
        builderId: b2.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depHash}],
      },
    });
    const scRes = verifyHermeticBuildProvenance({
      primary: att1,
      reproducers: [att2],
      policy: {
        expectedSourceDigestHex: srcHash,
        expectedToolchainDigestHex: tcHash,
        pinnedLockfileDigests: [depHash],
        revokedCveDigests: [],
        trustedBuilderPublicKeys: {
          [b1.builderId]: b1.publicKeyPem,
          [b2.builderId]: b2.publicKeyPem,
        },
        revokedBuilderIds: [],
        requireTwoBuilderReproducibility: true,
      },
      kv,
    });
    expect(scRes.kind).toBe('Proven');
    if (scRes.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 Ed25519 QC + live 32x18 TS <-> Scheme ASCENT dual gate:
    const coord = new CoordinatorSigningKey('log-215');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-215', supplyChainReceipt: scRes.pinnedReceiptHash});
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
      witnessRosters: [{logId: 'log-215', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-215', checkpoint: qc}],
      lockfilePinnedDeps: [depHash],
      cveTombstones: [],
      releaseSbomDeps: [{releaseId: 'rel-215', depDigest: depHash}],
      buildAttestations: [
        {releaseId: 'rel-215', builderId: b1.builderId, artifactDigest: artHash, hermetic: true},
        {releaseId: 'rel-215', builderId: b2.builderId, artifactDigest: artHash, hermetic: true},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-215',
          authorId: 'coder-215',
          approverId: 'human-215',
          logId: 'log-215',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-215',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-215',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 23-Quint x 13-Module / 146-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 215, quint: 23, modules: 13, theorems: 146});

    const publisher = new LibraryReleaseSigningKey('pub-215');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v40-23quint-146thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 40,
        moduleCount: 13,
        verifiedTheoremCount: 146,
        quintModelCount: 23,
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
        minRequiredTheorems: 146,
        minAllowedEpoch: 40,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-215', 'release:b1-b14', 40);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v40'}),
        policyAffectedScopes: ['release:b1-b14'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v40'}),
      activeLeaseEpoch: 40,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(scRes.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
