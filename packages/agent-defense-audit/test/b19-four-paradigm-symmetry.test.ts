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
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from '../src/transparency-log-equivocation.ts';
import {buildThresholdCheckpoint, WitnessCosigningKey} from '../src/witness-quorum-finality.ts';
import {
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  runLiveGerbilAscentMetaAudit,
  verifyReleaseWithIndependentAscentOracle,
} from '../src/ascent-meta-audit-bridge.ts';
import {
  GeoResidencySigningKey,
  verifyGeoResidencyPlacementOffline,
} from '../src/geo-residency-sovereignty.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from '../src/host-authorization-bridge.ts';
import {isLeanToolchainAvailable} from '../src/lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_TOP_FACADE_MODULE,
} from '../src/leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from '../src/leanpoo-fleet-audit.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from '../src/release-certificate-replay.ts';

describe('Phase 50 — Full B19 Four-Paradigm Symmetry: 28 Quint/MBT Models + 52x28 B1-B19 Gerbil ASCENT + 196-Theorem LeanPoo (10.198 / 30.05 AG261-AG265)', () => {
  test('AG261: Live 52x28 Gerbil Scheme ASCENT derives B19 geo_residency_violation for sanctioned target, LLM inference escape & invalid attestation while admitting intra-region local placement', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      geoAllowedRegions: ['eu-central-1', 'ch-zurich-1'],
      geoSanctionedRegions: ['sanctioned-x'],
      releaseGeoPlacements: [
        {
          releaseId: 'rel-geo-local-clean',
          sourceRegion: 'eu-central-1',
          targetRegion: 'eu-central-1',
          inferenceEndpointRegion: 'eu-central-1',
          attestationOk: true,
        },
        {
          releaseId: 'rel-geo-bad-target',
          sourceRegion: 'eu-central-1',
          targetRegion: 'sanctioned-x',
          inferenceEndpointRegion: 'eu-central-1',
          attestationOk: false,
        },
        {
          releaseId: 'rel-geo-inf-escape',
          sourceRegion: 'eu-central-1',
          targetRegion: 'eu-central-1',
          inferenceEndpointRegion: 'us-east-1',
          attestationOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-geo-local-clean',
          authorId: 'agent-261',
          approverId: 'human-261',
          logId: 'log-261',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-geo-bad-target',
          authorId: 'agent-261',
          approverId: 'human-261',
          logId: 'log-261',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-geo-inf-escape',
          authorId: 'agent-261',
          approverId: 'human-261',
          logId: 'log-261',
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

    expect(res.output.geo_residency_violation).toContainEqual([
      'rel-geo-bad-target',
      'sanctioned-x',
      'sanctioned-target-region',
    ]);
    expect(res.output.geo_residency_violation).toContainEqual([
      'rel-geo-bad-target',
      'sanctioned-x',
      'region-attestation-invalid',
    ]);
    expect(res.output.geo_residency_violation).toContainEqual([
      'rel-geo-inf-escape',
      'us-east-1',
      'inference-residency-escape',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-geo-bad-target',
      'geo-residency-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-geo-inf-escape',
      'geo-residency-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-geo-local-clean']]);
  }, 60_000);

  test('AG262: Live 52x28 Gerbil Scheme ASCENT derives B19 geo_cross_border_violation when crossing jurisdictions without valid permit while admitting permitted cross-border transfer', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      geoAllowedRegions: ['eu-central-1', 'ch-zurich-1'],
      releaseGeoPlacements: [
        {
          releaseId: 'rel-xb-permitted',
          sourceRegion: 'eu-central-1',
          targetRegion: 'ch-zurich-1',
          inferenceEndpointRegion: 'ch-zurich-1',
          attestationOk: true,
        },
        {
          releaseId: 'rel-xb-unpermitted',
          sourceRegion: 'eu-central-1',
          targetRegion: 'ch-zurich-1',
          inferenceEndpointRegion: 'ch-zurich-1',
          attestationOk: true,
        },
      ],
      geoTransferPermits: [
        {
          releaseId: 'rel-xb-permitted',
          sourceRegion: 'eu-central-1',
          targetRegion: 'ch-zurich-1',
          permitOk: true,
        },
        {
          releaseId: 'rel-xb-unpermitted',
          sourceRegion: 'eu-central-1',
          targetRegion: 'ch-zurich-1',
          permitOk: false,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-xb-permitted',
          authorId: 'agent-262',
          approverId: 'human-262',
          logId: 'log-262',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-xb-unpermitted',
          authorId: 'agent-262',
          approverId: 'human-262',
          logId: 'log-262',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.geo_cross_border_violation).toContainEqual([
      'rel-xb-unpermitted',
      'eu-central-1',
      'ch-zurich-1',
      'unapproved-cross-border-egress',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-xb-unpermitted',
      'unapproved-cross-border-egress',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-xb-permitted']]);
  }, 60_000);

  test('AG263: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on inference-escape & unpermitted cross-border egress releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      geoAllowedRegions: ['eu-central-1', 'ch-zurich-1'],
      releaseGeoPlacements: [
        {
          releaseId: 'rel-bug-inf-escape',
          sourceRegion: 'eu-central-1',
          targetRegion: 'eu-central-1',
          inferenceEndpointRegion: 'us-west-2',
          attestationOk: true,
        },
        {
          releaseId: 'rel-bug-xb-egress',
          sourceRegion: 'eu-central-1',
          targetRegion: 'ch-zurich-1',
          inferenceEndpointRegion: 'ch-zurich-1',
          attestationOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-bug-inf-escape',
          authorId: 'coder-263',
          approverId: 'human-263',
          logId: 'log-263',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-xb-egress',
          authorId: 'coder-263',
          approverId: 'human-263',
          logId: 'log-263',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateInf = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-inf-escape',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateInf.kind).toBe('Refuted');
    if (gateInf.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateInf.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateInf.ascentDisqualificationReasons).toContain('geo-residency-violation');

    const gateXb = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-xb-egress',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateXb.kind).toBe('Refuted');
    if (gateXb.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateXb.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateXb.ascentDisqualificationReasons).toContain('unapproved-cross-border-egress');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateInf.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateXb.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG264: Standalone 28-Quint x 52x28 ASCENT x 18-Module / 196-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(28);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('geo-residency-sovereignty');
    if (!isLeanToolchainAvailable()) return;

    const cliPath = resolve(import.meta.dir, '../src/leanpoo-fleet-audit.ts');
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

  test('AG265: 265-Case Full B1-B19 Four-Paradigm Symmetry Closure — Ed25519 Geo-Permit + 28 Quint x 52x28 ASCENT x 196-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B19 Ed25519 cross-border adequacy transfer attestation & permit:
    const euAuth = new GeoResidencySigningKey('eu-dpa-265', 'eu-central-1');
    const payloadDigestHex = sha256Digest({release: 'rel-265', phase: 50});
    const att = euAuth.attestRegionPlacement({
      tenantId: 'eu-sovereign-265',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      inferenceEndpointRegion: 'ch-zurich-1',
      payloadDigestHex,
      issuedAtEpoch: 50,
    });
    const permit = euAuth.issueCrossBorderTransferPermit({
      permitId: 'eu-ch-adequacy-265',
      legalBasis: 'adequacy-decision',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      payloadDigestHex,
      expiresAtEpoch: 65,
    });
    const geoCheck = verifyGeoResidencyPlacementOffline({
      attestation: JSON.parse(JSON.stringify(att)),
      transferPermit: JSON.parse(JSON.stringify(permit)),
      policy: {
        allowedRegions: ['eu-central-1', 'ch-zurich-1'],
        sanctionedRegions: ['sanctioned-x'],
        trustedAuthorityPublicKeys: {[euAuth.authorityId]: euAuth.publicKeyPem},
        revokedAuthorityIds: [],
        revokedPermitIds: [],
        currentEpoch: 50,
      },
      kv,
    });
    expect(geoCheck.kind).toBe('Proven');
    if (geoCheck.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 52x28 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-265');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-265', geoReceipt: geoCheck.pinnedReceiptHash});
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
      witnessRosters: [{logId: 'log-265', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-265', checkpoint: qc}],
      geoAllowedRegions: ['eu-central-1', 'ch-zurich-1'],
      geoSanctionedRegions: ['sanctioned-x'],
      releaseGeoPlacements: [
        {
          releaseId: 'rel-265',
          sourceRegion: att.sourceRegion,
          targetRegion: att.targetRegion,
          inferenceEndpointRegion: att.inferenceEndpointRegion,
          attestationOk: true,
        },
      ],
      geoTransferPermits: [
        {
          releaseId: 'rel-265',
          sourceRegion: permit.sourceRegion,
          targetRegion: permit.targetRegion,
          permitOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-265',
          authorId: 'coder-265',
          approverId: 'human-265',
          logId: 'log-265',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-265',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-265',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 28-Quint x 18-Module / 196-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 265, quint: 28, modules: 18, theorems: 196});

    const publisher = new LibraryReleaseSigningKey('pub-265');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v50-28quint-196thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 50,
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
        minAllowedEpoch: 50,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-265', 'release:b1-b19-full', 50);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v50'}),
        policyAffectedScopes: ['release:b1-b19-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v50'}),
      activeLeaseEpoch: 50,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(geoCheck.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
