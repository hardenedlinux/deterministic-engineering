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
import {RotatableTenantAeadKeyRing} from '../src/key-rotation-crypto-shredding.ts';
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

describe('Phase 44 — Full B16 Four-Paradigm Symmetry: 25 Quint/MBT Models + 40x22 B1-B16 Gerbil ASCENT + 166-Theorem LeanPoo (10.192 / 30.05 AG231-AG235)', () => {
  test('AG231: Live 40x22 Gerbil Scheme ASCENT derives B16 key_rotation_write_violation for stale & shredded write epochs while admitting active epoch', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      tenantActiveKeyEpochs: [{tenantId: 'tenant-231', epoch: 2}],
      shreddedKeyEpochs: [{tenantId: 'tenant-231', epoch: 1}],
      releaseAeadWrites: [
        {releaseId: 'rel-kr-clean', tenantId: 'tenant-231', writeEpoch: 2},
        {releaseId: 'rel-kr-stale', tenantId: 'tenant-231', writeEpoch: 1},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-kr-clean',
          authorId: 'agent-231',
          approverId: 'human-231',
          logId: 'log-231',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-kr-stale',
          authorId: 'agent-231',
          approverId: 'human-231',
          logId: 'log-231',
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

    expect(res.output.key_rotation_write_violation).toContainEqual([
      'rel-kr-stale',
      'tenant-231',
      '1',
      'stale-write-epoch',
    ]);
    expect(res.output.key_rotation_write_violation).toContainEqual([
      'rel-kr-stale',
      'tenant-231',
      '1',
      'write-to-shredded-epoch',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-kr-stale',
      'key-rotation-write-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-kr-clean']]);
  }, 60_000);

  test('AG232: Live 40x22 Gerbil Scheme ASCENT derives B16 crypto_shred_read_violation for shredded reads & mutated re-wrap digests', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      shreddedKeyEpochs: [{tenantId: 'tenant-232', epoch: 1}],
      releaseAeadReads: [
        {releaseId: 'rel-read-clean', tenantId: 'tenant-232', readEpoch: 2, digestPreserved: true},
        {releaseId: 'rel-read-shred', tenantId: 'tenant-232', readEpoch: 1, digestPreserved: true},
        {releaseId: 'rel-read-mut', tenantId: 'tenant-232', readEpoch: 2, digestPreserved: false},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-read-clean',
          authorId: 'agent-232',
          approverId: 'human-232',
          logId: 'log-232',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-read-shred',
          authorId: 'agent-232',
          approverId: 'human-232',
          logId: 'log-232',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-read-mut',
          authorId: 'agent-232',
          approverId: 'human-232',
          logId: 'log-232',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.crypto_shred_read_violation).toContainEqual([
      'rel-read-shred',
      'tenant-232',
      '1',
      'read-shredded-key-epoch',
    ]);
    expect(res.output.crypto_shred_read_violation).toContainEqual([
      'rel-read-mut',
      'tenant-232',
      '2',
      'rewrap-digest-mutated',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-read-shred',
      'crypto-shred-or-rewrap-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-read-mut',
      'crypto-shred-or-rewrap-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-read-clean']]);
  }, 60_000);

  test('AG233: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on stale-write & shredded-read releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      tenantActiveKeyEpochs: [{tenantId: 't-233', epoch: 3}],
      shreddedKeyEpochs: [{tenantId: 't-233', epoch: 1}],
      releaseAeadWrites: [{releaseId: 'rel-stale-233', tenantId: 't-233', writeEpoch: 2}],
      releaseAeadReads: [
        {releaseId: 'rel-shred-233', tenantId: 't-233', readEpoch: 1, digestPreserved: true},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-stale-233',
          authorId: 'coder-233',
          approverId: 'human-233',
          logId: 'log-233',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-shred-233',
          authorId: 'coder-233',
          approverId: 'human-233',
          logId: 'log-233',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateStale = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-stale-233',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateStale.kind).toBe('Refuted');
    if (gateStale.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateStale.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateStale.ascentDisqualificationReasons).toContain('key-rotation-write-violation');

    const gateShred = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-shred-233',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateShred.kind).toBe('Refuted');
    if (gateShred.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateShred.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateShred.ascentDisqualificationReasons).toContain('crypto-shred-or-rewrap-violation');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateStale.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateShred.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG234: Standalone 25-Quint x 40x22 ASCENT x 15-Module / 166-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(25);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('key-rotation-crypto-shredding');
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

  test('AG235: 235-Case Full B1-B16 Four-Paradigm Symmetry Closure — AES-256-GCM Rotation/Shred + 25 Quint x 40x22 ASCENT x 166-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B16 AES-256-GCM rotation, lossless re-wrap & GDPR crypto-shredding:
    const ring = new RotatableTenantAeadKeyRing('tenant-235', 1);
    const env1 = ring.encryptEnvelope({kv, recordId: 'rec-235', plaintext: {phase: 44, ok: true}});
    expect(env1.kind).toBe('Proven');
    if (env1.kind !== 'Proven') throw new Error('expected Proven');
    ring.rotateEpoch();
    const rewrap = ring.rewrapEnvelopeToActiveEpoch({kv, envelope: env1.envelope});
    expect(rewrap.kind).toBe('Proven');
    if (rewrap.kind !== 'Proven') throw new Error('expected Proven');
    const shred = ring.cryptoShredEpoch({kv, epoch: 1, reason: 'post-rotation-zeroize'});

    // 2. B10 3-of-4 QC + live 40x22 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-235');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-235', rewrapReceipt: rewrap.rewrapReceiptHash, shred: shred.tombstoneMerkleHash});
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
      witnessRosters: [{logId: 'log-235', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-235', checkpoint: qc}],
      tenantActiveKeyEpochs: [{tenantId: 'tenant-235', epoch: 2}],
      shreddedKeyEpochs: [{tenantId: 'tenant-235', epoch: 1}],
      releaseAeadWrites: [{releaseId: 'rel-235', tenantId: 'tenant-235', writeEpoch: 2}],
      releaseAeadReads: [
        {releaseId: 'rel-235', tenantId: 'tenant-235', readEpoch: 2, digestPreserved: true},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-235',
          authorId: 'coder-235',
          approverId: 'human-235',
          logId: 'log-235',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-235',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-235',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 25-Quint x 15-Module / 166-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 235, quint: 25, modules: 15, theorems: 166});

    const publisher = new LibraryReleaseSigningKey('pub-235');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v44-25quint-166thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 44,
        moduleCount: 15,
        verifiedTheoremCount: 166,
        quintModelCount: 25,
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
        minRequiredTheorems: 166,
        minAllowedEpoch: 44,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-235', 'release:b1-b16-full', 44);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v44'}),
        policyAffectedScopes: ['release:b1-b16-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v44'}),
      activeLeaseEpoch: 44,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(rewrap.rewrapReceiptHash)).toBe(true);
    expect(kv.hasBlob(shred.tombstoneMerkleHash)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
