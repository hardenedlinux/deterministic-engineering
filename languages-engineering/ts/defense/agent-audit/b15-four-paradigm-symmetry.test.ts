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
  EnclaveRootAttestationKey,
  issueHardwareEnclaveQuote,
  verifyEnclaveQuoteForKeyRelease,
} from './confidential-enclave-attestation.ts';
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

describe('Phase 42 — Full B15 Four-Paradigm Symmetry: 24 Quint/MBT Models + 36x20 B1-B15 Gerbil ASCENT + 156-Theorem LeanPoo (10.190 / 30.05 AG221-AG225)', () => {
  test('AG221: Live 36x20 Gerbil Scheme ASCENT derives B15 enclave_attestation_violation for debug enclave, TCB rollback, revoked platform & measurement mismatch', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      expectedEnclaveMeasurements: [
        {releaseId: 'rel-tee-clean', artifactDigest: 'art-42'},
        {releaseId: 'rel-tee-bad', artifactDigest: 'art-42'},
      ],
      enclaveQuotes: [
        {
          releaseId: 'rel-tee-clean',
          platformId: 'tdx-prod-1',
          measuredDigest: 'art-42',
          debugDisabled: true,
          tcbOk: true,
        },
        {
          releaseId: 'rel-tee-bad',
          platformId: 'tdx-revoked-9',
          measuredDigest: 'art-trojan',
          debugDisabled: false,
          tcbOk: false,
        },
      ],
      revokedTeePlatforms: ['tdx-revoked-9'],
      releaseProposals: [
        {
          releaseId: 'rel-tee-clean',
          authorId: 'agent-221',
          approverId: 'human-221',
          logId: 'log-221',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-tee-bad',
          authorId: 'agent-221',
          approverId: 'human-221',
          logId: 'log-221',
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

    expect(res.output.enclave_attestation_violation).toContainEqual([
      'rel-tee-bad',
      'debug-enclave-forbidden',
    ]);
    expect(res.output.enclave_attestation_violation).toContainEqual([
      'rel-tee-bad',
      'tcb-svn-rollback',
    ]);
    expect(res.output.enclave_attestation_violation).toContainEqual([
      'rel-tee-bad',
      'revoked-tee-platform',
    ]);
    expect(res.output.enclave_attestation_violation).toContainEqual([
      'rel-tee-bad',
      'enclave-measurement-mismatch',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-tee-bad',
      'enclave-attestation-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-tee-clean']]);
  }, 60_000);

  test('AG222: Live 36x20 Gerbil Scheme ASCENT derives B15 cross-release enclave_nonce_replay_violation via pure relational inequality', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      teeQuoteNonces: [
        {releaseId: 'rel-fresh-222', nonce: 'nonce-unique-222'},
        {releaseId: 'rel-replay-a', nonce: 'nonce-reused-222'},
        {releaseId: 'rel-replay-b', nonce: 'nonce-reused-222'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-fresh-222',
          authorId: 'agent-222',
          approverId: 'human-222',
          logId: 'log-222',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-replay-a',
          authorId: 'agent-222',
          approverId: 'human-222',
          logId: 'log-222',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-replay-b',
          authorId: 'agent-222',
          approverId: 'human-222',
          logId: 'log-222',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.enclave_nonce_replay_violation).toContainEqual([
      'rel-replay-a',
      'rel-replay-b',
      'nonce-reused-222',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-replay-a',
      'enclave-nonce-replay',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-replay-b',
      'enclave-nonce-replay',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-fresh-222']]);
  }, 60_000);

  test('AG223: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on debug-enclave & nonce-replayed releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      enclaveQuotes: [
        {
          releaseId: 'rel-dbg-223',
          platformId: 'tdx-1',
          measuredDigest: 'art-223',
          debugDisabled: false,
          tcbOk: true,
        },
      ],
      teeQuoteNonces: [
        {releaseId: 'rel-dup1-223', nonce: 'dup-223'},
        {releaseId: 'rel-dup2-223', nonce: 'dup-223'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-dbg-223',
          authorId: 'coder-223',
          approverId: 'human-223',
          logId: 'log-223',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-dup1-223',
          authorId: 'coder-223',
          approverId: 'human-223',
          logId: 'log-223',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-dup2-223',
          authorId: 'coder-223',
          approverId: 'human-223',
          logId: 'log-223',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateDbg = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-dbg-223',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateDbg.kind).toBe('Refuted');
    if (gateDbg.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateDbg.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateDbg.ascentDisqualificationReasons).toContain('enclave-attestation-violation');

    const gateDup = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-dup1-223',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateDup.kind).toBe('Refuted');
    if (gateDup.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateDup.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateDup.ascentDisqualificationReasons).toContain('enclave-nonce-replay');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateDbg.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateDup.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG224: Standalone 24-Quint x 36x20 ASCENT x 14-Module / 156-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBe(24);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('confidential-enclave-attestation');
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
    expect(out.quintModelCount).toBe(24);
    expect(out.ascentRulesPresent).toBe(true);
    expect(out.multiLangHarnessCount).toBe(8);
    expect(out.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(out.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(out.zeroMathlib).toBe(true);
    expect(out.zeroCedar).toBe(true);
  }, 45_000);

  test('AG225: 225-Case Full B1-B15 Four-Paradigm Symmetry Closure — B14->B15 + 24 Quint x 36x20 ASCENT x 156-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. B14 2-builder hermetic build -> B15 hardware TEE measured enclave chain:
    const b1 = new BuilderAttestationSigningKey('builder-1-225');
    const b2 = new BuilderAttestationSigningKey('builder-2-225');
    const tee = new EnclaveRootAttestationKey('tdx-prod-225');
    const srcHash = sha256Digest({commit: '4d6c646'});
    const tcHash = sha256Digest({toolchain: 'v42-hermetic'});
    const artHash = sha256Digest({enclave: 'agent-runtime-v42'});
    const depHash = sha256Digest({pkg: 'lean-poo@1.0.0'});

    const att1 = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-225-1',
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
        buildId: 'b-225-2',
        builderId: b2.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depHash}],
      },
    });
    const b14Res = verifyHermeticBuildProvenance({
      primary: att1,
      reproducers: [att2],
      policy: {
        expectedSourceDigestHex: srcHash,
        expectedToolchainDigestHex: tcHash,
        pinnedLockfileDigests: [depHash],
        revokedCveDigests: [],
        trustedBuilderPublicKeys: {[b1.builderId]: b1.publicKeyPem, [b2.builderId]: b2.publicKeyPem},
        revokedBuilderIds: [],
        requireTwoBuilderReproducibility: true,
      },
      kv,
    });
    expect(b14Res.kind).toBe('Proven');
    if (b14Res.kind !== 'Proven') throw new Error('expected Proven');

    const quote = issueHardwareEnclaveQuote({
      platformKey: tee,
      payload: {
        quoteId: 'q-225',
        platformId: tee.platformId,
        measuredEnclaveDigestHex: b14Res.artifactDigestHex,
        tcbSvn: 18,
        challengeNonce: 'nonce-225-fresh',
        debugModeDisabled: true,
      },
    });
    const b15Res = verifyEnclaveQuoteForKeyRelease({
      quote,
      policy: {
        expectedArtifactDigestHex: b14Res.artifactDigestHex,
        minRequiredTcbSvn: 16,
        expectedChallengeNonce: 'nonce-225-fresh',
        trustedPlatformPublicKeys: {[tee.platformId]: tee.publicKeyPem},
        revokedPlatformIds: [],
      },
      kv,
    });
    expect(b15Res.kind).toBe('Proven');
    if (b15Res.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 36x20 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-225');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-225', teeReceipt: b15Res.pinnedKeyReleaseReceiptHash});
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
      witnessRosters: [{logId: 'log-225', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-225', checkpoint: qc}],
      lockfilePinnedDeps: [depHash],
      releaseSbomDeps: [{releaseId: 'rel-225', depDigest: depHash}],
      buildAttestations: [
        {releaseId: 'rel-225', builderId: b1.builderId, artifactDigest: artHash, hermetic: true},
        {releaseId: 'rel-225', builderId: b2.builderId, artifactDigest: artHash, hermetic: true},
      ],
      expectedEnclaveMeasurements: [{releaseId: 'rel-225', artifactDigest: artHash}],
      enclaveQuotes: [
        {
          releaseId: 'rel-225',
          platformId: tee.platformId,
          measuredDigest: artHash,
          debugDisabled: true,
          tcbOk: true,
        },
      ],
      teeQuoteNonces: [{releaseId: 'rel-225', nonce: 'nonce-225-fresh'}],
      releaseProposals: [
        {
          releaseId: 'rel-225',
          authorId: 'coder-225',
          approverId: 'human-225',
          logId: 'log-225',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-225',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-225',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 24-Quint x 14-Module / 156-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(24);
          expect(rep.leanPooModuleCount).toBe(14);
          expect(rep.leanPooTheoremCount).toBe(156);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 225, quint: 24, modules: 14, theorems: 156});

    const publisher = new LibraryReleaseSigningKey('pub-225');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v42-24quint-156thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 42,
        moduleCount: 14,
        verifiedTheoremCount: 156,
        quintModelCount: 24,
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
        minRequiredTheorems: 156,
        minAllowedEpoch: 42,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-225', 'release:b1-b15-full', 42);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v42'}),
        policyAffectedScopes: ['release:b1-b15-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v42'}),
      activeLeaseEpoch: 42,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(b14Res.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(b15Res.pinnedKeyReleaseReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
