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
  verifyZkComplianceDisclosureOffline,
  ZkProverWitnessKey,
} from '../src/zk-selective-disclosure.ts';
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

describe('Phase 48 — Full B18 Four-Paradigm Symmetry: 27 Quint/MBT Models + 48x26 B1-B18 Gerbil ASCENT + 186-Theorem LeanPoo (10.196 / 30.05 AG251-AG255)', () => {
  test('AG251: Live 48x26 Gerbil Scheme ASCENT derives B18 zk_disclosure_violation for over-disclosure, missing required field, root mismatch & Sigma forgery while admitting clean ZK proof', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      zkForbiddenSecretFields: ['customerSsn'],
      zkRequiredPublicFields: ['soDApproved'],
      releaseZkProofs: [
        {
          releaseId: 'rel-zk-clean',
          proverId: 'prover-251',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-clean-251',
        },
        {
          releaseId: 'rel-zk-over',
          proverId: 'prover-251',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-over-251',
        },
        {
          releaseId: 'rel-zk-forged',
          proverId: 'prover-bad-251',
          rootOk: false,
          sigmaOk: false,
          nullifier: 'null-forged-251',
        },
      ],
      releaseZkDisclosedFields: [
        {releaseId: 'rel-zk-clean', fieldId: 'soDApproved'},
        {releaseId: 'rel-zk-over', fieldId: 'customerSsn'},
        {releaseId: 'rel-zk-forged', fieldId: 'soDApproved'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-zk-clean',
          authorId: 'agent-251',
          approverId: 'human-251',
          logId: 'log-251',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-zk-over',
          authorId: 'agent-251',
          approverId: 'human-251',
          logId: 'log-251',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-zk-forged',
          authorId: 'agent-251',
          approverId: 'human-251',
          logId: 'log-251',
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

    expect(res.output.zk_disclosure_violation).toContainEqual([
      'rel-zk-over',
      'customerSsn',
      'over-disclosure-of-secret-field',
    ]);
    expect(res.output.zk_disclosure_violation).toContainEqual([
      'rel-zk-over',
      'soDApproved',
      'missing-required-public-field',
    ]);
    expect(res.output.zk_disclosure_violation).toContainEqual([
      'rel-zk-forged',
      'prover-bad-251',
      'commitment-root-mismatch',
    ]);
    expect(res.output.zk_disclosure_violation).toContainEqual([
      'rel-zk-forged',
      'prover-bad-251',
      'zk-sigma-proof-invalid',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-zk-over',
      'zk-selective-disclosure-violation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-zk-forged',
      'zk-selective-disclosure-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-zk-clean']]);
  }, 60_000);

  test('AG252: Live 48x26 Gerbil Scheme ASCENT derives B18 zk_nullifier_replay_violation across distinct releases reusing the same nullifier while admitting fresh nullifiers', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      zkRequiredPublicFields: ['soDApproved'],
      releaseZkProofs: [
        {
          releaseId: 'rel-null-clean',
          proverId: 'prover-252',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-fresh-252',
        },
        {
          releaseId: 'rel-null-dup-a',
          proverId: 'prover-252',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-reused-252',
        },
        {
          releaseId: 'rel-null-dup-b',
          proverId: 'prover-252',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-reused-252',
        },
      ],
      releaseZkDisclosedFields: [
        {releaseId: 'rel-null-clean', fieldId: 'soDApproved'},
        {releaseId: 'rel-null-dup-a', fieldId: 'soDApproved'},
        {releaseId: 'rel-null-dup-b', fieldId: 'soDApproved'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-null-clean',
          authorId: 'agent-252',
          approverId: 'human-252',
          logId: 'log-252',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-null-dup-a',
          authorId: 'agent-252',
          approverId: 'human-252',
          logId: 'log-252',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-null-dup-b',
          authorId: 'agent-252',
          approverId: 'human-252',
          logId: 'log-252',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.zk_nullifier_replay_violation).toContainEqual([
      'rel-null-dup-a',
      'rel-null-dup-b',
      'null-reused-252',
    ]);
    expect(res.output.release_disqualified).toContainEqual(['rel-null-dup-a', 'zk-nullifier-replay']);
    expect(res.output.release_disqualified).toContainEqual(['rel-null-dup-b', 'zk-nullifier-replay']);
    expect(res.output.release_admitted).toEqual([['rel-null-clean']]);
  }, 60_000);

  test('AG253: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on ZK over-disclosure & nullifier-replay releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      zkForbiddenSecretFields: ['customerSsn'],
      zkRequiredPublicFields: ['soDApproved'],
      releaseZkProofs: [
        {
          releaseId: 'rel-bug-over',
          proverId: 'prover-253',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-over-253',
        },
        {
          releaseId: 'rel-bug-rep-1',
          proverId: 'prover-253',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-dup-253',
        },
        {
          releaseId: 'rel-bug-rep-2',
          proverId: 'prover-253',
          rootOk: true,
          sigmaOk: true,
          nullifier: 'null-dup-253',
        },
      ],
      releaseZkDisclosedFields: [
        {releaseId: 'rel-bug-over', fieldId: 'soDApproved'},
        {releaseId: 'rel-bug-over', fieldId: 'customerSsn'},
        {releaseId: 'rel-bug-rep-1', fieldId: 'soDApproved'},
        {releaseId: 'rel-bug-rep-2', fieldId: 'soDApproved'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-bug-over',
          authorId: 'coder-253',
          approverId: 'human-253',
          logId: 'log-253',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-rep-1',
          authorId: 'coder-253',
          approverId: 'human-253',
          logId: 'log-253',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-rep-2',
          authorId: 'coder-253',
          approverId: 'human-253',
          logId: 'log-253',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateOver = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-over',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateOver.kind).toBe('Refuted');
    if (gateOver.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateOver.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateOver.ascentDisqualificationReasons).toContain('zk-selective-disclosure-violation');

    const gateReplay = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-rep-2',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateReplay.kind).toBe('Refuted');
    if (gateReplay.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateReplay.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateReplay.ascentDisqualificationReasons).toContain('zk-nullifier-replay');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateOver.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateReplay.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG254: Standalone 27-Quint x 48x26 ASCENT x 17-Module / 186-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(27);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('zk-selective-disclosure');
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

  test('AG255: 255-Case Full B1-B18 Four-Paradigm Symmetry Closure — MODP-2048 Schnorr Sigma + 27 Quint x 48x26 ASCENT x 186-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B18 RFC 3526 MODP-2048 Schnorr Sigma NIZK + Salted Merkle Selective Disclosure:
    const prover = new ZkProverWitnessKey('zk-prover-255', [
      {fieldId: 'soDApproved', value: true, confidential: false},
      {fieldId: 'zeroMathlibAndCedar', value: true, confidential: false},
      {fieldId: 'customerSsn', value: '555-01-9999', confidential: true},
    ]);
    const policyDigestHex = sha256Digest({phase: 48, b18Symmetry: true});
    const zkProof = prover.generateSelectiveDisclosureProof({
      domainTag: 'de-qnt:b18-symmetry:v48',
      verifierNonce: 'nonce-255',
      policyDigestHex,
      discloseFieldIds: ['soDApproved', 'zeroMathlibAndCedar'],
    });
    const zkCheck = verifyZkComplianceDisclosureOffline({
      proof: JSON.parse(JSON.stringify(zkProof)),
      policy: {
        expectedDomainTag: 'de-qnt:b18-symmetry:v48',
        expectedVerifierNonce: 'nonce-255',
        expectedPolicyDigestHex: policyDigestHex,
        trustedProvers: {[prover.proverId]: prover.exportPublicBundle()},
        forbiddenSecretFieldIds: ['customerSsn'],
        requiredPublicFieldIds: ['soDApproved', 'zeroMathlibAndCedar'],
        spentNullifiers: [],
      },
      kv,
    });
    expect(zkCheck.kind).toBe('Proven');
    if (zkCheck.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 48x26 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-255');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-255', zkReceipt: zkCheck.pinnedReceiptHash});
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
      witnessRosters: [{logId: 'log-255', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-255', checkpoint: qc}],
      zkForbiddenSecretFields: ['customerSsn'],
      zkRequiredPublicFields: ['soDApproved', 'zeroMathlibAndCedar'],
      releaseZkProofs: [
        {
          releaseId: 'rel-255',
          proverId: prover.proverId,
          rootOk: true,
          sigmaOk: true,
          nullifier: zkProof.nullifierHex,
        },
      ],
      releaseZkDisclosedFields: [
        {releaseId: 'rel-255', fieldId: 'soDApproved'},
        {releaseId: 'rel-255', fieldId: 'zeroMathlibAndCedar'},
      ],
      releaseProposals: [
        {
          releaseId: 'rel-255',
          authorId: 'coder-255',
          approverId: 'human-255',
          logId: 'log-255',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-255',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-255',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 27-Quint x 17-Module / 186-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 255, quint: 27, modules: 17, theorems: 186});

    const publisher = new LibraryReleaseSigningKey('pub-255');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v48-27quint-186thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 48,
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
        minAllowedEpoch: 48,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-255', 'release:b1-b18-full', 48);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v48'}),
        policyAffectedScopes: ['release:b1-b18-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v48'}),
      activeLeaseEpoch: 48,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(zkCheck.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
