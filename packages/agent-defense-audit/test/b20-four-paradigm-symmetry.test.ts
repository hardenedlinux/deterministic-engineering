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
  FederatedOrgSigningKey,
  verifyFederatedReciprocityOffline,
  type FederatedOperationProposal,
} from '../src/federated-org-reciprocity.ts';
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

describe('Phase 52 — Full B20 Four-Paradigm Symmetry: 29 Quint/MBT Models + 56x30 B1-B20 Gerbil ASCENT + 206-Theorem LeanPoo (10.200 / 30.05 AG271-AG275)', () => {
  test('AG271: Live 56x30 Gerbil Scheme ASCENT derives B20 fed_reciprocity_violation for self-reciprocity, unratified treaty, revoked org & unilateral signing while admitting clean bilateral op', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      fedRatifiedTreaties: ['treaty-271'],
      fedRevokedOrgs: ['org-revoked-271'],
      releaseFedReciprocities: [
        {
          releaseId: 'rel-fed-clean',
          treatyId: 'treaty-271',
          originOrgId: 'org-a-271',
          targetOrgId: 'org-b-271',
          bilateralOk: true,
        },
        {
          releaseId: 'rel-fed-bad',
          treatyId: 'treaty-unrat-271',
          originOrgId: 'org-revoked-271',
          targetOrgId: 'org-revoked-271',
          bilateralOk: false,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-fed-clean',
          authorId: 'agent-271',
          approverId: 'human-271',
          logId: 'log-271',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-fed-bad',
          authorId: 'agent-271',
          approverId: 'human-271',
          logId: 'log-271',
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

    expect(res.output.fed_reciprocity_violation).toContainEqual([
      'rel-fed-bad',
      'org-revoked-271',
      'self-reciprocity-spoof',
    ]);
    expect(res.output.fed_reciprocity_violation).toContainEqual([
      'rel-fed-bad',
      'treaty-unrat-271',
      'unratified-federation-treaty',
    ]);
    expect(res.output.fed_reciprocity_violation).toContainEqual([
      'rel-fed-bad',
      'org-revoked-271',
      'revoked-origin-org',
    ]);
    expect(res.output.fed_reciprocity_violation).toContainEqual([
      'rel-fed-bad',
      'treaty-unrat-271',
      'unilateral-countersignature',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-fed-bad',
      'federated-reciprocity-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-fed-clean']]);
  }, 60_000);

  test('AG272: Live 56x30 Gerbil Scheme ASCENT derives B20 fed_dispute_freeze_violation on frozen bilateral treaties while admitting unfrozen treaties', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      fedRatifiedTreaties: ['treaty-open-272', 'treaty-frozen-272'],
      fedDisputeFreezes: ['treaty-frozen-272'],
      releaseFedReciprocities: [
        {
          releaseId: 'rel-fed-open',
          treatyId: 'treaty-open-272',
          originOrgId: 'org-a-272',
          targetOrgId: 'org-b-272',
          bilateralOk: true,
        },
        {
          releaseId: 'rel-fed-frozen',
          treatyId: 'treaty-frozen-272',
          originOrgId: 'org-a-272',
          targetOrgId: 'org-b-272',
          bilateralOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-fed-open',
          authorId: 'agent-272',
          approverId: 'human-272',
          logId: 'log-272',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-fed-frozen',
          authorId: 'agent-272',
          approverId: 'human-272',
          logId: 'log-272',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.fed_dispute_freeze_violation).toContainEqual([
      'rel-fed-frozen',
      'treaty-frozen-272',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-fed-frozen',
      'federated-dispute-freeze',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-fed-open']]);
  }, 60_000);

  test('AG273: N-Version Agreement Gate overrides buggy imperative TS coordinator claiming ADMIT on unilateral & dispute-frozen federated releases', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      fedRatifiedTreaties: ['treaty-273', 'treaty-frozen-273'],
      fedDisputeFreezes: ['treaty-frozen-273'],
      releaseFedReciprocities: [
        {
          releaseId: 'rel-bug-unilateral',
          treatyId: 'treaty-273',
          originOrgId: 'org-a-273',
          targetOrgId: 'org-b-273',
          bilateralOk: false,
        },
        {
          releaseId: 'rel-bug-frozen',
          treatyId: 'treaty-frozen-273',
          originOrgId: 'org-a-273',
          targetOrgId: 'org-b-273',
          bilateralOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-bug-unilateral',
          authorId: 'coder-273',
          approverId: 'human-273',
          logId: 'log-273',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bug-frozen',
          authorId: 'coder-273',
          approverId: 'human-273',
          logId: 'log-273',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gateUni = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-unilateral',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateUni.kind).toBe('Refuted');
    if (gateUni.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateUni.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateUni.ascentDisqualificationReasons).toContain('federated-reciprocity-violation');

    const gateFrz = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-bug-frozen',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gateFrz.kind).toBe('Refuted');
    if (gateFrz.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gateFrz.reason).toBe('oracle-disagreement-fail-closed');
    expect(gateFrz.ascentDisqualificationReasons).toContain('federated-dispute-freeze');

    kv.gcUnreferenced();
    expect(kv.hasBlob(gateUni.disagreementReceiptHash)).toBe(true);
    expect(kv.hasBlob(gateFrz.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG274: Standalone 29-Quint x 56x30 ASCENT x 19-Module / 206-Theorem LeanPoo CLI JSON Gate exits 0', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(29);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('federated-org-reciprocity');
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

  test('AG275: 275-Case Full B1-B20 Four-Paradigm Symmetry Closure — Bilateral Ed25519 Reciprocity + 29 Quint x 56x30 ASCENT x 206-Thm Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. Live B20 Bilateral Org-A <-> Org-B Ed25519 Reciprocity verification:
    const orgA = new FederatedOrgSigningKey('org-hardenedlinux-275');
    const orgB = new FederatedOrgSigningKey('org-cedar-host-275');
    const proposal: FederatedOperationProposal = {
      treatyId: 'treaty-b1-b20-v52',
      originOrgId: orgA.orgId,
      targetOrgId: orgB.orgId,
      scope: 'release:b1-b20-full-symmetry',
      payloadDigestHex: sha256Digest({phase: 52, quint: 29, theorems: 206}),
      epoch: 52,
    };
    const fedCheck = verifyFederatedReciprocityOffline({
      proposal,
      originCountersig: orgA.countersignProposal(proposal),
      targetCountersig: orgB.countersignProposal(proposal),
      policy: {
        trustedOrgPublicKeys: {[orgA.orgId]: orgA.publicKeyPem, [orgB.orgId]: orgB.publicKeyPem},
        revokedOrgIds: [],
        ratifiedTreaties: {
          'treaty-b1-b20-v52': {
            treatyId: 'treaty-b1-b20-v52',
            memberOrgIds: [orgA.orgId, orgB.orgId],
            allowedScopes: ['release:b1-b20-full-symmetry'],
            expiresAtEpoch: 70,
          },
        },
        activeDisputeFrozenTreatyIds: [],
        currentEpoch: 52,
      },
      kv,
    });
    expect(fedCheck.kind).toBe('Proven');
    if (fedCheck.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B10 3-of-4 QC + live 56x30 TS <-> Scheme ASCENT dual consensus:
    const coord = new CoordinatorSigningKey('log-275');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-275', fedReceipt: fedCheck.pinnedReceiptHash});
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
      witnessRosters: [{logId: 'log-275', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-275', checkpoint: qc}],
      fedRatifiedTreaties: [proposal.treatyId],
      releaseFedReciprocities: [
        {
          releaseId: 'rel-275',
          treatyId: proposal.treatyId,
          originOrgId: proposal.originOrgId,
          targetOrgId: proposal.targetOrgId,
          bilateralOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-275',
          authorId: 'coder-275',
          approverId: 'human-275',
          logId: 'log-275',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-275',
        },
      ],
    });

    if (isGerbilAscentRuntimeAvailable()) {
      const dualAscent = verifyReleaseWithIndependentAscentOracle({
        kv,
        releaseId: 'rel-275',
        imperativeTsVerdict: 'ADMIT',
        bundle,
        factBundleMerkleHash,
      });
      expect(dualAscent.kind).toBe('Proven');
    }

    // 3. 29-Quint x 19-Module / 206-Theorem air-gapped Ed25519 cert -> cedar-poo-spec:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 275, quint: 29, modules: 19, theorems: 206});

    const publisher = new LibraryReleaseSigningKey('pub-275');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v52-29quint-206thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 52,
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
        minAllowedEpoch: 52,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-275', 'release:b1-b20-full', 52);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v52'}),
        policyAffectedScopes: ['release:b1-b20-full'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v52'}),
      activeLeaseEpoch: 52,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(fedCheck.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 60_000);
});
