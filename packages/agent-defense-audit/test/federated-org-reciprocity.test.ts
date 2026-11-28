// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {
  AeadPartitionKey,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from '../src/durable-merkle-store.ts';
import {DelegationRootKey} from '../src/capability-attenuation.ts';
import {LinearBudgetTree} from '../src/durable-saga-budget.ts';
import {DeclassificationCapability} from '../src/difc-exfiltration-fence.ts';
import {CoordinatorSigningKey} from '../src/transparency-log-equivocation.ts';
import {WitnessCosigningKey} from '../src/witness-quorum-finality.ts';
import {ForwardSecureWitnessKey} from '../src/witness-epoch-reconfiguration.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from '../src/release-certificate-replay.ts';
import {ToolSandboxCapability} from '../src/tool-sandbox-rpc-boundary.ts';
import {BuilderAttestationSigningKey} from '../src/supply-chain-provenance.ts';
import {EnclaveRootAttestationKey} from '../src/confidential-enclave-attestation.ts';
import {RotatableTenantAeadKeyRing} from '../src/key-rotation-crypto-shredding.ts';
import {HybridPqSigningKey} from '../src/post-quantum-crypto-agility.ts';
import {ZkProverWitnessKey} from '../src/zk-selective-disclosure.ts';
import {GeoResidencySigningKey} from '../src/geo-residency-sovereignty.ts';
import {
  FederatedOrgSigningKey,
  verifyFederatedReciprocityOffline,
  type FederatedOperationProposal,
  type FederationVerificationPolicy,
} from '../src/federated-org-reciprocity.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from '../src/host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from '../src/lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_FEDERATED_ORG_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from '../src/leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from '../src/leanpoo-fleet-audit.ts';

const FED_ORG_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_FEDERATED_ORG_FACADE_MODULE,
)!.theorems;

describe('Phase 51 — 200+ Theorem Landmark: B20 Multi-Org Federated Reciprocity & 19-Module / 206-Theorem Pure LeanPoo Library (10.199 / 30.05 AG266-AG270)', () => {
  test('AG266: Live Lean 4 / LeanPoo verifies all 10 FederatedOrgReciprocity theorems + single-shot 206/206-theorem 19-module fleet attestation (surpassing 200+ theorems)', () => {
    expect(FED_ORG_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(19);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(206);
    expect(
      LEANPOO_LIBRARY_EXPORT_MANIFEST.some(
        m => m.moduleName === LEANPOO_FEDERATED_ORG_FACADE_MODULE,
      ),
    ).toBe(true);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_FEDERATED_ORG_FACADE_MODULE,
          namespacePrefix: LEANPOO_FEDERATED_ORG_FACADE_MODULE,
          expectedTheorems: FED_ORG_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_FEDERATED_ORG_FACADE_MODULE,
      namespacePrefix: LEANPOO_FEDERATED_ORG_FACADE_MODULE,
      expectedTheorems: FED_ORG_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(fleet.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(fleet.verifiedTheoremCount).toBeGreaterThanOrEqual(206);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG267: Bilateral Ed25519 Org-A <-> Org-B countersigning admits ratified cross-org proposal while refusing unilateral & forged countersignatures', () => {
    const kv = new ContentAddressedKvStore();
    const orgA = new FederatedOrgSigningKey('org-alpha-267');
    const orgB = new FederatedOrgSigningKey('org-beta-267');
    const proposal: FederatedOperationProposal = {
      treatyId: 'treaty-ab-267',
      originOrgId: orgA.orgId,
      targetOrgId: orgB.orgId,
      scope: 'audit:joint-model-release',
      payloadDigestHex: sha256Digest({jointRelease: 'v51'}),
      epoch: 51,
    };
    const sigA = orgA.countersignProposal(proposal);
    const sigB = orgB.countersignProposal(proposal);

    const policy: FederationVerificationPolicy = {
      trustedOrgPublicKeys: {[orgA.orgId]: orgA.publicKeyPem, [orgB.orgId]: orgB.publicKeyPem},
      revokedOrgIds: [],
      ratifiedTreaties: {
        'treaty-ab-267': {
          treatyId: 'treaty-ab-267',
          memberOrgIds: [orgA.orgId, orgB.orgId],
          allowedScopes: ['audit:joint-model-release'],
          expiresAtEpoch: 60,
        },
      },
      activeDisputeFrozenTreatyIds: [],
      currentEpoch: 51,
    };

    // 1. Clean bilateral countersignature passes & pins M1 receipt across GC:
    const ok = verifyFederatedReciprocityOffline({
      proposal: JSON.parse(JSON.stringify(proposal)),
      originCountersig: JSON.parse(JSON.stringify(sigA)),
      targetCountersig: JSON.parse(JSON.stringify(sigB)),
      policy,
      kv,
    });
    expect(ok.kind).toBe('Proven');
    if (ok.kind !== 'Proven') throw new Error('expected Proven');

    // 2. Unilateral (missing target countersignature) refused:
    expect(
      verifyFederatedReciprocityOffline({proposal, originCountersig: sigA, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'missing-or-invalid-bilateral-countersignature'});

    // 3. Forged target signature byte refused:
    const badSigB = {
      ...sigB,
      signatureHex:
        (sigB.signatureHex.startsWith('a') ? 'b' : 'a') + sigB.signatureHex.slice(1),
    };
    expect(
      verifyFederatedReciprocityOffline({
        proposal,
        originCountersig: sigA,
        targetCountersig: badSigB,
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'missing-or-invalid-bilateral-countersignature'});

    kv.gcUnreferenced();
    expect(kv.hasBlob(ok.pinnedReceiptHash!)).toBe(true);
  });

  test('AG268: Verifier refuses all 6 multi-org federation attacks (self-reciprocity, revoked org, active dispute freeze, unratified treaty, expired treaty, out-of-scope treaty)', () => {
    const orgA = new FederatedOrgSigningKey('org-alpha-268');
    const orgB = new FederatedOrgSigningKey('org-beta-268');
    const baseProposal: FederatedOperationProposal = {
      treatyId: 'treaty-ab-268',
      originOrgId: orgA.orgId,
      targetOrgId: orgB.orgId,
      scope: 'audit:joint-release',
      payloadDigestHex: sha256Digest({doc: 'fed-268'}),
      epoch: 51,
    };
    const sigA = orgA.countersignProposal(baseProposal);
    const sigB = orgB.countersignProposal(baseProposal);

    const basePolicy: FederationVerificationPolicy = {
      trustedOrgPublicKeys: {[orgA.orgId]: orgA.publicKeyPem, [orgB.orgId]: orgB.publicKeyPem},
      revokedOrgIds: [],
      ratifiedTreaties: {
        'treaty-ab-268': {
          treatyId: 'treaty-ab-268',
          memberOrgIds: [orgA.orgId, orgB.orgId],
          allowedScopes: ['audit:joint-release'],
          expiresAtEpoch: 60,
        },
      },
      activeDisputeFrozenTreatyIds: [],
      currentEpoch: 51,
    };

    // 1. Self-reciprocity spoof (originOrgId === targetOrgId) refused:
    const selfProp = {...baseProposal, targetOrgId: orgA.orgId};
    expect(
      verifyFederatedReciprocityOffline({
        proposal: selfProp,
        originCountersig: orgA.countersignProposal(selfProp),
        targetCountersig: orgA.countersignProposal(selfProp),
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'self-reciprocity-same-org-spoof'});

    // 2. Revoked member organization refused:
    expect(
      verifyFederatedReciprocityOffline({
        proposal: baseProposal,
        originCountersig: sigA,
        targetCountersig: sigB,
        policy: {...basePolicy, revokedOrgIds: [orgB.orgId]},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unregistered-or-revoked-org'});

    // 3. Active dispute freeze blocks execution immediately:
    expect(
      verifyFederatedReciprocityOffline({
        proposal: baseProposal,
        originCountersig: sigA,
        targetCountersig: sigB,
        policy: {...basePolicy, activeDisputeFrozenTreatyIds: ['treaty-ab-268']},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'active-dispute-freeze-blocking'});

    // 4. Unratified treaty refused:
    const unratProp = {...baseProposal, treatyId: 'treaty-unratified'};
    expect(
      verifyFederatedReciprocityOffline({
        proposal: unratProp,
        originCountersig: orgA.countersignProposal(unratProp),
        targetCountersig: orgB.countersignProposal(unratProp),
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unratified-or-expired-or-out-of-scope-treaty'});

    // 5. Expired treaty refused:
    expect(
      verifyFederatedReciprocityOffline({
        proposal: baseProposal,
        originCountersig: sigA,
        targetCountersig: sigB,
        policy: {...basePolicy, currentEpoch: 61},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unratified-or-expired-or-out-of-scope-treaty'});

    // 6. Out-of-scope treaty request refused:
    const badScopeProp = {...baseProposal, scope: 'admin:root-exec'};
    expect(
      verifyFederatedReciprocityOffline({
        proposal: badScopeProp,
        originCountersig: orgA.countersignProposal(badScopeProp),
        targetCountersig: orgB.countersignProposal(badScopeProp),
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unratified-or-expired-or-out-of-scope-treaty'});
  });

  test('AG269: All 17/17 R3 Non-Leakable M3 Capability Classes (including FederatedOrgSigningKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all17R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-269', 'scope:269', 1),
      new AeadPartitionKey('tenant-269'),
      new DelegationRootKey('root-269'),
      new LinearBudgetTree('agent-269', 269),
      new DeclassificationCapability('declass-269', ['tenant:269']),
      new CoordinatorSigningKey('log-269'),
      new WitnessCosigningKey('w-269'),
      new ForwardSecureWitnessKey('fw-269', 1),
      new LibraryReleaseSigningKey('pub-269'),
      new ToolSandboxCapability('agent-269', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-269'),
      new EnclaveRootAttestationKey('tee-node-269'),
      new RotatableTenantAeadKeyRing('tenant-ring-269', 1),
      new HybridPqSigningKey('pq-signer-269', 2),
      new ZkProverWitnessKey('zk-prover-269', [{fieldId: 'ok', value: true, confidential: false}]),
      new GeoResidencySigningKey('geo-auth-269', 'eu-central-1'),
      new FederatedOrgSigningKey('fed-org-269'),
    ];
    expect(all17R3Caps.length).toBe(17);
    for (const cap of all17R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-269', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG270: 270-Case & 206-Theorem Grand Landmark — 28 Quint x 52x28 ASCENT x 19-Mod / 206-Thm CLI + Bilateral Org Reciprocity + 90.154 -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    const repoRoot = resolve(import.meta.dir, '../../..');
    expect(
      existsSync(
        resolve(
          repoRoot,
          'docs/90-99-views/90-architecture-views/90.154-270-case-206-theorem-b1-b20-panoramic-architecture.svg',
        ),
      ),
    ).toBe(true);

    if (isLeanToolchainAvailable()) {
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
      expect(out.verifiedTheoremCount).toBeGreaterThanOrEqual(206);
      expect(out.zeroMathlib).toBe(true);
      expect(out.zeroCedar).toBe(true);
    }

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 270, quint: 28, modules: 19, theorems: 206});

    // B20 Bilateral Federation Reciprocity over the 206-theorem attestation digest:
    const orgA = new FederatedOrgSigningKey('org-hardenedlinux');
    const orgB = new FederatedOrgSigningKey('org-cedar-host');
    const proposal: FederatedOperationProposal = {
      treatyId: 'treaty-206-thm-v51',
      originOrgId: orgA.orgId,
      targetOrgId: orgB.orgId,
      scope: 'release:library-206-theorems',
      payloadDigestHex: attDigest,
      epoch: 51,
    };
    const fedVerified = verifyFederatedReciprocityOffline({
      proposal,
      originCountersig: orgA.countersignProposal(proposal),
      targetCountersig: orgB.countersignProposal(proposal),
      policy: {
        trustedOrgPublicKeys: {[orgA.orgId]: orgA.publicKeyPem, [orgB.orgId]: orgB.publicKeyPem},
        revokedOrgIds: [],
        ratifiedTreaties: {
          'treaty-206-thm-v51': {
            treatyId: 'treaty-206-thm-v51',
            memberOrgIds: [orgA.orgId, orgB.orgId],
            allowedScopes: ['release:library-206-theorems'],
            expiresAtEpoch: 65,
          },
        },
        activeDisputeFrozenTreatyIds: [],
        currentEpoch: 51,
      },
      kv,
    });
    expect(fedVerified.kind).toBe('Proven');
    if (fedVerified.kind !== 'Proven') throw new Error('expected Proven');

    const publisher = new LibraryReleaseSigningKey('pub-270');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v51-19mod-206thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 51,
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
        minAllowedEpoch: 51,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-270', 'release:b1-b20-206-theorems', 51);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v51-206-theorems'}),
        policyAffectedScopes: ['release:b1-b20-206-theorems'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v51-206-theorems'}),
      activeLeaseEpoch: 51,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(fedVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
