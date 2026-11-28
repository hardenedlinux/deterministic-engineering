// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
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
import {
  GeoResidencySigningKey,
  verifyGeoResidencyPlacementOffline,
  type GeoResidencyVerificationPolicy,
} from '../src/geo-residency-sovereignty.ts';
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
  LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from '../src/leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from '../src/leanpoo-fleet-audit.ts';

const GEO_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
)!.theorems;

describe('Phase 49 — B19 Cross-Region Sovereign Data-Residency & Geo-Fenced Governance + 18-Module / 196-Theorem LeanPoo Library (10.197 / 30.05 AG256-AG260)', () => {
  test('AG256: Live Lean 4 / LeanPoo verifies all 10 GeoResidencyAndSovereignty theorems + single-shot 196/196-theorem 18-module fleet attestation', () => {
    expect(GEO_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(18);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(196);
    expect(
      LEANPOO_LIBRARY_EXPORT_MANIFEST.some(
        m => m.moduleName === LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
      ),
    ).toBe(true);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
          namespacePrefix: LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
          expectedTheorems: GEO_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
      namespacePrefix: LEANPOO_GEO_RESIDENCY_FACADE_MODULE,
      expectedTheorems: GEO_THEOREMS,
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

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG257: Intra-region sovereign placement admits without cross-border permit (anti-P4) while cross-border transfer requires signed GDPR Chapter V permit', () => {
    const kv = new ContentAddressedKvStore();
    const euAuth = new GeoResidencySigningKey('eu-dpa-257', 'eu-central-1');
    const payloadDigestHex = sha256Digest({tenant: 'eu-bank-257', doc: 'loan-decision'});
    const policy: GeoResidencyVerificationPolicy = {
      allowedRegions: ['eu-central-1', 'eu-west-1', 'ch-zurich-1'],
      sanctionedRegions: ['sanctioned-zone-x'],
      trustedAuthorityPublicKeys: {[euAuth.authorityId]: euAuth.publicKeyPem},
      revokedAuthorityIds: [],
      revokedPermitIds: [],
      currentEpoch: 49,
    };

    // 1. Intra-region placement (eu-central-1 -> eu-central-1) succeeds with ZERO cross-border permit:
    const localAtt = euAuth.attestRegionPlacement({
      tenantId: 'eu-bank-257',
      sourceRegion: 'eu-central-1',
      targetRegion: 'eu-central-1',
      inferenceEndpointRegion: 'eu-west-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    const localRes = verifyGeoResidencyPlacementOffline({attestation: localAtt, policy, kv});
    expect(localRes.kind).toBe('Proven');
    if (localRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(localRes.crossBorderTransfer).toBe(false);

    // 2. Cross-border transfer (eu-central-1 -> ch-zurich-1) WITHOUT permit -> refused:
    const crossAtt = euAuth.attestRegionPlacement({
      tenantId: 'eu-bank-257',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      inferenceEndpointRegion: 'ch-zurich-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    expect(verifyGeoResidencyPlacementOffline({attestation: crossAtt, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'missing-cross-border-transfer-permit',
    });

    // 3. Cross-border transfer WITH signed adequacy-decision permit -> admitted & pinned across GC:
    const permit = euAuth.issueCrossBorderTransferPermit({
      permitId: 'eu-ch-adequacy-257',
      legalBasis: 'adequacy-decision',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      payloadDigestHex,
      expiresAtEpoch: 60,
    });
    const crossRes = verifyGeoResidencyPlacementOffline({
      attestation: JSON.parse(JSON.stringify(crossAtt)),
      transferPermit: JSON.parse(JSON.stringify(permit)),
      policy,
      kv,
    });
    expect(crossRes.kind).toBe('Proven');
    if (crossRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(crossRes.crossBorderTransfer).toBe(true);

    kv.gcUnreferenced();
    expect(kv.hasBlob(localRes.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(crossRes.pinnedReceiptHash!)).toBe(true);
  });

  test('AG258: Verifier refuses all 6 sovereign residency attacks (sanctioned target, LLM inference escape, revoked authority, forged sig, expired/revoked permit, payload transplant)', () => {
    const euAuth = new GeoResidencySigningKey('eu-dpa-258', 'eu-central-1');
    const payloadDigestHex = sha256Digest({doc: 'patient-record-258'});
    const basePolicy: GeoResidencyVerificationPolicy = {
      allowedRegions: ['eu-central-1', 'ch-zurich-1'],
      sanctionedRegions: ['sanctioned-zone-x'],
      trustedAuthorityPublicKeys: {[euAuth.authorityId]: euAuth.publicKeyPem},
      revokedAuthorityIds: [],
      revokedPermitIds: ['permit-revoked-258'],
      currentEpoch: 49,
    };

    // 1. Sanctioned/disallowed target region refused:
    const badTargetAtt = euAuth.attestRegionPlacement({
      tenantId: 't-258',
      sourceRegion: 'eu-central-1',
      targetRegion: 'sanctioned-zone-x',
      inferenceEndpointRegion: 'eu-central-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    expect(
      verifyGeoResidencyPlacementOffline({attestation: badTargetAtt, policy: basePolicy}),
    ).toMatchObject({kind: 'Refuted', reason: 'sanctioned-or-disallowed-target-region'});

    // 2. LLM inference endpoint residency escape (storage in EU, inference routed to us-east-1) refused:
    const badInfAtt = euAuth.attestRegionPlacement({
      tenantId: 't-258',
      sourceRegion: 'eu-central-1',
      targetRegion: 'eu-central-1',
      inferenceEndpointRegion: 'us-east-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    expect(
      verifyGeoResidencyPlacementOffline({attestation: badInfAtt, policy: basePolicy}),
    ).toMatchObject({kind: 'Refuted', reason: 'inference-endpoint-residency-escape'});

    // 3. Revoked regional authority refused:
    const cleanLocal = euAuth.attestRegionPlacement({
      tenantId: 't-258',
      sourceRegion: 'eu-central-1',
      targetRegion: 'eu-central-1',
      inferenceEndpointRegion: 'eu-central-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    expect(
      verifyGeoResidencyPlacementOffline({
        attestation: cleanLocal,
        policy: {...basePolicy, revokedAuthorityIds: [euAuth.authorityId]},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'unregistered-or-revoked-authority'});

    // 4. Forged attestation signature refused:
    const badSig =
      (cleanLocal.signatureHex.startsWith('a') ? 'b' : 'a') + cleanLocal.signatureHex.slice(1);
    expect(
      verifyGeoResidencyPlacementOffline({
        attestation: {...cleanLocal, signatureHex: badSig},
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'region-attestation-signature-invalid'});

    // 5. Revoked or expired cross-border permit refused:
    const crossAtt = euAuth.attestRegionPlacement({
      tenantId: 't-258',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      inferenceEndpointRegion: 'ch-zurich-1',
      payloadDigestHex,
      issuedAtEpoch: 49,
    });
    const revokedPermit = euAuth.issueCrossBorderTransferPermit({
      permitId: 'permit-revoked-258',
      legalBasis: 'standard-contractual-clauses',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      payloadDigestHex,
      expiresAtEpoch: 60,
    });
    expect(
      verifyGeoResidencyPlacementOffline({
        attestation: crossAtt,
        transferPermit: revokedPermit,
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'cross-border-permit-invalid-or-revoked'});

    // 6. Permit transplanted onto a different payloadDigestHex refused:
    const otherPayloadPermit = euAuth.issueCrossBorderTransferPermit({
      permitId: 'permit-other-258',
      legalBasis: 'adequacy-decision',
      sourceRegion: 'eu-central-1',
      targetRegion: 'ch-zurich-1',
      payloadDigestHex: sha256Digest({doc: 'different-doc'}),
      expiresAtEpoch: 60,
    });
    expect(
      verifyGeoResidencyPlacementOffline({
        attestation: crossAtt,
        transferPermit: otherPayloadPermit,
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'cross-border-permit-invalid-or-revoked'});
  });

  test('AG259: All 16/16 R3 Non-Leakable M3 Capability Classes (including GeoResidencySigningKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all16R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-259', 'scope:259', 1),
      new AeadPartitionKey('tenant-259'),
      new DelegationRootKey('root-259'),
      new LinearBudgetTree('agent-259', 259),
      new DeclassificationCapability('declass-259', ['tenant:259']),
      new CoordinatorSigningKey('log-259'),
      new WitnessCosigningKey('w-259'),
      new ForwardSecureWitnessKey('fw-259', 1),
      new LibraryReleaseSigningKey('pub-259'),
      new ToolSandboxCapability('agent-259', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-259'),
      new EnclaveRootAttestationKey('tee-node-259'),
      new RotatableTenantAeadKeyRing('tenant-ring-259', 1),
      new HybridPqSigningKey('pq-signer-259', 2),
      new ZkProverWitnessKey('zk-prover-259', [{fieldId: 'ok', value: true, confidential: false}]),
      new GeoResidencySigningKey('geo-auth-259', 'eu-central-1'),
    ];
    expect(all16R3Caps.length).toBe(16);
    for (const cap of all16R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-259', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG260: 260-Case & 18-Module / 196-Theorem Milestone — 27 Quint x 48x26 ASCENT x 196-Thm CLI + Sovereign Geo-Residency -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
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
      : sha256Digest({milestone: 260, quint: 27, modules: 18, theorems: 196});

    // B19 Geo-Fenced Sovereign Residency attestation bound to attDigest:
    const euAuth = new GeoResidencySigningKey('eu-sovereign-260', 'eu-central-1');
    const att = euAuth.attestRegionPlacement({
      tenantId: 'eu-sovereign-host',
      sourceRegion: 'eu-central-1',
      targetRegion: 'eu-central-1',
      inferenceEndpointRegion: 'eu-central-1',
      payloadDigestHex: attDigest,
      issuedAtEpoch: 49,
    });
    const geoVerified = verifyGeoResidencyPlacementOffline({
      attestation: JSON.parse(JSON.stringify(att)),
      policy: {
        allowedRegions: ['eu-central-1'],
        sanctionedRegions: ['sanctioned-zone-x'],
        trustedAuthorityPublicKeys: {[euAuth.authorityId]: euAuth.publicKeyPem},
        revokedAuthorityIds: [],
        revokedPermitIds: [],
        currentEpoch: 49,
      },
      kv,
    });
    expect(geoVerified.kind).toBe('Proven');
    if (geoVerified.kind !== 'Proven') throw new Error('expected Proven');

    const publisher = new LibraryReleaseSigningKey('pub-260');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v49-18mod-196thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 49,
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
        minAllowedEpoch: 49,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-260', 'release:b19-geo-residency', 49);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v49-eu-sovereign'}),
        policyAffectedScopes: ['release:b19-geo-residency'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v49-eu-sovereign'}),
      activeLeaseEpoch: 49,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(geoVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
