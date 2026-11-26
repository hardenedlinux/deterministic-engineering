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
} from './durable-merkle-store.ts';
import {DelegationRootKey} from './capability-attenuation.ts';
import {LinearBudgetTree} from './durable-saga-budget.ts';
import {DeclassificationCapability} from './difc-exfiltration-fence.ts';
import {CoordinatorSigningKey} from './transparency-log-equivocation.ts';
import {WitnessCosigningKey} from './witness-quorum-finality.ts';
import {ForwardSecureWitnessKey} from './witness-epoch-reconfiguration.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_RELEASE_CERT_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {auditFourParadigmCrossConsistency} from './leanpoo-fleet-audit.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
  type OfflineReleaseVerifierPolicy,
} from './release-certificate-replay.ts';

const RELEASE_CERT_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_RELEASE_CERT_FACADE_MODULE,
)!.theorems;

describe('Phase 32 — Air-Gapped Ed25519 Release Certificate Replay & 96-Theorem LeanPoo Library (10.180 / 90.150 / 30.05 AG166-AG170)', () => {
  test('AG166: Live Lean 4 / LeanPoo verifies all 10 ReleaseCertificateReplay theorems + single-shot 96/96-theorem 8-module fleet attestation', () => {
    expect(RELEASE_CERT_THEOREMS.length).toBe(10);
    const kv = new ContentAddressedKvStore();

    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_RELEASE_CERT_FACADE_MODULE,
          namespacePrefix: LEANPOO_RELEASE_CERT_FACADE_MODULE,
          expectedTheorems: RELEASE_CERT_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_RELEASE_CERT_FACADE_MODULE,
      namespacePrefix: LEANPOO_RELEASE_CERT_FACADE_MODULE,
      expectedTheorems: RELEASE_CERT_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(8);
    expect(fleet.verifiedTheoremCount).toBe(96);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG167: Ed25519 Publisher + 3-of-4 Threshold Witness SignedLibraryReleaseCertificate verifies 100% offline & enforces R3 key non-leakage', () => {
    const kv = new ContentAddressedKvStore();
    const publisher = new LibraryReleaseSigningKey('deterministic-engineering-qnt-release');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));

    // R3 mechanical reachability fence blocks LibraryReleaseSigningKey entering M1 or JSON!
    expect(() => kv.putBlob('leaked-publisher-key', {publisher})).toThrow(/R3 ReachabilityLeakError/);
    expect(() => JSON.stringify(publisher)).toThrow(/R3 ReachabilityLeakError/);

    const attDigest = sha256Digest({phase: 32, theorems: 96, zeroMathlib: true, zeroCedar: true});
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v32-epoch1',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_RELEASE_CERT_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 32,
        moduleCount: 8,
        verifiedTheoremCount: 96,
        quintModelCount: 19,
        zeroMathlib: true,
        zeroCedar: true,
      },
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });

    // Serialize across air-gap boundary (pure M1 JSON, zero private keys!):
    const airGappedCert = JSON.parse(JSON.stringify(cert));
    const policy: OfflineReleaseVerifierPolicy = {
      expectedAttestationDigest: attDigest,
      trustedPublisherPublicKeyPem: publisher.publicKeyPem,
      registeredWitnessPublicKeys: Object.fromEntries(
        witnesses.map(w => [w.publisherId, w.publicKeyPem]),
      ),
      minWitnessThreshold: 3,
      minRequiredTheorems: 96,
      minAllowedEpoch: 32,
      revokedCertIds: [],
    };

    const verdict = verifyLibraryReleaseCertificateOffline({cert: airGappedCert, policy, kv});
    expect(verdict.kind).toBe('Proven');
    if (verdict.kind !== 'Proven') throw new Error('expected Proven');
    expect(verdict.verifiedTheoremCount).toBe(96);
    expect(verdict.verifiedWitnessIds).toEqual(['w1', 'w2', 'w3']);
    kv.gcUnreferenced();
    expect(kv.hasBlob(verdict.pinnedOfflineReceiptHash!)).toBe(true);
  });

  test('AG168: Adversarial Offline Forgery Matrix blocks all 7 attack vectors (sig, count, purity, quorum/dup, stale epoch, revoked cert, digest mismatch)', () => {
    const publisher = new LibraryReleaseSigningKey('pub-168');
    const attacker = new LibraryReleaseSigningKey('attacker-168');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const attDigest = sha256Digest({release: 168});

    const basePolicy: OfflineReleaseVerifierPolicy = {
      expectedAttestationDigest: attDigest,
      trustedPublisherPublicKeyPem: publisher.publicKeyPem,
      registeredWitnessPublicKeys: Object.fromEntries(
        witnesses.map(w => [w.publisherId, w.publicKeyPem]),
      ),
      minWitnessThreshold: 3,
      minRequiredTheorems: 96,
      minAllowedEpoch: 32,
      revokedCertIds: ['cert-revoked-168'],
    };

    const basePayload = {
      certId: 'cert-ok-168',
      publisherId: publisher.publisherId,
      facadeModule: LEANPOO_RELEASE_CERT_FACADE_MODULE,
      attestationDigest: attDigest,
      releaseEpoch: 32,
      moduleCount: 8,
      verifiedTheoremCount: 96,
      quintModelCount: 19,
      zeroMathlib: true,
      zeroCedar: true,
    };

    // 1. Forged publisher Ed25519 signature (signed by attacker):
    const forgedPub = issueSignedLibraryReleaseCertificate({
      payload: basePayload,
      publisherKey: attacker,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: forgedPub, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'invalid-publisher-ed25519-signature'});

    // 2. Downgraded theorem count (76 < 96):
    const lowCount = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, verifiedTheoremCount: 76},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: lowCount, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'downgraded-theorem-count'});

    // 3. Impure Library (zeroMathlib = false OR zeroCedar = false):
    const impureMathlib = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, zeroMathlib: false},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: impureMathlib, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'impure-library-mathlib-or-cedar-detected'});

    const impureCedar = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, zeroCedar: false},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: impureCedar, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'impure-library-mathlib-or-cedar-detected'});

    // 4. Sub-quorum / duplicate witness stuffing (w1 repeated 3 times = only 1 distinct witness!):
    const dupWitness = issueSignedLibraryReleaseCertificate({
      payload: basePayload,
      publisherKey: publisher,
      witnessKeys: [witnesses[0]!, witnesses[0]!, witnesses[0]!],
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: dupWitness, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'insufficient-valid-witness-quorum', validWitnessCount: 1});

    // 5. Anti-downgrade stale epoch (31 < 32):
    const staleEpoch = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, releaseEpoch: 31},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: staleEpoch, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'stale-release-epoch-downgrade'});

    // 6. Revoked certificate ID:
    const revokedCert = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, certId: 'cert-revoked-168'},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: revokedCert, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'revoked-release-certificate'});

    // 7. Cross-release expected digest mismatch:
    const wrongDigest = issueSignedLibraryReleaseCertificate({
      payload: {...basePayload, attestationDigest: sha256Digest({otherRelease: 999})},
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });
    expect(
      verifyLibraryReleaseCertificateOffline({cert: wrongDigest, policy: basePolicy}),
    ).toEqual({kind: 'Refuted', reason: 'mismatched-expected-attestation-digest'});
  });

  test('AG169: Air-Gapped cedar-poo-spec Runtime consumes offline-verified 96-theorem cert & survives R1 disjoint Cedar upgrade + GC', () => {
    const kv = new ContentAddressedKvStore();
    const publisher = new LibraryReleaseSigningKey('pub-169');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({airgap169: 96});

    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-airgap-169',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_RELEASE_CERT_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 32,
        moduleCount: 8,
        verifiedTheoremCount: 96,
        quintModelCount: 19,
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
        minRequiredTheorems: 96,
        minAllowedEpoch: 32,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    // cedar-poo-spec Dual-Sovereign Gate consumes the offline-verified digest (zero lake call!):
    const lease = new LiveM3Capability('lease-airgap-169', 'runtime:admit', 32);
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
        policySnapshotDigest: sha256Digest({cedarSnap: 'v32'}),
        policyAffectedScopes: ['runtime:admit'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarSnap: 'v33-disjoint'}),
      policyChangedScopes: ['docs:editorial'],
      activeLeaseEpoch: 32,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);

  test('AG170: 170-Case Milestone — 9/9 R3 Non-Leakable M3 Capabilities & Live 96-Theorem CLI JSON Verification', () => {
    const kv = new ContentAddressedKvStore();

    // All 9 R3 non-serializable M3 capability classes MUST refuse M1 persistence:
    const all9R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-170', 'scope:170', 1),
      new AeadPartitionKey('tenant-170'),
      new DelegationRootKey('root-170'),
      new LinearBudgetTree('agent-170', 100),
      new DeclassificationCapability('declass-170', ['tenant:170']),
      new CoordinatorSigningKey('log-170'),
      new WitnessCosigningKey('w-170'),
      new ForwardSecureWitnessKey('fw-170', 1),
      new LibraryReleaseSigningKey('pub-170'),
    ];
    expect(all9R3Caps.length).toBe(9);
    for (const cap of all9R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe', {nested: {cap}})).toThrow(/R3 ReachabilityLeakError/);
    }

    if (!isLeanToolchainAvailable()) return;
    const cliPath = resolve(import.meta.dir, 'leanpoo-fleet-audit.ts');
    const proc = spawnSync('bun', [cliPath, '--json'], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    expect(proc.status).toBe(0);
    const out = JSON.parse(proc.stdout) as {
      verdict: string;
      moduleCount: number;
      verifiedTheoremCount: number;
      quintModelCount: number;
      zeroMathlib: boolean;
      zeroCedar: boolean;
    };
    expect(out.verdict).toBe('Proven');
    expect(out.moduleCount).toBe(8);
    expect(out.verifiedTheoremCount).toBe(96);
    expect(out.quintModelCount).toBe(19);
    expect(out.zeroMathlib).toBe(true);
    expect(out.zeroCedar).toBe(true);
  }, 45_000);
});
