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
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';
import {ToolSandboxCapability} from './tool-sandbox-rpc-boundary.ts';
import {BuilderAttestationSigningKey} from './supply-chain-provenance.ts';
import {EnclaveRootAttestationKey} from './confidential-enclave-attestation.ts';
import {RotatableTenantAeadKeyRing} from './key-rotation-crypto-shredding.ts';
import {
  HybridPqSigningKey,
  verifyHybridPqSignatureOffline,
  type HybridPqVerificationPolicy,
} from './post-quantum-crypto-agility.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_PQ_AGILITY_FACADE_MODULE,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';

const PQ_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_PQ_AGILITY_FACADE_MODULE,
)!.theorems;

describe('Phase 45 — B17 Post-Quantum Hybrid Cryptographic Agility & Anti-Downgrade + 16-Module / 176-Theorem LeanPoo Library (10.193 / 30.05 AG236-AG240)', () => {
  test('AG236: Live Lean 4 / LeanPoo verifies all 10 PostQuantumCryptoAgility theorems + single-shot 176/176-theorem 16-module fleet attestation', () => {
    expect(PQ_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBe(16);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBe(176);
    expect(LEANPOO_TOP_FACADE_MODULE).toBe(LEANPOO_PQ_AGILITY_FACADE_MODULE);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_PQ_AGILITY_FACADE_MODULE,
          namespacePrefix: LEANPOO_PQ_AGILITY_FACADE_MODULE,
          expectedTheorems: PQ_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_PQ_AGILITY_FACADE_MODULE,
      namespacePrefix: LEANPOO_PQ_AGILITY_FACADE_MODULE,
      expectedTheorems: PQ_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(16);
    expect(fleet.verifiedTheoremCount).toBe(176);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG237: Real Dual-AND Hybrid Combiner (Ed25519 AND SHA-256 Lamport-Diffie OTS Merkle Tree) verifies clean envelope & refuses mutating either leg', () => {
    const kv = new ContentAddressedKvStore();
    const key = new HybridPqSigningKey('pq-signer-237', 4);
    const pub = key.exportPublicBundle();
    const payloadDigest = sha256Digest({release: 'v45-long-horizon-merkle-root'});

    const env = key.signHybridDigest({
      domainTag: 'release-cert-pq-v1',
      payloadDigestHex: payloadDigest,
    });
    expect(env.otsLeafIndex).toBe(0);
    expect(key.remainingOtsLeaves).toBe(3);

    const policy: HybridPqVerificationPolicy = {
      minRequiredSuiteLevel: 2,
      expectedDomainTag: 'release-cert-pq-v1',
      deprecatedSuites: ['legacy-sha1'],
      trustedSigners: {[pub.signerId]: pub},
      usedOtsLeafIndicesBySigner: {},
    };

    // 1. Clean Dual-AND verification passes & pins M1 receipt across GC:
    const ok = verifyHybridPqSignatureOffline({
      envelope: JSON.parse(JSON.stringify(env)),
      policy,
      kv,
    });
    expect(ok.kind).toBe('Proven');
    if (ok.kind !== 'Proven') throw new Error('expected Proven');

    // 2. Flip classical Ed25519 signature -> refused even though PQ Lamport leg is valid:
    const badEd = (env.classicalSignatureHex.startsWith('a') ? 'b' : 'a') + env.classicalSignatureHex.slice(1);
    expect(
      verifyHybridPqSignatureOffline({envelope: {...env, classicalSignatureHex: badEd}, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'classical-ed25519-signature-invalid'});

    // 3. Flip 1 hex nibble in PQ Lamport preimage #17 -> refused even though Ed25519 leg is valid:
    const badPreimages = [...env.pqRevealedPreimagesHex];
    badPreimages[17] = (badPreimages[17]!.startsWith('0') ? '1' : '0') + badPreimages[17]!.slice(1);
    expect(
      verifyHybridPqSignatureOffline({envelope: {...env, pqRevealedPreimagesHex: badPreimages}, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'pq-lamport-signature-invalid'});

    // 4. Tamper PQ Merkle auth path -> refused:
    const badPath = env.pqMerkleAuthPath.map((s, idx) =>
      idx === 0 ? {...s, siblingHex: '0'.repeat(64)} : s,
    );
    expect(
      verifyHybridPqSignatureOffline({envelope: {...env, pqMerkleAuthPath: badPath}, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'pq-merkle-auth-path-invalid'});

    kv.gcUnreferenced();
    expect(kv.hasBlob(ok.pinnedReceiptHash!)).toBe(true);
  });

  test('AG238: Anti-Algorithm-Downgrade, Deprecated Suite, Domain Separation & Stateful OTS Leaf Anti-Reuse refuse all 5 agility attacks', () => {
    const key = new HybridPqSigningKey('pq-signer-238', 2);
    const pub = key.exportPublicBundle();
    const env0 = key.signHybridDigest({
      domainTag: 'governance-checkpoint-v1',
      payloadDigestHex: sha256Digest({ckpt: 1}),
    });
    const env1 = key.signHybridDigest({
      domainTag: 'governance-checkpoint-v1',
      payloadDigestHex: sha256Digest({ckpt: 2}),
    });
    expect(env1.otsLeafIndex).toBe(1);
    // Pool exhausted (2 of 2 leaves spent) -> MUST throw rather than reusing an OTS leaf!
    expect(() =>
      key.signHybridDigest({
        domainTag: 'governance-checkpoint-v1',
        payloadDigestHex: sha256Digest({ckpt: 3}),
      }),
    ).toThrow(/OTS pool exhausted/);

    const policy: HybridPqVerificationPolicy = {
      minRequiredSuiteLevel: 2,
      expectedDomainTag: 'governance-checkpoint-v1',
      deprecatedSuites: ['legacy-sha1'],
      trustedSigners: {[pub.signerId]: pub},
      usedOtsLeafIndicesBySigner: {[pub.signerId]: [0]},
    };

    // 1. Classical-only downgrade refused:
    expect(
      verifyHybridPqSignatureOffline({
        envelope: {...env1, suiteId: 'classical-ed25519-only'},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'algorithm-downgrade-refused'});

    // 2. Deprecated suite refused:
    expect(
      verifyHybridPqSignatureOffline({
        envelope: {...env1, suiteId: 'legacy-sha1'},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'deprecated-suite-refused'});

    // 3. Domain separation mismatch refused:
    expect(
      verifyHybridPqSignatureOffline({
        envelope: {...env1, domainTag: 'other-protocol'},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'domain-separation-mismatch'});

    // 4. Reused OTS leaf index 0 refused:
    expect(
      verifyHybridPqSignatureOffline({envelope: env0, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'ots-leaf-reuse-detected'});

    // 5. Fresh unused OTS leaf index 1 passes cleanly:
    expect(verifyHybridPqSignatureOffline({envelope: env1, policy}).kind).toBe('Proven');
  });

  test('AG239: All 14/14 R3 Non-Leakable M3 Capability Classes (including HybridPqSigningKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all14R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-239', 'scope:239', 1),
      new AeadPartitionKey('tenant-239'),
      new DelegationRootKey('root-239'),
      new LinearBudgetTree('agent-239', 239),
      new DeclassificationCapability('declass-239', ['tenant:239']),
      new CoordinatorSigningKey('log-239'),
      new WitnessCosigningKey('w-239'),
      new ForwardSecureWitnessKey('fw-239', 1),
      new LibraryReleaseSigningKey('pub-239'),
      new ToolSandboxCapability('agent-239', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-239'),
      new EnclaveRootAttestationKey('tee-node-239'),
      new RotatableTenantAeadKeyRing('tenant-ring-239', 1),
      new HybridPqSigningKey('pq-signer-239', 2),
    ];
    expect(all14R3Caps.length).toBe(14);
    for (const cap of all14R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-239', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG240: 240-Case & 16-Module / 176-Theorem Milestone — 25 Quint x 40x22 ASCENT x 176-Thm CLI + PQ Hybrid Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    if (isLeanToolchainAvailable()) {
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
      expect(out.facadeModule).toBe(LEANPOO_PQ_AGILITY_FACADE_MODULE);
      expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
      expect(out.ascentRulesPresent).toBe(true);
      expect(out.multiLangHarnessCount).toBe(8);
      expect(out.moduleCount).toBe(16);
      expect(out.verifiedTheoremCount).toBe(176);
      expect(out.zeroMathlib).toBe(true);
      expect(out.zeroCedar).toBe(true);
    }

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(16);
          expect(rep.leanPooTheoremCount).toBe(176);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 240, quint: 25, modules: 16, theorems: 176});

    // Co-sign the release attestation digest with Hybrid Ed25519 + PQ Lamport-Diffie key:
    const pqKey = new HybridPqSigningKey('pq-release-authority-240', 2);
    const pqEnv = pqKey.signHybridDigest({
      domainTag: 'library-release-pq-v45',
      payloadDigestHex: attDigest,
    });
    const pqVerified = verifyHybridPqSignatureOffline({
      envelope: JSON.parse(JSON.stringify(pqEnv)),
      policy: {
        minRequiredSuiteLevel: 2,
        expectedDomainTag: 'library-release-pq-v45',
        deprecatedSuites: ['legacy-sha1'],
        trustedSigners: {[pqKey.signerId]: pqKey.exportPublicBundle()},
      },
      kv,
    });
    expect(pqVerified.kind).toBe('Proven');
    if (pqVerified.kind !== 'Proven') throw new Error('expected Proven');

    const publisher = new LibraryReleaseSigningKey('pub-240');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v45-16mod-176thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_PQ_AGILITY_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 45,
        moduleCount: 16,
        verifiedTheoremCount: 176,
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
        minRequiredTheorems: 176,
        minAllowedEpoch: 45,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-240', 'release:b17-pq-hybrid', 45);
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
        policySnapshotDigest: sha256Digest({cedarPqPolicy: 'v45'}),
        policyAffectedScopes: ['release:b17-pq-hybrid'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPqPolicy: 'v45'}),
      activeLeaseEpoch: 45,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(pqVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
