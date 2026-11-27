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
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
  verifyConsistencyProof,
  verifySignedTreeHead,
} from './transparency-log-equivocation.ts';
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
  LEANPOO_KEY_ROTATION_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';

const KEY_ROTATION_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_KEY_ROTATION_FACADE_MODULE,
)!.theorems;

describe('Phase 43 — B16 Zero-Downtime AEAD Key Rotation & Cryptographic Erasure + 15-Module / 166-Theorem LeanPoo Library (10.191 / 30.05 AG226-AG230)', () => {
  test('AG226: Live Lean 4 / LeanPoo verifies all 10 KeyRotationAndCryptoShredding theorems + single-shot 166/166-theorem 15-module fleet attestation', () => {
    expect(KEY_ROTATION_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBe(15);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBe(166);
    expect(LEANPOO_TOP_FACADE_MODULE).toBe(LEANPOO_KEY_ROTATION_FACADE_MODULE);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_KEY_ROTATION_FACADE_MODULE,
          namespacePrefix: LEANPOO_KEY_ROTATION_FACADE_MODULE,
          expectedTheorems: KEY_ROTATION_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_KEY_ROTATION_FACADE_MODULE,
      namespacePrefix: LEANPOO_KEY_ROTATION_FACADE_MODULE,
      expectedTheorems: KEY_ROTATION_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(15);
    expect(fleet.verifiedTheoremCount).toBe(166);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG227: Zero-Downtime AEAD Key Rotation refuses stale-epoch writes & non-advancing re-wraps, preserves plaintext SHA-256 on re-wrap & blocks AAD transplant', () => {
    const kv = new ContentAddressedKvStore();
    const ringAlpha = new RotatableTenantAeadKeyRing('tenant-alpha', 1);
    const ringBeta = new RotatableTenantAeadKeyRing('tenant-beta', 1);

    const enc1 = ringAlpha.encryptEnvelope({
      kv,
      recordId: 'rec-227',
      plaintext: {ssnLast4: '4321', plan: 'enterprise'},
    });
    expect(enc1.kind).toBe('Proven');
    if (enc1.kind !== 'Proven') throw new Error('expected Proven');

    // Non-advancing re-wrap before rotation is refused:
    expect(
      ringAlpha.rewrapEnvelopeToActiveEpoch({kv, envelope: enc1.envelope}),
    ).toMatchObject({kind: 'Refuted', reason: 'rewrap-epoch-not-strictly-advancing'});

    // Rotate active epoch 1 -> 2:
    expect(ringAlpha.rotateEpoch()).toBe(2);

    // Stale-epoch new write under retired epoch 1 is refused:
    expect(
      ringAlpha.encryptEnvelope({
        kv,
        recordId: 'rec-stale',
        plaintext: {bad: true},
        requestedWriteEpoch: 1,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'stale-or-mismatched-write-epoch'});

    // Cross-tenant decrypt is refused:
    expect(ringBeta.decryptEnvelope(enc1.envelope)).toMatchObject({
      kind: 'Refuted',
      reason: 'tenant-aad-mismatch',
    });

    // AAD transplant (mutating recordId on ciphertext) fails AES-256-GCM authentication:
    expect(
      ringAlpha.decryptEnvelope({...enc1.envelope, recordId: 'rec-transplanted'}),
    ).toMatchObject({kind: 'Refuted', reason: 'aead-authentication-failed'});

    // Lossless re-wrap epoch 1 -> epoch 2 preserves plaintext digest verbatim:
    const rewrap = ringAlpha.rewrapEnvelopeToActiveEpoch({kv, envelope: enc1.envelope});
    expect(rewrap.kind).toBe('Proven');
    if (rewrap.kind !== 'Proven') throw new Error('expected Proven');
    expect(rewrap.fromEpoch).toBe(1);
    expect(rewrap.toEpoch).toBe(2);
    expect(rewrap.rewrappedEnvelope.plaintextDigestHex).toBe(enc1.envelope.plaintextDigestHex);

    const dec2 = ringAlpha.decryptEnvelope(rewrap.rewrappedEnvelope);
    expect(dec2.kind).toBe('Proven');
    if (dec2.kind !== 'Proven') throw new Error('expected Proven');
    expect(JSON.parse(dec2.plaintextJson)).toEqual({ssnLast4: '4321', plan: 'enterprise'});

    kv.gcUnreferenced();
    expect(kv.hasBlob(rewrap.rewrapReceiptHash)).toBe(true);
  });

  test('AG228: Cryptographic Erasure (GDPR Right-to-be-Forgotten vs. Immutable M1 Merkle Audit Log) shreds epoch 1 while keeping epoch 2 & Merkle root intact', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new CoordinatorSigningKey('log-gdpr-228');
    const log = new VerifiableTransparencyLog(coord);

    const ring = new RotatableTenantAeadKeyRing('tenant-gdpr', 1);
    const piiOld = ring.encryptEnvelope({
      kv,
      recordId: 'pii-erasure-target',
      plaintext: {email: 'alice@example.org', consent: 'revoked-later'},
    });
    const activeData = ring.encryptEnvelope({
      kv,
      recordId: 'active-ledger-record',
      plaintext: {ledgerId: 'L-228', amount: 500},
    });
    expect(piiOld.kind).toBe('Proven');
    expect(activeData.kind).toBe('Proven');
    if (piiOld.kind !== 'Proven' || activeData.kind !== 'Proven') throw new Error('expected Proven');

    // Anchor both encrypted M1 envelope hashes into the immutable RFC 6962 transparency log:
    log.appendEntry({envelopeHash: piiOld.envelope.envelopeMerkleHash});
    log.appendEntry({envelopeHash: activeData.envelope.envelopeMerkleHash});
    const sthBefore = log.issueSignedTreeHead(2);

    // Rotate to epoch 2 and re-wrap ONLY the active ledger record (leave piiOld on epoch 1):
    ring.rotateEpoch();
    const rewrappedActive = ring.rewrapEnvelopeToActiveEpoch({kv, envelope: activeData.envelope});
    expect(rewrappedActive.kind).toBe('Proven');
    if (rewrappedActive.kind !== 'Proven') throw new Error('expected Proven');

    // Execute GDPR cryptographic erasure on epoch 1:
    const tombstone = ring.cryptoShredEpoch({
      kv,
      epoch: 1,
      reason: 'GDPR-Article-17-right-to-erasure',
    });
    expect(ring.isEpochShredded(1)).toBe(true);

    // 1. Old epoch-1 PII ciphertext is PERMANENTLY unreadable:
    expect(ring.decryptEnvelope(piiOld.envelope)).toMatchObject({
      kind: 'Refuted',
      reason: 'epoch-crypto-shredded',
    });
    // 2. Active re-wrapped epoch-2 record remains 100% readable:
    const decActive = ring.decryptEnvelope(rewrappedActive.rewrappedEnvelope);
    expect(decActive.kind).toBe('Proven');
    // 3. Immutable M1 Merkle audit log root & inclusion proof remain 100% intact across GC!
    log.appendEntry({cryptoShredTombstone: tombstone.tombstoneMerkleHash});
    const sthAfter = log.issueSignedTreeHead(3);
    const consistency = log.getConsistencyProof(2, 3);
    expect(verifySignedTreeHead(sthBefore, coord.publicKeyPem)).toBe(true);
    expect(verifySignedTreeHead(sthAfter, coord.publicKeyPem)).toBe(true);
    expect(
      verifyConsistencyProof({
        firstSize: sthBefore.treeSize,
        secondSize: sthAfter.treeSize,
        firstRootHex: sthBefore.rootHashHex,
        secondRootHex: sthAfter.rootHashHex,
        proofHex: consistency,
      }),
    ).toBe(true);

    kv.gcUnreferenced();
    expect(kv.hasBlob(tombstone.tombstoneMerkleHash)).toBe(true);
    expect(kv.hasBlob(piiOld.envelope.envelopeMerkleHash)).toBe(true); // M1 hash intact, ciphertext unrecoverable!
  });

  test('AG229: All 13/13 R3 Non-Leakable M3 Capability Classes (including RotatableTenantAeadKeyRing) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all13R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-229', 'scope:229', 1),
      new AeadPartitionKey('tenant-229'),
      new DelegationRootKey('root-229'),
      new LinearBudgetTree('agent-229', 229),
      new DeclassificationCapability('declass-229', ['tenant:229']),
      new CoordinatorSigningKey('log-229'),
      new WitnessCosigningKey('w-229'),
      new ForwardSecureWitnessKey('fw-229', 1),
      new LibraryReleaseSigningKey('pub-229'),
      new ToolSandboxCapability('agent-229', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-229'),
      new EnclaveRootAttestationKey('tee-node-229'),
      new RotatableTenantAeadKeyRing('tenant-ring-229', 1),
    ];
    expect(all13R3Caps.length).toBe(13);
    for (const cap of all13R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-229', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG230: 230-Case & 15-Module / 166-Theorem Milestone — 24 Quint x 36x20 ASCENT x 166-Thm CLI JSON + Air-Gapped Cert -> cedar-poo-spec', () => {
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
      expect(out.facadeModule).toBe(LEANPOO_KEY_ROTATION_FACADE_MODULE);
      expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
      expect(out.ascentRulesPresent).toBe(true);
      expect(out.multiLangHarnessCount).toBe(8);
      expect(out.moduleCount).toBe(15);
      expect(out.verifiedTheoremCount).toBe(166);
      expect(out.zeroMathlib).toBe(true);
      expect(out.zeroCedar).toBe(true);
    }

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(24);
          expect(rep.leanPooModuleCount).toBe(15);
          expect(rep.leanPooTheoremCount).toBe(166);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 230, quint: 24, modules: 15, theorems: 166});

    const publisher = new LibraryReleaseSigningKey('pub-230');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v43-15mod-166thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_KEY_ROTATION_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 43,
        moduleCount: 15,
        verifiedTheoremCount: 166,
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
        minRequiredTheorems: 166,
        minAllowedEpoch: 43,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-230', 'release:b16-erasure', 43);
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
        policySnapshotDigest: sha256Digest({cedarErasurePolicy: 'v43'}),
        policyAffectedScopes: ['release:b16-erasure'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarErasurePolicy: 'v43'}),
      activeLeaseEpoch: 43,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
