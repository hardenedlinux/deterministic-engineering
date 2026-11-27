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
} from './post-quantum-crypto-agility.ts';
import {
  verifyZkComplianceDisclosureOffline,
  ZkProverWitnessKey,
  type ZkComplianceVerificationPolicy,
} from './zk-selective-disclosure.ts';
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
  LEANPOO_TOP_FACADE_MODULE,
  LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';

const ZK_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
)!.theorems;

describe('Phase 47 — B18 Zero-Knowledge Selective-Disclosure Compliance Proofs & 250-Case / 17-Module / 186-Theorem Grand Seal (10.195 / 30.05 AG246-AG250)', () => {
  test('AG246: Live Lean 4 / LeanPoo verifies all 10 ZeroKnowledgeSelectiveDisclosure theorems + single-shot 186/186-theorem 17-module fleet attestation', () => {
    expect(ZK_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(17);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(186);
    expect(
      LEANPOO_LIBRARY_EXPORT_MANIFEST.some(m => m.moduleName === LEANPOO_ZK_DISCLOSURE_FACADE_MODULE),
    ).toBe(true);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
          namespacePrefix: LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
          expectedTheorems: ZK_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
      namespacePrefix: LEANPOO_ZK_DISCLOSURE_FACADE_MODULE,
      expectedTheorems: ZK_THEOREMS,
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

  test('AG247: Real RFC 3526 MODP-2048 Schnorr Sigma NIZK + Salted Merkle Selective Disclosure verifies public predicates while hiding confidential PII & rejecting forgery', () => {
    const kv = new ContentAddressedKvStore();
    const prover = new ZkProverWitnessKey('tenant-prover-247', [
      {fieldId: 'soDApproved', value: true, confidential: false},
      {fieldId: 'riskBand', value: 'low', confidential: false},
      {fieldId: 'customerSsn', value: '123-45-6789', confidential: true},
      {fieldId: 'accountBalanceCents', value: 987654321, confidential: true},
    ]);
    const pub = prover.exportPublicBundle();
    const policyDigestHex = sha256Digest({regPolicy: 'eu-ai-act-2026'});

    // Prover-side fence blocks accidental disclosure of confidential fields by default:
    expect(() =>
      prover.generateSelectiveDisclosureProof({
        domainTag: 'b18-compliance-audit-v1',
        verifierNonce: 'nonce-247-a',
        policyDigestHex,
        discloseFieldIds: ['soDApproved', 'customerSsn'],
      }),
    ).toThrow(/B18 Prover Fence/);

    // Clean selective disclosure reveals ONLY public compliance predicates:
    const proof = prover.generateSelectiveDisclosureProof({
      domainTag: 'b18-compliance-audit-v1',
      verifierNonce: 'nonce-247-a',
      policyDigestHex,
      discloseFieldIds: ['soDApproved', 'riskBand'],
    });
    const serialized = JSON.stringify(proof);
    expect(serialized).not.toContain('123-45-6789');
    expect(serialized).not.toContain('987654321');

    const policy: ZkComplianceVerificationPolicy = {
      expectedDomainTag: 'b18-compliance-audit-v1',
      expectedVerifierNonce: 'nonce-247-a',
      expectedPolicyDigestHex: policyDigestHex,
      trustedProvers: {[pub.proverId]: pub},
      forbiddenSecretFieldIds: ['customerSsn', 'accountBalanceCents'],
      requiredPublicFieldIds: ['soDApproved', 'riskBand'],
      spentNullifiers: [],
    };

    const ok = verifyZkComplianceDisclosureOffline({
      proof: JSON.parse(serialized),
      policy,
      kv,
    });
    expect(ok.kind).toBe('Proven');
    if (ok.kind !== 'Proven') throw new Error('expected Proven');
    expect(ok.disclosedValues).toEqual({soDApproved: true, riskBand: 'low'});

    // 1. Tamper Schnorr Sigma scalar response s -> refused:
    const forgedS = (BigInt('0x' + proof.sigmaResponseSHex) + 1n).toString(16);
    expect(
      verifyZkComplianceDisclosureOffline({proof: {...proof, sigmaResponseSHex: forgedS}, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'zk-sigma-proof-invalid'});

    // 2. Tamper disclosed attribute value ('low' -> 'critical') -> Merkle opening refused:
    const forgedOpenings = proof.disclosedOpenings.map(o =>
      o.fieldId === 'riskBand' ? {...o, value: 'critical'} : o,
    );
    expect(
      verifyZkComplianceDisclosureOffline({
        proof: {...proof, disclosedOpenings: forgedOpenings},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'merkle-opening-invalid'});

    kv.gcUnreferenced();
    expect(kv.hasBlob(ok.pinnedReceiptHash!)).toBe(true);
  });

  test('AG248: Verifier refuses all 6 adversarial ZK compliance attacks (over-disclosure, nullifier replay, stale nonce, policy mismatch, missing required field, wrong commitment root)', () => {
    const prover = new ZkProverWitnessKey('tenant-prover-248', [
      {fieldId: 'soDApproved', value: true, confidential: false},
      {fieldId: 'riskBand', value: 'low', confidential: false},
      {fieldId: 'customerSsn', value: '999-88-7777', confidential: true},
    ]);
    const pub = prover.exportPublicBundle();
    const policyDigestHex = sha256Digest({regPolicy: 'sox-v47'});

    const cleanProof = prover.generateSelectiveDisclosureProof({
      domainTag: 'b18-audit-248',
      verifierNonce: 'nonce-248',
      policyDigestHex,
      discloseFieldIds: ['soDApproved', 'riskBand'],
    });
    const overDisclosedProof = prover.generateSelectiveDisclosureProof({
      domainTag: 'b18-audit-248',
      verifierNonce: 'nonce-248',
      policyDigestHex,
      discloseFieldIds: ['soDApproved', 'riskBand', 'customerSsn'],
      allowUnsafeOverDisclosureForNegativeTest: true,
    });
    const incompleteProof = prover.generateSelectiveDisclosureProof({
      domainTag: 'b18-audit-248',
      verifierNonce: 'nonce-248',
      policyDigestHex,
      discloseFieldIds: ['soDApproved'],
    });

    const basePolicy: ZkComplianceVerificationPolicy = {
      expectedDomainTag: 'b18-audit-248',
      expectedVerifierNonce: 'nonce-248',
      expectedPolicyDigestHex: policyDigestHex,
      trustedProvers: {[pub.proverId]: pub},
      forbiddenSecretFieldIds: ['customerSsn'],
      requiredPublicFieldIds: ['soDApproved', 'riskBand'],
      spentNullifiers: [],
    };

    // 1. Over-disclosure of confidential field refused:
    expect(
      verifyZkComplianceDisclosureOffline({proof: overDisclosedProof, policy: basePolicy}),
    ).toMatchObject({kind: 'Refuted', reason: 'over-disclosure-of-secret-field'});

    // 2. Nullifier replay refused:
    expect(
      verifyZkComplianceDisclosureOffline({
        proof: cleanProof,
        policy: {...basePolicy, spentNullifiers: [cleanProof.nullifierHex]},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'nullifier-replay-detected'});

    // 3. Stale verifier challenge nonce refused:
    expect(
      verifyZkComplianceDisclosureOffline({
        proof: cleanProof,
        policy: {...basePolicy, expectedVerifierNonce: 'nonce-248-fresh'},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'domain-or-nonce-or-policy-mismatch'});

    // 4. Policy digest mismatch refused:
    expect(
      verifyZkComplianceDisclosureOffline({
        proof: cleanProof,
        policy: {...basePolicy, expectedPolicyDigestHex: sha256Digest({regPolicy: 'other'})},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'domain-or-nonce-or-policy-mismatch'});

    // 5. Missing mandatory public compliance field refused:
    expect(
      verifyZkComplianceDisclosureOffline({proof: incompleteProof, policy: basePolicy}),
    ).toMatchObject({kind: 'Refuted', reason: 'missing-required-public-field'});

    // 6. Wrong commitment root refused:
    expect(
      verifyZkComplianceDisclosureOffline({
        proof: {...cleanProof, commitmentRootHex: 'f'.repeat(64)},
        policy: basePolicy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'commitment-root-mismatch'});
  });

  test('AG249: All 15/15 R3 Non-Leakable M3 Capability Classes (including ZkProverWitnessKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all15R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-249', 'scope:249', 1),
      new AeadPartitionKey('tenant-249'),
      new DelegationRootKey('root-249'),
      new LinearBudgetTree('agent-249', 249),
      new DeclassificationCapability('declass-249', ['tenant:249']),
      new CoordinatorSigningKey('log-249'),
      new WitnessCosigningKey('w-249'),
      new ForwardSecureWitnessKey('fw-249', 1),
      new LibraryReleaseSigningKey('pub-249'),
      new ToolSandboxCapability('agent-249', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-249'),
      new EnclaveRootAttestationKey('tee-node-249'),
      new RotatableTenantAeadKeyRing('tenant-ring-249', 1),
      new HybridPqSigningKey('pq-signer-249', 2),
      new ZkProverWitnessKey('zk-prover-249', [{fieldId: 'ok', value: true, confidential: false}]),
    ];
    expect(all15R3Caps.length).toBe(15);
    for (const cap of all15R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-249', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG250: 250-Case & 17-Module / 186-Theorem Grand Milestone — 26 Quint x 44x24 ASCENT x 186-Thm CLI + PQ Hybrid + ZK Compliance + 90.153 -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    const repoRoot = resolve(import.meta.dir, '../../../..');
    expect(
      existsSync(
        resolve(
          repoRoot,
          'docs/90-99-views/90-architecture-views/90.153-250-case-186-theorem-b1-b18-panoramic-architecture.svg',
        ),
      ),
    ).toBe(true);

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
      : sha256Digest({milestone: 250, quint: 26, modules: 17, theorems: 186});

    // 1. B17 PQ Hybrid signature over the 186-theorem fleet attestation digest:
    const pqKey = new HybridPqSigningKey('pq-authority-250', 2);
    const pqEnv = pqKey.signHybridDigest({
      domainTag: 'library-release-pq-v47',
      payloadDigestHex: attDigest,
    });
    const pqVerified = verifyHybridPqSignatureOffline({
      envelope: JSON.parse(JSON.stringify(pqEnv)),
      policy: {
        minRequiredSuiteLevel: 2,
        expectedDomainTag: 'library-release-pq-v47',
        deprecatedSuites: ['legacy-sha1'],
        trustedSigners: {[pqKey.signerId]: pqKey.exportPublicBundle()},
      },
      kv,
    });
    expect(pqVerified.kind).toBe('Proven');
    if (pqVerified.kind !== 'Proven') throw new Error('expected Proven');

    // 2. B18 Zero-Knowledge Selective-Disclosure Compliance Proof bound to attDigest (hiding confidential PII):
    const zkProver = new ZkProverWitnessKey('zk-compliance-250', [
      {fieldId: 'fourParadigmProven', value: true, confidential: false},
      {fieldId: 'zeroMathlibAndCedar', value: true, confidential: false},
      {fieldId: 'tenantInternalPii', value: 'TOP-SECRET-PII-250', confidential: true},
    ]);
    const zkProof = zkProver.generateSelectiveDisclosureProof({
      domainTag: 'b18-release-compliance-v47',
      verifierNonce: 'nonce-milestone-250',
      policyDigestHex: attDigest,
      discloseFieldIds: ['fourParadigmProven', 'zeroMathlibAndCedar'],
    });
    const zkVerified = verifyZkComplianceDisclosureOffline({
      proof: JSON.parse(JSON.stringify(zkProof)),
      policy: {
        expectedDomainTag: 'b18-release-compliance-v47',
        expectedVerifierNonce: 'nonce-milestone-250',
        expectedPolicyDigestHex: attDigest,
        trustedProvers: {[zkProver.proverId]: zkProver.exportPublicBundle()},
        forbiddenSecretFieldIds: ['tenantInternalPii'],
        requiredPublicFieldIds: ['fourParadigmProven', 'zeroMathlibAndCedar'],
        spentNullifiers: [],
      },
      kv,
    });
    expect(zkVerified.kind).toBe('Proven');
    if (zkVerified.kind !== 'Proven') throw new Error('expected Proven');

    // 3. Air-Gapped 3-of-4 Ed25519 Release Certificate -> cedar-poo-spec Dual-Sovereign Gate:
    const publisher = new LibraryReleaseSigningKey('pub-250');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v47-250case-186thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 47,
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
        minAllowedEpoch: 47,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-250', 'release:b1-b18-250-seal', 47);
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
        policySnapshotDigest: sha256Digest({cedarPolicy: 'v47-250-seal'}),
        policyAffectedScopes: ['release:b1-b18-250-seal'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarPolicy: 'v47-250-seal'}),
      activeLeaseEpoch: 47,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(pqVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(zkVerified.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
