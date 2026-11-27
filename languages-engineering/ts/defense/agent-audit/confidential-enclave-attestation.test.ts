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
import {
  BuilderAttestationSigningKey,
  issueBuildProvenanceAttestation,
  verifyHermeticBuildProvenance,
} from './supply-chain-provenance.ts';
import {
  EnclaveRootAttestationKey,
  issueHardwareEnclaveQuote,
  verifyEnclaveQuoteForKeyRelease,
  type EnclaveKeyReleasePolicySpec,
} from './confidential-enclave-attestation.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';

const ENCLAVE_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
)!.theorems;

describe('Phase 41 — B15 Confidential Compute / Hardware TEE Enclave Attestation + 14-Module / 156-Theorem LeanPoo Library (10.189 / 90.152 / 30.05 AG216-AG220)', () => {
  test('AG216: Live Lean 4 / LeanPoo verifies all 10 ConfidentialEnclaveAttestation theorems + single-shot 156/156-theorem 14-module fleet attestation', () => {
    expect(ENCLAVE_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBe(14);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBe(156);
    expect(LEANPOO_TOP_FACADE_MODULE).toBe(LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
          namespacePrefix: LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
          expectedTheorems: ENCLAVE_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
      namespacePrefix: LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
      expectedTheorems: ENCLAVE_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(14);
    expect(fleet.verifiedTheoremCount).toBe(156);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG217: B15 TEE Key-Release Attack Matrix refuses all 9 hardware-attestation attack vectors', () => {
    const platKey = new EnclaveRootAttestationKey('tdx-node-eu-01');
    const rogueKey = new EnclaveRootAttestationKey('rogue-node-99');
    const expectedArt = sha256Digest({artifact: 'prod-enclave-v41'});
    const freshNonce = 'nonce-217-fresh';

    const policy: EnclaveKeyReleasePolicySpec = {
      expectedArtifactDigestHex: expectedArt,
      minRequiredTcbSvn: 12,
      expectedChallengeNonce: freshNonce,
      trustedPlatformPublicKeys: {[platKey.platformId]: platKey.publicKeyPem},
      revokedPlatformIds: [],
      consumedNonces: ['nonce-217-old'],
    };

    const makeQuote = (overrides: Partial<Parameters<typeof issueHardwareEnclaveQuote>[0]['payload']> = {}) =>
      issueHardwareEnclaveQuote({
        platformKey: platKey,
        payload: {
          quoteId: 'q-217',
          platformId: platKey.platformId,
          measuredEnclaveDigestHex: expectedArt,
          tcbSvn: 14,
          challengeNonce: freshNonce,
          debugModeDisabled: true,
          ...overrides,
        },
      });

    // 1. Debug-mode enclave:
    expect(verifyEnclaveQuoteForKeyRelease({quote: makeQuote({debugModeDisabled: false}), policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'debug-enclave-forbidden',
    });
    // 2. Measurement mismatch:
    expect(
      verifyEnclaveQuoteForKeyRelease({
        quote: makeQuote({measuredEnclaveDigestHex: sha256Digest({artifact: 'trojan-enclave'})}),
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'enclave-measurement-mismatch'});
    // 3. TCB SVN rollback:
    expect(verifyEnclaveQuoteForKeyRelease({quote: makeQuote({tcbSvn: 11}), policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'tcb-svn-rollback-detected',
    });
    // 4. Mismatched nonce:
    expect(
      verifyEnclaveQuoteForKeyRelease({quote: makeQuote({challengeNonce: 'wrong-nonce'}), policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'challenge-nonce-mismatch'});
    // 5. Replayed consumed nonce:
    expect(
      verifyEnclaveQuoteForKeyRelease({quote: makeQuote({challengeNonce: 'nonce-217-old'}), policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'challenge-nonce-replayed'});
    // 6. Tampered quote digest:
    const good = makeQuote();
    expect(
      verifyEnclaveQuoteForKeyRelease({
        quote: {...good, payload: {...good.payload, tcbSvn: 99}},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'quote-digest-tampered'});
    // 7. Forged hardware signature:
    const badSig = (good.hardwareSignatureHex.startsWith('a') ? 'b' : 'a') + good.hardwareSignatureHex.slice(1);
    expect(
      verifyEnclaveQuoteForKeyRelease({quote: {...good, hardwareSignatureHex: badSig}, policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'forged-hardware-signature'});
    // 8. Unregistered platform:
    const rogueQuote = issueHardwareEnclaveQuote({
      platformKey: rogueKey,
      payload: {
        quoteId: 'q-rogue',
        platformId: rogueKey.platformId,
        measuredEnclaveDigestHex: expectedArt,
        tcbSvn: 14,
        challengeNonce: freshNonce,
        debugModeDisabled: true,
      },
    });
    expect(verifyEnclaveQuoteForKeyRelease({quote: rogueQuote, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'unregistered-platform',
    });
    // 9. Revoked platform:
    expect(
      verifyEnclaveQuoteForKeyRelease({
        quote: good,
        policy: {...policy, revokedPlatformIds: [platKey.platformId]},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'revoked-platform'});
  });

  test('AG218: End-to-End B14 -> B15 Chain of Trust binds 2-builder reproducible artifact digest to running hardware TEE enclave across GC', () => {
    const kv = new ContentAddressedKvStore();
    const b1 = new BuilderAttestationSigningKey('builder-1-218');
    const b2 = new BuilderAttestationSigningKey('builder-2-218');
    const srcHash = sha256Digest({commit: '9495691'});
    const tcHash = sha256Digest({toolchain: 'lean4.34-hermetic'});
    const artHash = sha256Digest({enclaveImage: 'deterministic-agent-v41'});
    const depHash = sha256Digest({pkg: 'lean-poo@1.0.0'});

    const att1 = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b14-218-1',
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
        buildId: 'b14-218-2',
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

    // Now B15 hardware TEE boots the exact B14-verified artifact digest:
    const teeKey = new EnclaveRootAttestationKey('sev-snp-prod-01');
    const quote = issueHardwareEnclaveQuote({
      platformKey: teeKey,
      payload: {
        quoteId: 'quote-218-prod',
        platformId: teeKey.platformId,
        measuredEnclaveDigestHex: b14Res.artifactDigestHex,
        tcbSvn: 16,
        challengeNonce: 'fresh-challenge-218',
        debugModeDisabled: true,
      },
    });
    const b15Res = verifyEnclaveQuoteForKeyRelease({
      quote: JSON.parse(JSON.stringify(quote)),
      policy: {
        expectedArtifactDigestHex: b14Res.artifactDigestHex,
        minRequiredTcbSvn: 15,
        expectedChallengeNonce: 'fresh-challenge-218',
        trustedPlatformPublicKeys: {[teeKey.platformId]: teeKey.publicKeyPem},
        revokedPlatformIds: [],
      },
      kv,
    });
    expect(b15Res.kind).toBe('Proven');
    if (b15Res.kind !== 'Proven') throw new Error('expected Proven');
    expect(b15Res.measuredEnclaveDigestHex).toBe(artHash);

    kv.gcUnreferenced();
    expect(kv.hasBlob(b14Res.pinnedReceiptHash!)).toBe(true);
    expect(kv.hasBlob(b15Res.pinnedKeyReleaseReceiptHash!)).toBe(true);
  });

  test('AG219: All 12/12 R3 Non-Leakable M3 Capability Classes (including EnclaveRootAttestationKey) mechanically refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();
    const all12R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-219', 'scope:219', 1),
      new AeadPartitionKey('tenant-219'),
      new DelegationRootKey('root-219'),
      new LinearBudgetTree('agent-219', 219),
      new DeclassificationCapability('declass-219', ['tenant:219']),
      new CoordinatorSigningKey('log-219'),
      new WitnessCosigningKey('w-219'),
      new ForwardSecureWitnessKey('fw-219', 1),
      new LibraryReleaseSigningKey('pub-219'),
      new ToolSandboxCapability('agent-219', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-219'),
      new EnclaveRootAttestationKey('tee-node-219'),
    ];
    expect(all12R3Caps.length).toBe(12);
    for (const cap of all12R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-219', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }
  });

  test('AG220: 220-Case & 14-Module / 156-Theorem Grand Regression Seal — 23 Quint x 32x18 ASCENT x 156-Thm CLI + Air-Gapped Cert -> cedar-poo-spec', () => {
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
      expect(out.facadeModule).toBe(LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE);
      expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
      expect(out.ascentRulesPresent).toBe(true);
      expect(out.multiLangHarnessCount).toBe(8);
      expect(out.moduleCount).toBe(14);
      expect(out.verifiedTheoremCount).toBe(156);
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
      : sha256Digest({milestone: 220, quint: 23, modules: 14, theorems: 156});

    const publisher = new LibraryReleaseSigningKey('pub-220');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v41-14mod-156thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_ENCLAVE_ATTESTATION_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 41,
        moduleCount: 14,
        verifiedTheoremCount: 156,
        quintModelCount: 23,
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
        minAllowedEpoch: 41,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-220', 'release:b1-b15-tee', 41);
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
        policySnapshotDigest: sha256Digest({cedarTeePolicy: 'v41'}),
        policyAffectedScopes: ['release:b1-b15-tee'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarTeePolicy: 'v41'}),
      activeLeaseEpoch: 41,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
