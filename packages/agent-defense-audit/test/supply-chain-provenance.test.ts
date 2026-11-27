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
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from '../src/leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from '../src/leanpoo-fleet-audit.ts';
import {
  BuilderAttestationSigningKey,
  issueBuildProvenanceAttestation,
  verifyHermeticBuildProvenance,
  type HermeticSupplyChainPolicy,
} from '../src/supply-chain-provenance.ts';

const SUPPLY_CHAIN_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
)!.theorems;

describe('Phase 39 — B14 Hermetic Supply-Chain & Reproducible Build Provenance + 13-Module / 146-Theorem LeanPoo Library (10.187 / 30.05 AG206-AG210)', () => {
  test('AG206: Live Lean 4 / LeanPoo verifies all 10 SupplyChainProvenance theorems + single-shot fleet attestation', () => {
    expect(SUPPLY_CHAIN_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBeGreaterThanOrEqual(13);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBeGreaterThanOrEqual(146);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
          namespacePrefix: LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
          expectedTheorems: SUPPLY_CHAIN_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
      namespacePrefix: LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
      expectedTheorems: SUPPLY_CHAIN_THEOREMS,
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

  test('AG207: B14 Anti-Slopsquatting, CVE-Tombstone, Hermeticity & Source/Toolchain Digest Binding refuse all 5 supply-chain attacks', () => {
    const b1 = new BuilderAttestationSigningKey('builder-eu-1');
    const b2 = new BuilderAttestationSigningKey('builder-us-2');
    const srcHash = sha256Digest({commit: 'e8a2cef'});
    const tcHash = sha256Digest({lean: '4.34.0', bun: '1.3.11'});
    const artHash = sha256Digest({artifact: 'bin-v39'});
    const depGood = sha256Digest({pkg: 'lean-poo@1.0.0'});
    const depSlop = sha256Digest({pkg: 'hallucinated-ai-pkg@9.9.9'});
    const depCve = sha256Digest({pkg: 'compromised-xz@5.6.1'});

    const policy: HermeticSupplyChainPolicy = {
      expectedSourceDigestHex: srcHash,
      expectedToolchainDigestHex: tcHash,
      pinnedLockfileDigests: [depGood, depCve],
      revokedCveDigests: [depCve],
      trustedBuilderPublicKeys: {
        [b1.builderId]: b1.publicKeyPem,
        [b2.builderId]: b2.publicKeyPem,
      },
      revokedBuilderIds: [],
      requireTwoBuilderReproducibility: false,
    };

    // 1. Slopsquatting / unpinned dependency:
    const attSlop = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-207-slop',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [
          {packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depGood},
          {packageName: 'hallucinated-ai-pkg', version: '9.9.9', contentDigestHex: depSlop},
        ],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: attSlop, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'unpinned-slopsquatting-dependency',
    });

    // 2. CVE-tombstoned dependency (even if still listed in old lockfile!):
    const attCve = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-207-cve',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'compromised-xz', version: '5.6.1', contentDigestHex: depCve}],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: attCve, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'tombstoned-cve-dependency',
    });

    // 3. Non-hermetic network-leaking build:
    const attNet = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-207-net',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: false,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depGood}],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: attNet, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'non-hermetic-network-build',
    });

    // 4. Source digest mismatch:
    const attBadSrc = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-207-src',
        builderId: b1.builderId,
        sourceDigestHex: sha256Digest({commit: 'backdoored-branch'}),
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depGood}],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: attBadSrc, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'source-digest-mismatch',
    });

    // 5. Toolchain digest mismatch:
    const attBadTc = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-207-tc',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: sha256Digest({compiler: 'trojaned-cc'}),
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'lean-poo', version: '1.0.0', contentDigestHex: depGood}],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: attBadTc, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'toolchain-digest-mismatch',
    });
  });

  test('AG208: B14 2-Builder Reproducible-Build Parity & Ed25519 Cryptography catch Ken Thompson divergence, self-reproduction & forged/revoked builders', () => {
    const b1 = new BuilderAttestationSigningKey('builder-primary');
    const b2 = new BuilderAttestationSigningKey('builder-reproducer');
    const rogue = new BuilderAttestationSigningKey('builder-rogue');
    const srcHash = sha256Digest({commit: 'v39'});
    const tcHash = sha256Digest({toolchain: 'hermetic-v39'});
    const artClean = sha256Digest({bytes: 'clean-binary'});
    const artBackdoor = sha256Digest({bytes: 'compiler-injected-backdoor'});
    const depGood = sha256Digest({pkg: 'core@1.0'});

    const policy: HermeticSupplyChainPolicy = {
      expectedSourceDigestHex: srcHash,
      expectedToolchainDigestHex: tcHash,
      pinnedLockfileDigests: [depGood],
      revokedCveDigests: [],
      trustedBuilderPublicKeys: {
        [b1.builderId]: b1.publicKeyPem,
        [b2.builderId]: b2.publicKeyPem,
      },
      revokedBuilderIds: [],
      requireTwoBuilderReproducibility: true,
    };

    const primary = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'b-208',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artClean,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'core', version: '1.0', contentDigestHex: depGood}],
      },
    });

    // 1. Self-reproduction does NOT satisfy 2-builder reproducibility:
    expect(
      verifyHermeticBuildProvenance({primary, reproducers: [primary], policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'missing-independent-reproducer'});

    // 2. Diverging 2nd builder output (Trusting Trust / backdoor) is refused:
    const divergingRep = issueBuildProvenanceAttestation({
      builderKey: b2,
      payload: {
        buildId: 'b-208-rep',
        builderId: b2.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artBackdoor,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'core', version: '1.0', contentDigestHex: depGood}],
      },
    });
    expect(
      verifyHermeticBuildProvenance({primary, reproducers: [divergingRep], policy}),
    ).toMatchObject({kind: 'Refuted', reason: 'reproducible-build-mismatch'});

    // 3. Forged builder signature (flipped hex nibble):
    const forgedSig =
      (primary.builderSignatureHex.startsWith('a') ? 'b' : 'a') +
      primary.builderSignatureHex.slice(1);
    expect(
      verifyHermeticBuildProvenance({
        primary: {...primary, builderSignatureHex: forgedSig},
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'forged-builder-signature'});

    // 4. Payload tampered without updating digest:
    expect(
      verifyHermeticBuildProvenance({
        primary: {
          ...primary,
          payload: {...primary.payload, artifactDigestHex: artBackdoor},
        },
        policy,
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'payload-digest-tampered'});

    // 5. Unregistered rogue builder:
    const rogueAtt = issueBuildProvenanceAttestation({
      builderKey: rogue,
      payload: {
        buildId: 'b-208-rogue',
        builderId: rogue.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artClean,
        hermeticNoNetwork: true,
        sbomDeps: [{packageName: 'core', version: '1.0', contentDigestHex: depGood}],
      },
    });
    expect(verifyHermeticBuildProvenance({primary: rogueAtt, policy})).toMatchObject({
      kind: 'Refuted',
      reason: 'unregistered-builder',
    });

    // 6. Revoked builder:
    expect(
      verifyHermeticBuildProvenance({
        primary,
        policy: {...policy, revokedBuilderIds: [b1.builderId]},
      }),
    ).toMatchObject({kind: 'Refuted', reason: 'revoked-builder'});
  });

  test('AG209: Clean 2-Builder Hermetic SLSA/in-toto Provenance survives GC & all 11/11 R3 M3 Capability Classes refuse M1 persistence', () => {
    const kv = new ContentAddressedKvStore();

    // 1. All 11 R3 non-serializable M3 capability classes mechanically refuse M1 persistence:
    const all11R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-209', 'scope:209', 1),
      new AeadPartitionKey('tenant-209'),
      new DelegationRootKey('root-209'),
      new LinearBudgetTree('agent-209', 209),
      new DeclassificationCapability('declass-209', ['tenant:209']),
      new CoordinatorSigningKey('log-209'),
      new WitnessCosigningKey('w-209'),
      new ForwardSecureWitnessKey('fw-209', 1),
      new LibraryReleaseSigningKey('pub-209'),
      new ToolSandboxCapability('agent-209', ['db:read'], 1),
      new BuilderAttestationSigningKey('builder-209'),
    ];
    expect(all11R3Caps.length).toBe(11);
    for (const cap of all11R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-209', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }

    // 2. Clean 2-builder reproducible hermetic build verification + GC survival:
    const b1 = new BuilderAttestationSigningKey('builder-alpha');
    const b2 = new BuilderAttestationSigningKey('builder-beta');
    const srcHash = sha256Digest({commit: 'v39-clean'});
    const tcHash = sha256Digest({toolchain: 'pinned-v39'});
    const artHash = sha256Digest({binary: 'deterministic-release-v39'});
    const dep1 = sha256Digest({pkg: 'lean-poo@1.0.0'});
    const dep2 = sha256Digest({pkg: 'gerbil-ascent@0.18'});

    const primary = issueBuildProvenanceAttestation({
      builderKey: b1,
      payload: {
        buildId: 'build-209-clean',
        builderId: b1.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [
          {packageName: 'lean-poo', version: '1.0.0', contentDigestHex: dep1},
          {packageName: 'gerbil-ascent', version: '0.18', contentDigestHex: dep2},
        ],
      },
    });
    const reproducer = issueBuildProvenanceAttestation({
      builderKey: b2,
      payload: {
        buildId: 'build-209-repro',
        builderId: b2.builderId,
        sourceDigestHex: srcHash,
        toolchainDigestHex: tcHash,
        artifactDigestHex: artHash,
        hermeticNoNetwork: true,
        sbomDeps: [
          {packageName: 'gerbil-ascent', version: '0.18', contentDigestHex: dep2},
          {packageName: 'lean-poo', version: '1.0.0', contentDigestHex: dep1},
        ],
      },
    });

    const verified = verifyHermeticBuildProvenance({
      primary: JSON.parse(JSON.stringify(primary)),
      reproducers: [JSON.parse(JSON.stringify(reproducer))],
      policy: {
        expectedSourceDigestHex: srcHash,
        expectedToolchainDigestHex: tcHash,
        pinnedLockfileDigests: [dep1, dep2],
        revokedCveDigests: [],
        trustedBuilderPublicKeys: {
          [b1.builderId]: b1.publicKeyPem,
          [b2.builderId]: b2.publicKeyPem,
        },
        revokedBuilderIds: [],
        requireTwoBuilderReproducibility: true,
      },
      kv,
    });
    expect(verified.kind).toBe('Proven');
    if (verified.kind !== 'Proven') throw new Error('expected Proven');
    expect(verified.verifiedReproducerIds).toEqual(['builder-beta']);
    kv.gcUnreferenced();
    expect(kv.hasBlob(verified.pinnedReceiptHash!)).toBe(true);
  });

  test('AG210: 210-Case & 13-Module / 146-Theorem Milestone — 22 Quint x 146-Thm CLI JSON + Air-Gapped Ed25519 Cert -> cedar-poo-spec', () => {
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
          expect(rep.leanPooModuleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 210, quint: 22, modules: 13, theorems: 146});

    const publisher = new LibraryReleaseSigningKey('pub-210');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v39-13mod-146thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_SUPPLY_CHAIN_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 39,
        moduleCount: 13,
        verifiedTheoremCount: 146,
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
        minRequiredTheorems: 146,
        minAllowedEpoch: 39,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-210', 'release:b14-artifact', 39);
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
        policySnapshotDigest: sha256Digest({cedarArtifactPolicy: 'v39'}),
        policyAffectedScopes: ['release:b14-artifact'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarArtifactPolicy: 'v39'}),
      activeLeaseEpoch: 39,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
