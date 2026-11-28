// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 39 (10.187): Business Extension B14 — Hermetic Supply-Chain & Reproducible
 * Build Provenance Attestation (SLSA / in-toto, Anti-Slopsquatting Lockfile Pinning,
 * CVE Tombstones & 2-Builder Bit-for-Bit Parity).
 *
 * Runtime counterpart to the 13th LeanPoo module `SupplyChainProvenance.lean`:
 *   1. `BuilderAttestationSigningKey`: 11th R3 non-leakable M3 capability class
 *      (real Ed25519 builder key mechanically blocked from entering M1 persistence).
 *   2. `issueBuildProvenanceAttestation`: signs canonical M1 SLSA/in-toto payload
 *      binding `(sourceDigest, toolchainDigest, artifactDigest, sbomDeps, hermeticNoNetwork)`.
 *   3. `verifyHermeticBuildProvenance`: 100% air-gapped offline verifier enforcing:
 *      - Source & toolchain digest binding
 *      - Hermetic sandbox isolation (`hermeticNoNetwork === true`)
 *      - Anti-slopsquatting: every SBOM dependency digest MUST exist in signed `M1` lockfile
 *      - CVE/compromised-digest tombstone refusal
 *      - Independent 2-builder reproducible-build bit-for-bit parity (`reproducedDigest === artifactDigest`)
 *      - Builder Ed25519 signature & non-revocation (public-key-only verification)
 *      - Pins immutable `M1` `SupplyChainAdmissionReceipt` in `ContentAddressedKvStore`.
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

/**
 * 11th R3 non-leakable M3 capability class: Hermetic Builder Ed25519 signing key
 * for SLSA/in-toto build provenance attestation. Mechanically blocked from M1 persistence.
 */
export class BuilderAttestationSigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly builderId: string) {
    this.capabilityId = `supply-chain-builder-ed25519:${builderId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  signProvenanceDigest(payloadDigestHex: string): string {
    return sign(null, Buffer.from(payloadDigestHex, 'utf8'), this.privateKey).toString('hex');
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: BuilderAttestationSigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export interface SbomDependencyEntry {
  readonly packageName: string;
  readonly version: string;
  readonly contentDigestHex: string;
}

export interface BuildProvenancePayload {
  readonly buildId: string;
  readonly builderId: string;
  readonly sourceDigestHex: string;
  readonly toolchainDigestHex: string;
  readonly artifactDigestHex: string;
  readonly hermeticNoNetwork: boolean;
  readonly sbomDeps: readonly SbomDependencyEntry[];
}

export interface SignedBuildProvenanceAttestation {
  readonly payload: BuildProvenancePayload;
  readonly payloadDigestHex: string;
  readonly builderSignatureHex: string;
}

export interface HermeticSupplyChainPolicy {
  readonly expectedSourceDigestHex: string;
  readonly expectedToolchainDigestHex: string;
  readonly pinnedLockfileDigests: readonly string[];
  readonly revokedCveDigests: readonly string[];
  readonly trustedBuilderPublicKeys: Readonly<Record<string, string>>;
  readonly revokedBuilderIds: readonly string[];
  readonly requireTwoBuilderReproducibility: boolean;
}

export type SupplyChainVerificationVerdict =
  | {
      kind: 'Proven';
      buildId: string;
      builderId: string;
      artifactDigestHex: string;
      verifiedReproducerIds: string[];
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'payload-digest-tampered'
        | 'unregistered-builder'
        | 'revoked-builder'
        | 'forged-builder-signature'
        | 'source-digest-mismatch'
        | 'toolchain-digest-mismatch'
        | 'non-hermetic-network-build'
        | 'unpinned-slopsquatting-dependency'
        | 'tombstoned-cve-dependency'
        | 'missing-independent-reproducer'
        | 'reproducible-build-mismatch';
      detail: string;
    };

export function computeBuildProvenancePayloadDigest(payload: BuildProvenancePayload): string {
  const canonicalDeps = [...payload.sbomDeps]
    .map(d => ({
      packageName: d.packageName,
      version: d.version,
      contentDigestHex: d.contentDigestHex,
    }))
    .sort((a, b) =>
      `${a.packageName}@${a.version}:${a.contentDigestHex}`.localeCompare(
        `${b.packageName}@${b.version}:${b.contentDigestHex}`,
      ),
    );
  return sha256Digest({
    domain: 'deterministic-engineering-qnt::b14-slsa-build-provenance-v1',
    buildId: payload.buildId,
    builderId: payload.builderId,
    sourceDigestHex: payload.sourceDigestHex,
    toolchainDigestHex: payload.toolchainDigestHex,
    artifactDigestHex: payload.artifactDigestHex,
    hermeticNoNetwork: payload.hermeticNoNetwork,
    sbomDeps: canonicalDeps,
  });
}

export function issueBuildProvenanceAttestation(params: {
  payload: BuildProvenancePayload;
  builderKey: BuilderAttestationSigningKey;
}): SignedBuildProvenanceAttestation {
  if (params.payload.builderId !== params.builderKey.builderId) {
    throw new Error(
      `Builder key mismatch: payload claims '${params.payload.builderId}' but key belongs to '${params.builderKey.builderId}'`,
    );
  }
  const payloadDigestHex = computeBuildProvenancePayloadDigest(params.payload);
  const builderSignatureHex = params.builderKey.signProvenanceDigest(payloadDigestHex);
  return {
    payload: params.payload,
    payloadDigestHex,
    builderSignatureHex,
  };
}

function verifySingleAttestationSignature(
  att: SignedBuildProvenanceAttestation,
  policy: HermeticSupplyChainPolicy,
): {ok: true} | {ok: false; reason: 'payload-digest-tampered' | 'unregistered-builder' | 'revoked-builder' | 'forged-builder-signature'; detail: string} {
  const expectedDigest = computeBuildProvenancePayloadDigest(att.payload);
  if (expectedDigest !== att.payloadDigestHex) {
    return {
      ok: false,
      reason: 'payload-digest-tampered',
      detail: `Recomputed provenance digest '${expectedDigest}' != claimed '${att.payloadDigestHex}'`,
    };
  }
  if (policy.revokedBuilderIds.includes(att.payload.builderId)) {
    return {
      ok: false,
      reason: 'revoked-builder',
      detail: `Builder '${att.payload.builderId}' is revoked`,
    };
  }
  const pubPem = policy.trustedBuilderPublicKeys[att.payload.builderId];
  if (!pubPem) {
    return {
      ok: false,
      reason: 'unregistered-builder',
      detail: `Builder '${att.payload.builderId}' is not in trustedBuilderPublicKeys`,
    };
  }
  let sigOk = false;
  let sigErrDetail = '';
  try {
    sigOk = verify(
      null,
      Buffer.from(att.payloadDigestHex, 'utf8'),
      pubPem,
      Buffer.from(att.builderSignatureHex, 'hex'),
    );
  } catch (err) {
    sigOk = false;
    sigErrDetail = err instanceof Error ? err.message : String(err);
  }
  if (!sigOk) {
    return {
      ok: false,
      reason: 'forged-builder-signature',
      detail: `Ed25519 signature verification failed for builder '${att.payload.builderId}'${sigErrDetail ? `: ${sigErrDetail}` : ''}`,
    };
  }
  return {ok: true};
}

/**
 * 100% Air-Gapped Offline Verifier for B14 SLSA/in-toto Hermetic & Reproducible Build Provenance.
 */
export function verifyHermeticBuildProvenance(params: {
  primary: SignedBuildProvenanceAttestation;
  reproducers?: readonly SignedBuildProvenanceAttestation[];
  policy: HermeticSupplyChainPolicy;
  kv?: ContentAddressedKvStore;
}): SupplyChainVerificationVerdict {
  const {primary, policy} = params;

  // 1. Cryptographic signature, digest integrity & builder revocation check on primary attestation:
  const primarySig = verifySingleAttestationSignature(primary, policy);
  if (!primarySig.ok) {
    return {kind: 'Refuted', reason: primarySig.reason, detail: primarySig.detail};
  }

  // 2. Source & toolchain digest binding:
  if (primary.payload.sourceDigestHex !== policy.expectedSourceDigestHex) {
    return {
      kind: 'Refuted',
      reason: 'source-digest-mismatch',
      detail: `Source digest '${primary.payload.sourceDigestHex}' != expected '${policy.expectedSourceDigestHex}'`,
    };
  }
  if (primary.payload.toolchainDigestHex !== policy.expectedToolchainDigestHex) {
    return {
      kind: 'Refuted',
      reason: 'toolchain-digest-mismatch',
      detail: `Toolchain digest '${primary.payload.toolchainDigestHex}' != expected '${policy.expectedToolchainDigestHex}'`,
    };
  }

  // 3. Hermetic isolation (zero network access during build):
  if (!primary.payload.hermeticNoNetwork) {
    return {
      kind: 'Refuted',
      reason: 'non-hermetic-network-build',
      detail: `Build '${primary.payload.buildId}' was not executed in a hermetic network-isolated sandbox`,
    };
  }

  // 4. Anti-slopsquatting lockfile pinning & CVE tombstone blocking across entire SBOM:
  const pinnedSet = new Set(policy.pinnedLockfileDigests);
  const cveSet = new Set(policy.revokedCveDigests);
  for (const dep of primary.payload.sbomDeps) {
    if (cveSet.has(dep.contentDigestHex)) {
      return {
        kind: 'Refuted',
        reason: 'tombstoned-cve-dependency',
        detail: `SBOM dependency '${dep.packageName}@${dep.version}' (${dep.contentDigestHex}) is CVE-tombstoned`,
      };
    }
    if (!pinnedSet.has(dep.contentDigestHex)) {
      return {
        kind: 'Refuted',
        reason: 'unpinned-slopsquatting-dependency',
        detail: `SBOM dependency '${dep.packageName}@${dep.version}' (${dep.contentDigestHex}) is absent from signed M1 lockfile`,
      };
    }
  }

  // 5. Independent 2-builder reproducible-build bit-for-bit parity:
  const verifiedReproducerIds: string[] = [];
  for (const rep of params.reproducers ?? []) {
    if (rep.payload.builderId === primary.payload.builderId) {
      continue; // Self-reproduction does not count as an independent second builder
    }
    const repSig = verifySingleAttestationSignature(rep, policy);
    if (!repSig.ok) {
      return {kind: 'Refuted', reason: repSig.reason, detail: repSig.detail};
    }
    if (
      rep.payload.sourceDigestHex !== policy.expectedSourceDigestHex ||
      rep.payload.toolchainDigestHex !== policy.expectedToolchainDigestHex ||
      !rep.payload.hermeticNoNetwork
    ) {
      return {
        kind: 'Refuted',
        reason: 'non-hermetic-network-build',
        detail: `Reproducer '${rep.payload.builderId}' violated source/toolchain/hermeticity preconditions`,
      };
    }
    if (rep.payload.artifactDigestHex !== primary.payload.artifactDigestHex) {
      return {
        kind: 'Refuted',
        reason: 'reproducible-build-mismatch',
        detail: `Reproducer '${rep.payload.builderId}' produced '${rep.payload.artifactDigestHex}' != primary '${primary.payload.artifactDigestHex}'`,
      };
    }
    if (!verifiedReproducerIds.includes(rep.payload.builderId)) {
      verifiedReproducerIds.push(rep.payload.builderId);
    }
  }
  verifiedReproducerIds.sort();

  if (policy.requireTwoBuilderReproducibility && verifiedReproducerIds.length === 0) {
    return {
      kind: 'Refuted',
      reason: 'missing-independent-reproducer',
      detail: `2-builder reproducibility required, but no independent builder corroborated '${primary.payload.builderId}'`,
    };
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b14-supply-chain-provenance-receipt',
      {
        buildId: primary.payload.buildId,
        primaryBuilderId: primary.payload.builderId,
        verifiedReproducerIds,
        sourceDigestHex: primary.payload.sourceDigestHex,
        toolchainDigestHex: primary.payload.toolchainDigestHex,
        artifactDigestHex: primary.payload.artifactDigestHex,
        primaryPayloadDigestHex: primary.payloadDigestHex,
        sbomCount: primary.payload.sbomDeps.length,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    buildId: primary.payload.buildId,
    builderId: primary.payload.builderId,
    artifactDigestHex: primary.payload.artifactDigestHex,
    verifiedReproducerIds,
    pinnedReceiptHash,
  };
}
