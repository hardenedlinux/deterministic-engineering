// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 49 (10.197): Business Extension B19 — Cross-Region Sovereign Data-Residency &
 * Geo-Fenced AI Governance (GDPR Chapter V Adequacy / SCC Transfer Permits & LLM
 * Inference-Endpoint Residency Fencing).
 *
 * Prevents regulated tenant artifacts, embeddings, or LLM inference prompts from silently
 * escaping sovereign jurisdictional boundaries across multi-region cloud clusters:
 *   1. `GeoResidencySigningKey`: 16th R3 non-leakable M3 capability class holding an
 *      Ed25519 regional sovereignty signing key; issues signed `RegionPlacementAttestation`
 *      and `CrossBorderTransferPermit` envelopes.
 *   2. `verifyGeoResidencyPlacementOffline`: 100% air-gapped verifier checking:
 *        - Allowed & non-sanctioned target storage region AND LLM inference endpoint region
 *        - Non-revoked regional sovereignty authority & valid Ed25519 attestation signature
 *        - Cross-border transfers (`sourceRegion !== targetRegion`) MUST carry a valid
 *          Ed25519-signed adequacy/SCC transfer permit bound to `(source, target, payloadDigest)`
 *        - Intra-region placements (`sourceRegion === targetRegion`) require NO cross-border
 *          permit (anti-P4 defensive bloat)
 *   3. Pins immutable `M1` `b19-geo-residency-receipt` surviving aggressive GC.
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export interface RegionPlacementAttestation {
  readonly authorityId: string;
  readonly tenantId: string;
  readonly sourceRegion: string;
  readonly targetRegion: string;
  readonly inferenceEndpointRegion: string;
  readonly payloadDigestHex: string;
  readonly issuedAtEpoch: number;
  readonly signatureHex: string;
}

export interface CrossBorderTransferPermit {
  readonly permitId: string;
  readonly authorityId: string;
  readonly legalBasis: 'adequacy-decision' | 'standard-contractual-clauses';
  readonly sourceRegion: string;
  readonly targetRegion: string;
  readonly payloadDigestHex: string;
  readonly expiresAtEpoch: number;
  readonly signatureHex: string;
}

export interface GeoResidencyVerificationPolicy {
  readonly allowedRegions: readonly string[];
  readonly sanctionedRegions: readonly string[];
  readonly trustedAuthorityPublicKeys: Readonly<Record<string, string>>;
  readonly revokedAuthorityIds: readonly string[];
  readonly revokedPermitIds: readonly string[];
  readonly currentEpoch: number;
}

export type GeoResidencyVerificationVerdict =
  | {
      kind: 'Proven';
      tenantId: string;
      sourceRegion: string;
      targetRegion: string;
      inferenceEndpointRegion: string;
      crossBorderTransfer: boolean;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'sanctioned-or-disallowed-target-region'
        | 'inference-endpoint-residency-escape'
        | 'unregistered-or-revoked-authority'
        | 'region-attestation-signature-invalid'
        | 'missing-cross-border-transfer-permit'
        | 'cross-border-permit-invalid-or-revoked';
      detail: string;
    };

function attestationSigningPayload(a: Omit<RegionPlacementAttestation, 'signatureHex'>): Buffer {
  return Buffer.from(
    sha256Digest({
      domain: 'b19-region-placement-attestation-v1',
      authorityId: a.authorityId,
      tenantId: a.tenantId,
      sourceRegion: a.sourceRegion,
      targetRegion: a.targetRegion,
      inferenceEndpointRegion: a.inferenceEndpointRegion,
      payloadDigestHex: a.payloadDigestHex,
      issuedAtEpoch: a.issuedAtEpoch,
    }),
    'hex',
  );
}

function permitSigningPayload(p: Omit<CrossBorderTransferPermit, 'signatureHex'>): Buffer {
  return Buffer.from(
    sha256Digest({
      domain: 'b19-cross-border-transfer-permit-v1',
      permitId: p.permitId,
      authorityId: p.authorityId,
      legalBasis: p.legalBasis,
      sourceRegion: p.sourceRegion,
      targetRegion: p.targetRegion,
      payloadDigestHex: p.payloadDigestHex,
      expiresAtEpoch: p.expiresAtEpoch,
    }),
    'hex',
  );
}

/**
 * 16th R3 non-leakable M3 capability class: Regional Sovereignty Signing Key.
 * Mechanically refused by `ContentAddressedKvStore` and `JSON.stringify`.
 */
export class GeoResidencySigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(
    readonly authorityId: string,
    readonly jurisdiction: string,
  ) {
    this.capabilityId = `geo-residency-authority:${authorityId}:${jurisdiction}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  attestRegionPlacement(params: {
    tenantId: string;
    sourceRegion: string;
    targetRegion: string;
    inferenceEndpointRegion: string;
    payloadDigestHex: string;
    issuedAtEpoch: number;
  }): RegionPlacementAttestation {
    const body = {
      authorityId: this.authorityId,
      tenantId: params.tenantId,
      sourceRegion: params.sourceRegion,
      targetRegion: params.targetRegion,
      inferenceEndpointRegion: params.inferenceEndpointRegion,
      payloadDigestHex: params.payloadDigestHex,
      issuedAtEpoch: params.issuedAtEpoch,
    };
    const signatureHex = sign(null, attestationSigningPayload(body), this.privateKey).toString(
      'hex',
    );
    return {...body, signatureHex};
  }

  issueCrossBorderTransferPermit(params: {
    permitId: string;
    legalBasis: 'adequacy-decision' | 'standard-contractual-clauses';
    sourceRegion: string;
    targetRegion: string;
    payloadDigestHex: string;
    expiresAtEpoch: number;
  }): CrossBorderTransferPermit {
    const body = {
      permitId: params.permitId,
      authorityId: this.authorityId,
      legalBasis: params.legalBasis,
      sourceRegion: params.sourceRegion,
      targetRegion: params.targetRegion,
      payloadDigestHex: params.payloadDigestHex,
      expiresAtEpoch: params.expiresAtEpoch,
    };
    const signatureHex = sign(null, permitSigningPayload(body), this.privateKey).toString('hex');
    return {...body, signatureHex};
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: GeoResidencySigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

function verifyEd25519Hex(
  pubPem: string,
  msg: Buffer,
  sigHex: string,
): {kind: 'Proven'} | {kind: 'Refuted'; detail: string} {
  try {
    const valid = verify(null, msg, pubPem, Buffer.from(sigHex, 'hex'));
    return valid
      ? {kind: 'Proven'}
      : {kind: 'Refuted', detail: 'Ed25519 signature bytes do not match payload digest'};
  } catch (err) {
    return {
      kind: 'Refuted',
      detail: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * 100% Air-Gapped Offline Verifier for B19 Sovereign Data-Residency & Cross-Border Transfers.
 */
export function verifyGeoResidencyPlacementOffline(params: {
  attestation: RegionPlacementAttestation;
  transferPermit?: CrossBorderTransferPermit;
  policy: GeoResidencyVerificationPolicy;
  kv?: ContentAddressedKvStore;
}): GeoResidencyVerificationVerdict {
  const {attestation, transferPermit, policy} = params;

  // 1. Target region allowlist & sanction check:
  if (
    !policy.allowedRegions.includes(attestation.targetRegion) ||
    policy.sanctionedRegions.includes(attestation.targetRegion)
  ) {
    return {
      kind: 'Refuted',
      reason: 'sanctioned-or-disallowed-target-region',
      detail: `Target region '${attestation.targetRegion}' violates sovereign residency policy`,
    };
  }

  // 2. LLM inference endpoint residency check:
  if (
    !policy.allowedRegions.includes(attestation.inferenceEndpointRegion) ||
    policy.sanctionedRegions.includes(attestation.inferenceEndpointRegion)
  ) {
    return {
      kind: 'Refuted',
      reason: 'inference-endpoint-residency-escape',
      detail: `Inference endpoint '${attestation.inferenceEndpointRegion}' escapes sovereign residency fence`,
    };
  }

  // 3. Authority registration, revocation & Ed25519 attestation signature:
  const authPub = policy.trustedAuthorityPublicKeys[attestation.authorityId];
  if (!authPub || policy.revokedAuthorityIds.includes(attestation.authorityId)) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-or-revoked-authority',
      detail: `Regional authority '${attestation.authorityId}' is unregistered or revoked`,
    };
  }
  const {signatureHex, ...attBody} = attestation;
  const attSigRes = verifyEd25519Hex(authPub, attestationSigningPayload(attBody), signatureHex);
  if (attSigRes.kind !== 'Proven') {
    return {
      kind: 'Refuted',
      reason: 'region-attestation-signature-invalid',
      detail: `Ed25519 signature verification failed on RegionPlacementAttestation: ${attSigRes.detail}`,
    };
  }

  // 4. Cross-border transfer permit check (ONLY required when sourceRegion !== targetRegion):
  const crossBorderTransfer = attestation.sourceRegion !== attestation.targetRegion;
  if (crossBorderTransfer) {
    if (!transferPermit) {
      return {
        kind: 'Refuted',
        reason: 'missing-cross-border-transfer-permit',
        detail: `Cross-border transfer '${attestation.sourceRegion}' -> '${attestation.targetRegion}' requires a signed adequacy/SCC permit`,
      };
    }
    const permitPub = policy.trustedAuthorityPublicKeys[transferPermit.authorityId];
    if (
      !permitPub ||
      policy.revokedAuthorityIds.includes(transferPermit.authorityId) ||
      policy.revokedPermitIds.includes(transferPermit.permitId) ||
      transferPermit.expiresAtEpoch < policy.currentEpoch ||
      transferPermit.sourceRegion !== attestation.sourceRegion ||
      transferPermit.targetRegion !== attestation.targetRegion ||
      transferPermit.payloadDigestHex !== attestation.payloadDigestHex
    ) {
      return {
        kind: 'Refuted',
        reason: 'cross-border-permit-invalid-or-revoked',
        detail: `Transfer permit '${transferPermit.permitId}' is revoked, expired, or unbound to this transfer`,
      };
    }
    const {signatureHex: pSigHex, ...pBody} = transferPermit;
    const permitSigRes = verifyEd25519Hex(permitPub, permitSigningPayload(pBody), pSigHex);
    if (permitSigRes.kind !== 'Proven') {
      return {
        kind: 'Refuted',
        reason: 'cross-border-permit-invalid-or-revoked',
        detail: `Ed25519 signature verification failed on CrossBorderTransferPermit '${transferPermit.permitId}': ${permitSigRes.detail}`,
      };
    }
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b19-geo-residency-receipt',
      {
        authorityId: attestation.authorityId,
        tenantId: attestation.tenantId,
        sourceRegion: attestation.sourceRegion,
        targetRegion: attestation.targetRegion,
        inferenceEndpointRegion: attestation.inferenceEndpointRegion,
        payloadDigestHex: attestation.payloadDigestHex,
        crossBorderTransfer,
        permitId: crossBorderTransfer ? transferPermit?.permitId ?? null : null,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    tenantId: attestation.tenantId,
    sourceRegion: attestation.sourceRegion,
    targetRegion: attestation.targetRegion,
    inferenceEndpointRegion: attestation.inferenceEndpointRegion,
    crossBorderTransfer,
    pinnedReceiptHash,
  };
}
