// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 32 (10.180): Ed25519 Threshold-Cosigned `SignedLibraryReleaseCertificate`
 * & 100% Air-Gapped Offline Verifier for `cedar-poo-spec` Runtime Consumption.
 *
 * Bridges build-time four-paradigm formal proof verification (Lean 4 / LeanPoo +
 * Quint/Apalache + Gerbil ASCENT + CBMC/5-Lang) into air-gapped runtime hosts
 * (`cedar-poo-spec`) that verify Library purity, theorem cardinality, anti-downgrade
 * epoch, revocation, publisher Ed25519 signature, and 2f+1 witness cosignatures
 * using ONLY public keys (zero `lake`, zero network, zero private key exposure).
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

/**
 * 8th R3 non-leakable M3 capability class: Publisher Ed25519 signing key for
 * `SignedLibraryReleaseCertificate` issuance. Mechanically blocked from entering M1.
 */
export class LibraryReleaseSigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly publisherId: string) {
    this.capabilityId = `release-publisher-ed25519:${publisherId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  signPayloadDigest(payloadDigestHex: string): string {
    return sign(null, Buffer.from(payloadDigestHex, 'utf8'), this.privateKey).toString('hex');
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: LibraryReleaseSigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export interface ReleaseCertPayload {
  certId: string;
  publisherId: string;
  facadeModule: string;
  attestationDigest: string;
  releaseEpoch: number;
  moduleCount: number;
  verifiedTheoremCount: number;
  quintModelCount: number;
  zeroMathlib: boolean;
  zeroCedar: boolean;
}

export interface ReleaseWitnessCosignature {
  witnessId: string;
  signatureHex: string;
}

export interface SignedLibraryReleaseCertificate {
  payload: ReleaseCertPayload;
  payloadDigestHex: string;
  publisherSignatureHex: string;
  witnessCosignatures: ReleaseWitnessCosignature[];
}

export function computeReleaseCertPayloadDigest(payload: ReleaseCertPayload): string {
  return sha256Digest({
    domain: 'deterministic-engineering-qnt::library-release-cert-v1',
    ...payload,
  });
}

export function cosignReleasePayload(
  witnessKey: LibraryReleaseSigningKey,
  payloadDigestHex: string,
): ReleaseWitnessCosignature {
  return {
    witnessId: witnessKey.publisherId,
    signatureHex: witnessKey.signPayloadDigest(`witness-cosig::${payloadDigestHex}`),
  };
}

export function issueSignedLibraryReleaseCertificate(params: {
  payload: ReleaseCertPayload;
  publisherKey: LibraryReleaseSigningKey;
  witnessKeys: readonly LibraryReleaseSigningKey[];
}): SignedLibraryReleaseCertificate {
  const payloadDigestHex = computeReleaseCertPayloadDigest(params.payload);
  const publisherSignatureHex = params.publisherKey.signPayloadDigest(payloadDigestHex);
  const witnessCosignatures = params.witnessKeys.map(wk =>
    cosignReleasePayload(wk, payloadDigestHex),
  );
  return {
    payload: {...params.payload},
    payloadDigestHex,
    publisherSignatureHex,
    witnessCosignatures,
  };
}

export interface OfflineReleaseVerifierPolicy {
  expectedAttestationDigest: string;
  trustedPublisherPublicKeyPem: string;
  registeredWitnessPublicKeys: Readonly<Record<string, string>>;
  minWitnessThreshold: number;
  minRequiredTheorems: number;
  minAllowedEpoch: number;
  revokedCertIds: readonly string[];
}

export type OfflineReleaseCertVerdict =
  | {
      kind: 'Proven';
      certId: string;
      attestationDigest: string;
      releaseEpoch: number;
      verifiedTheoremCount: number;
      verifiedWitnessIds: string[];
      pinnedOfflineReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'payload-digest-tampered'
        | 'invalid-publisher-ed25519-signature'
        | 'impure-library-mathlib-or-cedar-detected'
        | 'downgraded-theorem-count'
        | 'stale-release-epoch-downgrade'
        | 'revoked-release-certificate'
        | 'mismatched-expected-attestation-digest'
        | 'insufficient-valid-witness-quorum';
      validWitnessCount?: number;
    };

/**
 * 100% Air-Gapped Offline Verifier (zero `lake`, zero network, public keys only).
 * Runtime mirror of `ReleaseCertificateReplay.verifyReleaseCertOffline`.
 */
export function verifyLibraryReleaseCertificateOffline(params: {
  cert: SignedLibraryReleaseCertificate;
  policy: OfflineReleaseVerifierPolicy;
  kv?: ContentAddressedKvStore;
}): OfflineReleaseCertVerdict {
  const {cert, policy} = params;

  const recomputedDigest = computeReleaseCertPayloadDigest(cert.payload);
  if (recomputedDigest !== cert.payloadDigestHex) {
    return {kind: 'Refuted', reason: 'payload-digest-tampered'};
  }

  let pubSigValid = false;
  try {
    pubSigValid = verify(
      null,
      Buffer.from(cert.payloadDigestHex, 'utf8'),
      policy.trustedPublisherPublicKeyPem,
      Buffer.from(cert.publisherSignatureHex, 'hex'),
    );
  } catch {
    pubSigValid = false;
  }
  if (!pubSigValid) {
    return {kind: 'Refuted', reason: 'invalid-publisher-ed25519-signature'};
  }

  if (!cert.payload.zeroMathlib || !cert.payload.zeroCedar) {
    return {kind: 'Refuted', reason: 'impure-library-mathlib-or-cedar-detected'};
  }
  if (cert.payload.attestationDigest !== policy.expectedAttestationDigest) {
    return {kind: 'Refuted', reason: 'mismatched-expected-attestation-digest'};
  }
  if (cert.payload.verifiedTheoremCount < policy.minRequiredTheorems) {
    return {kind: 'Refuted', reason: 'downgraded-theorem-count'};
  }
  if (cert.payload.releaseEpoch < policy.minAllowedEpoch) {
    return {kind: 'Refuted', reason: 'stale-release-epoch-downgrade'};
  }
  if (policy.revokedCertIds.includes(cert.payload.certId)) {
    return {kind: 'Refuted', reason: 'revoked-release-certificate'};
  }

  // Verify distinct registered witness Ed25519 cosignatures:
  const validWitnessSet = new Set<string>();
  const rejectedWitnessIds: string[] = [];
  const witnessMsg = Buffer.from(`witness-cosig::${cert.payloadDigestHex}`, 'utf8');
  for (const cosig of cert.witnessCosignatures) {
    const pubPem = policy.registeredWitnessPublicKeys[cosig.witnessId];
    if (!pubPem || validWitnessSet.has(cosig.witnessId)) continue;
    let sigOk = false;
    try {
      sigOk = verify(null, witnessMsg, pubPem, Buffer.from(cosig.signatureHex, 'hex'));
    } catch {
      sigOk = false;
    }
    if (sigOk) {
      validWitnessSet.add(cosig.witnessId);
    } else {
      rejectedWitnessIds.push(cosig.witnessId);
    }
  }

  if (validWitnessSet.size < policy.minWitnessThreshold) {
    return {
      kind: 'Refuted',
      reason: 'insufficient-valid-witness-quorum',
      validWitnessCount: validWitnessSet.size,
    };
  }

  const verifiedWitnessIds = [...validWitnessSet].sort();
  let pinnedOfflineReceiptHash: string | undefined;
  if (params.kv) {
    pinnedOfflineReceiptHash = params.kv.putBlob(
      'offline-release-cert-verification',
      {
        certId: cert.payload.certId,
        attestationDigest: cert.payload.attestationDigest,
        releaseEpoch: cert.payload.releaseEpoch,
        verifiedTheoremCount: cert.payload.verifiedTheoremCount,
        verifiedWitnessIds,
        zeroMathlib: true,
        zeroCedar: true,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedOfflineReceiptHash);
  }

  return {
    kind: 'Proven',
    certId: cert.payload.certId,
    attestationDigest: cert.payload.attestationDigest,
    releaseEpoch: cert.payload.releaseEpoch,
    verifiedTheoremCount: cert.payload.verifiedTheoremCount,
    verifiedWitnessIds,
    pinnedOfflineReceiptHash,
  };
}
