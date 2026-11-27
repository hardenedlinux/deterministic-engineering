// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 41 (10.189): Business Extension B15 — Confidential Compute / Hardware TEE
 * Enclave Attestation & Zero-Trust Measured Key-Release (`B14 -> B15` Chain of Trust).
 *
 * Runtime counterpart to the 14th LeanPoo module `ConfidentialEnclaveAttestation.lean`:
 *   1. `EnclaveRootAttestationKey`: 12th R3 non-leakable M3 capability class
 *      (real Ed25519 hardware attestation root key mechanically blocked from M1).
 *   2. `issueHardwareEnclaveQuote`: signs canonical TEE quote binding
 *      `(platformId, measuredEnclaveDigestHex, tcbSvn, challengeNonce, debugModeDisabled)`.
 *   3. `verifyEnclaveQuoteForKeyRelease`: 100% air-gapped offline verifier enforcing:
 *      - Hardware root Ed25519 signature & platform non-revocation
 *      - Production debug-mode lockout (`debugModeDisabled === true`)
 *      - Measured binary pinning (`measuredEnclaveDigestHex === expectedArtifactDigestHex`)
 *      - Hardware TCB SVN anti-rollback floor (`tcbSvn >= minRequiredTcbSvn`)
 *      - Fresh single-use challenge nonce anti-replay binding
 *      - Pins immutable `M1` `EnclaveKeyReleaseReceipt` in `ContentAddressedKvStore`.
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

/**
 * 12th R3 non-leakable M3 capability class: Hardware TEE Root Attestation Ed25519 key.
 * Mechanically blocked from entering M1 persistence via `M3_NON_SERIALIZABLE_CAPABILITY`.
 */
export class EnclaveRootAttestationKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly platformId: string) {
    this.capabilityId = `tee-hardware-root-ed25519:${platformId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  signQuoteDigest(quoteDigestHex: string): string {
    return sign(null, Buffer.from(quoteDigestHex, 'utf8'), this.privateKey).toString('hex');
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: EnclaveRootAttestationKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export interface HardwareEnclaveQuotePayload {
  readonly quoteId: string;
  readonly platformId: string;
  readonly measuredEnclaveDigestHex: string;
  readonly tcbSvn: number;
  readonly challengeNonce: string;
  readonly debugModeDisabled: boolean;
}

export interface SignedHardwareEnclaveQuote {
  readonly payload: HardwareEnclaveQuotePayload;
  readonly quoteDigestHex: string;
  readonly hardwareSignatureHex: string;
}

export interface EnclaveKeyReleasePolicySpec {
  readonly expectedArtifactDigestHex: string;
  readonly minRequiredTcbSvn: number;
  readonly expectedChallengeNonce: string;
  readonly trustedPlatformPublicKeys: Readonly<Record<string, string>>;
  readonly revokedPlatformIds: readonly string[];
  readonly consumedNonces?: readonly string[];
}

export type EnclaveKeyReleaseVerdict =
  | {
      kind: 'Proven';
      quoteId: string;
      platformId: string;
      measuredEnclaveDigestHex: string;
      tcbSvn: number;
      pinnedKeyReleaseReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'quote-digest-tampered'
        | 'unregistered-platform'
        | 'revoked-platform'
        | 'forged-hardware-signature'
        | 'debug-enclave-forbidden'
        | 'enclave-measurement-mismatch'
        | 'tcb-svn-rollback-detected'
        | 'challenge-nonce-mismatch'
        | 'challenge-nonce-replayed';
      detail: string;
    };

export function computeEnclaveQuoteDigest(payload: HardwareEnclaveQuotePayload): string {
  return sha256Digest({
    domain: 'deterministic-engineering-qnt::b15-hardware-tee-quote-v1',
    quoteId: payload.quoteId,
    platformId: payload.platformId,
    measuredEnclaveDigestHex: payload.measuredEnclaveDigestHex,
    tcbSvn: payload.tcbSvn,
    challengeNonce: payload.challengeNonce,
    debugModeDisabled: payload.debugModeDisabled,
  });
}

export function issueHardwareEnclaveQuote(params: {
  payload: HardwareEnclaveQuotePayload;
  platformKey: EnclaveRootAttestationKey;
}): SignedHardwareEnclaveQuote {
  if (params.payload.platformId !== params.platformKey.platformId) {
    throw new Error(
      `Platform key mismatch: payload claims '${params.payload.platformId}' but key belongs to '${params.platformKey.platformId}'`,
    );
  }
  const quoteDigestHex = computeEnclaveQuoteDigest(params.payload);
  const hardwareSignatureHex = params.platformKey.signQuoteDigest(quoteDigestHex);
  return {
    payload: params.payload,
    quoteDigestHex,
    hardwareSignatureHex,
  };
}

/**
 * 100% Air-Gapped Offline Verifier for B15 Confidential Compute / TEE Enclave Key-Release.
 */
export function verifyEnclaveQuoteForKeyRelease(params: {
  quote: SignedHardwareEnclaveQuote;
  policy: EnclaveKeyReleasePolicySpec;
  kv?: ContentAddressedKvStore;
}): EnclaveKeyReleaseVerdict {
  const {quote, policy} = params;

  const recomputedDigest = computeEnclaveQuoteDigest(quote.payload);
  if (recomputedDigest !== quote.quoteDigestHex) {
    return {
      kind: 'Refuted',
      reason: 'quote-digest-tampered',
      detail: `Recomputed quote digest '${recomputedDigest}' != claimed '${quote.quoteDigestHex}'`,
    };
  }

  if (policy.revokedPlatformIds.includes(quote.payload.platformId)) {
    return {
      kind: 'Refuted',
      reason: 'revoked-platform',
      detail: `Hardware platform '${quote.payload.platformId}' is revoked`,
    };
  }

  const pubPem = policy.trustedPlatformPublicKeys[quote.payload.platformId];
  if (!pubPem) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-platform',
      detail: `Hardware platform '${quote.payload.platformId}' is not registered`,
    };
  }

  let sigOk = false;
  let sigErr = '';
  try {
    sigOk = verify(
      null,
      Buffer.from(quote.quoteDigestHex, 'utf8'),
      pubPem,
      Buffer.from(quote.hardwareSignatureHex, 'hex'),
    );
  } catch (err) {
    sigOk = false;
    sigErr = err instanceof Error ? err.message : String(err);
  }
  if (!sigOk) {
    return {
      kind: 'Refuted',
      reason: 'forged-hardware-signature',
      detail: `Hardware quote signature verification failed for '${quote.payload.platformId}'${sigErr ? `: ${sigErr}` : ''}`,
    };
  }

  if (!quote.payload.debugModeDisabled) {
    return {
      kind: 'Refuted',
      reason: 'debug-enclave-forbidden',
      detail: `Enclave quote '${quote.payload.quoteId}' has debug mode enabled; production M3 key release forbidden`,
    };
  }

  if (quote.payload.measuredEnclaveDigestHex !== policy.expectedArtifactDigestHex) {
    return {
      kind: 'Refuted',
      reason: 'enclave-measurement-mismatch',
      detail: `Measured enclave '${quote.payload.measuredEnclaveDigestHex}' != expected B14 artifact '${policy.expectedArtifactDigestHex}'`,
    };
  }

  if (quote.payload.tcbSvn < policy.minRequiredTcbSvn) {
    return {
      kind: 'Refuted',
      reason: 'tcb-svn-rollback-detected',
      detail: `Hardware TCB SVN ${quote.payload.tcbSvn} < minimum required floor ${policy.minRequiredTcbSvn}`,
    };
  }

  if ((policy.consumedNonces ?? []).includes(quote.payload.challengeNonce)) {
    return {
      kind: 'Refuted',
      reason: 'challenge-nonce-replayed',
      detail: `Challenge nonce '${quote.payload.challengeNonce}' was already consumed`,
    };
  }

  if (quote.payload.challengeNonce !== policy.expectedChallengeNonce) {
    return {
      kind: 'Refuted',
      reason: 'challenge-nonce-mismatch',
      detail: `Quote nonce '${quote.payload.challengeNonce}' != expected fresh challenge '${policy.expectedChallengeNonce}'`,
    };
  }

  let pinnedKeyReleaseReceiptHash: string | undefined;
  if (params.kv) {
    pinnedKeyReleaseReceiptHash = params.kv.putBlob(
      'b15-enclave-key-release-receipt',
      {
        quoteId: quote.payload.quoteId,
        platformId: quote.payload.platformId,
        measuredEnclaveDigestHex: quote.payload.measuredEnclaveDigestHex,
        tcbSvn: quote.payload.tcbSvn,
        challengeNonce: quote.payload.challengeNonce,
        quoteDigestHex: quote.quoteDigestHex,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedKeyReleaseReceiptHash);
  }

  return {
    kind: 'Proven',
    quoteId: quote.payload.quoteId,
    platformId: quote.payload.platformId,
    measuredEnclaveDigestHex: quote.payload.measuredEnclaveDigestHex,
    tcbSvn: quote.payload.tcbSvn,
    pinnedKeyReleaseReceiptHash,
  };
}
