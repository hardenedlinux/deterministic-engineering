// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 51 (10.199): Business Extension B20 — Multi-Org Federated Reciprocity &
 * Cross-Domain Dispute Arbitration (Bilateral Ed25519 Countersigning, Ratified Treaties,
 * Member Revocation & Active Dispute-Freeze Preemption).
 *
 * Enables independent sovereign organizations (`Org-A` <-> `Org-B`) to execute cross-org
 * AI governance operations without trusting a single centralized coordinator:
 *   1. `FederatedOrgSigningKey`: 17th R3 non-leakable M3 capability class holding an
 *      organization's Ed25519 federation signing key.
 *   2. `verifyFederatedReciprocityOffline`: 100% air-gapped verifier enforcing:
 *        - Distinct organizations (`originOrgId !== targetOrgId`) — blocks self-reciprocity
 *        - Both orgs registered & non-revoked
 *        - Ratified bilateral treaty covering `(originOrgId, targetOrgId, scope)` and non-expired
 *        - Zero active dispute freeze on the treaty or org pair
 *        - Valid Ed25519 countersignatures from BOTH `originOrgId` AND `targetOrgId`
 *   3. Pins immutable `M1` `b20-federated-reciprocity-receipt` surviving aggressive GC.
 */

import {generateKeyPairSync, sign, verify, type KeyObject} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export interface FederatedOperationProposal {
  readonly treatyId: string;
  readonly originOrgId: string;
  readonly targetOrgId: string;
  readonly scope: string;
  readonly payloadDigestHex: string;
  readonly epoch: number;
}

export interface OrgCountersignature {
  readonly signerOrgId: string;
  readonly proposalDigestHex: string;
  readonly signatureHex: string;
}

export interface BilateralTreatySpec {
  readonly treatyId: string;
  readonly memberOrgIds: readonly [string, string];
  readonly allowedScopes: readonly string[];
  readonly expiresAtEpoch: number;
}

export interface FederationVerificationPolicy {
  readonly trustedOrgPublicKeys: Readonly<Record<string, string>>;
  readonly revokedOrgIds: readonly string[];
  readonly ratifiedTreaties: Readonly<Record<string, BilateralTreatySpec>>;
  readonly activeDisputeFrozenTreatyIds: readonly string[];
  readonly currentEpoch: number;
}

export type FederatedReciprocityVerdict =
  | {
      kind: 'Proven';
      treatyId: string;
      originOrgId: string;
      targetOrgId: string;
      proposalDigestHex: string;
      pinnedReceiptHash?: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'self-reciprocity-same-org-spoof'
        | 'unregistered-or-revoked-org'
        | 'unratified-or-expired-or-out-of-scope-treaty'
        | 'active-dispute-freeze-blocking'
        | 'missing-or-invalid-bilateral-countersignature';
      detail: string;
    };

export function computeFederatedProposalDigest(p: FederatedOperationProposal): string {
  return sha256Digest({
    domain: 'b20-federated-reciprocity-proposal-v1',
    treatyId: p.treatyId,
    originOrgId: p.originOrgId,
    targetOrgId: p.targetOrgId,
    scope: p.scope,
    payloadDigestHex: p.payloadDigestHex,
    epoch: p.epoch,
  });
}

function verifyEd25519Signature(
  pubPem: string,
  digestHex: string,
  sigHex: string,
): {kind: 'Proven'} | {kind: 'Refuted'; detail: string} {
  try {
    const ok = verify(null, Buffer.from(digestHex, 'hex'), pubPem, Buffer.from(sigHex, 'hex'));
    return ok
      ? {kind: 'Proven'}
      : {kind: 'Refuted', detail: 'Ed25519 signature bytes do not match proposal digest'};
  } catch (err) {
    return {
      kind: 'Refuted',
      detail: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * 17th R3 non-leakable M3 capability class: Federated Organization Signing Key.
 * Mechanically refused by `ContentAddressedKvStore` and `JSON.stringify`.
 */
export class FederatedOrgSigningKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(readonly orgId: string) {
    this.capabilityId = `federated-org-signing-key:${orgId}`;
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({type: 'spki', format: 'pem'}).toString();
  }

  countersignProposal(proposal: FederatedOperationProposal): OrgCountersignature {
    const proposalDigestHex = computeFederatedProposalDigest(proposal);
    const signatureHex = sign(
      null,
      Buffer.from(proposalDigestHex, 'hex'),
      this.privateKey,
    ).toString('hex');
    return {
      signerOrgId: this.orgId,
      proposalDigestHex,
      signatureHex,
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: FederatedOrgSigningKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

/**
 * 100% Air-Gapped Offline Verifier for B20 Multi-Org Bilateral Federated Reciprocity.
 */
export function verifyFederatedReciprocityOffline(params: {
  proposal: FederatedOperationProposal;
  originCountersig?: OrgCountersignature;
  targetCountersig?: OrgCountersignature;
  policy: FederationVerificationPolicy;
  kv?: ContentAddressedKvStore;
}): FederatedReciprocityVerdict {
  const {proposal, originCountersig, targetCountersig, policy} = params;

  // 1. Distinct organization identities (anti-self-reciprocity):
  if (proposal.originOrgId === proposal.targetOrgId) {
    return {
      kind: 'Refuted',
      reason: 'self-reciprocity-same-org-spoof',
      detail: `Origin and target organization cannot both be '${proposal.originOrgId}'`,
    };
  }

  // 2. Both orgs registered & non-revoked:
  const originPub = policy.trustedOrgPublicKeys[proposal.originOrgId];
  const targetPub = policy.trustedOrgPublicKeys[proposal.targetOrgId];
  if (
    !originPub ||
    !targetPub ||
    policy.revokedOrgIds.includes(proposal.originOrgId) ||
    policy.revokedOrgIds.includes(proposal.targetOrgId)
  ) {
    return {
      kind: 'Refuted',
      reason: 'unregistered-or-revoked-org',
      detail: `Organization '${proposal.originOrgId}' or '${proposal.targetOrgId}' is unregistered or revoked`,
    };
  }

  // 3. Ratified bilateral treaty, membership, scope & non-expiration:
  const treaty = policy.ratifiedTreaties[proposal.treatyId];
  if (
    !treaty ||
    policy.currentEpoch > treaty.expiresAtEpoch ||
    !treaty.allowedScopes.includes(proposal.scope) ||
    !(
      (treaty.memberOrgIds[0] === proposal.originOrgId &&
        treaty.memberOrgIds[1] === proposal.targetOrgId) ||
      (treaty.memberOrgIds[0] === proposal.targetOrgId &&
        treaty.memberOrgIds[1] === proposal.originOrgId)
    )
  ) {
    return {
      kind: 'Refuted',
      reason: 'unratified-or-expired-or-out-of-scope-treaty',
      detail: `Treaty '${proposal.treatyId}' is unratified, expired, or does not cover scope '${proposal.scope}'`,
    };
  }

  // 4. Active dispute freeze preemption:
  if (policy.activeDisputeFrozenTreatyIds.includes(proposal.treatyId)) {
    return {
      kind: 'Refuted',
      reason: 'active-dispute-freeze-blocking',
      detail: `Bilateral treaty '${proposal.treatyId}' is frozen under active dispute arbitration`,
    };
  }

  // 5. Bilateral Ed25519 countersignatures from BOTH originOrgId AND targetOrgId:
  const expectedDigest = computeFederatedProposalDigest(proposal);
  if (
    !originCountersig ||
    !targetCountersig ||
    originCountersig.signerOrgId !== proposal.originOrgId ||
    targetCountersig.signerOrgId !== proposal.targetOrgId ||
    originCountersig.proposalDigestHex !== expectedDigest ||
    targetCountersig.proposalDigestHex !== expectedDigest
  ) {
    return {
      kind: 'Refuted',
      reason: 'missing-or-invalid-bilateral-countersignature',
      detail: 'Both distinct originOrg and targetOrg countersignatures matching proposal digest are required',
    };
  }

  const oVer = verifyEd25519Signature(originPub, expectedDigest, originCountersig.signatureHex);
  if (oVer.kind !== 'Proven') {
    return {
      kind: 'Refuted',
      reason: 'missing-or-invalid-bilateral-countersignature',
      detail: `Origin org '${proposal.originOrgId}' signature failed: ${oVer.detail}`,
    };
  }
  const tVer = verifyEd25519Signature(targetPub, expectedDigest, targetCountersig.signatureHex);
  if (tVer.kind !== 'Proven') {
    return {
      kind: 'Refuted',
      reason: 'missing-or-invalid-bilateral-countersignature',
      detail: `Target org '${proposal.targetOrgId}' signature failed: ${tVer.detail}`,
    };
  }

  let pinnedReceiptHash: string | undefined;
  if (params.kv) {
    pinnedReceiptHash = params.kv.putBlob(
      'b20-federated-reciprocity-receipt',
      {
        treatyId: proposal.treatyId,
        originOrgId: proposal.originOrgId,
        targetOrgId: proposal.targetOrgId,
        scope: proposal.scope,
        proposalDigestHex: expectedDigest,
        epoch: proposal.epoch,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedReceiptHash);
  }

  return {
    kind: 'Proven',
    treatyId: proposal.treatyId,
    originOrgId: proposal.originOrgId,
    targetOrgId: proposal.targetOrgId,
    proposalDigestHex: expectedDigest,
    pinnedReceiptHash,
  };
}
