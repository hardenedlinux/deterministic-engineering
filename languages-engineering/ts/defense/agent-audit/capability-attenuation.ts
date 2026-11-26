// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 12 (Business Extension B3, 10.160):
 * Cross-Trust-Boundary Multi-Agent Delegation, Macaroon-Style Cryptographic
 * Capability Attenuation (NDSS 2014), and KeyKOS/EROS Cascading Revocation.
 *
 * Eliminates Confused Deputy & Privilege Laundering in multi-hop agent supply chains:
 *   1. Non-Serializable M3 Root Signing Key (`DelegationRootKey`, branded with R3
 *      `M3_NON_SERIALIZABLE_CAPABILITY`) — can never leak into M1 Merkle blobs.
 *   2. Macaroon HMAC-SHA256 Caveat Chaining — every child hop chains its canonical
 *      caveats over its parent's MAC (`HMAC(parentMac, childCaveatDigest)`), making
 *      ancestor caveat stripping or forgery cryptographically detectable.
 *   3. Strict Monotonic Attenuation Meet — path prefixes (segment-boundary safe),
 *      action subsets, shrinking TTL, strictly decreasing hop budget, and non-delegable
 *      leaf confinement (`delegatable: false`).
 *   4. Live M3 Cascading Ancestor Revocation — revoking any intermediate certificate or
 *      principal instantly invalidates its entire downstream delegation subtree at use time.
 *   5. Immutable M1 Chain-of-Custody Audit Receipts — records full delegator lineage for
 *      zero-wash forensic attribution across organizational boundaries.
 */

import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export type DelegatedAction = 'read' | 'write' | 'execute' | 'approve' | 'admin';

export interface CapabilityCaveats {
  allowedPathPrefixes: string[];
  allowedActions: DelegatedAction[];
  expiresAtEpoch: number;
  remainingHops: number;
  delegatable: boolean;
}

export interface DelegationCertificate {
  certId: string;
  certMerkleHash: string;
  parentCertHash: string | null;
  rootCertHash: string;
  delegatorId: string;
  delegateeId: string;
  caveats: CapabilityCaveats;
  chainMacHex: string;
  issuedAtEpoch: number;
}

export interface DelegatedExecutionAuditReceipt {
  receiptMerkleHash: string;
  leafCertHash: string;
  custodyLineage: string[];
  callerId: string;
  targetPath: string;
  action: DelegatedAction;
  executedAtEpoch: number;
}

/**
 * R3 Non-Serializable M3 Root Key for Macaroon HMAC caveat chaining.
 * Mechanically blocked from entering M1 persistence by `assertM1Persistable`.
 */
export class DelegationRootKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  private readonly secret: Buffer;

  constructor(authorityId: string, secretBytes?: Buffer) {
    this.capabilityId = `delegation-root-key:${authorityId}`;
    this.secret = secretBytes ? Buffer.from(secretBytes) : randomBytes(32);
  }

  computeHmac(keyMaterial: Buffer | null, message: string): Buffer {
    const key = keyMaterial ?? this.secret;
    return createHmac('sha256', key).update(message, 'utf8').digest();
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: DelegationRootKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

function normalizePath(p: string): string {
  const cleaned = p.replace(/\/+/g, '/').replace(/\/$/, '');
  return cleaned === '' ? '/' : cleaned;
}

/**
 * Segment-boundary-safe prefix check:
 * `/src/parser/a.ts` is within `/src/parser`, while `/src/parser-evil/a.ts` is NOT!
 */
export function isPathWithinPrefix(candidatePath: string, allowedPrefix: string): boolean {
  const cand = normalizePath(candidatePath);
  const pref = normalizePath(allowedPrefix);
  if (cand.includes('..')) return false;
  if (pref === '/') return cand.startsWith('/');
  return cand === pref || cand.startsWith(`${pref}/`);
}

function canonicalCaveatPayload(params: {
  certId: string;
  parentCertHash: string | null;
  delegatorId: string;
  delegateeId: string;
  caveats: CapabilityCaveats;
  issuedAtEpoch: number;
}): string {
  return sha256Digest({
    certId: params.certId,
    parentCertHash: params.parentCertHash,
    delegatorId: params.delegatorId,
    delegateeId: params.delegateeId,
    caveats: {
      allowedPathPrefixes: [...params.caveats.allowedPathPrefixes].map(normalizePath).sort(),
      allowedActions: [...params.caveats.allowedActions].sort(),
      expiresAtEpoch: params.caveats.expiresAtEpoch,
      remainingHops: params.caveats.remainingHops,
      delegatable: params.caveats.delegatable,
    },
    issuedAtEpoch: params.issuedAtEpoch,
  });
}

export type AttenuationVerdict =
  | {kind: 'Delegated'; cert: DelegationCertificate}
  | {
      kind: 'Refuted';
      reason:
        | 'parent-not-delegatable'
        | 'hop-budget-exhausted'
        | 'scope-escalation-path'
        | 'scope-escalation-action'
        | 'ttl-escalation-forbidden'
        | 'self-delegation-noop-forbidden'
        | 'parent-mac-invalid';
    };

export type DelegatedAuthorizationVerdict =
  | {
      kind: 'Authorized';
      receipt: DelegatedExecutionAuditReceipt;
      effectiveCaveats: CapabilityCaveats;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'empty-or-broken-chain'
        | 'bearer-identity-mismatch'
        | 'chain-mac-tampered'
        | 'monotonic-attenuation-violated'
        | 'hop-depth-violated'
        | 'ancestor-not-delegatable'
        | 'ancestor-revoked-cascade'
        | 'capability-expired'
        | 'path-out-of-scope'
        | 'action-out-of-scope';
      revokedAncestorId?: string;
    };

export class CapabilityDelegationAuthority {
  private readonly certsByHash = new Map<string, DelegationCertificate>();
  private readonly revokedCertHashes = new Set<string>();
  private readonly revokedPrincipals = new Set<string>();

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly rootKey: DelegationRootKey,
  ) {}

  mintRootCertificate(params: {
    certId: string;
    rootAuthorityId: string;
    delegateeId: string;
    caveats: CapabilityCaveats;
    issuedAtEpoch: number;
  }): DelegationCertificate {
    const normalizedCaveats: CapabilityCaveats = {
      allowedPathPrefixes: [...params.caveats.allowedPathPrefixes].map(normalizePath).sort(),
      allowedActions: [...params.caveats.allowedActions].sort(),
      expiresAtEpoch: params.caveats.expiresAtEpoch,
      remainingHops: params.caveats.remainingHops,
      delegatable: params.caveats.delegatable,
    };

    const msg = canonicalCaveatPayload({
      certId: params.certId,
      parentCertHash: null,
      delegatorId: params.rootAuthorityId,
      delegateeId: params.delegateeId,
      caveats: normalizedCaveats,
      issuedAtEpoch: params.issuedAtEpoch,
    });
    const macHex = this.rootKey.computeHmac(null, msg).toString('hex');

    const certMerkleHash = this.kv.putBlob(
      'delegation-cert-root',
      {
        certId: params.certId,
        parentCertHash: null,
        delegatorId: params.rootAuthorityId,
        delegateeId: params.delegateeId,
        caveats: normalizedCaveats,
        chainMacHex: macHex,
        issuedAtEpoch: params.issuedAtEpoch,
      },
      [],
    );
    this.kv.pinHistoricalCut(certMerkleHash);

    const cert: DelegationCertificate = {
      certId: params.certId,
      certMerkleHash,
      parentCertHash: null,
      rootCertHash: certMerkleHash,
      delegatorId: params.rootAuthorityId,
      delegateeId: params.delegateeId,
      caveats: normalizedCaveats,
      chainMacHex: macHex,
      issuedAtEpoch: params.issuedAtEpoch,
    };
    this.certsByHash.set(certMerkleHash, cert);
    return cert;
  }

  /**
   * Monotonically attenuates `parentCert` into a child certificate chained by
   * Macaroon HMAC (`HMAC(parentMac, canonicalChildPayload)`).
   * Note: In Macaroons, the holder only needs `parentCert.chainMacHex` (never the root key!)
   * to append narrowing caveats.
   */
  attenuateAndDelegate(params: {
    certId: string;
    parentCert: DelegationCertificate;
    delegateeId: string;
    childCaveats: CapabilityCaveats;
    issuedAtEpoch: number;
  }): AttenuationVerdict {
    const p = params.parentCert;
    if (!p.caveats.delegatable) {
      return {kind: 'Refuted', reason: 'parent-not-delegatable'};
    }
    if (p.caveats.remainingHops <= 0 || params.childCaveats.remainingHops >= p.caveats.remainingHops || params.childCaveats.remainingHops < 0) {
      return {kind: 'Refuted', reason: 'hop-budget-exhausted'};
    }
    if (params.delegateeId === p.delegateeId) {
      return {kind: 'Refuted', reason: 'self-delegation-noop-forbidden'};
    }
    if (params.childCaveats.expiresAtEpoch > p.caveats.expiresAtEpoch) {
      return {kind: 'Refuted', reason: 'ttl-escalation-forbidden'};
    }

    // Strict action subset check:
    const parentActions = new Set(p.caveats.allowedActions);
    if (
      params.childCaveats.allowedActions.length === 0 ||
      params.childCaveats.allowedActions.some(a => !parentActions.has(a))
    ) {
      return {kind: 'Refuted', reason: 'scope-escalation-action'};
    }

    // Strict segment-safe path confinement check:
    if (
      params.childCaveats.allowedPathPrefixes.length === 0 ||
      params.childCaveats.allowedPathPrefixes.some(
        cp => !p.caveats.allowedPathPrefixes.some(pp => isPathWithinPrefix(cp, pp)),
      )
    ) {
      return {kind: 'Refuted', reason: 'scope-escalation-path'};
    }

    const parentMacBuf = Buffer.from(p.chainMacHex, 'hex');
    if (parentMacBuf.length !== 32) {
      return {kind: 'Refuted', reason: 'parent-mac-invalid'};
    }

    const normalizedCaveats: CapabilityCaveats = {
      allowedPathPrefixes: [...params.childCaveats.allowedPathPrefixes].map(normalizePath).sort(),
      allowedActions: [...params.childCaveats.allowedActions].sort(),
      expiresAtEpoch: params.childCaveats.expiresAtEpoch,
      remainingHops: params.childCaveats.remainingHops,
      delegatable: params.childCaveats.delegatable,
    };

    const msg = canonicalCaveatPayload({
      certId: params.certId,
      parentCertHash: p.certMerkleHash,
      delegatorId: p.delegateeId,
      delegateeId: params.delegateeId,
      caveats: normalizedCaveats,
      issuedAtEpoch: params.issuedAtEpoch,
    });
    // Macaroon chaining: HMAC keyed by parent's chain MAC (no root key needed to narrow!).
    const childMacHex = createHmac('sha256', parentMacBuf).update(msg, 'utf8').digest('hex');

    const certMerkleHash = this.kv.putBlob(
      'delegation-cert-hop',
      {
        certId: params.certId,
        parentCertHash: p.certMerkleHash,
        rootCertHash: p.rootCertHash,
        delegatorId: p.delegateeId,
        delegateeId: params.delegateeId,
        caveats: normalizedCaveats,
        chainMacHex: childMacHex,
        issuedAtEpoch: params.issuedAtEpoch,
      },
      [p.certMerkleHash],
    );
    this.kv.pinHistoricalCut(certMerkleHash);

    const cert: DelegationCertificate = {
      certId: params.certId,
      certMerkleHash,
      parentCertHash: p.certMerkleHash,
      rootCertHash: p.rootCertHash,
      delegatorId: p.delegateeId,
      delegateeId: params.delegateeId,
      caveats: normalizedCaveats,
      chainMacHex: childMacHex,
      issuedAtEpoch: params.issuedAtEpoch,
    };
    this.certsByHash.set(certMerkleHash, cert);
    return {kind: 'Delegated', cert};
  }

  /**
   * Live M3 caretaker revocation: revoking a certificate or principal instantly
   * cascades to every downstream descendant at consumption-time verification.
   */
  revokeCertificate(certMerkleHash: string): void {
    this.revokedCertHashes.add(certMerkleHash);
  }

  revokePrincipal(principalId: string): void {
    this.revokedPrincipals.add(principalId);
  }

  /**
   * Verifies the complete root -> leaf delegation chain at consumption time:
   *  1. Recomputes Macaroon HMAC chain from live M3 `rootKey` (catches tampering/stripping).
   *  2. Re-verifies strict monotonic attenuation across every hop (defense-in-depth).
   *  3. Checks live M3 cascading revocation on every ancestor certificate & principal.
   *  4. Verifies bearer identity, TTL, target path, and action against effective caveats.
   *  5. Persists an immutable M1 `DelegatedExecutionAuditReceipt` with full custody lineage.
   */
  authorizeDelegatedAction(params: {
    chain: DelegationCertificate[];
    callerId: string;
    targetPath: string;
    action: DelegatedAction;
    nowEpoch: number;
  }): DelegatedAuthorizationVerdict {
    if (params.chain.length === 0) {
      return {kind: 'Refuted', reason: 'empty-or-broken-chain'};
    }

    const leaf = params.chain[params.chain.length - 1]!;
    if (leaf.delegateeId !== params.callerId) {
      return {kind: 'Refuted', reason: 'bearer-identity-mismatch'};
    }

    let expectedMac: Buffer | null = null;
    let prevCert: DelegationCertificate | null = null;
    const custodyLineage: string[] = [];

    for (let i = 0; i < params.chain.length; i++) {
      const hop = params.chain[i]!;
      if (i === 0) {
        if (hop.parentCertHash !== null) {
          return {kind: 'Refuted', reason: 'empty-or-broken-chain'};
        }
        custodyLineage.push(hop.delegatorId);
      } else {
        if (!prevCert || hop.parentCertHash !== prevCert.certMerkleHash) {
          return {kind: 'Refuted', reason: 'empty-or-broken-chain'};
        }
        if (hop.delegatorId !== prevCert.delegateeId) {
          return {kind: 'Refuted', reason: 'empty-or-broken-chain'};
        }
        if (!prevCert.caveats.delegatable) {
          return {kind: 'Refuted', reason: 'ancestor-not-delegatable'};
        }
        if (
          prevCert.caveats.remainingHops <= 0 ||
          hop.caveats.remainingHops >= prevCert.caveats.remainingHops ||
          hop.caveats.remainingHops < 0
        ) {
          return {kind: 'Refuted', reason: 'hop-depth-violated'};
        }
        if (hop.caveats.expiresAtEpoch > prevCert.caveats.expiresAtEpoch) {
          return {kind: 'Refuted', reason: 'monotonic-attenuation-violated'};
        }
        const prevActions = new Set(prevCert.caveats.allowedActions);
        if (hop.caveats.allowedActions.some(a => !prevActions.has(a))) {
          return {kind: 'Refuted', reason: 'monotonic-attenuation-violated'};
        }
        if (
          hop.caveats.allowedPathPrefixes.some(
            cp => !prevCert!.caveats.allowedPathPrefixes.some(pp => isPathWithinPrefix(cp, pp)),
          )
        ) {
          return {kind: 'Refuted', reason: 'monotonic-attenuation-violated'};
        }
      }

      // Live M3 cascading revocation check on every hop & principal:
      if (this.revokedCertHashes.has(hop.certMerkleHash)) {
        return {
          kind: 'Refuted',
          reason: 'ancestor-revoked-cascade',
          revokedAncestorId: hop.certId,
        };
      }
      if (this.revokedPrincipals.has(hop.delegatorId)) {
        return {
          kind: 'Refuted',
          reason: 'ancestor-revoked-cascade',
          revokedAncestorId: hop.delegatorId,
        };
      }
      if (this.revokedPrincipals.has(hop.delegateeId)) {
        return {
          kind: 'Refuted',
          reason: 'ancestor-revoked-cascade',
          revokedAncestorId: hop.delegateeId,
        };
      }

      // Recompute Macaroon HMAC step from M3 root key (constant-time comparison):
      const msg = canonicalCaveatPayload({
        certId: hop.certId,
        parentCertHash: hop.parentCertHash,
        delegatorId: hop.delegatorId,
        delegateeId: hop.delegateeId,
        caveats: hop.caveats,
        issuedAtEpoch: hop.issuedAtEpoch,
      });
      expectedMac = this.rootKey.computeHmac(expectedMac, msg);
      const presentedMac = Buffer.from(hop.chainMacHex, 'hex');
      if (
        presentedMac.length !== expectedMac.length ||
        !timingSafeEqual(presentedMac, expectedMac)
      ) {
        return {kind: 'Refuted', reason: 'chain-mac-tampered'};
      }

      if (params.nowEpoch > hop.caveats.expiresAtEpoch) {
        return {kind: 'Refuted', reason: 'capability-expired'};
      }

      custodyLineage.push(hop.delegateeId);
      prevCert = hop;
    }

    // Final leaf scope check against target path and action:
    const effectiveCaveats = leaf.caveats;
    if (!effectiveCaveats.allowedActions.includes(params.action)) {
      return {kind: 'Refuted', reason: 'action-out-of-scope'};
    }
    if (!effectiveCaveats.allowedPathPrefixes.some(p => isPathWithinPrefix(params.targetPath, p))) {
      return {kind: 'Refuted', reason: 'path-out-of-scope'};
    }

    const receiptMerkleHash = this.kv.putBlob(
      'delegated-execution-audit-receipt',
      {
        leafCertHash: leaf.certMerkleHash,
        custodyLineage,
        callerId: params.callerId,
        targetPath: normalizePath(params.targetPath),
        action: params.action,
        executedAtEpoch: params.nowEpoch,
      },
      [leaf.certMerkleHash],
    );
    this.kv.pinHistoricalCut(receiptMerkleHash);

    return {
      kind: 'Authorized',
      effectiveCaveats,
      receipt: {
        receiptMerkleHash,
        leafCertHash: leaf.certMerkleHash,
        custodyLineage,
        callerId: params.callerId,
        targetPath: normalizePath(params.targetPath),
        action: params.action,
        executedAtEpoch: params.nowEpoch,
      },
    };
  }
}
