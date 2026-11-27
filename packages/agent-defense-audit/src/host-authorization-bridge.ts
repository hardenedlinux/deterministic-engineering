// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 26 (10.174): Policy-Engine-Agnostic Dual-Sovereignty Bridge
 * (Library `deterministic-engineering-qnt` <-> Consuming Authorization Host `cedar-poo-spec`).
 *
 * Strictly preserves the Library vs. Host separation:
 *   - Concrete Cedar policies, principal/action/resource evaluation, and tenant rules
 *     live in `cedar-poo-spec` (producing a `HostAuthorizationReceipt`).
 *   - This library enforces Dual-Sovereignty Conjunction Soundness:
 *       1. Canonical Cedar `Forbid`-overrides-`Permit` & closed-world default-deny helper.
 *       2. Library `Refuted` CANNOT be bypassed by a Host `Permit`.
 *       3. Host `Forbid` or `Pending` CANNOT be bypassed by Library `Finalized`.
 *       4. `BoundOperation` anti-replay (`boundOpDigest === expectedOpDigest`).
 *       5. `PolicySnapshot` drift fence with `R1` disjoint-scope preservation.
 *       6. `AuthorityConsumption` use-time live `M3` lease check (TOCTOU fence).
 *       7. `R3` non-serializable reachability guard on pinned `M1` admission receipts.
 */

import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import type {EpochCheckpointVerdict} from './witness-epoch-reconfiguration.ts';

export type HostPolicyDecision = 'Permit' | 'Forbid' | 'Pending';

export interface HostPolicyEvalInput {
  permitMatched: boolean;
  forbidMatched: boolean;
  contextReady: boolean;
}

/**
 * Canonical Cedar-compatible closed-world host decision evaluator (`Forbid` overrides `Permit`).
 */
export function evaluateHostPolicySemantics(inp: HostPolicyEvalInput): HostPolicyDecision {
  if (inp.forbidMatched) return 'Forbid';
  if (!inp.contextReady) return 'Pending';
  if (inp.permitMatched) return 'Permit';
  return 'Forbid';
}

/**
 * Policy-engine-agnostic authorization receipt supplied by a consuming host (e.g. `cedar-poo-spec`),
 * aligned with `CedarPooSpec.Admission.{BoundOperation,PolicySnapshot,AuthorityConsumption}`.
 */
export interface HostAuthorizationReceipt {
  hostSystem: string;
  decision: HostPolicyDecision;
  boundOperationDigest: string;
  policySnapshotDigest: string;
  policyAffectedScopes: readonly string[];
  /** Optional M3 live lease inspected at consumption time (NEVER persisted into M1!). */
  liveAuthorityLease?: LiveM3Capability;
  authorityLiveAtUse: boolean;
  /** Optional raw metadata audited by R3 guard if persisted. */
  extraMetadata?: Record<string, unknown>;
}

export type DualSovereignVerdict =
  | {
      kind: 'Proven';
      operationDigest: string;
      policySnapshotDigest: string;
      libraryCheckpointDigest: string;
      dualSovereignReceiptHash: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'library-verdict-refused'
        | 'host-policy-forbid'
        | 'host-policy-pending'
        | 'bound-operation-digest-mismatch'
        | 'stale-policy-snapshot-digest'
        | 'authority-revoked-at-consumption';
      detail?: string;
    };

/**
 * Evaluates the Dual-Sovereignty Conjunction Gate combining:
 *   - Library cryptographic finality (`EpochCheckpointVerdict` from B10/B10b/B10c), AND
 *   - Consuming-host authorization receipt (`cedar-poo-spec`),
 * pinning an immutable `M1` `DualSovereignAdmissionReceipt` (never leaking `M3` handles!).
 */
export function evaluateDualSovereignGate(params: {
  kv: ContentAddressedKvStore;
  libraryVerdict: EpochCheckpointVerdict;
  hostReceipt: HostAuthorizationReceipt;
  expectedOperationDigest: string;
  activePolicySnapshotDigest: string;
  policyChangedScopes?: readonly string[];
  activeLeaseEpoch?: number;
}): DualSovereignVerdict {
  const {kv, libraryVerdict, hostReceipt} = params;

  // 1. Cedar Permit can NEVER bypass a Library cryptographic/quorum/slashing refusal!
  if (libraryVerdict.kind !== 'FinalizedInEpoch') {
    return {
      kind: 'Refuted',
      reason: 'library-verdict-refused',
      detail: libraryVerdict.reason,
    };
  }

  // 2. Library Finalized can NEVER bypass Host Forbid or unresolved Pending!
  if (hostReceipt.decision === 'Forbid') {
    return {kind: 'Refuted', reason: 'host-policy-forbid'};
  }
  if (hostReceipt.decision === 'Pending') {
    return {kind: 'Refuted', reason: 'host-policy-pending'};
  }

  // 3. BoundOperation / OperationIdentity anti-replay check:
  if (hostReceipt.boundOperationDigest !== params.expectedOperationDigest) {
    return {kind: 'Refuted', reason: 'bound-operation-digest-mismatch'};
  }

  // 4. PolicySnapshot drift fence with R1 disjoint-scope preservation:
  if (hostReceipt.policySnapshotDigest !== params.activePolicySnapshotDigest) {
    const changed = new Set(params.policyChangedScopes ?? []);
    const intersects =
      changed.size === 0 ||
      hostReceipt.policyAffectedScopes.some(scope => changed.has(scope));
    if (intersects) {
      return {kind: 'Refuted', reason: 'stale-policy-snapshot-digest'};
    }
  }

  // 5. AuthorityConsumption use-time M3 lease verification (TOCTOU fence):
  const leaseStale =
    hostReceipt.liveAuthorityLease !== undefined &&
    params.activeLeaseEpoch !== undefined &&
    hostReceipt.liveAuthorityLease.revocationEpoch < params.activeLeaseEpoch;
  if (!hostReceipt.authorityLiveAtUse || leaseStale) {
    return {kind: 'Refuted', reason: 'authority-revoked-at-consumption'};
  }

  // 6. Pin pure M1 DualSovereignAdmissionReceipt (R3 guard rejects any buried M3 handle in extraMetadata!):
  const receiptPayload = {
    hostSystem: hostReceipt.hostSystem,
    decision: hostReceipt.decision,
    operationDigest: params.expectedOperationDigest,
    policySnapshotDigest: params.activePolicySnapshotDigest,
    libraryEpoch: libraryVerdict.epoch,
    libraryTreeSize: libraryVerdict.treeSize,
    libraryRootHashHex: libraryVerdict.rootHashHex,
    libraryCheckpointDigest: libraryVerdict.checkpointDigest,
    verifiedWitnessIds: libraryVerdict.verifiedWitnessIds,
    extraMetadata: hostReceipt.extraMetadata ?? {},
  };
  const dualSovereignReceiptHash = kv.putBlob(
    'dual-sovereign-admission-receipt',
    {...receiptPayload, receiptDigest: sha256Digest(receiptPayload)},
    [],
  );
  kv.pinHistoricalCut(dualSovereignReceiptHash);

  return {
    kind: 'Proven',
    operationDigest: params.expectedOperationDigest,
    policySnapshotDigest: params.activePolicySnapshotDigest,
    libraryCheckpointDigest: libraryVerdict.checkpointDigest,
    dualSovereignReceiptHash,
  };
}
