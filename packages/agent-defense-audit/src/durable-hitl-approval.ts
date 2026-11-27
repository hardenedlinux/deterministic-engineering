// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 11 (Business Extension B5, 10.159):
 * Long-Horizon Human-in-the-Loop (HITL) Durable Pause/Resume,
 * Baseline/Policy-Drift Re-Approval, Anti-Fatigue Cold Projection,
 * Cold M1-Only Hibernation (R3), and Anti-Nagging Veto Persistence.
 *
 * Addresses five structural failure modes of naive HITL agent pause/resume:
 *   1. Stale-Approval TOCTOU across multi-day human think-time (baseline drift,
 *      intersecting policy upgrade, or TTL expiry invalidates stale approval).
 *   2. Approval Fatigue & Social Engineering (human approver receives ONLY a
 *      cold M1-projected `HumanDecisionBrief`, stripping untrusted M2 prose).
 *   3. Hibernation Resource Leak & Live-Handle Serialization Trap (enforces R3
 *      `assertM1Persistable` and drops all M3 leases before entering cold pause).
 *   4. Single-Use Consumption & Duplicate-Webhook Replay Fencing (atomic
 *      consumption + fresh monotonic M3 execution lease on resume).
 *   5. Anti-Nagging / Human MFA-Bombing Prevention (human veto persists as an
 *      immutable M1 negative constraint with bounded re-submission budget).
 */

import {
  assertM1Persistable,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';

export interface HitlColdReceipt {
  receiptId: string;
  kind: 'ast-audit' | 'apalache-proof' | 'mbt-coverage' | 'canary-plan' | 'rollback-cut';
  digest: string;
  passed: boolean;
}

export interface HitlProposalInput {
  proposalId: string;
  semanticTarget: string;
  requesterId: string;
  baseCutHash: string;
  policyEpochHash: string;
  affectedScopes: string[];
  diffDigest: string;
  rollbackCutHash: string;
  coldReceipts: HitlColdReceipt[];
  /**
   * Untrusted M2 agent commentary / chain-of-thought / persuasion prose.
   * NEVER forwarded into the HumanDecisionBrief (anti-fatigue & injection firewall).
   */
  untrustedAgentProse?: string;
  /**
   * Optional arbitrary metadata checked by R3 assertM1Persistable so live M3
   * handles/leases can never leak into cold hibernation.
   */
  metadata?: Record<string, unknown>;
  /**
   * Optional M1 evidence digest demonstrating how a prior human veto constraint
   * was explicitly addressed in a revised proposal.
   */
  vetoResolutionEvidenceHash?: string;
  requiredApprovals?: number;
  ttlEpochs: number;
  nowEpoch: number;
}

export interface HumanDecisionBrief {
  suspensionId: string;
  proposalId: string;
  proposalHash: string;
  semanticTarget: string;
  requesterId: string;
  baseCutHash: string;
  policyEpochHash: string;
  affectedScopes: string[];
  diffDigest: string;
  rollbackCutHash: string;
  verifiedReceiptDigests: string[];
  requiredApprovals: number;
  expiresAtEpoch: number;
  strippedUntrustedProseBytes: number;
}

export interface SuspensionAnchor {
  suspensionId: string;
  proposalId: string;
  proposalHash: string;
  semanticTarget: string;
  requesterId: string;
  baseCutHash: string;
  policyEpochHash: string;
  affectedScopes: string[];
  diffDigest: string;
  rollbackCutHash: string;
  requiredApprovals: number;
  suspendedAtEpoch: number;
  expiresAtEpoch: number;
  m3LeaseRevokedAtSuspend: true;
  anchorMerkleHash: string;
}

export interface HumanApprovalReceipt {
  approvalDigest: string;
  suspensionId: string;
  proposalHash: string;
  approverId: string;
  boundBaseCutHash: string;
  boundPolicyEpochHash: string;
  signedAtEpoch: number;
  expiresAtEpoch: number;
  receiptMerkleHash: string;
}

export interface HumanVetoConstraint {
  vetoMerkleHash: string;
  suspensionId: string;
  proposalHash: string;
  semanticTarget: string;
  vetoedBy: string;
  reasonCode: string;
  requiredFixConstraint: string;
  vetoedAtEpoch: number;
}

export type SuspendVerdict =
  | {
      kind: 'SuspendedCold';
      anchor: SuspensionAnchor;
      brief: HumanDecisionBrief;
      revokedLeaseId: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'missing-pinned-rollback-cut'
        | 'unverified-cold-receipts'
        | 'vetoed-proposal-resubmission-blocked'
        | 'human-veto-budget-exhausted';
      vetoConstraint?: HumanVetoConstraint;
    };

export type HumanApprovalRecordVerdict =
  | {
      kind: 'Recorded';
      receipt: HumanApprovalReceipt;
      approvalsCollected: number;
      requiredApprovals: number;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'unknown-suspension'
        | 'sod-requester-self-approval-forbidden'
        | 'duplicate-approver-in-quorum'
        | 'suspension-already-vetoed'
        | 'suspension-already-consumed'
        | 'approval-expired';
    };

export interface LiveWorldContext {
  currentBaseCutHash: string;
  currentPolicyEpochHash: string;
  /**
   * Scopes affected by any policy upgrade since `policyEpochHash`.
   * Used for R1 bounded policy co-evolution: if disjoint from the proposal's
   * `affectedScopes`, the upgrade does not invalidate prior approval.
   */
  policyChangedScopes: string[];
  currentEpoch: number;
  emergencyFreezeActive: boolean;
}

export type HitlResumeVerdict =
  | {
      kind: 'AdmitAndResume';
      suspensionId: string;
      proposalHash: string;
      executionLease: LiveM3Capability;
      executionEpoch: number;
      policyCoEvolutionMode: 'exact-match' | 'r1-bounded-disjoint-upgrade';
      consumedApprovalDigests: string[];
    }
  | {
      kind: 'PendingReapproval';
      reason:
        | 'baseline-drift-reapproval-required'
        | 'policy-drift-reapproval-required'
        | 'approval-expired'
        | 'quorum-incomplete';
      suspensionId: string;
      intersectingScopes?: string[];
      approvalsCollected?: number;
      requiredApprovals?: number;
    }
  | {
      kind: 'AlreadyConsumedNoop';
      suspensionId: string;
      proposalHash: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'unknown-suspension'
        | 'proposal-binding-mismatch'
        | 'human-vetoed'
        | 'emergency-freeze-active'
        | 'm3-lease-not-revoked';
    };

export class DurableHitlApprovalEngine {
  private monotonicExecutionEpoch = 1;
  private readonly anchors = new Map<string, SuspensionAnchor>();
  private readonly approvalsBySuspension = new Map<string, HumanApprovalReceipt[]>();
  private readonly vetoesBySuspension = new Map<string, HumanVetoConstraint>();
  private readonly vetoesBySemanticTarget = new Map<string, HumanVetoConstraint>();
  private readonly rejectedProposalHashes = new Set<string>();
  private readonly resubmissionAttemptsByTarget = new Map<string, number>();
  private readonly consumedSuspensions = new Set<string>();
  private readonly revokedLeaseIds = new Set<string>();

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly maxResubmissionsAfterVeto = 2,
  ) {}

  getMonotonicExecutionEpoch(): number {
    return this.monotonicExecutionEpoch;
  }

  isLeaseRevoked(leaseId: string): boolean {
    return this.revokedLeaseIds.has(leaseId);
  }

  /**
   * Transitions an active agent into zero-cost M1-only cold hibernation:
   *  1. Enforces R3 `assertM1Persistable` on proposal metadata (blocks leaked M3 handles).
   *  2. Enforces anti-nagging veto persistence (blocks identical or unaddressed retries).
   *  3. Drops/revokes the active M3 execution lease before checkpointing M1 anchor.
   *  4. Projects a cold `HumanDecisionBrief` stripped of untrusted M2 agent prose.
   */
  suspendForApproval(
    proposal: HitlProposalInput,
    activeLeaseToDrop: LiveM3Capability,
  ): SuspendVerdict {
    // R3: Guarantee zero live M3 capabilities enter cold M1 hibernation state.
    assertM1Persistable(proposal.metadata ?? null, 'proposal.metadata');
    assertM1Persistable(proposal.coldReceipts, 'proposal.coldReceipts');

    if (!proposal.rollbackCutHash || !this.kv.hasBlob(proposal.rollbackCutHash)) {
      return {kind: 'Refuted', reason: 'missing-pinned-rollback-cut'};
    }
    if (
      proposal.coldReceipts.length === 0 ||
      proposal.coldReceipts.some(r => !r.passed || !r.digest)
    ) {
      return {kind: 'Refuted', reason: 'unverified-cold-receipts'};
    }

    const proposalHash = sha256Digest({
      proposalId: proposal.proposalId,
      semanticTarget: proposal.semanticTarget,
      diffDigest: proposal.diffDigest,
      affectedScopes: [...proposal.affectedScopes].sort(),
      rollbackCutHash: proposal.rollbackCutHash,
      vetoResolutionEvidenceHash: proposal.vetoResolutionEvidenceHash ?? null,
    });

    // Anti-Nagging / Human MFA-Bombing Prevention:
    const priorVeto = this.vetoesBySemanticTarget.get(proposal.semanticTarget);
    if (priorVeto) {
      if (this.rejectedProposalHashes.has(proposalHash) || !proposal.vetoResolutionEvidenceHash) {
        return {
          kind: 'Refuted',
          reason: 'vetoed-proposal-resubmission-blocked',
          vetoConstraint: priorVeto,
        };
      }
      const attempts = (this.resubmissionAttemptsByTarget.get(proposal.semanticTarget) ?? 0) + 1;
      if (attempts > this.maxResubmissionsAfterVeto) {
        return {
          kind: 'Refuted',
          reason: 'human-veto-budget-exhausted',
          vetoConstraint: priorVeto,
        };
      }
      this.resubmissionAttemptsByTarget.set(proposal.semanticTarget, attempts);
    }

    // Drop/revoke active M3 lease BEFORE writing the cold M1 suspension anchor.
    this.revokedLeaseIds.add(activeLeaseToDrop.capabilityId);

    const requiredApprovals = Math.max(1, proposal.requiredApprovals ?? 1);
    const expiresAtEpoch = proposal.nowEpoch + Math.max(1, proposal.ttlEpochs);
    const suspensionId = `susp-${sha256Digest({
      proposalHash,
      baseCutHash: proposal.baseCutHash,
      policyEpochHash: proposal.policyEpochHash,
      nowEpoch: proposal.nowEpoch,
    }).slice(0, 16)}`;

    const anchorPayload = {
      suspensionId,
      proposalId: proposal.proposalId,
      proposalHash,
      semanticTarget: proposal.semanticTarget,
      requesterId: proposal.requesterId,
      baseCutHash: proposal.baseCutHash,
      policyEpochHash: proposal.policyEpochHash,
      affectedScopes: [...proposal.affectedScopes].sort(),
      diffDigest: proposal.diffDigest,
      rollbackCutHash: proposal.rollbackCutHash,
      requiredApprovals,
      suspendedAtEpoch: proposal.nowEpoch,
      expiresAtEpoch,
      m3LeaseRevokedAtSuspend: true as const,
      revokedLeaseId: activeLeaseToDrop.capabilityId,
    };

    const anchorMerkleHash = this.kv.putBlob('hitl-suspension-anchor', anchorPayload, [
      proposal.rollbackCutHash,
    ]);
    this.kv.pinHistoricalCut(anchorMerkleHash);

    const anchor: SuspensionAnchor = {
      suspensionId,
      proposalId: proposal.proposalId,
      proposalHash,
      semanticTarget: proposal.semanticTarget,
      requesterId: proposal.requesterId,
      baseCutHash: proposal.baseCutHash,
      policyEpochHash: proposal.policyEpochHash,
      affectedScopes: [...proposal.affectedScopes].sort(),
      diffDigest: proposal.diffDigest,
      rollbackCutHash: proposal.rollbackCutHash,
      requiredApprovals,
      suspendedAtEpoch: proposal.nowEpoch,
      expiresAtEpoch,
      m3LeaseRevokedAtSuspend: true,
      anchorMerkleHash,
    };

    this.anchors.set(suspensionId, anchor);
    this.approvalsBySuspension.set(suspensionId, []);

    // Project cold M1-only HumanDecisionBrief: strip 100% of untrusted M2 prose.
    const strippedUntrustedProseBytes = proposal.untrustedAgentProse
      ? Buffer.byteLength(proposal.untrustedAgentProse, 'utf8')
      : 0;

    const brief: HumanDecisionBrief = {
      suspensionId,
      proposalId: proposal.proposalId,
      proposalHash,
      semanticTarget: proposal.semanticTarget,
      requesterId: proposal.requesterId,
      baseCutHash: proposal.baseCutHash,
      policyEpochHash: proposal.policyEpochHash,
      affectedScopes: [...proposal.affectedScopes].sort(),
      diffDigest: proposal.diffDigest,
      rollbackCutHash: proposal.rollbackCutHash,
      verifiedReceiptDigests: proposal.coldReceipts.map(r => `${r.kind}:${r.digest}`),
      requiredApprovals,
      expiresAtEpoch,
      strippedUntrustedProseBytes,
    };

    return {
      kind: 'SuspendedCold',
      anchor,
      brief,
      revokedLeaseId: activeLeaseToDrop.capabilityId,
    };
  }

  /**
   * Records a cryptographically bound M1 human approval receipt enforcing SoD
   * (approver != requester) and distinct principals for multi-party quorum.
   */
  recordHumanApproval(params: {
    suspensionId: string;
    approverId: string;
    signedAtEpoch: number;
    boundBaseCutHash?: string;
    boundPolicyEpochHash?: string;
    extendedTtlEpochs?: number;
  }): HumanApprovalRecordVerdict {
    const anchor = this.anchors.get(params.suspensionId);
    if (!anchor) return {kind: 'Refuted', reason: 'unknown-suspension'};
    if (this.consumedSuspensions.has(params.suspensionId)) {
      return {kind: 'Refuted', reason: 'suspension-already-consumed'};
    }
    if (this.vetoesBySuspension.has(params.suspensionId)) {
      return {kind: 'Refuted', reason: 'suspension-already-vetoed'};
    }
    if (!params.approverId || params.approverId === anchor.requesterId) {
      return {kind: 'Refuted', reason: 'sod-requester-self-approval-forbidden'};
    }

    const effectiveExpiresAt =
      params.extendedTtlEpochs !== undefined
        ? params.signedAtEpoch + Math.max(1, params.extendedTtlEpochs)
        : anchor.expiresAtEpoch;
    if (params.signedAtEpoch > effectiveExpiresAt) {
      return {kind: 'Refuted', reason: 'approval-expired'};
    }

    const boundBaseCutHash = params.boundBaseCutHash ?? anchor.baseCutHash;
    const boundPolicyEpochHash = params.boundPolicyEpochHash ?? anchor.policyEpochHash;

    const existing = this.approvalsBySuspension.get(params.suspensionId) ?? [];
    // If human re-approves against a NEW drifted baseline/policy, replace their prior binding
    // for this suspension; if approving the SAME (baseline, policy) twice, reject duplicate quorum!
    const sameBindingDuplicate = existing.some(
      r =>
        r.approverId === params.approverId &&
        r.boundBaseCutHash === boundBaseCutHash &&
        r.boundPolicyEpochHash === boundPolicyEpochHash,
    );
    if (sameBindingDuplicate) {
      return {kind: 'Refuted', reason: 'duplicate-approver-in-quorum'};
    }

    const filtered = existing.filter(r => r.approverId !== params.approverId);
    const approvalDigest = sha256Digest({
      suspensionId: params.suspensionId,
      proposalHash: anchor.proposalHash,
      approverId: params.approverId,
      boundBaseCutHash,
      boundPolicyEpochHash,
      signedAtEpoch: params.signedAtEpoch,
      expiresAtEpoch: effectiveExpiresAt,
    });

    const receiptMerkleHash = this.kv.putBlob(
      'hitl-approval-receipt',
      {
        approvalDigest,
        suspensionId: params.suspensionId,
        proposalHash: anchor.proposalHash,
        approverId: params.approverId,
        boundBaseCutHash,
        boundPolicyEpochHash,
        signedAtEpoch: params.signedAtEpoch,
        expiresAtEpoch: effectiveExpiresAt,
      },
      [anchor.anchorMerkleHash],
    );

    const receipt: HumanApprovalReceipt = {
      approvalDigest,
      suspensionId: params.suspensionId,
      proposalHash: anchor.proposalHash,
      approverId: params.approverId,
      boundBaseCutHash,
      boundPolicyEpochHash,
      signedAtEpoch: params.signedAtEpoch,
      expiresAtEpoch: effectiveExpiresAt,
      receiptMerkleHash,
    };

    filtered.push(receipt);
    this.approvalsBySuspension.set(params.suspensionId, filtered);

    return {
      kind: 'Recorded',
      receipt,
      approvalsCollected: filtered.length,
      requiredApprovals: anchor.requiredApprovals,
    };
  }

  /**
   * Records an immutable M1 human veto constraint that blocks execution and
   * prevents nagging re-submissions of the same proposal.
   */
  recordHumanVeto(params: {
    suspensionId: string;
    vetoedBy: string;
    reasonCode: string;
    requiredFixConstraint: string;
    vetoedAtEpoch: number;
  }): HumanVetoConstraint {
    const anchor = this.anchors.get(params.suspensionId);
    if (!anchor) {
      throw new Error(`Unknown suspensionId '${params.suspensionId}'`);
    }
    const vetoPayload = {
      suspensionId: params.suspensionId,
      proposalHash: anchor.proposalHash,
      semanticTarget: anchor.semanticTarget,
      vetoedBy: params.vetoedBy,
      reasonCode: params.reasonCode,
      requiredFixConstraint: params.requiredFixConstraint,
      vetoedAtEpoch: params.vetoedAtEpoch,
    };
    const vetoMerkleHash = this.kv.putBlob('hitl-veto-constraint', vetoPayload, [
      anchor.anchorMerkleHash,
    ]);
    this.kv.pinHistoricalCut(vetoMerkleHash);

    const constraint: HumanVetoConstraint = {
      vetoMerkleHash,
      ...vetoPayload,
    };
    this.vetoesBySuspension.set(params.suspensionId, constraint);
    this.vetoesBySemanticTarget.set(anchor.semanticTarget, constraint);
    this.rejectedProposalHashes.add(anchor.proposalHash);
    return constraint;
  }

  /**
   * Evaluates live world admissibility upon wake-up and, only if every guard holds,
   * atomically consumes the approval receipts and mints a fresh single-use monotonic
   * M3 execution lease scoped strictly to `proposalHash`.
   */
  evaluateAndResume(params: {
    suspensionId: string;
    expectedProposalHash: string;
    world: LiveWorldContext;
  }): HitlResumeVerdict {
    const anchor = this.anchors.get(params.suspensionId);
    if (!anchor) return {kind: 'Refuted', reason: 'unknown-suspension'};
    if (anchor.proposalHash !== params.expectedProposalHash) {
      return {kind: 'Refuted', reason: 'proposal-binding-mismatch'};
    }
    if (!anchor.m3LeaseRevokedAtSuspend) {
      return {kind: 'Refuted', reason: 'm3-lease-not-revoked'};
    }
    if (this.vetoesBySuspension.has(params.suspensionId)) {
      return {kind: 'Refuted', reason: 'human-vetoed'};
    }
    if (this.consumedSuspensions.has(params.suspensionId)) {
      return {
        kind: 'AlreadyConsumedNoop',
        suspensionId: params.suspensionId,
        proposalHash: anchor.proposalHash,
      };
    }
    if (params.world.emergencyFreezeActive) {
      return {kind: 'Refuted', reason: 'emergency-freeze-active'};
    }

    const receipts = this.approvalsBySuspension.get(params.suspensionId) ?? [];
    if (receipts.length < anchor.requiredApprovals) {
      return {
        kind: 'PendingReapproval',
        reason: 'quorum-incomplete',
        suspensionId: params.suspensionId,
        approvalsCollected: receipts.length,
        requiredApprovals: anchor.requiredApprovals,
      };
    }

    // Every receipt in the quorum must be fresh (not expired) and match live baseline.
    for (const r of receipts) {
      if (params.world.currentEpoch > r.expiresAtEpoch) {
        return {
          kind: 'PendingReapproval',
          reason: 'approval-expired',
          suspensionId: params.suspensionId,
        };
      }
      if (r.boundBaseCutHash !== params.world.currentBaseCutHash) {
        return {
          kind: 'PendingReapproval',
          reason: 'baseline-drift-reapproval-required',
          suspensionId: params.suspensionId,
        };
      }
    }

    // Policy drift evaluation with R1 bounded negative-dependency co-evolution:
    const allMatchPolicyExactly = receipts.every(
      r => r.boundPolicyEpochHash === params.world.currentPolicyEpochHash,
    );
    let policyCoEvolutionMode: 'exact-match' | 'r1-bounded-disjoint-upgrade' = 'exact-match';
    if (!allMatchPolicyExactly) {
      const proposalScopeSet = new Set(anchor.affectedScopes);
      const intersecting = params.world.policyChangedScopes.filter(s => proposalScopeSet.has(s));
      if (intersecting.length > 0 || params.world.policyChangedScopes.length === 0) {
        // Fail closed when changed scopes intersect OR when change scope is unknown/empty!
        return {
          kind: 'PendingReapproval',
          reason: 'policy-drift-reapproval-required',
          suspensionId: params.suspensionId,
          intersectingScopes: intersecting,
        };
      }
      policyCoEvolutionMode = 'r1-bounded-disjoint-upgrade';
    }

    // Atomic single-use consumption + fresh monotonic M3 execution lease!
    this.consumedSuspensions.add(params.suspensionId);
    this.monotonicExecutionEpoch += 1;
    const executionEpoch = this.monotonicExecutionEpoch;
    const consumedApprovalDigests = receipts.map(r => r.approvalDigest);

    this.kv.putBlob(
      'hitl-resume-consumption',
      {
        suspensionId: params.suspensionId,
        proposalHash: anchor.proposalHash,
        executionEpoch,
        policyCoEvolutionMode,
        consumedApprovalDigests,
        resumedAtEpoch: params.world.currentEpoch,
      },
      [anchor.anchorMerkleHash, ...receipts.map(r => r.receiptMerkleHash)],
    );

    const executionLease = new LiveM3Capability(
      `hitl-exec-${params.suspensionId}-ep${executionEpoch}`,
      `proposal:${anchor.proposalHash}`,
      executionEpoch,
    );

    return {
      kind: 'AdmitAndResume',
      suspensionId: params.suspensionId,
      proposalHash: anchor.proposalHash,
      executionLease,
      executionEpoch,
      policyCoEvolutionMode,
      consumedApprovalDigests,
    };
  }
}
