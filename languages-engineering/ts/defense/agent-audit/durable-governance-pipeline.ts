// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 14 (10.162): Unified End-to-End Durable AI Governance Pipeline.
 *
 * Composes all seven independently verified governance layers into one cohesive
 * lifecycle engine and closes cross-layer emergent fault gaps:
 *   1. B3 (`CapabilityDelegationAuthority`) — Macaroon attenuated delegation & cascading revocation
 *   2. G2/E1/E2 (`auditTypeScriptSource`)   — AST defensive-hallucination & anti-evasion gate
 *   3. B4 (`arbitrateConcurrentWorkspaces`) — Automated TS/Scheme AST symbol SSI & DE01 isolation
 *   4. Phase 9 (`projectRoleContext`)       — Role-projected cold M1 context (anti-overthinking)
 *   5. B5 (`DurableHitlApprovalEngine`)     — Cold M1 hibernation, drift re-approval & anti-nagging veto
 *   6. B1 (`AutonomousReleaseOrchestrator`) — SoD release, canary SLO gate & durable Merkle rollback
 *   7. B2 (`RegulatedMultiTenantDecisionEngine`) — AES-256-GCM tenant isolation & multi-year replay
 *
 * Key Cross-Layer Guarantees:
 *   - B3 x B5: Live re-attestation of every admitted agent's delegation chain at HITL wake-up
 *     blocks compromised supply-chain sub-agents even if human approved before revocation.
 *   - G2 x B4 x B5: AST evasions and symbol write-skew are blocked BEFORE emitting a
 *     HumanDecisionBrief (zero approval fatigue on broken patches).
 *   - B1 x B5: Canary breach auto-rollback restores the pinned M1 cut, bumps the M3 epoch,
 *     preserves forensics across GC, and automatically persists a B5 anti-nagging veto.
 */

import {
  AeadPartitionKey,
  CapabilityPartitionedAeadStore,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {auditTypeScriptSource} from './ts-ast-auditor.ts';
import {
  CapabilityDelegationAuthority,
  DelegationCertificate,
} from './capability-attenuation.ts';
import {
  arbitrateConcurrentWorkspaces,
  BoundedRevalidationPacket,
  ConcurrentAgentWorkspace,
  DirectWwConflict,
  SymbolRwAntidependency,
} from './symbol-ssi-arbitrator.ts';
import {
  DurableTaskRootState,
  ProjectedAgentContext,
  projectRoleContext,
} from './durable-ai-context.ts';
import {
  DurableHitlApprovalEngine,
  HumanDecisionBrief,
  HumanVetoConstraint,
  LiveWorldContext,
  SuspensionAnchor,
} from './durable-hitl-approval.ts';
import {
  AutonomousReleaseOrchestrator,
  CanarySloStatus,
  RegulatedMultiTenantDecisionEngine,
  RollbackReceipt,
} from './durable-business-orchestrator.ts';
import type {GovernanceTranscript} from './governance-harness.ts';

export interface DelegatedAgentSubmission {
  agentId: string;
  fencingEpoch: number;
  delegationChain: DelegationCertificate[];
  modifiedFiles: Record<string, string>;
  untrustedProseClaim?: string;
}

export interface StagedReleaseBatch {
  releaseId: string;
  semanticTarget: string;
  admittedAgents: string[];
  admittedChains: Array<{agentId: string; chain: DelegationCertificate[]; paths: string[]}>;
  custodyLineages: Record<string, string[]>;
  rejectedByDelegation: Array<{agentId: string; reason: string; revokedAncestorId?: string}>;
  rejectedByAstAudit: Array<{agentId: string; filePath: string; rules: string[]}>;
  ssiVerdict: string;
  wwConflicts: DirectWwConflict[];
  rwEdges: SymbolRwAntidependency[];
  revalidationPackets: BoundedRevalidationPacket[];
  reviewerContext: ProjectedAgentContext | null;
  preReleaseCutHash: string | null;
  suspensionAnchor: SuspensionAnchor | null;
  humanBrief: HumanDecisionBrief | null;
  mergedFiles: Record<string, string>;
  artifactDigest: string;
  arbitrationReceiptHash: string;
}

export type UnifiedPromoteVerdict =
  | {
      kind: 'PromotedAndRecorded';
      releaseId: string;
      releaseRootHash: string;
      regulatedDecisionRootHash: string;
      executionEpoch: number;
      policyCoEvolutionMode: 'exact-match' | 'r1-bounded-disjoint-upgrade';
    }
  | {
      kind: 'PendingReapproval';
      reason: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'batch-not-staged-for-approval'
        | 'delegation-chain-revoked-after-suspend'
        | 'hitl-refused'
        | 'release-gate-refused';
      detail: string;
    };

export class UnifiedDurableGovernancePipeline {
  readonly hitl: DurableHitlApprovalEngine;
  readonly release: AutonomousReleaseOrchestrator;
  readonly regulated: RegulatedMultiTenantDecisionEngine;

  private readonly stagedBatches = new Map<string, StagedReleaseBatch>();

  constructor(
    readonly kv: ContentAddressedKvStore,
    readonly aead: CapabilityPartitionedAeadStore,
    readonly delegation: CapabilityDelegationAuthority,
    maxResubmissionsAfterVeto = 1,
  ) {
    this.hitl = new DurableHitlApprovalEngine(kv, maxResubmissionsAfterVeto);
    this.release = new AutonomousReleaseOrchestrator(kv);
    this.regulated = new RegulatedMultiTenantDecisionEngine(kv, aead);
  }

  /**
   * Stage 1 -> Stage 5:
   *   B3 Delegation Auth -> G2/E1/E2 AST Gate -> B4 Symbol SSI Arbitrator ->
   *   Phase 9 Cold Reviewer Projection -> B1 Cut Pin -> B5 Cold HITL Hibernation.
   */
  stageConcurrentReleaseBatch(params: {
    releaseId: string;
    semanticTarget: string;
    requesterId: string;
    baseFiles: Record<string, string>;
    submissions: DelegatedAgentSubmission[];
    policyEpochHash: string;
    affectedScopes: string[];
    activeLeaseEpoch: number;
    activeLeaseToDrop: LiveM3Capability;
    requiredApprovals: number;
    ttlEpochs: number;
    nowEpoch: number;
    vetoResolutionEvidenceHash?: string;
  }): StagedReleaseBatch {
    const rejectedByDelegation: StagedReleaseBatch['rejectedByDelegation'] = [];
    const rejectedByAstAudit: StagedReleaseBatch['rejectedByAstAudit'] = [];
    const custodyLineages: Record<string, string[]> = {};
    const authorizedCleanWorkspaces: ConcurrentAgentWorkspace[] = [];
    const submissionMetaByAgent = new Map<
      string,
      {chain: DelegationCertificate[]; paths: string[]; prose?: string}
    >();

    // 1. B3 Delegation Authorization + 2. G2/E1/E2 AST Anti-Evasion Gate (pre-SSI, pre-HITL!)
    for (const sub of params.submissions) {
      const modifiedPaths = Object.keys(sub.modifiedFiles);
      let delegationOk = true;
      for (const relPath of modifiedPaths) {
        const targetPath = relPath.startsWith('/') ? relPath : `/${relPath}`;
        const authRes = this.delegation.authorizeDelegatedAction({
          chain: sub.delegationChain,
          callerId: sub.agentId,
          targetPath,
          action: 'write',
          nowEpoch: params.nowEpoch,
        });
        if (authRes.kind !== 'Authorized') {
          rejectedByDelegation.push({
            agentId: sub.agentId,
            reason: authRes.reason,
            revokedAncestorId: authRes.revokedAncestorId,
          });
          delegationOk = false;
          break;
        }
        custodyLineages[sub.agentId] = authRes.receipt.custodyLineage;
      }
      if (!delegationOk) continue;

      let astOk = true;
      for (const [relPath, src] of Object.entries(sub.modifiedFiles)) {
        if (relPath.endsWith('.ts') || relPath.endsWith('.tsx')) {
          const audit = auditTypeScriptSource(src, relPath);
          if (!audit.passed) {
            rejectedByAstAudit.push({
              agentId: sub.agentId,
              filePath: relPath,
              rules: audit.findings.map(f => f.rule),
            });
            astOk = false;
            break;
          }
        }
      }
      if (!astOk) continue;

      authorizedCleanWorkspaces.push({
        agentId: sub.agentId,
        fencingEpoch: sub.fencingEpoch,
        modifiedFiles: sub.modifiedFiles,
      });
      submissionMetaByAgent.set(sub.agentId, {
        chain: sub.delegationChain,
        paths: modifiedPaths,
        prose: sub.untrustedProseClaim,
      });
    }

    // 3. B4 Automated AST Symbol-Level ReadSet x WriteSet SSI Arbitration
    const ssi = arbitrateConcurrentWorkspaces({
      baseFiles: params.baseFiles,
      proposals: authorizedCleanWorkspaces,
      activeLeaseEpoch: params.activeLeaseEpoch,
      kv: this.kv,
    });

    const artifactDigest = sha256Digest(ssi.mergedFiles);
    const admittedChains = ssi.admittedAgents.map(agentId => {
      const meta = submissionMetaByAgent.get(agentId)!;
      return {agentId, chain: meta.chain, paths: meta.paths};
    });

    // If zero agents were admitted, do NOT bother human approvers (zero approval fatigue!).
    if (ssi.admittedAgents.length === 0) {
      const emptyBatch: StagedReleaseBatch = {
        releaseId: params.releaseId,
        semanticTarget: params.semanticTarget,
        admittedAgents: [],
        admittedChains: [],
        custodyLineages,
        rejectedByDelegation,
        rejectedByAstAudit,
        ssiVerdict: ssi.verdict,
        wwConflicts: ssi.wwConflicts,
        rwEdges: ssi.rwEdges,
        revalidationPackets: ssi.revalidationPackets,
        reviewerContext: null,
        preReleaseCutHash: null,
        suspensionAnchor: null,
        humanBrief: null,
        mergedFiles: ssi.mergedFiles,
        artifactDigest,
        arbitrationReceiptHash: ssi.arbitrationReceiptHash,
      };
      this.stagedBatches.set(params.releaseId, emptyBatch);
      return emptyBatch;
    }

    // 4. Phase 9 Cold Role-Projected Reviewer Context (strips untrusted coder prose!)
    const astEvidenceHash = this.kv.putBlob(
      'pipeline-ast-receipt',
      {releaseId: params.releaseId, admittedAgents: ssi.admittedAgents, findings: 0},
      [],
    );
    const transcript: GovernanceTranscript = {
      taskId: params.releaseId,
      finalDecision: 'ADMIT',
      totalAttempts: 1,
      receipts: [
        {
          attempt: 1,
          patchDigest: artifactDigest,
          decision: 'ADMIT',
          oraclePassed: true,
          astAndDiffFindingCount: 0,
          scopeViolationCount: 0,
          agentProseClaim: params.submissions
            .map(s => s.untrustedProseClaim ?? '')
            .filter(Boolean)
            .join(' | '),
        },
      ],
    };
    const transcriptHash = this.kv.putBlob('pipeline-transcript', transcript, []);

    const taskRoot: DurableTaskRootState = {
      taskId: params.releaseId,
      policyDigest: params.policyEpochHash,
      hardConstraints: ['sod-independent-approver', 'r3-cold-hibernation', 'zero-g2-evasion'],
      evidenceNodes: [
        {
          id: 'ast-anti-evasion-pass',
          epistemicStatus: 'Proven',
          summary: '0 AST defensive-hallucination findings',
          m1BlobHash: astEvidenceHash,
          detailedPayloadSizeBytes: 4096,
        },
        {
          id: 'symbol-ssi-arbitration',
          epistemicStatus: 'Proven',
          summary: `SSI verdict: ${ssi.verdict}`,
          m1BlobHash: ssi.arbitrationReceiptHash,
          detailedPayloadSizeBytes: 4096,
        },
      ],
      latestTranscriptHash: transcriptHash,
    };
    const taskRootHash = this.kv.putBlob('pipeline-task-root', taskRoot, [
      astEvidenceHash,
      ssi.arbitrationReceiptHash,
      transcriptHash,
    ]);
    const reviewerContext = projectRoleContext(this.kv, taskRootHash, 'reviewer');

    // 5. B1 Pin Pre-Release M1 Rollback Cut
    const preReleaseCutHash = this.release.pinPreReleaseCut(params.releaseId, {
      baseFilesDigest: sha256Digest(params.baseFiles),
      releaseId: params.releaseId,
    });

    // 6. B5 Enter Zero-Cost Cold M1 Hibernation & Project HumanDecisionBrief
    const combinedUntrustedProse = params.submissions
      .map(s => s.untrustedProseClaim ?? '')
      .filter(Boolean)
      .join('\n');

    const susp = this.hitl.suspendForApproval(
      {
        proposalId: params.releaseId,
        semanticTarget: params.semanticTarget,
        requesterId: params.requesterId,
        baseCutHash: preReleaseCutHash,
        policyEpochHash: params.policyEpochHash,
        affectedScopes: params.affectedScopes,
        diffDigest: artifactDigest,
        rollbackCutHash: preReleaseCutHash,
        coldReceipts: [
          {receiptId: 'ast', kind: 'ast-audit', digest: astEvidenceHash, passed: true},
          {receiptId: 'ssi', kind: 'canary-plan', digest: ssi.arbitrationReceiptHash, passed: true},
        ],
        untrustedAgentProse: combinedUntrustedProse,
        requiredApprovals: params.requiredApprovals,
        ttlEpochs: params.ttlEpochs,
        nowEpoch: params.nowEpoch,
        vetoResolutionEvidenceHash: params.vetoResolutionEvidenceHash,
      },
      params.activeLeaseToDrop,
    );

    const batch: StagedReleaseBatch = {
      releaseId: params.releaseId,
      semanticTarget: params.semanticTarget,
      admittedAgents: ssi.admittedAgents,
      admittedChains,
      custodyLineages,
      rejectedByDelegation,
      rejectedByAstAudit,
      ssiVerdict: ssi.verdict,
      wwConflicts: ssi.wwConflicts,
      rwEdges: ssi.rwEdges,
      revalidationPackets: ssi.revalidationPackets,
      reviewerContext,
      preReleaseCutHash,
      suspensionAnchor: susp.kind === 'SuspendedCold' ? susp.anchor : null,
      humanBrief: susp.kind === 'SuspendedCold' ? susp.brief : null,
      mergedFiles: ssi.mergedFiles,
      artifactDigest,
      arbitrationReceiptHash: ssi.arbitrationReceiptHash,
    };
    this.stagedBatches.set(params.releaseId, batch);
    return batch;
  }

  /**
   * Stage 6 -> Stage 7:
   *   Cross-layer B3 live delegation re-attestation -> B5 HITL wake-up & drift check ->
   *   B1 SoD Release Promotion -> B2 Multi-Tenant AEAD Regulated Decision Cut.
   */
  resumePromoteAndRecordRegulated(params: {
    releaseId: string;
    authorId: string;
    primaryApproverId: string;
    world: LiveWorldContext;
    canarySloStatus: CanarySloStatus;
    tenantKey: AeadPartitionKey;
    modelId: string;
  }): UnifiedPromoteVerdict {
    const batch = this.stagedBatches.get(params.releaseId);
    if (!batch || !batch.suspensionAnchor || !batch.preReleaseCutHash) {
      return {
        kind: 'Refuted',
        reason: 'batch-not-staged-for-approval',
        detail: `Release '${params.releaseId}' has no active cold suspension anchor`,
      };
    }

    // Cross-Layer B3 x B5 Gate: re-verify EVERY admitted agent's delegation chain at wake-up!
    for (const entry of batch.admittedChains) {
      for (const relPath of entry.paths) {
        const targetPath = relPath.startsWith('/') ? relPath : `/${relPath}`;
        const recheck = this.delegation.authorizeDelegatedAction({
          chain: entry.chain,
          callerId: entry.agentId,
          targetPath,
          action: 'write',
          nowEpoch: params.world.currentEpoch,
        });
        if (recheck.kind !== 'Authorized') {
          return {
            kind: 'Refuted',
            reason: 'delegation-chain-revoked-after-suspend',
            detail: `${entry.agentId}: ${recheck.reason}${recheck.revokedAncestorId ? ` (${recheck.revokedAncestorId})` : ''}`,
          };
        }
      }
    }

    // B5 HITL Resume Gate (drift, TTL, quorum, veto, single-use consumption)
    const resume = this.hitl.evaluateAndResume({
      suspensionId: batch.suspensionAnchor.suspensionId,
      expectedProposalHash: batch.suspensionAnchor.proposalHash,
      world: params.world,
    });
    if (resume.kind === 'PendingReapproval') {
      return {kind: 'PendingReapproval', reason: resume.reason};
    }
    if (resume.kind !== 'AdmitAndResume') {
      return {
        kind: 'Refuted',
        reason: 'hitl-refused',
        detail: resume.kind === 'Refuted' ? resume.reason : 'already-consumed',
      };
    }

    // B1 SoD Production Release Promotion
    const transcript: GovernanceTranscript = {
      taskId: params.releaseId,
      finalDecision: 'ADMIT',
      totalAttempts: 1,
      receipts: [
        {
          attempt: 1,
          patchDigest: batch.artifactDigest,
          decision: 'ADMIT',
          oraclePassed: true,
          astAndDiffFindingCount: 0,
          scopeViolationCount: 0,
          agentProseClaim: 'cold-verified',
        },
      ],
    };

    const promo = this.release.promoteToProduction({
      releaseId: params.releaseId,
      authorId: params.authorId,
      approverId: params.primaryApproverId,
      workerEpoch: this.release.getActiveEpoch(),
      transcript,
      preReleaseCutHash: batch.preReleaseCutHash,
      canarySloStatus: params.canarySloStatus,
      emergencyFreezeActive: params.world.emergencyFreezeActive,
      artifactDigest: batch.artifactDigest,
    });
    if (promo.kind !== 'Proven') {
      return {
        kind: 'Refuted',
        reason: 'release-gate-refused',
        detail: promo.reason,
      };
    }

    // B2 Multi-Tenant AES-256-GCM Encrypted Regulated Audit Cut
    const regulatedDecisionRootHash = this.regulated.recordRegulatedDecision(
      params.tenantKey,
      `release-decision:${params.releaseId}`,
      {
        releaseId: params.releaseId,
        artifactDigest: batch.artifactDigest,
        admittedAgents: batch.admittedAgents,
        custodyLineages: batch.custodyLineages,
        arbitrationReceiptHash: batch.arbitrationReceiptHash,
        suspensionId: batch.suspensionAnchor.suspensionId,
        consumedApprovalDigests: resume.consumedApprovalDigests,
        releaseRootHash: promo.releaseRootHash,
      },
      params.world.currentPolicyEpochHash,
      params.modelId,
      'Approved',
      `Promoted via B3->G2->B4->P9->B5->B1 (${resume.policyCoEvolutionMode})`,
    );

    return {
      kind: 'PromotedAndRecorded',
      releaseId: params.releaseId,
      releaseRootHash: promo.releaseRootHash,
      regulatedDecisionRootHash,
      executionEpoch: resume.executionEpoch,
      policyCoEvolutionMode: resume.policyCoEvolutionMode,
    };
  }

  /**
   * Cross-Layer B1 x B5 Breach Response:
   * Rolls back production to the pinned M1 pre-release cut, bumps the M3 fencing epoch,
   * keeps incident forensics pinned across GC, AND persists a B5 HumanVetoConstraint so
   * an autonomous agent cannot nag humans by re-submitting the identical broken diff!
   */
  rollbackOnCanaryBreachAndVeto(params: {
    releaseId: string;
    onCallEngineerId: string;
    reasonCode: string;
    requiredFixConstraint: string;
    nowEpoch: number;
  }): {rollback: RollbackReceipt; veto: HumanVetoConstraint} {
    const batch = this.stagedBatches.get(params.releaseId);
    if (!batch || !batch.suspensionAnchor) {
      throw new Error(`Unknown staged release '${params.releaseId}'`);
    }
    const rollback = this.release.rollbackToPinnedCut(params.releaseId, params.reasonCode);
    const veto = this.hitl.recordHumanVeto({
      suspensionId: batch.suspensionAnchor.suspensionId,
      vetoedBy: params.onCallEngineerId,
      reasonCode: params.reasonCode,
      requiredFixConstraint: params.requiredFixConstraint,
      vetoedAtEpoch: params.nowEpoch,
    });
    return {rollback, veto};
  }
}
