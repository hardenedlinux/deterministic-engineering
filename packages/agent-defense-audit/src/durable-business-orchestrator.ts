// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 10: High-Stakes Production Business Extensions of Durable AI Governance (10.158).
 *
 * Composes our entire Durable AI & Defensive Engineering stack into two production business engines:
 *   - Scenario B1 (`AutonomousReleaseOrchestrator`):
 *       Autonomous PR -> Audit -> Separation of Duties (Author != Approver) -> Pinned M1 Pre-Release Cut
 *       -> Live M3 Emergency-Freeze & Canary SLO Gate -> Durable Rollback with Forensic Preservation
 *       and Monotonic M3 Lease Fencing.
 *   - Scenario B2 (`RegulatedMultiTenantDecisionEngine`):
 *       Per-tenant AES-256-GCM AEAD partition isolation (zero cross-tenant leakage) + pinned M1
 *       cryptographic decision cuts enabling 100% deterministic multi-year regulatory replay even
 *       after chat history compaction and GC.
 */

import {
  AeadPartitionKey,
  CapabilityPartitionedAeadStore,
  ContentAddressedKvStore,
  sha256Digest,
} from './durable-merkle-store.ts';
import type {GovernanceTranscript} from './governance-harness.ts';

// ── Scenario B1: Autonomous SoD Release, Canary & Durable Merkle Rollback ──

export type CanarySloStatus = 'Healthy' | 'PendingScope' | 'Breached';

export interface ProductionReleaseRequest {
  releaseId: string;
  authorId: string;
  approverId: string;
  workerEpoch: number;
  transcript: GovernanceTranscript;
  preReleaseCutHash: string | null;
  canarySloStatus: CanarySloStatus;
  emergencyFreezeActive: boolean;
  artifactDigest: string;
}

export type ReleasePromotionVerdict =
  | {kind: 'Proven'; releaseRootHash: string; releaseId: string; epoch: number}
  | {
      kind: 'Refuted';
      reason:
        | 'sod-self-approval-forbidden'
        | 'audit-not-admitted'
        | 'missing-pinned-rollback-cut'
        | 'emergency-freeze-active'
        | 'canary-slo-breached'
        | 'fenced-stale-release-epoch';
    }
  | {kind: 'PendingScope'; reason: 'canary-slo-pending'};

export interface RollbackReceipt {
  releaseId: string;
  restoredPreReleaseCutHash: string;
  failedReleaseForensicHash: string;
  newFencingEpoch: number;
  reason: string;
}

export class AutonomousReleaseOrchestrator {
  private activeEpoch = 1;
  private activeProdCutHash: string | null = null;
  private readonly pinnedPreReleaseCuts = new Map<string, string>();
  private readonly releaseRoots = new Map<string, string>();

  constructor(private readonly kv: ContentAddressedKvStore) {}

  getActiveEpoch(): number {
    return this.activeEpoch;
  }

  getActiveProdCutHash(): string | null {
    return this.activeProdCutHash;
  }

  pinPreReleaseCut(releaseId: string, prodSnapshot: Record<string, unknown>): string {
    const hash = this.kv.putBlob('pre-release-cut', {releaseId, prodSnapshot}, []);
    this.kv.pinHistoricalCut(hash);
    this.pinnedPreReleaseCuts.set(releaseId, hash);
    if (!this.activeProdCutHash) this.activeProdCutHash = hash;
    return hash;
  }

  promoteToProduction(req: ProductionReleaseRequest): ReleasePromotionVerdict {
    if (req.workerEpoch !== this.activeEpoch) {
      return {kind: 'Refuted', reason: 'fenced-stale-release-epoch'};
    }
    if (!req.approverId || req.approverId === req.authorId) {
      return {kind: 'Refuted', reason: 'sod-self-approval-forbidden'};
    }
    if (req.transcript.finalDecision !== 'ADMIT') {
      return {kind: 'Refuted', reason: 'audit-not-admitted'};
    }
    if (
      !req.preReleaseCutHash ||
      this.pinnedPreReleaseCuts.get(req.releaseId) !== req.preReleaseCutHash ||
      !this.kv.hasBlob(req.preReleaseCutHash)
    ) {
      return {kind: 'Refuted', reason: 'missing-pinned-rollback-cut'};
    }
    if (req.emergencyFreezeActive) {
      return {kind: 'Refuted', reason: 'emergency-freeze-active'};
    }
    if (req.canarySloStatus === 'PendingScope') {
      return {kind: 'PendingScope', reason: 'canary-slo-pending'};
    }
    if (req.canarySloStatus === 'Breached') {
      return {kind: 'Refuted', reason: 'canary-slo-breached'};
    }

    const transcriptHash = this.kv.putBlob('release-transcript', req.transcript, []);
    const releaseRootHash = this.kv.putBlob(
      'prod-release-record',
      {
        releaseId: req.releaseId,
        authorId: req.authorId,
        approverId: req.approverId,
        artifactDigest: req.artifactDigest,
        preReleaseCutHash: req.preReleaseCutHash,
        transcriptHash,
        epoch: this.activeEpoch,
      },
      [req.preReleaseCutHash, transcriptHash],
    );
    this.kv.pinHistoricalCut(releaseRootHash);
    this.releaseRoots.set(req.releaseId, releaseRootHash);
    this.activeProdCutHash = releaseRootHash;
    return {kind: 'Proven', releaseRootHash, releaseId: req.releaseId, epoch: this.activeEpoch};
  }

  /**
   * Deterministic rollback on canary/prod SLO breach:
   * restores the pinned M1 pre-release cut, bumps the M3 fencing epoch to fence stalled workers,
   * and keeps 100% of failed rollout forensics pinned across GC.
   */
  rollbackToPinnedCut(releaseId: string, reason: string): RollbackReceipt {
    const preCut = this.pinnedPreReleaseCuts.get(releaseId);
    const failedRoot = this.releaseRoots.get(releaseId);
    if (!preCut || !failedRoot) {
      throw new Error(`Cannot roll back unknown release '${releaseId}'`);
    }
    this.activeEpoch += 1;
    this.activeProdCutHash = preCut;
    // Pin failed release forensic cut explicitly so GC can never purge incident evidence!
    this.kv.pinHistoricalCut(failedRoot);
    const rollbackRecordHash = this.kv.putBlob(
      'release-rollback-record',
      {releaseId, restoredPreReleaseCutHash: preCut, failedReleaseForensicHash: failedRoot, newEpoch: this.activeEpoch, reason},
      [preCut, failedRoot],
    );
    this.kv.pinHistoricalCut(rollbackRecordHash);
    return {
      releaseId,
      restoredPreReleaseCutHash: preCut,
      failedReleaseForensicHash: failedRoot,
      newFencingEpoch: this.activeEpoch,
      reason,
    };
  }
}

// ── Scenario B2: Multi-Tenant AEAD Regulated Workflow & Deterministic Decision Replay ──

export interface RegulatedDecisionProof {
  tenantId: string;
  decisionId: string;
  inputRowKey: string;
  inputCipherDigest: string;
  policyDigest: string;
  modelId: string;
  verdict: 'Approved' | 'Rejected' | 'EscalatedToHuman';
  rationaleDigest: string;
}

export type RegulatoryReplayVerdict<TInput = unknown> =
  | {
      kind: 'Proven';
      proof: RegulatedDecisionProof;
      decryptedInput: TInput;
      integrityVerified: true;
    }
  | {
      kind: 'Refuted';
      reason: 'unauthorized-partition-key' | 'aead-integrity-or-aad-tamper' | 'missing-row' | 'cipher-digest-mismatch';
    };

export class RegulatedMultiTenantDecisionEngine {
  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly aead: CapabilityPartitionedAeadStore,
  ) {}

  recordRegulatedDecision<TInput>(
    tenantKey: AeadPartitionKey,
    decisionId: string,
    sensitiveInput: TInput,
    policyDigest: string,
    modelId: string,
    verdict: RegulatedDecisionProof['verdict'],
    rationaleSummary: string,
  ): string {
    const inputRowKey = `decision-input:${decisionId}`;
    const encRow = this.aead.putEncryptedRow(tenantKey, inputRowKey, sensitiveInput);
    const inputCipherDigest = sha256Digest(encRow);
    const rationaleDigest = sha256Digest({decisionId, rationaleSummary});
    const proof: RegulatedDecisionProof = {
      tenantId: tenantKey.partitionId,
      decisionId,
      inputRowKey,
      inputCipherDigest,
      policyDigest,
      modelId,
      verdict,
      rationaleDigest,
    };
    const decisionRootHash = this.kv.putBlob('regulated-decision-proof', proof, []);
    // Pin as immutable regulatory cut so multi-year audit replay survives GC & compaction!
    this.kv.pinHistoricalCut(decisionRootHash);
    return decisionRootHash;
  }

  replayDecisionAudit<TInput = unknown>(
    callerTenantKey: AeadPartitionKey,
    decisionRootHash: string,
  ): RegulatoryReplayVerdict<TInput> {
    const proof = this.kv.getBlob<RegulatedDecisionProof>(decisionRootHash).payload;
    const dec = this.aead.getEncryptedRow<TInput>(callerTenantKey, proof.tenantId, proof.inputRowKey);
    if (dec.kind !== 'Proven') {
      return dec;
    }
    return {
      kind: 'Proven',
      proof,
      decryptedInput: dec.value,
      integrityVerified: true,
    };
  }
}
