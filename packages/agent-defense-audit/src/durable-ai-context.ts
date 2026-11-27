// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 9: Durable AI — Role-Projected Context (Truth vs View), Anti-Overthinking
 * Sufficiency Offloading, and Multi-Agent ReadSet x WriteSet SSI Write-Skew Governance (10.157).
 *
 * Core Principle:
 *   - Durable Merkle State (`ContentAddressedKvStore`) is the single authoritative Truth.
 *   - LLM Context (`ProjectedAgentContext`) is a disposable, role-sanitized Materialized View
 *     reconstructed deterministically from the committed Merkle root:
 *       1. Settled M1 `Proven` facts are projected as compact hash anchors (`rethinkForbidden: true`)
 *          to prevent LLM overthinking / circular re-derivation on long-horizon tasks.
 *       2. Historical `Refuted` dead-ends stay permanently pinned so agents never re-explore
 *          disproved paths after Context compaction or agent handoff.
 *       3. Reviewer views mechanically strip untrusted Coder `agentProseClaim` text to block
 *          prompt-injection and sycophancy across agent boundaries.
 *   - Concurrent multi-agent merges track Cahill-style SSI `ReadSet x WriteSet` rw-antidependencies
 *     plus monotonic M3 lease fencing epochs to catch disjoint-file Semantic Write-Skew.
 */

import {
  ContentAddressedKvStore,
  sha256Digest,
} from './durable-merkle-store.ts';
import type {GovernanceTranscript} from './governance-harness.ts';

export type AgentRole = 'planner' | 'coder' | 'reviewer';

export interface EvidenceGraphNode {
  id: string;
  epistemicStatus: 'Proven' | 'Refuted' | 'PendingScope' | 'PendingMethod';
  summary: string;
  m1BlobHash: string;
  detailedPayloadSizeBytes: number;
}

export interface DurableTaskRootState {
  taskId: string;
  policyDigest: string;
  hardConstraints: string[];
  evidenceNodes: EvidenceGraphNode[];
  latestTranscriptHash: string | null;
}

export interface ProjectedAgentContext {
  role: AgentRole;
  sourceRootHash: string;
  policyDigest: string;
  hardConstraints: string[];
  /** Compact M1 hash anchors: LLM must NOT waste thinking tokens re-deriving settled facts */
  settledFactAnchors: Array<{id: string; m1BlobHash: string; rethinkForbidden: true}>;
  /** Permanently pinned refuted dead-ends: LLM must NOT re-explore these paths */
  refutedDeadEnds: Array<{id: string; summary: string; m1BlobHash: string}>;
  /** Narrow unresolved frontier where the LLM should concentrate its thinking budget */
  openFrontier: Array<{id: string; status: 'PendingScope' | 'PendingMethod'; summary: string}>;
  /** Role-sanitized handoff summary: Reviewer NEVER receives Coder free-form proseClaim! */
  handoffReceipts: Array<{
    attempt: number;
    patchDigest: string;
    decision: string;
    oraclePassed: boolean;
    findingCount: number;
    proseClaim?: string;
  }>;
  projectionDigest: string;
}

/**
 * Deterministically projects an ephemeral, role-sanitized LLM Context View purely from
 * the Durable Merkle State (zero reliance on raw chat history!).
 */
export function projectRoleContext(
  kv: ContentAddressedKvStore,
  taskRootHash: string,
  role: AgentRole,
): ProjectedAgentContext {
  const rootBlob = kv.getBlob<DurableTaskRootState>(taskRootHash);
  const state = rootBlob.payload;

  const settledFactAnchors: ProjectedAgentContext['settledFactAnchors'] = [];
  const refutedDeadEnds: ProjectedAgentContext['refutedDeadEnds'] = [];
  const openFrontier: ProjectedAgentContext['openFrontier'] = [];

  for (const node of state.evidenceNodes) {
    // Verify M1 Merkle anchor integrity on projection
    kv.getBlob(node.m1BlobHash);
    if (node.epistemicStatus === 'Proven') {
      settledFactAnchors.push({id: node.id, m1BlobHash: node.m1BlobHash, rethinkForbidden: true});
    } else if (node.epistemicStatus === 'Refuted') {
      refutedDeadEnds.push({id: node.id, summary: node.summary, m1BlobHash: node.m1BlobHash});
    } else {
      openFrontier.push({id: node.id, status: node.epistemicStatus, summary: node.summary});
    }
  }

  const handoffReceipts: ProjectedAgentContext['handoffReceipts'] = [];
  if (state.latestTranscriptHash) {
    const transcript = kv.getBlob<GovernanceTranscript>(state.latestTranscriptHash).payload;
    for (const r of transcript.receipts) {
      if (role === 'reviewer') {
        // Strict prompt-injection & sycophancy firewall: strip agentProseClaim completely!
        handoffReceipts.push({
          attempt: r.attempt,
          patchDigest: r.patchDigest,
          decision: r.decision,
          oraclePassed: r.oraclePassed,
          findingCount: r.astAndDiffFindingCount + r.scopeViolationCount,
        });
      } else {
        handoffReceipts.push({
          attempt: r.attempt,
          patchDigest: r.patchDigest,
          decision: r.decision,
          oraclePassed: r.oraclePassed,
          findingCount: r.astAndDiffFindingCount + r.scopeViolationCount,
          proseClaim: r.agentProseClaim,
        });
      }
    }
  }

  const body = {
    role,
    sourceRootHash: taskRootHash,
    policyDigest: state.policyDigest,
    hardConstraints: [...state.hardConstraints],
    settledFactAnchors,
    refutedDeadEnds,
    openFrontier,
    handoffReceipts,
  };
  return {
    ...body,
    projectionDigest: sha256Digest(body),
  };
}

// ── Multi-Agent ReadSet x WriteSet SSI Semantic Write-Skew & Lease Fencing ──

export interface AgentSsiCommitProposal {
  agentId: string;
  fencingEpoch: number;
  /** Exact M1 digests of files/contracts/interfaces the agent READ to justify its edits */
  readSet: Record<string, string>;
  /** Exact M1 digests of files the agent MODIFIED */
  writeSet: Record<string, string>;
}

export interface RwAntidependencyEdge {
  staleReaderAgent: string;
  writerAgent: string;
  file: string;
  readDigest: string;
  writtenDigest: string;
}

export type MultiAgentSsiMergeVerdict =
  | {kind: 'Proven'; mergedWrites: Record<string, string>}
  | {kind: 'Conflict'; conflictingFiles: string[]}
  | {kind: 'PendingRevalidation'; reason: 'semantic-write-skew'; rwEdges: RwAntidependencyEdge[]}
  | {kind: 'Refuted'; reason: 'fenced-stale-agent-epoch'; staleAgent: string; expectedEpoch: number; actualEpoch: number};

/**
 * Evaluates two concurrent Agent branch proposals under Cahill-style SSI + M3 Lease Fencing:
 *   1. Refuses any stalled worker holding an outdated fencing epoch.
 *   2. Preserves Write-Write divergent edits as explicit `Conflict` (never LWW).
 *   3. Detects ReadSet x WriteSet semantic write-skew even when WriteSets are 100% disjoint!
 */
export function evaluateMultiAgentSsiMerge(
  activeLeaseEpoch: number,
  proposalA: AgentSsiCommitProposal,
  proposalB: AgentSsiCommitProposal,
): MultiAgentSsiMergeVerdict {
  for (const p of [proposalA, proposalB]) {
    if (p.fencingEpoch !== activeLeaseEpoch) {
      return {
        kind: 'Refuted',
        reason: 'fenced-stale-agent-epoch',
        staleAgent: p.agentId,
        expectedEpoch: activeLeaseEpoch,
        actualEpoch: p.fencingEpoch,
      };
    }
  }

  // 1. Write-Write conflict check
  const wwConflicts: string[] = [];
  for (const file of Object.keys(proposalA.writeSet)) {
    if (file in proposalB.writeSet && proposalA.writeSet[file] !== proposalB.writeSet[file]) {
      wwConflicts.push(file);
    }
  }
  if (wwConflicts.length > 0) {
    return {kind: 'Conflict', conflictingFiles: wwConflicts.sort()};
  }

  // 2. Read-Write antidependency check (Semantic Write-Skew even on disjoint file diffs!)
  const rwEdges: RwAntidependencyEdge[] = [];
  const checkRw = (reader: AgentSsiCommitProposal, writer: AgentSsiCommitProposal) => {
    for (const [file, readDigest] of Object.entries(reader.readSet)) {
      if (file in writer.writeSet && writer.writeSet[file] !== readDigest) {
        rwEdges.push({
          staleReaderAgent: reader.agentId,
          writerAgent: writer.agentId,
          file,
          readDigest,
          writtenDigest: writer.writeSet[file]!,
        });
      }
    }
  };
  checkRw(proposalA, proposalB);
  checkRw(proposalB, proposalA);

  if (rwEdges.length > 0) {
    return {kind: 'PendingRevalidation', reason: 'semantic-write-skew', rwEdges};
  }

  return {
    kind: 'Proven',
    mergedWrites: {...proposalA.writeSet, ...proposalB.writeSet},
  };
}
