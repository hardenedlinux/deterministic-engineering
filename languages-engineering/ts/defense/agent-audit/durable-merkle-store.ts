// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 6: Orthogonal Persistence (gerbil-persist) x Durable Multi-Agent Governance Engine (10.156).
 *
 * Emulates `mighty-gerbils/gerbil-persist`'s core architecture and fuses it with
 * Deterministic Engineering's M1/M2/M3 mutability stratification:
 *   1. Content-Addressed Merkle DAG (M1 immutable): every patch, receipt, handoff, and
 *      transcript is addressed by SHA-256 digest (acyclic by construction; zero amnesia).
 *   2. Minimal KV + Single Atomic Mutable Root Cell (M3): concurrent agents evolve
 *      independently and commit only after Pre-Commit Hook stability settles all peers.
 *   3. Reference-Counted / Reachability GC: sweeps unreferenced scratch blobs while
 *      preserving 100% of active roots and pinned historical cuts (F2 anti-purge).
 *   4. Crash-Resume M3 Re-Attestation & PendingUnknownEffect Intent Fence: persisted
 *      pre-crash authority is NEVER trusted across a crash/pause; unresolved side-effect
 *      intents surface as PendingUnknownEffect rather than blindly replaying.
 *   5. O(1) Time-Travel Branching from any historical Merkle root.
 */

import {createHash} from 'node:crypto';
import type {GovernanceTranscript} from './governance-harness.ts';

export interface MerkleBlob<T = unknown> {
  kind: string;
  payload: T;
  refs: string[];
}

export interface DurableRootCell {
  branch: string;
  version: number;
  rootHash: string;
  inFlightIntent: string | null;
}

export interface HandoffMerkleNode {
  parentRoot: string | null;
  fromAgent: string;
  toAgent: string;
  transcriptDigest: string;
  finalDecision: GovernanceTranscript['finalDecision'];
  attemptsUsed: number;
}

export type ResumeDispatchVerdict =
  | {kind: 'Proven'; intentDigest: string; rootHash: string}
  | {kind: 'Refuted'; reason: string}
  | {kind: 'PendingUnknownEffect'; unresolvedIntent: string};

function canonicalJson(val: unknown): string {
  if (val === null || typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) return '[' + val.map(canonicalJson).join(',') + ']';
  const obj = val as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

export function sha256Digest(data: unknown): string {
  return createHash('sha256').update(canonicalJson(data)).digest('hex');
}

/**
 * Minimal Content-Addressed KV Store (gerbil-persist least-common-denominator abstraction).
 */
export class ContentAddressedKvStore {
  private readonly blobs = new Map<string, string>();
  private readonly roots = new Map<string, DurableRootCell>();
  private readonly pinnedCuts = new Set<string>();

  putBlob<T>(kind: string, payload: T, refs: string[] = []): string {
    for (const r of refs) {
      if (!this.blobs.has(r)) {
        throw new Error(`Dangling Merkle reference '${r}' rejected (fail-closed)`);
      }
    }
    const envelope: MerkleBlob<T> = {kind, payload, refs: [...refs].sort()};
    const raw = canonicalJson(envelope);
    const hash = createHash('sha256').update(raw).digest('hex');
    this.blobs.set(hash, raw);
    return hash;
  }

  getBlob<T = unknown>(hash: string): MerkleBlob<T> {
    const raw = this.blobs.get(hash);
    if (!raw) throw new Error(`Missing Merkle blob '${hash}'`);
    const actualHash = createHash('sha256').update(raw).digest('hex');
    if (actualHash !== hash) {
      throw new Error(`Merkle integrity violation: expected ${hash}, got ${actualHash}`);
    }
    return JSON.parse(raw) as MerkleBlob<T>;
  }

  hasBlob(hash: string): boolean {
    return this.blobs.has(hash);
  }

  blobCount(): number {
    return this.blobs.size;
  }

  getRoot(branch = 'main'): DurableRootCell | null {
    const cell = this.roots.get(branch);
    return cell ? {...cell} : null;
  }

  atomicSwapRoot(
    branch: string,
    expectedVersion: number,
    newRootHash: string,
    inFlightIntent: string | null,
  ): DurableRootCell {
    if (!this.blobs.has(newRootHash)) {
      throw new Error(`Cannot anchor root to missing Merkle hash '${newRootHash}'`);
    }
    const cur = this.roots.get(branch);
    const curVer = cur?.version ?? 0;
    if (curVer !== expectedVersion) {
      throw new Error(`Atomic M3 root CAS conflict on '${branch}': expected v${expectedVersion}, actual v${curVer}`);
    }
    const next: DurableRootCell = {
      branch,
      version: curVer + 1,
      rootHash: newRootHash,
      inFlightIntent,
    };
    this.roots.set(branch, next);
    return {...next};
  }

  pinHistoricalCut(hash: string): void {
    if (!this.blobs.has(hash)) throw new Error(`Cannot pin unknown Merkle cut '${hash}'`);
    this.pinnedCuts.add(hash);
  }

  /**
   * Acyclic reachability GC (gerbil-persist ref-count semantics):
   * preserves every node reachable from any branch root OR any pinned historical cut,
   * and reclaims only unreferenced scratch blobs.
   */
  gcUnreferenced(): {removed: number; retained: number} {
    const reachable = new Set<string>();
    const queue: string[] = [];
    for (const cell of this.roots.values()) queue.push(cell.rootHash);
    for (const pinned of this.pinnedCuts) queue.push(pinned);

    while (queue.length > 0) {
      const h = queue.pop()!;
      if (reachable.has(h) || !this.blobs.has(h)) continue;
      reachable.add(h);
      const blob = this.getBlob(h);
      for (const ref of blob.refs) queue.push(ref);
    }

    let removed = 0;
    for (const h of [...this.blobs.keys()]) {
      if (!reachable.has(h)) {
        this.blobs.delete(h);
        removed++;
      }
    }
    return {removed, retained: this.blobs.size};
  }
}

export interface LiveAuthorityOracle {
  isAuthorized(agentId: string, scope: string): boolean;
}

/**
 * Durable Multi-Agent Coordinator backed by ContentAddressedKvStore.
 * Strictly separates persisted M1 Merkleized evidence from live M3 resume-time authority.
 */
export class DurableMultiAgentCoordinator {
  private readonly preCommitReady = new Map<string, boolean>();
  private resumeReattested = false;

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly branch = 'main',
    private readonly participants: readonly string[] = ['planner', 'coder', 'reviewer'],
  ) {
    for (const p of participants) this.preCommitReady.set(p, false);
  }

  /** Pre-commit hook: each concurrent agent must settle to a stable rollback/rollforward point */
  markAgentStable(agentId: string): void {
    if (!this.preCommitReady.has(agentId)) {
      throw new Error(`Unknown participant '${agentId}'`);
    }
    this.preCommitReady.set(agentId, true);
  }

  allParticipantsStable(): boolean {
    for (const ready of this.preCommitReady.values()) {
      if (!ready) return false;
    }
    return true;
  }

  /**
   * Evidence-Carrying Handoff: commits immutable M1 transcript + handoff node and atomically
   * swaps the single M3 root ONLY when pre-commit stability holds across all concurrent agents.
   */
  commitEvidenceHandoff(
    fromAgent: string,
    toAgent: string,
    transcript: GovernanceTranscript,
  ): DurableRootCell {
    if (!this.allParticipantsStable()) {
      throw new Error('Pre-commit refusal: not all concurrent agents settled to a stable point');
    }
    const cur = this.kv.getRoot(this.branch);
    const parentRoot = cur?.rootHash ?? null;
    const expectedVersion = cur?.version ?? 0;

    // Persist immutable M1 transcript blob (zero amnesia across handoffs & restarts)
    const transcriptHash = this.kv.putBlob('governance-transcript', transcript, []);
    const handoffRefs = parentRoot ? [parentRoot, transcriptHash] : [transcriptHash];
    const handoffNode: HandoffMerkleNode = {
      parentRoot,
      fromAgent,
      toAgent,
      transcriptDigest: transcriptHash,
      finalDecision: transcript.finalDecision,
      attemptsUsed: transcript.attemptsUsed,
    };
    const newRootHash = this.kv.putBlob('agent-handoff', handoffNode, handoffRefs);
    const nextCell = this.kv.atomicSwapRoot(
      this.branch,
      expectedVersion,
      newRootHash,
      cur?.inFlightIntent ?? null,
    );
    // Reset pre-commit hook flags for next epoch
    for (const p of this.participants) this.preCommitReady.set(p, false);
    return nextCell;
  }

  /**
   * Simulates a hard crash & cold restart: creates a brand-new coordinator instance with
   * ZERO in-memory state, verifying Merkle lineage from the KV root and forcing M3 re-attestation.
   */
  static coldRestartFromKv(
    kv: ContentAddressedKvStore,
    branch = 'main',
    participants: readonly string[] = ['planner', 'coder', 'reviewer'],
  ): {coordinator: DurableMultiAgentCoordinator; lineage: HandoffMerkleNode[]} {
    const coord = new DurableMultiAgentCoordinator(kv, branch, participants);
    coord.resumeReattested = false;
    const lineage = coord.loadVerifiedLineage();
    return {coordinator: coord, lineage};
  }

  loadVerifiedLineage(): HandoffMerkleNode[] {
    const root = this.kv.getRoot(this.branch);
    if (!root) return [];
    const chain: HandoffMerkleNode[] = [];
    let cursor: string | null = root.rootHash;
    while (cursor) {
      const blob = this.kv.getBlob<HandoffMerkleNode>(cursor);
      // Verify referenced transcript blob integrity too
      this.kv.getBlob<GovernanceTranscript>(blob.payload.transcriptDigest);
      chain.push(blob.payload);
      cursor = blob.payload.parentRoot;
    }
    return chain;
  }

  /**
   * Resume-Time M3 Re-Attestation & PendingUnknownEffect Intent Fence:
   * Never trusts persisted pre-crash permissions; refuses zombie authority and unresolved intents.
   */
  resumeAndDispatchEffect(
    agentId: string,
    scope: string,
    effectPayload: Record<string, unknown>,
    liveAuthority: LiveAuthorityOracle,
  ): ResumeDispatchVerdict {
    const cur = this.kv.getRoot(this.branch);
    if (!cur) {
      return {kind: 'Refuted', reason: 'no-committed-merkle-root'};
    }
    // Live M3 authority check at resume/consumption time (blocks zombie permits!)
    if (!liveAuthority.isAuthorized(agentId, scope)) {
      this.resumeReattested = false;
      return {kind: 'Refuted', reason: 'zombie-authority-revoked-during-outage'};
    }
    this.resumeReattested = true;

    // PendingUnknownEffect fence: never blindly replay an unresolved pre-crash intent!
    if (cur.inFlightIntent !== null) {
      return {kind: 'PendingUnknownEffect', unresolvedIntent: cur.inFlightIntent};
    }

    const intentDigest = this.kv.putBlob('effect-intent', {agentId, scope, effectPayload}, [cur.rootHash]);
    this.kv.atomicSwapRoot(this.branch, cur.version, cur.rootHash, intentDigest);
    return {kind: 'Proven', intentDigest, rootHash: cur.rootHash};
  }

  reconcileIntentOutcome(): void {
    const cur = this.kv.getRoot(this.branch);
    if (!cur || cur.inFlightIntent === null) return;
    this.kv.atomicSwapRoot(this.branch, cur.version, cur.rootHash, null);
  }

  /** O(1) Time-Travel Fork from any historical M1 Merkle root without mutating the source branch */
  forkBranchFromRoot(newBranch: string, historicalRootHash: string): DurableMultiAgentCoordinator {
    if (this.kv.getRoot(newBranch) !== null) {
      throw new Error(`Branch '${newBranch}' already exists`);
    }
    this.kv.atomicSwapRoot(newBranch, 0, historicalRootHash, null);
    return new DurableMultiAgentCoordinator(this.kv, newBranch, this.participants);
  }

  isResumeReattested(): boolean {
    return this.resumeReattested;
  }
}
