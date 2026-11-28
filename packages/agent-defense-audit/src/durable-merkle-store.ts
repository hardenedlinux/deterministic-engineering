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

import {createCipheriv, createDecipheriv, createHash, randomBytes} from 'node:crypto';
import type {GovernanceTranscript} from './governance-harness.ts';

/**
 * R3 (10.156): Unforgeable runtime symbol branding non-serializable M3 live capabilities.
 * Mechanically eliminates PJama-style accidental reachability leaks into M1 Merkle blobs.
 */
export const M3_NON_SERIALIZABLE_CAPABILITY = Symbol.for(
  'deterministic-engineering.m3.non-serializable-capability',
);

export class LiveM3Capability {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;

  constructor(
    readonly capabilityId: string,
    readonly scope: string,
    readonly revocationEpoch: number,
  ) {}

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: LiveM3Capability '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export function assertM1Persistable(value: unknown, path = 'root', seen = new Set<unknown>()): void {
  if (value === null || value === undefined) return;
  const t = typeof value;
  if (t === 'boolean' || t === 'number' || t === 'string') return;
  if (t === 'function' || t === 'symbol') {
    throw new Error(`R3 ReachabilityLeakError: non-persistable ${t} at '${path}'`);
  }
  if (t === 'object') {
    if (seen.has(value)) return;
    seen.add(value);
    const rec = value as Record<string | symbol, unknown>;
    if (rec[M3_NON_SERIALIZABLE_CAPABILITY] === true || rec.nonSerializable === true) {
      const id = typeof rec.capabilityId === 'string' ? rec.capabilityId : 'unknown-m3';
      throw new Error(
        `R3 ReachabilityLeakError: accidental reachability leak of M3 capability '${id}' at '${path}'`,
      );
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        assertM1Persistable(value[i], `${path}[${i}]`, seen);
      }
      return;
    }
    for (const [k, v] of Object.entries(rec)) {
      assertM1Persistable(v, `${path}.${k}`, seen);
    }
  }
}

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
    // R3 mechanical reachability-leak fence: reject any object graph reaching an M3 live capability!
    assertM1Persistable(payload, `blob(${kind})`);
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

// ── R1: Hot Policy Co-Evolution Across Suspended Agents (Delimited Yield + M2 Manifest) ──

export interface SuspendedVerdictRecord {
  verdictId: string;
  policyDigest: string;
  dependentDomains: string[];
  m1EvidenceHashes: string[];
  status: 'Valid' | 'PendingRevalidation';
}

export interface HotPolicyUpgradeResult {
  newPolicyDigest: string;
  revalidationRequired: string[];
  stillValid: string[];
  reusedM1EvidenceCount: number;
}

export function hotUpgradePolicyAndRevalidate(
  kv: ContentAddressedKvStore,
  suspendedVerdicts: readonly SuspendedVerdictRecord[],
  newPolicyDigest: string,
  changedDomains: readonly string[],
): {updated: SuspendedVerdictRecord[]; summary: HotPolicyUpgradeResult} {
  const changed = new Set(changedDomains);
  const revalidationRequired: string[] = [];
  const stillValid: string[] = [];
  const reusedEvidence = new Set<string>();

  const updated = suspendedVerdicts.map(v => {
    for (const h of v.m1EvidenceHashes) {
      // Verify M1 Merkle evidence integrity stays intact across hot upgrade (no replay/purge!)
      kv.getBlob(h);
      reusedEvidence.add(h);
    }
    const affected =
      v.policyDigest !== newPolicyDigest &&
      v.dependentDomains.some(d => changed.has(d));
    if (affected) {
      revalidationRequired.push(v.verdictId);
      return {...v, status: 'PendingRevalidation' as const};
    }
    stillValid.push(v.verdictId);
    return {...v, status: 'Valid' as const};
  });

  return {
    updated,
    summary: {
      newPolicyDigest,
      revalidationRequired,
      stillValid,
      reusedM1EvidenceCount: reusedEvidence.size,
    },
  };
}

// ── R2: Per-Agent Merkle Branches + Chandy-Lamport Async Marker Cuts (Straggler-Free) ──

export interface AgentBranchCommit {
  agentId: string;
  parentHash: string | null;
  fileDigests: Record<string, string>;
}

export interface CrossAgentMessage {
  id: string;
  fromAgent: string;
  toAgent: string;
  payloadHash: string;
}

export interface AsyncGlobalCut {
  cutId: string;
  branchRoots: Record<string, string>;
  capturedInFlightMessages: CrossAgentMessage[];
}

export type BranchMergeVerdict =
  | {kind: 'Proven'; mergedRootHash: string; mergedFiles: Record<string, string>}
  | {kind: 'Conflict'; conflictingFiles: string[]};

export class PerAgentAsyncCutCoordinator {
  private readonly agentBranches = new Map<string, string>();
  private readonly blockedAgents = new Set<string>();
  private readonly inFlightChannel: CrossAgentMessage[] = [];

  constructor(private readonly kv: ContentAddressedKvStore) {}

  markAgentBlocked(agentId: string, blocked: boolean): void {
    if (blocked) this.blockedAgents.add(agentId);
    else this.blockedAgents.delete(agentId);
  }

  /** Fast agents commit at full local speed to their own branch even while peers are blocked (R2 straggler freedom) */
  commitAgentBranch(agentId: string, fileDigests: Record<string, string>): DurableRootCell {
    const branchName = `agent/${agentId}`;
    const cur = this.kv.getRoot(branchName);
    const parentHash = cur?.rootHash ?? null;
    const node: AgentBranchCommit = {agentId, parentHash, fileDigests};
    const refs = parentHash ? [parentHash] : [];
    const commitHash = this.kv.putBlob('agent-branch-commit', node, refs);
    const cell = this.kv.atomicSwapRoot(branchName, cur?.version ?? 0, commitHash, null);
    this.agentBranches.set(agentId, commitHash);
    return cell;
  }

  sendCrossAgentMessage(fromAgent: string, toAgent: string, payloadHash: string): CrossAgentMessage {
    if (!this.kv.hasBlob(payloadHash)) {
      throw new Error(`Cannot send cross-agent message with unknown M1 payload '${payloadHash}'`);
    }
    const msg: CrossAgentMessage = {
      id: `msg-${this.inFlightChannel.length + 1}`,
      fromAgent,
      toAgent,
      payloadHash,
    };
    this.inFlightChannel.push(msg);
    return msg;
  }

  /** Chandy-Lamport asynchronous marker cut: snapshots local branch roots + drains in-flight channel messages */
  recordAsyncCut(cutId: string): AsyncGlobalCut {
    const branchRoots: Record<string, string> = {};
    for (const [agentId, rootHash] of this.agentBranches.entries()) {
      branchRoots[agentId] = rootHash;
    }
    const capturedInFlightMessages = this.inFlightChannel.splice(0, this.inFlightChannel.length);
    const cut: AsyncGlobalCut = {cutId, branchRoots, capturedInFlightMessages};
    const refs = [
      ...Object.values(branchRoots),
      ...capturedInFlightMessages.map(m => m.payloadHash),
    ];
    this.kv.putBlob('async-global-cut', cut, refs);
    return cut;
  }

  /** Explicit conflict-preserving merge across two agent branches (forbids silent LWW erasure!) */
  mergeTwoBranches(
    baseFiles: Record<string, string>,
    agentA: string,
    agentB: string,
  ): BranchMergeVerdict {
    const hashA = this.agentBranches.get(agentA);
    const hashB = this.agentBranches.get(agentB);
    if (!hashA || !hashB) {
      throw new Error(`Both branches '${agentA}' and '${agentB}' must have commits before merge`);
    }
    const filesA = this.kv.getBlob<AgentBranchCommit>(hashA).payload.fileDigests;
    const filesB = this.kv.getBlob<AgentBranchCommit>(hashB).payload.fileDigests;

    const allKeys = new Set([...Object.keys(baseFiles), ...Object.keys(filesA), ...Object.keys(filesB)]);
    const mergedFiles: Record<string, string> = {};
    const conflictingFiles: string[] = [];

    for (const key of [...allKeys].sort()) {
      const baseV = baseFiles[key];
      const aV = filesA[key] ?? baseV;
      const bV = filesB[key] ?? baseV;
      const aChanged = aV !== baseV;
      const bChanged = bV !== baseV;
      if (aChanged && bChanged && aV !== bV) {
        conflictingFiles.push(key);
      } else if (aChanged && aV !== undefined) {
        mergedFiles[key] = aV;
      } else if (bChanged && bV !== undefined) {
        mergedFiles[key] = bV;
      } else if (baseV !== undefined) {
        mergedFiles[key] = baseV;
      }
    }

    if (conflictingFiles.length > 0) {
      return {kind: 'Conflict', conflictingFiles};
    }
    const mergedRootHash = this.kv.putBlob('merged-agent-cut', {agentA, agentB, mergedFiles}, [hashA, hashB]);
    return {kind: 'Proven', mergedRootHash, mergedFiles};
  }
}

// ── R4: Stochastic LLM Memoization vs. M2 Semantic-Drift Selective Re-Prompting ──

export interface LlmUpstreamEnv {
  repoCommitDigest: string;
  promptTemplateDigest: string;
  policyDigest: string;
  modelId: string;
}

export interface LlmMemoEntry {
  stepId: string;
  env: LlmUpstreamEnv;
  m1OutputHash: string;
}

export type LlmMemoLookupVerdict<T = unknown> =
  | {kind: 'ReuseM1'; m1OutputHash: string; output: T}
  | {kind: 'InvalidatedByDrift'; driftedAxes: Array<keyof LlmUpstreamEnv>; priorM1Hash: string}
  | {kind: 'CacheMiss'};

export class LlmMemoizationLedger {
  private readonly entries = new Map<string, LlmMemoEntry>();

  constructor(private readonly kv: ContentAddressedKvStore) {}

  recordLlmStep<T>(stepId: string, env: LlmUpstreamEnv, output: T): LlmMemoEntry {
    const m1OutputHash = this.kv.putBlob('m1-llm-step-output', {stepId, output}, []);
    const entry: LlmMemoEntry = {stepId, env: {...env}, m1OutputHash};
    this.entries.set(stepId, entry);
    return entry;
  }

  lookupStep<T = unknown>(stepId: string, currentEnv: LlmUpstreamEnv): LlmMemoLookupVerdict<T> {
    const entry = this.entries.get(stepId);
    if (!entry) return {kind: 'CacheMiss'};

    const driftedAxes: Array<keyof LlmUpstreamEnv> = [];
    for (const axis of ['repoCommitDigest', 'promptTemplateDigest', 'policyDigest', 'modelId'] as const) {
      if (entry.env[axis] !== currentEnv[axis]) driftedAxes.push(axis);
    }
    if (driftedAxes.length > 0) {
      return {kind: 'InvalidatedByDrift', driftedAxes, priorM1Hash: entry.m1OutputHash};
    }
    const blob = this.kv.getBlob<{stepId: string; output: T}>(entry.m1OutputHash);
    return {kind: 'ReuseM1', m1OutputHash: entry.m1OutputHash, output: blob.payload.output};
  }
}

// ── R5: Byzantine / Prompt-Injected Peers — Capability-Partitioned AES-256-GCM AEAD Store ──

export class AeadPartitionKey {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  private readonly keyBytes: Buffer;

  constructor(readonly partitionId: string, keyBytes?: Buffer) {
    this.capabilityId = `aead-key:${partitionId}`;
    this.keyBytes = keyBytes ?? randomBytes(32);
    if (this.keyBytes.length !== 32) {
      throw new Error('AES-256-GCM requires a 32-byte key');
    }
  }

  /** Package-internal raw key accessor for AEAD cipher operations */
  _rawKey(): Buffer {
    return this.keyBytes;
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: AeadPartitionKey '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export interface EncryptedKvRow {
  partitionId: string;
  rowKey: string;
  ivHex: string;
  authTagHex: string;
  ciphertextHex: string;
}

export type AeadReadVerdict<T = unknown> =
  | {kind: 'Proven'; value: T}
  | {kind: 'Refuted'; reason: 'missing-row' | 'unauthorized-partition-key' | 'aead-integrity-or-aad-tamper'};

/**
 * gerbil-persist row-level encryption x EROS capability isolation:
 * Every row is encrypted with AES-256-GCM and AAD-bound to `partitionId:rowKey`,
 * blocking both unauthorized reads and cross-partition ciphertext transplant attacks.
 */
export class CapabilityPartitionedAeadStore {
  private readonly rows = new Map<string, EncryptedKvRow>();

  private rowAddress(partitionId: string, rowKey: string): string {
    return `${partitionId}::${rowKey}`;
  }

  putEncryptedRow<T>(key: AeadPartitionKey, rowKey: string, payload: T): EncryptedKvRow {
    assertM1Persistable(payload, `encrypted(${key.partitionId}/${rowKey})`);
    const iv = randomBytes(12);
    const aad = Buffer.from(`${key.partitionId}:${rowKey}`, 'utf8');
    const cipher = createCipheriv('aes-256-gcm', key._rawKey(), iv);
    cipher.setAAD(aad);
    const plaintext = Buffer.from(canonicalJson(payload), 'utf8');
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const row: EncryptedKvRow = {
      partitionId: key.partitionId,
      rowKey,
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      ciphertextHex: encrypted.toString('hex'),
    };
    this.rows.set(this.rowAddress(key.partitionId, rowKey), row);
    return {...row};
  }

  /** Simulates Byzantine storage tampering or cross-partition ciphertext transplant */
  injectRawRowForTest(partitionId: string, rowKey: string, rawRow: EncryptedKvRow): void {
    this.rows.set(this.rowAddress(partitionId, rowKey), {...rawRow});
  }

  getEncryptedRow<T = unknown>(
    callerKey: AeadPartitionKey,
    partitionId: string,
    rowKey: string,
  ): AeadReadVerdict<T> {
    const row = this.rows.get(this.rowAddress(partitionId, rowKey));
    if (!row) return {kind: 'Refuted', reason: 'missing-row'};
    if (callerKey.partitionId !== partitionId) {
      return {kind: 'Refuted', reason: 'unauthorized-partition-key'};
    }
    try {
      const iv = Buffer.from(row.ivHex, 'hex');
      const authTag = Buffer.from(row.authTagHex, 'hex');
      const ciphertext = Buffer.from(row.ciphertextHex, 'hex');
      const aad = Buffer.from(`${partitionId}:${rowKey}`, 'utf8');
      const decipher = createDecipheriv('aes-256-gcm', callerKey._rawKey(), iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      return {kind: 'Proven', value: JSON.parse(decrypted) as T};
    } catch {
      return {kind: 'Refuted', reason: 'aead-integrity-or-aad-tamper'};
    }
  }
}
