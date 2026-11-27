// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 17 (Business Extension B8, 10.165):
 * Durable Memory-Poisoning Defense, Independent Quorum Fact Promotion,
 * and Doyle (1979) / de Kleer (1986) ATMS Causal Belief Retraction.
 *
 * Solves the dark side of Orthogonal Persistence for long-horizon AI Agents:
 *   1. Two-Tier Memory Stratification:
 *        - M2 Provisional Working Memory (quarantined candidates; never authoritative),
 *        - M1 Verified Long-Term Memory (requires Trusted/Verified integrity +
 *          either a cold deterministic oracle proof OR k-of-N independent witness quorum).
 *   2. ATMS Multi-Justification DAG:
 *        - Every derived M1 belief records one or more independent justification sets
 *          (`justifications: string[][]`, each inner array being a conjunctive set of
 *          supporting belief IDs).
 *        - Retracting a poisoned belief (`retractPoisonedBelief`) cascades deterministically
 *          to every downstream belief whose support sets ALL broke, while PRESERVING
 *          any belief backed by an alternative clean justification set AND leaving all
 *          unrelated beliefs untouched (DE01 zero global memory purge!).
 *   3. Poison Immunization Tombstones:
 *        - Every retracted poisoned claim digest is pinned as an immutable M1 tombstone
 *          blocking future re-ingestion of the exact same poisoned rule across sessions.
 *   4. Principal Compromise Cascade (`retractByCompromisedPrincipal`):
 *        - Bridges B3 revocation directly to B8 memory: when a contractor/agent is
 *          compromised, revokes every belief solely attested by that principal and
 *          cascades through the ATMS DAG!
 */

import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';
import type {IntegrityLevel} from './difc-exfiltration-fence.ts';

export type MemoryBeliefStatus = 'ProvisionalM2' | 'VerifiedM1' | 'RetractedPoisoned';

export interface MemoryBeliefNode {
  beliefId: string;
  claimText: string;
  claimDigest: string;
  proposerId: string;
  sourceIntegrity: IntegrityLevel;
  secrecyTags: readonly string[];
  status: MemoryBeliefStatus;
  oracleReceiptHash: string | null;
  independentAttesters: string[];
  /**
   * ATMS disjunctive list of conjunctive justification sets:
   * A derived belief stays Active (In) as long as AT LEAST ONE inner set has ALL
   * its supporting beliefIds currently `VerifiedM1`!
   * Empty outer array = base/root belief (justified by its own oracle/quorum).
   */
  justifications: string[][];
  merkleHash: string;
}

export interface RetractionForensicTombstone {
  tombstoneMerkleHash: string;
  rootBeliefId: string;
  claimDigest: string;
  reason: string;
  retractedBeliefIds: string[];
  survivedViaAltJustificationIds: string[];
}

export type MemoryProposeVerdict =
  | {kind: 'QuarantinedProvisional'; belief: MemoryBeliefNode}
  | {kind: 'Refuted'; reason: 'poisoned-claim-immunized' | 'duplicate-belief-id'};

export type MemoryPromoteVerdict =
  | {kind: 'PromotedM1'; belief: MemoryBeliefNode; promotionMode: 'cold-oracle' | 'independent-quorum'}
  | {
      kind: 'Refuted';
      reason:
        | 'unknown-belief'
        | 'poisoned-claim-immunized'
        | 'untrusted-source-quarantined'
        | 'insufficient-quorum-or-oracle'
        | 'sod-proposer-self-attestation-forbidden'
        | 'duplicate-attester-in-quorum'
        | 'supporting-belief-not-verified';
    };

export class DurableMemoryTmsStore {
  private readonly beliefs = new Map<string, MemoryBeliefNode>();
  private readonly immunizedClaimDigests = new Map<string, RetractionForensicTombstone>();

  constructor(
    private readonly kv: ContentAddressedKvStore,
    private readonly defaultQuorumSize = 2,
  ) {}

  getBelief(beliefId: string): MemoryBeliefNode | undefined {
    return this.beliefs.get(beliefId);
  }

  getActiveVerifiedBeliefs(): MemoryBeliefNode[] {
    return [...this.beliefs.values()].filter(b => b.status === 'VerifiedM1');
  }

  getKnowledgeCutHash(): string {
    const active = this.getActiveVerifiedBeliefs()
      .map(b => `${b.beliefId}:${b.merkleHash}`)
      .sort();
    return sha256Digest(active);
  }

  /**
   * Stage 1: Every new agent claim enters M2 Provisional Memory (quarantined).
   * Blocked immediately if its canonical claimDigest matches an immunized poison tombstone!
   */
  proposeProvisionalBelief(params: {
    beliefId: string;
    claimText: string;
    proposerId: string;
    sourceIntegrity: IntegrityLevel;
    secrecyTags?: readonly string[];
    justifications?: string[][];
  }): MemoryProposeVerdict {
    if (this.beliefs.has(params.beliefId)) {
      return {kind: 'Refuted', reason: 'duplicate-belief-id'};
    }
    const claimDigest = sha256Digest(params.claimText.trim());
    if (this.immunizedClaimDigests.has(claimDigest)) {
      return {kind: 'Refuted', reason: 'poisoned-claim-immunized'};
    }

    const secrecyTags = [...new Set(params.secrecyTags ?? [])].sort();
    const justifications = (params.justifications ?? []).map(set => [...new Set(set)].sort());
    const merkleHash = this.kv.putBlob(
      'tms-provisional-m2',
      {
        beliefId: params.beliefId,
        claimDigest,
        proposerId: params.proposerId,
        sourceIntegrity: params.sourceIntegrity,
        secrecyTags,
        justifications,
      },
      [],
    );

    const node: MemoryBeliefNode = {
      beliefId: params.beliefId,
      claimText: params.claimText,
      claimDigest,
      proposerId: params.proposerId,
      sourceIntegrity: params.sourceIntegrity,
      secrecyTags,
      status: 'ProvisionalM2',
      oracleReceiptHash: null,
      independentAttesters: [],
      justifications,
      merkleHash,
    };
    this.beliefs.set(params.beliefId, node);
    return {kind: 'QuarantinedProvisional', belief: node};
  }

  /**
   * Stage 2: Promotes a Provisional M2 belief into immutable M1 Verified Memory ONLY if:
   *  - Not immunized as poisoned,
   *  - `sourceIntegrity !== 'UntrustedExternal'`,
   *  - If derived (`justifications.length > 0`), at least one justification set has ALL
   *    supporting beliefs currently `VerifiedM1`,
   *  - Backed by EITHER a verified `oracleReceiptHash` OR `>= requiredQuorum` distinct
   *    independent attesters (enforcing SoD: attester !== proposer).
   */
  promoteToVerifiedMemory(params: {
    beliefId: string;
    oracleReceiptHash?: string;
    attesters?: string[];
    requiredQuorum?: number;
  }): MemoryPromoteVerdict {
    const node = this.beliefs.get(params.beliefId);
    if (!node) return {kind: 'Refuted', reason: 'unknown-belief'};
    if (this.immunizedClaimDigests.has(node.claimDigest) || node.status === 'RetractedPoisoned') {
      return {kind: 'Refuted', reason: 'poisoned-claim-immunized'};
    }
    if (node.sourceIntegrity === 'UntrustedExternal') {
      return {kind: 'Refuted', reason: 'untrusted-source-quarantined'};
    }

    // If derived belief, verify at least one justification set is currently all-VerifiedM1!
    if (node.justifications.length > 0 && !this.hasSurvivingJustification(node)) {
      return {kind: 'Refuted', reason: 'supporting-belief-not-verified'};
    }

    const attesters = params.attesters ?? [];
    if (attesters.some(a => a === node.proposerId)) {
      return {kind: 'Refuted', reason: 'sod-proposer-self-attestation-forbidden'};
    }
    const distinctAttesters = [...new Set(attesters)];
    if (distinctAttesters.length !== attesters.length) {
      return {kind: 'Refuted', reason: 'duplicate-attester-in-quorum'};
    }

    const quorumNeeded = Math.max(1, params.requiredQuorum ?? this.defaultQuorumSize);
    const hasOracle = Boolean(params.oracleReceiptHash && this.kv.hasBlob(params.oracleReceiptHash));
    const hasQuorum = distinctAttesters.length >= quorumNeeded;

    if (!hasOracle && !hasQuorum) {
      return {kind: 'Refuted', reason: 'insufficient-quorum-or-oracle'};
    }

    const promotionMode = hasOracle ? 'cold-oracle' : 'independent-quorum';
    const parentRefs: string[] = [];
    if (params.oracleReceiptHash && this.kv.hasBlob(params.oracleReceiptHash)) {
      parentRefs.push(params.oracleReceiptHash);
    }
    for (const jSet of node.justifications) {
      for (const depId of jSet) {
        const dep = this.beliefs.get(depId);
        if (dep) parentRefs.push(dep.merkleHash);
      }
    }

    const verifiedHash = this.kv.putBlob(
      'tms-verified-m1',
      {
        beliefId: node.beliefId,
        claimDigest: node.claimDigest,
        proposerId: node.proposerId,
        promotionMode,
        oracleReceiptHash: params.oracleReceiptHash ?? null,
        independentAttesters: distinctAttesters,
        justifications: node.justifications,
      },
      [...new Set(parentRefs)],
    );
    this.kv.pinHistoricalCut(verifiedHash);

    node.status = 'VerifiedM1';
    node.oracleReceiptHash = params.oracleReceiptHash ?? null;
    node.independentAttesters = distinctAttesters;
    node.merkleHash = verifiedHash;

    return {kind: 'PromotedM1', belief: node, promotionMode};
  }

  /**
   * Attaches an independent alternative ATMS justification set to an existing belief
   * (de Kleer 1986), enabling survival if another justification is later retracted.
   */
  addAlternativeJustification(beliefId: string, cleanSupportingBeliefIds: string[]): boolean {
    const node = this.beliefs.get(beliefId);
    if (!node || node.status !== 'VerifiedM1') return false;
    if (
      cleanSupportingBeliefIds.length === 0 ||
      cleanSupportingBeliefIds.some(id => this.beliefs.get(id)?.status !== 'VerifiedM1')
    ) {
      return false;
    }
    node.justifications.push([...new Set(cleanSupportingBeliefIds)].sort());
    return true;
  }

  /**
   * Doyle (1979) / de Kleer (1986) Causal ATMS Retraction + Immunization Tombstone:
   * Retracts `rootBeliefId`, cascades to every downstream belief that loses ALL valid
   * justification sets, preserves beliefs with surviving clean justifications and all
   * unrelated beliefs (DE01), and pins an immutable M1 poison-immunization tombstone.
   */
  retractPoisonedBelief(rootBeliefId: string, reason: string): RetractionForensicTombstone {
    const root = this.beliefs.get(rootBeliefId);
    if (!root) {
      throw new Error(`Unknown beliefId '${rootBeliefId}'`);
    }

    root.status = 'RetractedPoisoned';
    const retractedIds = new Set<string>([rootBeliefId]);
    const survivedAltIds = new Set<string>();

    // Fixed-point ATMS propagation over the justification DAG:
    let changed = true;
    while (changed) {
      changed = false;
      for (const node of this.beliefs.values()) {
        if (node.status !== 'VerifiedM1' || node.justifications.length === 0) continue;
        const dependsOnRetracted = node.justifications.some(jSet =>
          jSet.some(depId => retractedIds.has(depId)),
        );
        if (!dependsOnRetracted) continue;

        if (this.hasSurvivingJustification(node)) {
          survivedAltIds.add(node.beliefId);
        } else {
          node.status = 'RetractedPoisoned';
          retractedIds.add(node.beliefId);
          survivedAltIds.delete(node.beliefId);
          changed = true;
        }
      }
    }

    const tombstonePayload = {
      rootBeliefId,
      claimDigest: root.claimDigest,
      reason,
      retractedBeliefIds: [...retractedIds].sort(),
      survivedViaAltJustificationIds: [...survivedAltIds].sort(),
    };
    const tombstoneMerkleHash = this.kv.putBlob('tms-retraction-tombstone', tombstonePayload, [
      root.merkleHash,
    ]);
    this.kv.pinHistoricalCut(tombstoneMerkleHash);

    const tombstone: RetractionForensicTombstone = {
      tombstoneMerkleHash,
      ...tombstonePayload,
    };
    this.immunizedClaimDigests.set(root.claimDigest, tombstone);
    return tombstone;
  }

  /**
   * Cross-layer B3 x B8 bridge: when a principal (e.g. contractor agent) is compromised,
   * retracts every belief proposed or solely attested by that principal (without a cold
   * deterministic oracle receipt) and cascades through the ATMS graph!
   */
  retractByCompromisedPrincipal(
    compromisedPrincipalId: string,
    reason: string,
  ): RetractionForensicTombstone[] {
    const tombstones: RetractionForensicTombstone[] = [];
    for (const node of this.beliefs.values()) {
      if (node.status !== 'VerifiedM1') continue;
      if (node.oracleReceiptHash) continue; // Cold deterministic oracle proof remains valid!
      const remainingCleanAttesters = node.independentAttesters.filter(
        a => a !== compromisedPrincipalId,
      );
      const proposedByCompromised = node.proposerId === compromisedPrincipalId;
      if (proposedByCompromised || remainingCleanAttesters.length < this.defaultQuorumSize) {
        tombstones.push(this.retractPoisonedBelief(node.beliefId, reason));
      }
    }
    return tombstones;
  }

  private hasSurvivingJustification(node: MemoryBeliefNode): boolean {
    return node.justifications.some(
      jSet =>
        jSet.length > 0 &&
        jSet.every(depId => this.beliefs.get(depId)?.status === 'VerifiedM1'),
    );
  }
}
