// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 36 (B12, 10.184): Controlled Multi-Agent Context Distillation &
 * Epistemic Provenance Preservation Engine.
 *
 * Runtime implementation paired with `ContextDistillationAndProvenance.lean`:
 *   1. Anti-Amnesia: every pinned M1 negative constraint / veto tombstone in the
 *      source context DAG MUST be preserved verbatim in the distilled bundle.
 *   2. Anti-Hallucination: every cited hash in the distilled bundle MUST belong
 *      to the input source DAG (rejects fabricated M1 receipt hashes).
 *   3. Anti-Secrecy-Stripping: paraphrasing NEVER drops DIFC secrecy tags without
 *      an audited M3 declassification receipt.
 *   4. Anti-Integrity-Laundering: output integrity is strictly bounded by the
 *      monotonic lattice meet of all input items (`UntrustedExternal < AgentDerived < TrustedSystem`).
 *   5. Token Budget Ceiling: distilled payload strictly respects `maxTokens`.
 */

import {
  assertM1Persistable,
  ContentAddressedKvStore,
  sha256Digest,
} from './durable-merkle-store.ts';

export type ContextIntegrityRank = 'UntrustedExternal' | 'AgentDerived' | 'TrustedSystem';

const INTEGRITY_ORDER: Readonly<Record<ContextIntegrityRank, number>> = {
  UntrustedExternal: 0,
  AgentDerived: 1,
  TrustedSystem: 2,
};

export interface SourceContextItem {
  itemId: string;
  itemHash: string;
  isPinnedM1Constraint: boolean;
  integrity: ContextIntegrityRank;
  secrecyTags: readonly string[];
  summaryText: string;
}

export interface CandidateDistillation {
  distilledText: string;
  retainedPinnedHashes: readonly string[];
  citedSourceHashes: readonly string[];
  claimedOutputIntegrity: ContextIntegrityRank;
  claimedSecrecyTags: readonly string[];
  tokenCount: number;
}

export type DistillationVerdict =
  | {
      kind: 'Proven';
      distilledText: string;
      retainedPinnedHashes: string[];
      citedSourceHashes: string[];
      outputIntegrity: ContextIntegrityRank;
      outputSecrecyTags: string[];
      tokenCount: number;
      distillationMerkleHash: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'pinned-m1-constraint-dropped'
        | 'hallucinated-source-citation'
        | 'secrecy-tag-stripped-by-summarizer'
        | 'integrity-laundering-elevated-above-inputs'
        | 'distilled-context-exceeds-token-budget';
      detail: string;
    };

export class ControlledContextDistiller {
  constructor(private readonly kv: ContentAddressedKvStore) {}

  /**
   * Fail-closed gate verifying a candidate LLM context distillation against
   * the authoritative source DAG before pinning the compacted bundle in M1.
   */
  admitDistillation(params: {
    sources: readonly SourceContextItem[];
    candidate: CandidateDistillation;
    maxTokens: number;
  }): DistillationVerdict {
    assertM1Persistable(params.candidate, 'distillation.candidate');

    const {sources, candidate, maxTokens} = params;
    const sourceHashSet = new Set(sources.map(s => s.itemHash));
    const retainedSet = new Set(candidate.retainedPinnedHashes);
    const claimedSecrecySet = new Set(candidate.claimedSecrecyTags);

    // 1. Every pinned M1 constraint MUST be retained:
    for (const src of sources) {
      if (src.isPinnedM1Constraint && !retainedSet.has(src.itemHash)) {
        return {
          kind: 'Refuted',
          reason: 'pinned-m1-constraint-dropped',
          detail: `${src.itemId}:${src.itemHash}`,
        };
      }
    }

    // 2. Every cited source hash MUST exist in the input DAG:
    for (const cited of candidate.citedSourceHashes) {
      if (!sourceHashSet.has(cited)) {
        return {
          kind: 'Refuted',
          reason: 'hallucinated-source-citation',
          detail: cited,
        };
      }
    }

    // 3. Every secrecy tag on any source item MUST be preserved:
    for (const src of sources) {
      for (const tag of src.secrecyTags) {
        if (!claimedSecrecySet.has(tag)) {
          return {
            kind: 'Refuted',
            reason: 'secrecy-tag-stripped-by-summarizer',
            detail: `${src.itemId} stripped ${tag}`,
          };
        }
      }
    }

    // 4. Output integrity MUST NOT exceed the minimum (meet) of all source inputs:
    const claimedRank = INTEGRITY_ORDER[candidate.claimedOutputIntegrity];
    for (const src of sources) {
      const srcRank = INTEGRITY_ORDER[src.integrity];
      if (claimedRank > srcRank) {
        return {
          kind: 'Refuted',
          reason: 'integrity-laundering-elevated-above-inputs',
          detail: `claimed=${candidate.claimedOutputIntegrity} > source(${src.itemId})=${src.integrity}`,
        };
      }
    }

    // 5. Strict token budget ceiling:
    if (candidate.tokenCount > maxTokens) {
      return {
        kind: 'Refuted',
        reason: 'distilled-context-exceeds-token-budget',
        detail: `${candidate.tokenCount} > ${maxTokens}`,
      };
    }

    const retainedPinnedHashes = [...retainedSet].sort();
    const citedSourceHashes = [...new Set(candidate.citedSourceHashes)].sort();
    const outputSecrecyTags = [...claimedSecrecySet].sort();

    const distillationMerkleHash = this.kv.putBlob(
      'controlled-context-distillation',
      {
        distilledTextDigest: sha256Digest(candidate.distilledText),
        retainedPinnedHashes,
        citedSourceHashes,
        outputIntegrity: candidate.claimedOutputIntegrity,
        outputSecrecyTags,
        tokenCount: candidate.tokenCount,
      },
      [],
    );
    this.kv.pinHistoricalCut(distillationMerkleHash);

    return {
      kind: 'Proven',
      distilledText: candidate.distilledText,
      retainedPinnedHashes,
      citedSourceHashes,
      outputIntegrity: candidate.claimedOutputIntegrity,
      outputSecrecyTags,
      tokenCount: candidate.tokenCount,
      distillationMerkleHash,
    };
  }

  /**
   * Deterministic safe distillation helper: computes exact integrity meet,
   * secrecy tag union, verbatim pinned M1 retention, and grounded citations.
   */
  distillSafely(params: {
    sources: readonly SourceContextItem[];
    distilledText: string;
    tokenCount: number;
    maxTokens: number;
  }): DistillationVerdict {
    let minRank = INTEGRITY_ORDER.TrustedSystem;
    let outputIntegrity: ContextIntegrityRank = 'TrustedSystem';
    const secrecyUnion = new Set<string>();
    const retainedPinnedHashes: string[] = [];
    const citedSourceHashes: string[] = [];

    for (const src of params.sources) {
      citedSourceHashes.push(src.itemHash);
      if (src.isPinnedM1Constraint) retainedPinnedHashes.push(src.itemHash);
      for (const t of src.secrecyTags) secrecyUnion.add(t);
      const r = INTEGRITY_ORDER[src.integrity];
      if (r < minRank) {
        minRank = r;
        outputIntegrity = src.integrity;
      }
    }

    return this.admitDistillation({
      sources: params.sources,
      candidate: {
        distilledText: params.distilledText,
        retainedPinnedHashes,
        citedSourceHashes,
        claimedOutputIntegrity: outputIntegrity,
        claimedSecrecyTags: [...secrecyUnion].sort(),
        tokenCount: params.tokenCount,
      },
      maxTokens: params.maxTokens,
    });
  }
}
