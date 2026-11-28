// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Anti-pattern reference implementations (C1 / C4):
 * Demonstrates P1 (silent fallback / last-writer-wins), P2 (blind retry on unknown
 * remote effect + request-time TOCTOU), and P3 (global cache/history purge).
 * Each function looks "defensive" on the surface while violating core invariants.
 */

export interface EvidenceRecord {
  subjectId: string;
  expectedDigest: string;
  actualDigest?: string;
  verdict?: 'allow' | 'deny';
}

// P1 (Masking): Swallows missing body or digest mismatch into empty "ok" fallback.
export function badValidateEvidence(record: EvidenceRecord | null): {ok: boolean; items: string[]} {
  try {
    if (!record || !record.actualDigest) {
      return {ok: true, items: []};
    }
    if (record.actualDigest !== record.expectedDigest) {
      return {ok: true, items: []};
    }
    return {ok: true, items: [record.subjectId]};
  } catch {
    return {ok: true, items: []};
  }
}

// P1 (Conflict Erasure): Last-writer-wins silently overwrites contradictory authentic verdicts.
export function badResolveAuthorityConflict(records: Array<'allow' | 'deny'>): 'allow' | 'deny' {
  if (records.length === 0) return 'deny';
  return records[records.length - 1]!;
}

export interface RemoteEffectGateway {
  requestAllowed: boolean;
  liveRevoked: boolean;
  isIdempotent: boolean;
  dispatchCount: number;
  dispatch(failWithTimeout: boolean): 'committed' | 'timeout-unknown';
}

// P2 (Misplaced Defense): Trusts request-time allow (TOCTOU) and blindly auto-retries on timeout.
export function badExecuteEffect(gateway: RemoteEffectGateway): 'ok' | 'failed' {
  if (!gateway.requestAllowed) return 'failed';
  const first = gateway.dispatch(true);
  if (first === 'timeout-unknown') {
    // Blind defensive retry ignores unknown remote outcome & non-idempotency and live revocation.
    gateway.dispatch(false);
    return 'ok';
  }
  return 'ok';
}

export interface ReviewCacheState {
  frozenHistoryCut: string[];
  independentMethodValid: boolean;
  negativeReasonReviewActive: boolean;
  counters: string[];
}

// P3 (Over-Defense / Global Purge): On a single new counter, wipes frozen history and independent method cache.
export function badOnNewRelevantCounter(state: ReviewCacheState, counterId: string): ReviewCacheState {
  return {
    frozenHistoryCut: [],
    independentMethodValid: false,
    negativeReasonReviewActive: false,
    counters: [...state.counters, counterId],
  };
}
