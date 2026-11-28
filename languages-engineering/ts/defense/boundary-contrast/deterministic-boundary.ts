// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Deterministic boundary replacements (C2 / C4):
 * Replaces P1-P3 defensive anti-patterns with explicit 6-state epistemic outcomes,
 * consumption-time authority + idempotency contracts, and bounded incremental revalidation.
 */

import type {EvidenceRecord, RemoteEffectGateway, ReviewCacheState} from './bad-defensive.ts';

export type EpistemicOutcome<T> =
  | {kind: 'Proven'; value: T}
  | {kind: 'Refuted'; reason: string}
  | {kind: 'PendingMethod'; missingMethod: string}
  | {kind: 'PendingScope'; missingPremise: string}
  | {kind: 'Conflict'; competingRecords: ReadonlyArray<string>}
  | {kind: 'SetupDefect'; defect: string};

// C2 replacement for P1 silent fallback: exact trust-boundary parsing with distinct epistemic states.
export function validateEvidenceBoundary(record: EvidenceRecord | null): EpistemicOutcome<string> {
  if (!record) {
    return {kind: 'SetupDefect', defect: 'missing-expected-evidence-record'};
  }
  if (record.actualDigest === undefined) {
    return {kind: 'SetupDefect', defect: 'missing-expected-body-digest'};
  }
  if (record.actualDigest !== record.expectedDigest) {
    return {kind: 'Refuted', reason: 'digest-mismatch'};
  }
  return {kind: 'Proven', value: record.subjectId};
}

// C2 replacement for P1 last-writer-wins: preserve contradictory authentic records as explicit Conflict.
export function resolveAuthorityBoundary(records: ReadonlyArray<'allow' | 'deny'>): EpistemicOutcome<'allow' | 'deny'> {
  if (records.length === 0) {
    return {kind: 'PendingScope', missingPremise: 'authority-record-absent'};
  }
  const hasAllow = records.includes('allow');
  const hasDeny = records.includes('deny');
  if (hasAllow && hasDeny) {
    return {kind: 'Conflict', competingRecords: [...records]};
  }
  return {kind: 'Proven', value: hasAllow ? 'allow' : 'deny'};
}

export type EffectOutcome =
  | {kind: 'Committed'; attempts: number}
  | {kind: 'RefusedRevokedAtUse'}
  | {kind: 'PendingUnknownEffect'; attempts: number};

// C2 replacement for P2 TOCTOU & blind retry: check live M3 authority at consumption, never auto-retry non-idempotent unknown effect.
export function executeEffectBoundary(gateway: RemoteEffectGateway): EffectOutcome {
  if (!gateway.requestAllowed || gateway.liveRevoked) {
    return {kind: 'RefusedRevokedAtUse'};
  }
  const first = gateway.dispatch(true);
  if (first === 'committed') {
    return {kind: 'Committed', attempts: gateway.dispatchCount};
  }
  if (!gateway.isIdempotent) {
    return {kind: 'PendingUnknownEffect', attempts: gateway.dispatchCount};
  }
  // Even for idempotent retry, re-check live consumption-time authority before retrying.
  if (gateway.liveRevoked) {
    return {kind: 'RefusedRevokedAtUse'};
  }
  gateway.dispatch(false);
  return {kind: 'Committed', attempts: gateway.dispatchCount};
}

// C2 replacement for P3 global purge: invalidate only the negative-dependency review while preserving immutable history & independent M1 method result.
export function onNewRelevantCounterBounded(state: ReviewCacheState, counterId: string): ReviewCacheState {
  return {
    frozenHistoryCut: [...state.frozenHistoryCut],
    independentMethodValid: state.independentMethodValid,
    negativeReasonReviewActive: false,
    counters: [...state.counters, counterId],
  };
}
