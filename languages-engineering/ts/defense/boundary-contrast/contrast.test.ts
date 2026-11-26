// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {
  badExecuteEffect,
  badOnNewRelevantCounter,
  badResolveAuthorityConflict,
  badValidateEvidence,
  type RemoteEffectGateway,
} from './bad-defensive.ts';
import {
  executeEffectBoundary,
  onNewRelevantCounterBounded,
  resolveAuthorityBoundary,
  validateEvidenceBoundary,
} from './deterministic-boundary.ts';

function makeGateway(opts: {
  requestAllowed: boolean;
  liveRevoked: boolean;
  isIdempotent: boolean;
}): RemoteEffectGateway {
  return {
    ...opts,
    dispatchCount: 0,
    dispatch(failWithTimeout: boolean) {
      this.dispatchCount += 1;
      return failWithTimeout ? 'timeout-unknown' : 'committed';
    },
  };
}

describe('C4 TypeScript paired contrast: bad-defensive vs deterministic-boundary', () => {
  test('P1 masking: bad-defensive swallows missing body & digest mismatch into ok; boundary separates SetupDefect vs Refuted', () => {
    const missing = {subjectId: 'art-1', expectedDigest: 'sha256:aaa'};
    const mismatch = {subjectId: 'art-1', expectedDigest: 'sha256:aaa', actualDigest: 'sha256:bbb'};

    // Bad defensive code masks both failures as ok=true empty success:
    expect(badValidateEvidence(missing)).toEqual({ok: true, items: []});
    expect(badValidateEvidence(mismatch)).toEqual({ok: true, items: []});

    // Deterministic boundary preserves exact epistemic states:
    expect(validateEvidenceBoundary(missing)).toEqual({
      kind: 'SetupDefect',
      defect: 'missing-expected-body-digest',
    });
    expect(validateEvidenceBoundary(mismatch)).toEqual({
      kind: 'Refuted',
      reason: 'digest-mismatch',
    });
    expect(
      validateEvidenceBoundary({subjectId: 'art-1', expectedDigest: 'sha256:aaa', actualDigest: 'sha256:aaa'}),
    ).toEqual({kind: 'Proven', value: 'art-1'});
  });

  test('P1 conflict erasure: bad-defensive uses last-writer-wins; boundary preserves Conflict and PendingScope', () => {
    expect(badResolveAuthorityConflict(['deny', 'allow'])).toBe('allow');
    expect(resolveAuthorityBoundary(['deny', 'allow'])).toEqual({
      kind: 'Conflict',
      competingRecords: ['deny', 'allow'],
    });
    expect(resolveAuthorityBoundary([])).toEqual({
      kind: 'PendingScope',
      missingPremise: 'authority-record-absent',
    });
  });

  test('P2 TOCTOU & blind retry: bad-defensive executes under live revocation and duplicates non-idempotent unknown effect', () => {
    const badRevoked = makeGateway({requestAllowed: true, liveRevoked: true, isIdempotent: false});
    expect(badExecuteEffect(badRevoked)).toBe('ok');
    expect(badRevoked.dispatchCount).toBe(2); // Unauthorized AND duplicated!

    const goodRevoked = makeGateway({requestAllowed: true, liveRevoked: true, isIdempotent: false});
    expect(executeEffectBoundary(goodRevoked)).toEqual({kind: 'RefusedRevokedAtUse'});
    expect(goodRevoked.dispatchCount).toBe(0);

    const goodUnknown = makeGateway({requestAllowed: true, liveRevoked: false, isIdempotent: false});
    expect(executeEffectBoundary(goodUnknown)).toEqual({kind: 'PendingUnknownEffect', attempts: 1});
    expect(goodUnknown.dispatchCount).toBe(1);

    const goodIdempotent = makeGateway({requestAllowed: true, liveRevoked: false, isIdempotent: true});
    expect(executeEffectBoundary(goodIdempotent)).toEqual({kind: 'Committed', attempts: 2});
  });

  test('P3 global purge vs bounded negative-dependency revalidation (DE01)', () => {
    const initial = {
      frozenHistoryCut: ['kOld:r2m'],
      independentMethodValid: true,
      negativeReasonReviewActive: true,
      counters: ['ELateCounter'],
    };

    const purged = badOnNewRelevantCounter(initial, 'ENew');
    expect(purged.frozenHistoryCut).toEqual([]);
    expect(purged.independentMethodValid).toBe(false);

    const bounded = onNewRelevantCounterBounded(initial, 'ENew');
    expect(bounded.frozenHistoryCut).toEqual(['kOld:r2m']);
    expect(bounded.independentMethodValid).toBe(true);
    expect(bounded.negativeReasonReviewActive).toBe(false);
    expect(bounded.counters).toEqual(['ELateCounter', 'ENew']);
  });
});
