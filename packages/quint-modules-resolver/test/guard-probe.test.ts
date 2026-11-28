// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {probeGuardNecessity} from '../src/guard-probe.ts';

const repoRoot = resolve(import.meta.dir, '../../..');
const unknownEffectQnt = join(
  repoRoot,
  'packages/quint-models/engineering/defense/unknown-effect-retry/UnknownEffectRetry.qnt',
);

describe('E2.2 Automated guard-probe necessity & redundancy auditor', () => {
  test('classifies an essential guard as essential (Apalache finds counterexample)', () => {
    const report = probeGuardNecessity(unknownEffectQnt, {
      action: 'retryEffect',
      guardExpr: 'h.idempotentContract',
      maxSteps: 6,
    });
    expect(report.classification).toBe('essential');
    expect(report.counterexampleFound).toBe(true);
  }, 60_000);

  test('classifies an injected redundant defensive guard as redundant-or-under-modeled', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'qmr-redundant-probe-'));
    try {
      const original = readFileSync(unknownEffectQnt, 'utf8');
      // Inject a redundant defensive guard `(h.dispatches >= 0)` into retryEffect
      const withRedundant = original.replace(
        'action retryEffect = if ((h.requestAllowed and h.effectUnknown and h.idempotentContract and not(h.authorityRevoked)))',
        'action retryEffect = if ((h.requestAllowed and h.effectUnknown and (h.dispatches >= 0) and h.idempotentContract and not(h.authorityRevoked)))',
      );
      expect(withRedundant).not.toBe(original);
      const tempFile = join(tempDir, 'UnknownEffectRetryRedundant.qnt');
      writeFileSync(tempFile, withRedundant, 'utf8');

      const report = probeGuardNecessity(tempFile, {
        action: 'retryEffect',
        guardExpr: '(h.dispatches >= 0)',
        maxSteps: 6,
      });
      expect(report.classification).toBe('redundant-or-under-modeled');
      expect(report.counterexampleFound).toBe(false);
    } finally {
      rmSync(tempDir, {recursive: true, force: true});
    }
  }, 60_000);

  test('fails closed on missing action or absent guard expression', () => {
    expect(() =>
      probeGuardNecessity(unknownEffectQnt, {
        action: 'nonexistentAction',
        guardExpr: 'h.idempotentContract',
      }),
    ).toThrow(/not found/);

    expect(() =>
      probeGuardNecessity(unknownEffectQnt, {
        action: 'retryEffect',
        guardExpr: 'h.nonexistentGuardExpr',
      }),
    ).toThrow(/not found/);
  });
});
