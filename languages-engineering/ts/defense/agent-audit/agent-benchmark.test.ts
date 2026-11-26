// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E3.2: Independent TypeScript half of the 16-case AI Agent Defensive Coding Benchmark (30.05).
 * Fixed independent gold:
 *   - 8 negative cases (AG01-AG02, AG04-AG05, AG07-AG08, AG10-AG11) across all 4 G2 hallucination classes
 *   - 2 clean positive controls (AG13 real deterministic-boundary.ts, AG14 legitimate epistemic catch)
 *   - Plus live cross-check on bad-defensive.ts
 * Asserts 100% recall, 100% precision, 0 false negatives, 0 false positives.
 */

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {auditTypeScriptSource, type HallucinationClass} from './ts-ast-auditor.ts';

interface BenchmarkCase {
  id: string;
  expectedPass: boolean;
  expectedClass?: HallucinationClass;
  source: string;
}

const TS_BENCHMARK_CASES: BenchmarkCase[] = [
  // ── P1 / G2: silent-fallback ──
  {
    id: 'AG01-ts-catch-returns-ok-true',
    expectedPass: false,
    expectedClass: 'silent-fallback',
    source: `
      export function parseReceipt(raw: string) {
        try {
          return { ok: true, data: JSON.parse(raw) };
        } catch (err) {
          return { ok: true, data: [] };
        }
      }
    `,
  },
  {
    id: 'AG02-ts-empty-catch-swallow',
    expectedPass: false,
    expectedClass: 'silent-fallback',
    source: `
      export function syncRevocation(fn: () => void) {
        try {
          fn();
        } catch {}
      }
    `,
  },
  // ── G2: floor-weakening ──
  {
    id: 'AG04-ts-skip-test-and-zero-coverage',
    expectedPass: false,
    expectedClass: 'floor-weakening',
    source: `
      const cfg = { minCoverage: 0, requireCountermodels: false };
      test.skip('authority revocation race', () => {
        expect(true).toBe(true);
      });
    `,
  },
  {
    id: 'AG05-ts-allow-global-purge',
    expectedPass: false,
    expectedClass: 'floor-weakening',
    source: `
      export const policyOverride = {
        allowGlobalPurge: true,
        requireUseTimeWitness: false,
      };
    `,
  },
  // ── P4 / G2: redundant-defensive-glue ──
  {
    id: 'AG07-ts-redundant-typeof-and-noop-rethrow',
    expectedPass: false,
    expectedClass: 'redundant-defensive-glue',
    source: `
      export function formatId(id: string): string {
        if (typeof id !== 'string') {
          throw new Error('impossible');
        }
        try {
          return id.trim();
        } catch (e) {
          throw e;
        }
      }
    `,
  },
  {
    id: 'AG08-ts-duplicate-null-guard',
    expectedPass: false,
    expectedClass: 'redundant-defensive-glue',
    source: `
      export function loadSubject(x: string | null): string {
        if (!x) return 'missing';
        if (!x) return 'still-missing';
        return x;
      }
    `,
  },
  // ── G2: fabricated-evidence ──
  {
    id: 'AG10-ts-ungrounded-verified-stub',
    expectedPass: false,
    expectedClass: 'fabricated-evidence',
    source: `
      export function verifySignature(_payload: string) {
        return { verified: true, issuer: 'stub' };
      }
    `,
  },
  {
    id: 'AG11-ts-todo-unverified-positive-return',
    expectedPass: false,
    expectedClass: 'fabricated-evidence',
    source: `
      export function checkAuthorityBoundary(_token: string): boolean {
        // TODO: verify revocation epoch later
        return true;
      }
    `,
  },
  // ── Clean Positive Controls (must produce 0 false positives) ──
  {
    id: 'AG13-ts-real-deterministic-boundary',
    expectedPass: true,
    source: readFileSync(join(import.meta.dir, '../boundary-contrast/deterministic-boundary.ts'), 'utf8'),
  },
  {
    id: 'AG14-ts-legitimate-epistemic-catch',
    expectedPass: true,
    source: `
      export type Outcome = { kind: 'Proven'; data: unknown } | { kind: 'Refuted'; reason: string };
      export function parseStrict(raw: string): Outcome {
        try {
          return { kind: 'Proven', data: JSON.parse(raw) };
        } catch (err) {
          return { kind: 'Refuted', reason: err instanceof Error ? err.message : 'parse-error' };
        }
      }
    `,
  },
];

describe('E3.2 Agent Defensive Coding Benchmark (TypeScript AST, 30.05)', () => {
  test('achieves 100% recall on all 8 negative cases and 0% false positives on clean controls', () => {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    let tn = 0;

    for (const c of TS_BENCHMARK_CASES) {
      const report = auditTypeScriptSource(c.source, `${c.id}.ts`);
      if (c.expectedPass) {
        if (report.passed) tn += 1;
        else fp += 1;
        expect(report.findings, `False positive in ${c.id}`).toEqual([]);
      } else {
        const hitClass = c.expectedClass
          ? report.findings.some(f => f.hallucinationClass === c.expectedClass)
          : !report.passed;
        if (hitClass) tp += 1;
        else fn += 1;
        expect(report.passed, `Missed hallucination in ${c.id}`).toBe(false);
        expect(hitClass, `Wrong hallucination class in ${c.id}`).toBe(true);
      }
    }

    expect(tp).toBe(8);
    expect(tn).toBe(2);
    expect(fp).toBe(0);
    expect(fn).toBe(0);
  });

  test('AST auditor flags real bad-defensive.ts with exact line numbers', () => {
    const badSrc = readFileSync(join(import.meta.dir, '../boundary-contrast/bad-defensive.ts'), 'utf8');
    const report = auditTypeScriptSource(badSrc, 'bad-defensive.ts');
    expect(report.passed).toBe(false);
    expect(report.countsByClass['silent-fallback']).toBeGreaterThanOrEqual(3);
    expect(report.countsByClass['floor-weakening']).toBeGreaterThanOrEqual(1);
    for (const f of report.findings) {
      expect(f.line).toBeGreaterThan(0);
      expect(f.column).toBeGreaterThan(0);
    }
  });
});
