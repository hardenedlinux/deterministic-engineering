// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {
  auditSourceByPath,
  auditUnifiedDiff,
  parseUnifiedDiffAddedLines,
} from './multi-lang-auditor.ts';
import type {HallucinationClass} from './ts-ast-auditor.ts';

const repoRoot = resolve(import.meta.dir, '../../../..');
const cliPath = resolve(import.meta.dir, 'agent-defense-audit.ts');

interface MultiLangBenchCase {
  id: string;
  fileName: string;
  source: string;
  expectedPass: boolean;
  expectedClasses: HallucinationClass[];
}

// Benchmark extension AG17-AG24 for 30.05 (C, C++, Rust, Scheme parity, and diff scoping)
const MULTI_LANG_BENCHMARK_CASES: MultiLangBenchCase[] = [
  {
    id: 'AG17',
    fileName: 'c/bad_defensive.c',
    source: readFileSync(
      resolve(repoRoot, 'languages-engineering/c/defense/silent-fallback-contrast/bad_defensive.c'),
      'utf8',
    ),
    expectedPass: false,
    expectedClasses: ['silent-fallback'],
  },
  {
    id: 'AG18',
    fileName: 'cpp/bad_defensive.hpp',
    source: readFileSync(
      resolve(repoRoot, 'languages-engineering/cpp/defense/raii-fallback-contrast/bad_defensive.hpp'),
      'utf8',
    ),
    expectedPass: false,
    expectedClasses: ['silent-fallback'],
  },
  {
    id: 'AG19',
    fileName: 'c/floor_weakening_and_stub.cpp',
    source: `
#define NDEBUG
#include <cassert>
bool verifyReceipt(const char* r) {
  return true;
}
void checkGate() {
  assert(true);
}
`,
    expectedPass: false,
    expectedClasses: ['floor-weakening', 'fabricated-evidence'],
  },
  {
    id: 'AG20',
    fileName: 'rust/silent_fallback_and_glue.rs',
    source: `
fn load_budget(raw: Result<usize, &'static str>) -> usize {
  raw.unwrap_or_default()
}
fn wrap(res: Result<(), &'static str>) -> Result<(), &'static str> {
  match res {
    Ok(v) => Ok(v),
    Err(e) => Err(e),
  }
}
`,
    expectedPass: false,
    expectedClasses: ['silent-fallback', 'redundant-defensive-glue'],
  },
  {
    id: 'AG21',
    fileName: 'rust/floor_weakening_and_stub.rs',
    source: `
fn verify_proof_witness(_raw: &[u8]) -> bool {
  true
}
#[test]
#[ignore]
fn broken_gate() {
  assert!(true);
}
`,
    expectedPass: false,
    expectedClasses: ['floor-weakening', 'fabricated-evidence'],
  },
  {
    id: 'AG22',
    fileName: 'c/deterministic_boundary.c',
    source: readFileSync(
      resolve(repoRoot, 'languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c'),
      'utf8',
    ),
    expectedPass: true,
    expectedClasses: [],
  },
  {
    id: 'AG23',
    fileName: 'cpp/deterministic_boundary.hpp',
    source: readFileSync(
      resolve(repoRoot, 'languages-engineering/cpp/defense/raii-fallback-contrast/deterministic_boundary.hpp'),
      'utf8',
    ),
    expectedPass: true,
    expectedClasses: [],
  },
  {
    id: 'AG24',
    fileName: 'rust/contrast.rs',
    source: readFileSync(
      resolve(repoRoot, 'languages-engineering/rust/defense/ownership-boundary-contrast/contrast.rs'),
      'utf8',
    ),
    expectedPass: true,
    expectedClasses: [],
  },
];

describe('E3.3 Multi-Language Agent Defense Audit & Diff Gate (30.05 AG17-AG24)', () => {
  test('achieves 100% recall and 0% false positives across C, C++, Rust, and live Scheme files', () => {
    for (const c of MULTI_LANG_BENCHMARK_CASES) {
      const report = auditSourceByPath(c.source, c.fileName);
      expect(report).not.toBeNull();
      expect(report!.passed).toBe(c.expectedPass);
      for (const cls of c.expectedClasses) {
        expect(report!.countsByClass[cls]).toBeGreaterThan(0);
      }
      if (c.expectedPass) {
        expect(report!.findings).toEqual([]);
      }
    }

    // Live Scheme library positive controls + negative control parity
    const liveScheme1 = readFileSync(resolve(repoRoot, 'library/defensive-boundaries/objects.ss'), 'utf8');
    const liveScheme2 = readFileSync(resolve(repoRoot, 'library/defensive-governance/objects.ss'), 'utf8');
    expect(auditSourceByPath(liveScheme1, 'library/defensive-boundaries/objects.ss')!.passed).toBe(true);
    expect(auditSourceByPath(liveScheme2, 'library/defensive-governance/objects.ss')!.passed).toBe(true);

    const badScheme = `
(def (bad-fn)
  (with-catch (lambda (_) '()) (lambda () (error "boom"))))
(def bad-cfg (.o allow-global-purge?: #t verified?: #t witness: #f))
(guard vacuous #t)
`;
    const badSchemeReport = auditSourceByPath(badScheme, 'bad.ss')!;
    expect(badSchemeReport.passed).toBe(false);
    expect(badSchemeReport.countsByClass['silent-fallback']).toBeGreaterThan(0);
    expect(badSchemeReport.countsByClass['floor-weakening']).toBeGreaterThan(0);
    expect(badSchemeReport.countsByClass['redundant-defensive-glue']).toBeGreaterThan(0);
    expect(badSchemeReport.countsByClass['fabricated-evidence']).toBeGreaterThan(0);
  });

  test('unified diff scoping ignores untouched legacy hallucinations and flags only newly added lines', () => {
    const fileWithLegacyAndNew = [
      'export function legacyBad() {',
      '  try { return 1; } catch {}', // line 2: untouched legacy line
      '}',
      'export function newClean(x: string): {kind: "Refuted"; reason: string} {',
      '  try { throw new Error(x); } catch (e) { return {kind: "Refuted", reason: String(e)}; }', // line 5: added clean
      '}',
      'export function newAgentHallucination(): {verified: boolean} {',
      '  return {verified: true};', // line 8: added fabricated-evidence
      '}',
    ].join('\n');

    const cleanDiff = [
      'diff --git a/src/sample.ts b/src/sample.ts',
      '--- a/src/sample.ts',
      '+++ b/src/sample.ts',
      '@@ -4,0 +4,3 @@',
      '+export function newClean(x: string): {kind: "Refuted"; reason: string} {',
      '+  try { throw new Error(x); } catch (e) { return {kind: "Refuted", reason: String(e)}; }',
      '+}',
    ].join('\n');

    const addedClean = parseUnifiedDiffAddedLines(cleanDiff);
    expect([...addedClean.get('src/sample.ts')!]).toEqual([4, 5, 6]);
    const cleanReports = auditUnifiedDiff(cleanDiff, () => fileWithLegacyAndNew);
    expect(cleanReports.length).toBe(1);
    expect(cleanReports[0]!.passed).toBe(true);
    expect(cleanReports[0]!.scopedToAddedLines).toBe(true);

    const badDiff = [
      'diff --git a/src/sample.ts b/src/sample.ts',
      '--- a/src/sample.ts',
      '+++ b/src/sample.ts',
      '@@ -7,0 +7,3 @@',
      '+export function newAgentHallucination(): {verified: boolean} {',
      '+  return {verified: true};',
      '+}',
    ].join('\n');
    const badReports = auditUnifiedDiff(badDiff, () => fileWithLegacyAndNew);
    expect(badReports.length).toBe(1);
    expect(badReports[0]!.passed).toBe(false);
    expect(badReports[0]!.findings[0]!.hallucinationClass).toBe('fabricated-evidence');
    expect(badReports[0]!.findings[0]!.line).toBe(8);
  });

  test('CLI exits 0 on clean multi-language deterministic boundaries and 1 on bad-defensive files', () => {
    const cleanProc = Bun.spawnSync(
      [
        'bun',
        cliPath,
        '--json',
        '--files',
        'languages-engineering/ts/defense/boundary-contrast/deterministic-boundary.ts',
        'languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c',
        'languages-engineering/cpp/defense/raii-fallback-contrast/deterministic_boundary.hpp',
        'languages-engineering/rust/defense/ownership-boundary-contrast/contrast.rs',
        'library/defensive-governance/objects.ss',
      ],
      {cwd: repoRoot, stdout: 'pipe', stderr: 'pipe'},
    );
    expect(cleanProc.exitCode).toBe(0);
    const cleanJson = JSON.parse(cleanProc.stdout.toString());
    expect(cleanJson.passed).toBe(true);
    expect(cleanJson.totalFindings).toBe(0);
    expect(cleanJson.reports.length).toBe(5);

    const badProc = Bun.spawnSync(
      [
        'bun',
        cliPath,
        '--json',
        '--files',
        'languages-engineering/ts/defense/boundary-contrast/bad-defensive.ts',
        'languages-engineering/c/defense/silent-fallback-contrast/bad_defensive.c',
        'languages-engineering/cpp/defense/raii-fallback-contrast/bad_defensive.hpp',
      ],
      {cwd: repoRoot, stdout: 'pipe', stderr: 'pipe'},
    );
    expect(badProc.exitCode).toBe(1);
    const badJson = JSON.parse(badProc.stdout.toString());
    expect(badJson.passed).toBe(false);
    expect(badJson.totalFindings).toBeGreaterThanOrEqual(4);
  });
});
