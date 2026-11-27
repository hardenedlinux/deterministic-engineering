// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {
  auditDiffObligationDeletions,
  auditSourceByPath,
  auditUnifiedDiff,
  parseUnifiedDiffAddedLines,
} from './multi-lang-auditor.ts';
import {
  formatAgentRepairPacket,
  formatSarifReport,
} from './remediation-catalog.ts';
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

  test('G2-v2 Anti-Evasion & Diff-Delta Benchmark (30.05 AG25-AG32): log-and-swallow, type/assertion bypass, diff deletion, SARIF 2.1.0 & repair packet', () => {
    // AG25: TS E1 log-and-swallow (console.error before returning [])
    const ag25 = auditSourceByPath(
      `export function loadItems(): string[] { try { return []; } catch (e) { console.error(e); return []; } }`,
      'evasion/log-swallow.ts',
    )!;
    expect(ag25.passed).toBe(false);
    expect(ag25.findings.some(f => f.rule === 'catch-log-and-swallow')).toBe(true);

    // AG26: TS E2 @ts-ignore + as any + conditional expect inside if (res.ok)
    const ag26 = auditSourceByPath(
      `
// @ts-ignore bypass strict boundary
export function castBypass(x: unknown): string { return x as any; }
export function check(res: {ok: boolean; v: number}) {
  if (res.ok) { expect(res.v).toBe(1); }
}
`,
      'evasion/type-and-assert-bypass.ts',
    )!;
    expect(ag26.passed).toBe(false);
    expect(ag26.findings.some(f => f.rule === 'ts-ignore-boundary-bypass')).toBe(true);
    expect(ag26.findings.some(f => f.rule === 'ts-as-any-boundary-bypass')).toBe(true);
    expect(ag26.findings.some(f => f.rule === 'conditional-vacuous-assertion')).toBe(true);

    // AG27: Rust E1 log-and-swallow + E2 #[allow(unused_must_use)]
    const ag27 = auditSourceByPath(
      `
#[allow(unused_must_use)]
fn run_op(res: Result<u64, &'static str>) -> Result<u64, &'static str> {
  match res {
    Ok(v) => Ok(v),
    Err(e) => { eprintln!("{}", e); Ok(0) }
  }
}
`,
      'evasion/rust_evasion.rs',
    )!;
    expect(ag27.passed).toBe(false);
    expect(ag27.findings.some(f => f.rule === 'rust-allow-unused-must-use')).toBe(true);
    expect(ag27.findings.some(f => f.rule === 'rust-err-log-and-swallow')).toBe(true);

    // AG28: C++ E1 catch log-and-swallow without rethrow
    const ag28 = auditSourceByPath(
      `
#include <iostream>
void sync_state() {
  try { throw 1; } catch (...) { std::cerr << "oops"; }
}
`,
      'evasion/cpp_log_swallow.cpp',
    )!;
    expect(ag28.passed).toBe(false);
    expect(ag28.findings.some(f => f.rule === 'cpp-catch-log-and-swallow')).toBe(true);

    // AG29: E3 Diff-Delta silent deletion of assertions in a PR diff
    const deleteAssertDiff = [
      'diff --git a/test/sample.test.ts b/test/sample.test.ts',
      '--- a/test/sample.test.ts',
      '+++ b/test/sample.test.ts',
      '@@ -10,2 +10,0 @@',
      '-expect(verdict.kind).toBe("Refuted");',
      '-expect(verdict.reason).toBe("revoked");',
    ].join('\n');
    const ag29 = auditDiffObligationDeletions(deleteAssertDiff);
    expect(ag29.length).toBe(1);
    expect(ag29[0]!.findings.some(f => f.rule === 'diff-deleted-assertion')).toBe(true);

    // AG30: E3 Diff-Delta silent deletion of Band-5 floor and formal guard/countermodel
    const deleteFloorAndGuardDiff = [
      'diff --git a/packages/quint-models/example/objects.ss b/packages/quint-models/example/objects.ss',
      '--- a/packages/quint-models/example/objects.ss',
      '+++ b/packages/quint-models/example/objects.ss',
      '@@ -40,2 +40,0 @@',
      '-  allow-global-purge?: #f',
      '-  (guard check-authority-at-use (not (. h revoked)))',
    ].join('\n');
    const ag30 = auditDiffObligationDeletions(deleteFloorAndGuardDiff);
    expect(ag30.length).toBe(1);
    expect(ag30[0]!.findings.some(f => f.rule === 'diff-deleted-governance-floor')).toBe(true);
    expect(ag30[0]!.findings.some(f => f.rule === 'diff-deleted-formal-guard-or-countermodel')).toBe(true);

    // AG31: Clean positive control — balanced assertion refactor (1 removed, 1 added => 0 deletion findings)
    const balancedRefactorDiff = [
      'diff --git a/test/sample.test.ts b/test/sample.test.ts',
      '--- a/test/sample.test.ts',
      '+++ b/test/sample.test.ts',
      '@@ -10,1 +10,1 @@',
      '-expect(verdict.kind).toBe("Refuted");',
      '+expect(verdict).toEqual({kind: "Refuted", reason: "revoked"});',
    ].join('\n');
    expect(auditDiffObligationDeletions(balancedRefactorDiff)).toEqual([]);

    // AG32: SARIF 2.1.0 + Agent Repair Packet CLI outputs bind C2 replacements & anti-evasion warnings
    const sarif = formatSarifReport([ag25, ag26, ...ag29]);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results.length).toBeGreaterThanOrEqual(5);
    expect(sarif.runs[0]!.results[0]!.properties.antiEvasionWarning.length).toBeGreaterThan(20);

    const repair = formatAgentRepairPacket([ag25, ...ag30]);
    expect(repair.decision).toBe('REFUSE');
    expect(repair.boundedRetryPolicy.onBudgetExhausted).toBe('EscalateToHuman');
    expect(repair.findings.some(f => f.remediation.antiPatternId === 'g2.silent-obligation-deletion')).toBe(true);

    const sarifProc = Bun.spawnSync(
      ['bun', cliPath, '--sarif', '--files', 'languages-engineering/ts/defense/boundary-contrast/bad-defensive.ts'],
      {cwd: repoRoot, stdout: 'pipe', stderr: 'pipe'},
    );
    expect(sarifProc.exitCode).toBe(1);
    const parsedSarif = JSON.parse(sarifProc.stdout.toString());
    expect(parsedSarif.version).toBe('2.1.0');
    expect(parsedSarif.runs[0].results.length).toBeGreaterThan(0);

    const feedbackProc = Bun.spawnSync(
      ['bun', cliPath, '--agent-feedback', '--files', 'languages-engineering/ts/defense/boundary-contrast/deterministic-boundary.ts'],
      {cwd: repoRoot, stdout: 'pipe', stderr: 'pipe'},
    );
    expect(feedbackProc.exitCode).toBe(0);
    const parsedFeedback = JSON.parse(feedbackProc.stdout.toString());
    expect(parsedFeedback.decision).toBe('ADMIT');
    expect(parsedFeedback.totalFindings).toBe(0);
  });

  test('Real-world Rust precision (calibrated on 490-file marlin-agent-core): zero FP on fail-closed/typed-failure/Option/match-guard while preserving all silent-fallback catches', () => {
    // 1. Clean real-world Rust patterns observed in marlin-agent-core MUST produce 0 findings:
    const cleanMarlinRust = `
      pub fn is_actor_fenced(&self, actor: &str) -> bool {
        self.inner.lock().map(|g| g.fenced.contains(actor)).unwrap_or(true)
      }
      fn handle_exec(res: Result<Receipt, ExecErr>) -> Outcome {
        match res {
          Ok(r) => Outcome::completed(r),
          Err(error) => {
            log_receipt(Receipt::failed(error));
            Outcome::failed(error)
          }
        }
      }
      fn read_opt(path: &Path) -> Result<Option<String>, io::Error> {
        match fs::read_to_string(path) {
          Ok(text) => Ok(Some(text)),
          Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
          Err(error) => Err(error),
        }
      }
      fn grpc_gate(res: Result<Ack, Denial>) -> Result<Response<Reply>, Status> {
        match res {
          Ok(ack) => Ok(Response::new(Reply::ok(ack))),
          Err(denial) => Ok(Response::new(Reply::denied(denial))),
        }
      }
      fn cli_main(res: Result<(), String>) {
        match res {
          Ok(()) => std::process::exit(0),
          Err(err) => {
            eprintln!("fatal: {err}");
            std::process::exit(1);
          }
        }
      }
      fn render_label(opt: Option<&str>, map: &HashMap<String, String>) -> String {
        let a = opt.as_deref().unwrap_or("");
        let b = map.get("k").cloned().unwrap_or_default();
        format!("{a}:{b}")
      }
    `;
    const cleanReport = auditSourceByPath(cleanMarlinRust, 'marlin_clean.rs')!;
    expect(cleanReport.passed).toBe(true);
    expect(cleanReport.findings).toEqual([]);

    // 2. Real-world Marlin silent-fallback defects MUST STILL BE CAUGHT:
    const badMarlinRust = `
      fn boot_bridge() -> String {
        let token = std::env::var("MARLIN_BRIDGE_TOKEN").unwrap_or_default();
        token
      }
      fn parse_epoch(facets: &HashMap<String, String>) -> u64 {
        facets.get("revocation_epoch").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
      }
      fn reconcile(owner: &Owner) -> Option<Report> {
        match owner.reconcile_persisted_processes() {
          Ok(r) => Some(r),
          Err(error) => {
            eprintln!("reconcile failed: {error}");
            None
          }
        }
      }
    `;
    const badReport = auditSourceByPath(badMarlinRust, 'marlin_defects.rs')!;
    expect(badReport.passed).toBe(false);
    expect(badReport.findings.some(f => f.rule === 'rust-unwrap-or-default')).toBe(true);
    expect(badReport.findings.some(f => f.rule === 'rust-unwrap-or-constant')).toBe(true);
    expect(badReport.findings.some(f => f.rule === 'rust-err-log-and-swallow')).toBe(true);
  });

  test('Native Go & upgraded Scheme G2 auditors (10.209, calibrated on 251 Go + 240 Scheme real Marlin files)', () => {
    // 1. Go negative control covering all 4 G2 hallucination classes:
    const badGo = `
package auth
import ("fmt"; "log"; "testing")
//nolint:errcheck
func DeleteSecret(path string) error {
  err := removeBlob(path)
  if err != nil {
    return nil
  }
  if err2 := syncDisk(path); err2 != nil {
    log.Printf("sync failed: %v", err2)
  }
  defer func() { recover() }()
  return nil
}
func WrapRecover() {
  defer func() {
    if r := recover(); r != nil { panic(r) }
  }()
}
func VerifyReceipt(raw []byte) bool {
  return true
}
func TestGate(t *testing.T) {
  t.Skip("flaky")
}
`;
    const badGoRep = auditSourceByPath(badGo, 'auth/keychain_bad.go')!;
    expect(badGoRep.language).toBe('go');
    expect(badGoRep.passed).toBe(false);
    expect(badGoRep.findings.some(f => f.rule === 'go-if-err-return-nil')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-if-err-log-and-swallow')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-recover-swallow')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-noop-recover-repanic')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-stub-verify-returns-true')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-test-skip')).toBe(true);
    expect(badGoRep.findings.some(f => f.rule === 'go-nolint-errcheck')).toBe(true);

    // 2. Clean idiomatic Go (propagated err, narrow os.ErrNotExist, CLI os.Exit(1)) => 0 findings:
    const cleanGo = `
package auth
import ("errors"; "fmt"; "os")
func DeleteSecret(path string) error {
  if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
    return fmt.Errorf("delete secret %s: %w", path, err)
  }
  return nil
}
func main() {
  if err := DeleteSecret("/tmp/x"); err != nil {
    fmt.Fprintf(os.Stderr, "fatal: %v\\n", err)
    os.Exit(1)
  }
}
`;
    const cleanGoRep = auditSourceByPath(cleanGo, 'auth/keychain_clean.go')!;
    expect(cleanGoRep.passed).toBe(true);
    expect(cleanGoRep.findings).toEqual([]);

    // 3. Upgraded Gerbil Scheme: catches (try ... (catch (_) '())) & (with-catch (lambda (e) (displayln e) 0) ...)
    const badScheme = `
(def (bad-try thunk)
  (try (thunk) (catch (_) '())))
(def (bad-log-swallow thunk)
  (with-catch (lambda (e) (displayln e) 0) thunk))
`;
    const badSchemeRep = auditSourceByPath(badScheme, 'bad_gerbil.ss')!;
    expect(badSchemeRep.passed).toBe(false);
    expect(badSchemeRep.findings.some(f => f.rule === 'scheme-try-catch-constant-fallback')).toBe(true);
    expect(badSchemeRep.findings.some(f => f.rule === 'scheme-with-catch-log-and-swallow')).toBe(true);

    // 4. Clean Gerbil Scheme (cleanup + re-raise) => 0 findings:
    const cleanScheme = `
(def (safe-read input)
  (with-catch (lambda (failure) (close-input-port input) (raise failure))
    (lambda () (read input))))
`;
    const cleanSchemeRep = auditSourceByPath(cleanScheme, 'clean_gerbil.ss')!;
    expect(cleanSchemeRep.passed).toBe(true);
    expect(cleanSchemeRep.findings).toEqual([]);

    // 5. E3 diff-delta catches deleted Go test assertions (t.Fatalf / require.NoError):
    const deletedGoAssertDiff = [
      'diff --git a/control/auth/keychain_test.go b/control/auth/keychain_test.go',
      '--- a/control/auth/keychain_test.go',
      '+++ b/control/auth/keychain_test.go',
      '@@ -12,2 +12,0 @@',
      '-  t.Fatalf("expected error on corrupt secret")',
      '-  require.NoError(t, err)',
    ].join('\n');
    const goDiffRep = auditDiffObligationDeletions(deletedGoAssertDiff);
    expect(goDiffRep.length).toBe(1);
    expect(goDiffRep[0]!.language).toBe('go');
    expect(goDiffRep[0]!.findings.some(f => f.rule === 'diff-deleted-assertion')).toBe(true);
  });
});
