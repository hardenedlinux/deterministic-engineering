#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E3.3: `agent-defense-audit` CLI — AI Agent Patch / PR Defensive Hallucination Gate.
 *
 * Usage:
 *   bun packages/agent-defense-audit/src/agent-defense-audit.ts --files <path...> [--json]
 *   bun packages/agent-defense-audit/src/agent-defense-audit.ts --dir <dir...> [--lang=go,rust] [--exclude-tests] [--json]
 *   bun packages/agent-defense-audit/src/agent-defense-audit.ts --diff [--staged] [--json]
 *   bun packages/agent-defense-audit/src/agent-defense-audit.ts --diff-file <patch> [--json]
 *   bun packages/agent-defense-audit/src/agent-defense-audit.ts --probe-quint <file.qnt> --action=<name> --guard=<expr> [--max-steps=6] [--json]
 *
 * Exit codes:
 *   0 -> Clean (0 G2 hallucination findings; Quint guard-probe classified `essential` if invoked)
 *   1 -> Refused (G2 hallucination found, or Quint guard classified `redundant-or-under-modeled`)
 *   2 -> Invalid CLI usage / unreadable input
 */

import {existsSync, readdirSync, readFileSync, realpathSync, statSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {
  auditSourceByPath,
  auditUnifiedDiff,
  detectAuditLanguage,
  parseUnifiedDiffHunks,
  type MultiLangAuditReport,
  type SupportedAuditLanguage,
} from './multi-lang-auditor.ts';
import {
  evaluateScopeFence,
} from './governance-harness.ts';
import {
  formatAgentRepairPacket,
  formatSarifReport,
  getRemediationDirective,
} from './remediation-catalog.ts';

interface CliOptions {
  mode: 'files' | 'dir' | 'diff' | 'diff-file' | 'probe-quint';
  files: string[];
  dirs: string[];
  langs: SupportedAuditLanguage[];
  staged: boolean;
  excludeTests: boolean;
  excludeNegativeFixtures: boolean;
  diffFile?: string;
  scopeGlobs: string[];
  forbidGlobs: string[];
  quintFile?: string;
  quintAction?: string;
  quintGuard?: string;
  quintMaxSteps?: string;
  outputFormat: 'text' | 'json' | 'sarif' | 'agent-feedback';
}

const NEGATIVE_FIXTURE_RE = /(^|\/)(bad[_-]defensive|bad[_-]aging)\.[^/]+$/;
const TEST_FILE_RE = /(?:_test\.go|_test\.rs|-test\.ss|\.test\.[cm]?[jt]sx?|\.spec\.[cm]?[jt]sx?)$/i;
const DEFAULT_SKIP_DIRS = new Set([
  '.git',
  '.devenv',
  '.data',
  '.cache',
  '.gerbil',
  '.lake',
  '.next',
  'node_modules',
  'target',
  'vendor',
  'dist',
  'build',
  'out',
]);
const TEST_SKIP_DIRS = new Set(['tests', 'test', 't', 'benches', 'examples', '__tests__']);

export function collectAuditFilesFromDirs(
  dirs: readonly string[],
  opts: {
    cwd?: string;
    langs?: readonly SupportedAuditLanguage[];
    excludeTests?: boolean;
    excludeNegativeFixtures?: boolean;
  } = {},
): string[] {
  const rawCwd = opts.cwd ?? process.cwd();
  const cwd = existsSync(rawCwd) ? realpathSync(rawCwd) : rawCwd;
  const langFilter = opts.langs && opts.langs.length > 0 ? new Set(opts.langs) : null;
  const collected: string[] = [];

  const walk = (absDir: string) => {
    const entries = readdirSync(absDir, {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || DEFAULT_SKIP_DIRS.has(entry.name)) continue;
        if (opts.excludeTests && TEST_SKIP_DIRS.has(entry.name)) continue;
        walk(join(absDir, entry.name));
      } else if (entry.isFile()) {
        const full = join(absDir, entry.name);
        const rel = relative(cwd, full).replaceAll('\\', '/');
        const lang = detectAuditLanguage(rel);
        if (!lang) continue;
        if (langFilter && !langFilter.has(lang)) continue;
        if (opts.excludeTests && TEST_FILE_RE.test(entry.name)) continue;
        if ((opts.excludeNegativeFixtures || opts.excludeTests) && NEGATIVE_FIXTURE_RE.test(rel)) continue;
        collected.push(rel);
      }
    }
  };

  for (const dir of dirs) {
    const full = resolve(cwd, dir);
    if (!existsSync(full) || !statSync(full).isDirectory()) {
      throw new Error(`Directory not found: ${dir}`);
    }
    walk(realpathSync(full));
  }

  return [...new Set(collected)].sort();
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    mode: 'files',
    files: [],
    dirs: [],
    langs: [],
    staged: false,
    excludeTests: false,
    excludeNegativeFixtures: false,
    scopeGlobs: [],
    forbidGlobs: [],
    outputFormat: 'text',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') {
      opts.outputFormat = 'json';
    } else if (a === '--sarif') {
      opts.outputFormat = 'sarif';
    } else if (a === '--agent-feedback') {
      opts.outputFormat = 'agent-feedback';
    } else if (a === '--diff') {
      opts.mode = 'diff';
    } else if (a === '--staged') {
      opts.staged = true;
    } else if (a === '--exclude-tests') {
      opts.excludeTests = true;
    } else if (a === '--exclude-negative-fixtures') {
      opts.excludeNegativeFixtures = true;
    } else if (a === '--dir') {
      opts.mode = 'dir';
    } else if (a.startsWith('--lang=')) {
      const raw = a.slice('--lang='.length).split(',').filter(Boolean);
      for (const l of raw) {
        const norm = l === 'ts' || l === 'js' ? 'typescript' : l === 'c' || l === 'cpp' ? 'c-cpp' : l;
        if (norm === 'typescript' || norm === 'c-cpp' || norm === 'rust' || norm === 'go' || norm === 'scheme') {
          opts.langs.push(norm);
        } else {
          console.error(`Unsupported --lang value: ${l}`);
          process.exit(2);
        }
      }
    } else if (a === '--diff-file') {
      opts.mode = 'diff-file';
      opts.diffFile = argv[++i];
    } else if (a.startsWith('--scope=')) {
      opts.scopeGlobs.push(...a.slice('--scope='.length).split(',').filter(Boolean));
    } else if (a.startsWith('--forbid-paths=')) {
      opts.forbidGlobs.push(...a.slice('--forbid-paths='.length).split(',').filter(Boolean));
    } else if (a === '--probe-quint') {
      opts.mode = 'probe-quint';
      opts.quintFile = argv[++i];
    } else if (a.startsWith('--action=')) {
      opts.quintAction = a.slice('--action='.length);
    } else if (a.startsWith('--guard=')) {
      opts.quintGuard = a.slice('--guard='.length);
    } else if (a.startsWith('--max-steps=')) {
      opts.quintMaxSteps = a.slice('--max-steps='.length);
    } else if (a === '--files') {
      opts.mode = 'files';
    } else if (!a.startsWith('--')) {
      if (opts.mode === 'dir') {
        opts.dirs.push(a);
      } else {
        opts.files.push(a);
      }
    }
  }
  return opts;
}

function formatTextReports(reports: MultiLangAuditReport[]): string {
  const lines: string[] = [];
  let totalFindings = 0;
  for (const r of reports) {
    totalFindings += r.findings.length;
    const scope = r.scopedToAddedLines ? 'diff-scoped' : 'full-file';
    if (r.passed) {
      lines.push(`PASS [${r.language}/${scope}] ${r.fileName} (0 findings)`);
    } else {
      lines.push(`REFUSE [${r.language}/${scope}] ${r.fileName} (${r.findings.length} findings)`);
      for (const f of r.findings) {
        const rem = getRemediationDirective(f);
        lines.push(`  ${r.fileName}:${f.line}:${f.column} [${f.hallucinationClass}/${f.rule}] ${f.detail}`);
        lines.push(`    -> C2 (${rem.antiPatternId}): ${rem.c2Replacement}`);
      }
    }
  }
  lines.push(`Summary: audited=${reports.length} findings=${totalFindings}`);
  return lines.join('\n');
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.mode === 'probe-quint') {
    if (!opts.quintFile || !opts.quintAction || !opts.quintGuard) {
      console.error('Usage: --probe-quint <file.qnt> --action=<name> --guard=<expr> [--max-steps=6] [--json]');
      process.exit(2);
    }
    const repoRoot = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const args = [
      'bun',
      resolverCli,
      'guard-probe',
      opts.quintFile,
      `--action=${opts.quintAction}`,
      `--guard-expr=${opts.quintGuard}`,
    ];
    if (opts.quintMaxSteps) args.push(`--max-steps=${opts.quintMaxSteps}`);
    if (opts.outputFormat !== 'text') args.push('--json');
    const proc = Bun.spawnSync(args, {cwd: process.cwd(), stdout: 'pipe', stderr: 'pipe'});
    const out = proc.stdout.toString();
    const err = proc.stderr.toString();
    if (out) process.stdout.write(out);
    if (err) process.stderr.write(err);
    if (proc.exitCode !== 0) process.exit(2);
    // Refuse if redundant-or-under-modeled
    if (out.includes('redundant-or-under-modeled')) process.exit(1);
    process.exit(0);
  }

  let reports: MultiLangAuditReport[] = [];

  if (opts.mode === 'diff' || opts.mode === 'diff-file') {
    let diffText = '';
    if (opts.mode === 'diff-file') {
      if (!opts.diffFile || !existsSync(opts.diffFile)) {
        console.error(`Diff file not found: ${opts.diffFile ?? '(missing)'}`);
        process.exit(2);
      }
      diffText = readFileSync(opts.diffFile, 'utf8');
    } else {
      const gitArgs = ['git', 'diff', '-U0'];
      if (opts.staged) gitArgs.push('--cached');
      const proc = Bun.spawnSync(gitArgs, {cwd: process.cwd(), stdout: 'pipe', stderr: 'pipe'});
      if (proc.exitCode !== 0) {
        console.error(`git diff failed: ${proc.stderr.toString()}`);
        process.exit(2);
      }
      diffText = proc.stdout.toString();
    }
    const rawDiffReports = auditUnifiedDiff(diffText, relPath => {
      const full = resolve(process.cwd(), relPath);
      return existsSync(full) ? readFileSync(full, 'utf8') : null;
    });
    const diffReports = opts.excludeNegativeFixtures
      ? rawDiffReports.filter(r => !NEGATIVE_FIXTURE_RE.test(r.fileName))
      : rawDiffReports;
    const touchedFiles = [...new Set(parseUnifiedDiffHunks(diffText).map(h => h.filePath))];
    const scopeReports =
      opts.scopeGlobs.length > 0 || opts.forbidGlobs.length > 0
        ? evaluateScopeFence(touchedFiles, {
            allowedPaths: opts.scopeGlobs.length > 0 ? opts.scopeGlobs : undefined,
            protectedGovernancePaths: opts.forbidGlobs.length > 0 ? opts.forbidGlobs : undefined,
          })
        : [];
    reports = [...scopeReports, ...diffReports];
  } else if (opts.mode === 'dir') {
    const dirs = opts.dirs.length > 0 ? opts.dirs : ['.'];
    for (const dir of dirs) {
      const full = resolve(process.cwd(), dir);
      if (!existsSync(full) || !statSync(full).isDirectory()) {
        console.error(`Directory not found: ${dir}`);
        process.exit(2);
      }
    }
    const targetFiles = collectAuditFilesFromDirs(dirs, {
      cwd: process.cwd(),
      langs: opts.langs,
      excludeTests: opts.excludeTests,
      excludeNegativeFixtures: opts.excludeNegativeFixtures,
    });
    for (const file of targetFiles) {
      const full = resolve(process.cwd(), file);
      const report = auditSourceByPath(readFileSync(full, 'utf8'), file);
      if (report) reports.push(report);
    }
  } else {
    if (opts.files.length === 0) {
      console.error('Usage: agent-defense-audit.ts --files <path...> | --dir <dir...> [--lang=...] [--exclude-tests] | --diff [--staged] | --diff-file <patch> | --probe-quint ...');
      process.exit(2);
    }
    for (const file of opts.files) {
      const full = resolve(process.cwd(), file);
      if (!existsSync(full)) {
        console.error(`File not found: ${file}`);
        process.exit(2);
      }
      const report = auditSourceByPath(readFileSync(full, 'utf8'), file);
      if (report) reports.push(report);
    }
  }

  const totalFindings = reports.reduce((acc, r) => acc + r.findings.length, 0);
  if (opts.outputFormat === 'sarif') {
    console.log(JSON.stringify(formatSarifReport(reports), null, 2));
  } else if (opts.outputFormat === 'agent-feedback') {
    console.log(JSON.stringify(formatAgentRepairPacket(reports), null, 2));
  } else if (opts.outputFormat === 'json') {
    console.log(JSON.stringify({passed: totalFindings === 0, totalFindings, reports}, null, 2));
  } else {
    console.log(formatTextReports(reports));
  }
  process.exit(totalFindings === 0 ? 0 : 1);
}

if (import.meta.main) {
  main();
}
