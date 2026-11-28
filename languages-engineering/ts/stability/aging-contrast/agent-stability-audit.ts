#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * `agent-stability-audit` CLI — Multi-Language AI Agent Software Aging & ADV-L4 Confinement Gate (SM2-SM36).
 *
 * Usage:
 *   bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts --files <path...> [--json|--sarif|--agent-feedback]
 *   bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts --dir <dir...> [--lang=rust,go,ts,c,cpp] [--exclude-tests] [--json|--sarif|--agent-feedback]
 *   bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts --diff [--staged] [--json|--sarif|--agent-feedback]
 *
 * Exit codes:
 *   0 -> Clean (0 software aging / ADV-L4 confinement findings)
 *   1 -> Refused (1+ SM2-SM36 findings)
 *   2 -> Invalid CLI usage / unreadable input
 */

import {existsSync, readdirSync, readFileSync, realpathSync, statSync} from 'node:fs';
import {join, relative, resolve} from 'node:path';
import {
  auditFileForAging,
  detectAgingLanguage,
  type AgingLanguage,
  type FileAgingAuditReport,
} from './aging-ast-auditor.ts';
import {
  formatAgingRepairPacket,
  formatAgingSarif,
  getAgingRemediation,
} from './aging-governance-harness.ts';

interface CliOpts {
  mode: 'files' | 'dir' | 'diff';
  files: string[];
  dirs: string[];
  langs: AgingLanguage[];
  excludeTests: boolean;
  staged: boolean;
  format: 'text' | 'json' | 'sarif' | 'agent-feedback';
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

function parseLanguageFilter(raw: string): AgingLanguage[] {
  const out: AgingLanguage[] = [];
  for (const token of raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    if (token === 'rust' || token === 'rs') out.push('rust');
    else if (token === 'go') out.push('go');
    else if (token === 'ts' || token === 'typescript' || token === 'js') out.push('ts');
    else if (token === 'c') out.push('c');
    else if (token === 'cpp' || token === 'c++') out.push('cpp');
    else {
      console.error(`Unsupported language in --lang: ${token}`);
      process.exit(2);
    }
  }
  return [...new Set(out)];
}

function parseArgs(argv: string[]): CliOpts {
  const opts: CliOpts = {
    mode: 'files',
    files: [],
    dirs: [],
    langs: [],
    excludeTests: false,
    staged: false,
    format: 'text',
  };
  let collecting: 'files' | 'dirs' = 'files';
  for (const a of argv) {
    if (a === '--json') opts.format = 'json';
    else if (a === '--sarif') opts.format = 'sarif';
    else if (a === '--agent-feedback') opts.format = 'agent-feedback';
    else if (a === '--diff') opts.mode = 'diff';
    else if (a === '--staged') opts.staged = true;
    else if (a === '--exclude-tests') opts.excludeTests = true;
    else if (a === '--files') {
      opts.mode = 'files';
      collecting = 'files';
    } else if (a === '--dir') {
      opts.mode = 'dir';
      collecting = 'dirs';
    } else if (a.startsWith('--lang=')) {
      opts.langs.push(...parseLanguageFilter(a.slice('--lang='.length)));
    } else if (!a.startsWith('--')) {
      if (collecting === 'dirs') opts.dirs.push(a);
      else opts.files.push(a);
    }
  }
  return opts;
}

function collectFilesFromDirs(
  dirs: readonly string[],
  langs: readonly AgingLanguage[],
  excludeTests: boolean,
): string[] {
  const cwd = existsSync(process.cwd()) ? realpathSync(process.cwd()) : process.cwd();
  const langFilter = langs.length > 0 ? new Set(langs) : null;
  const collected: string[] = [];

  const walk = (absDir: string) => {
    const entries = readdirSync(absDir, {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || DEFAULT_SKIP_DIRS.has(entry.name)) continue;
        if (excludeTests && TEST_SKIP_DIRS.has(entry.name)) continue;
        walk(join(absDir, entry.name));
      } else if (entry.isFile()) {
        const full = join(absDir, entry.name);
        const rel = relative(cwd, full).replaceAll('\\', '/');
        const lang = detectAgingLanguage(rel);
        if (!lang) continue;
        if (langFilter && !langFilter.has(lang)) continue;
        if (excludeTests && (TEST_FILE_RE.test(entry.name) || NEGATIVE_FIXTURE_RE.test(rel))) continue;
        collected.push(full);
      }
    }
  };

  for (const dir of dirs) {
    const full = resolve(cwd, dir);
    if (!existsSync(full) || !statSync(full).isDirectory()) {
      console.error(`Directory not found: ${dir}`);
      process.exit(2);
    }
    walk(realpathSync(full));
  }

  return [...new Set(collected)].sort();
}

function collectDiffFiles(staged: boolean): string[] {
  const args = ['git', 'diff', '--name-only', '--diff-filter=ACMR'];
  if (staged) args.push('--staged');
  const proc = Bun.spawnSync(args, {cwd: process.cwd(), stdout: 'pipe', stderr: 'pipe'});
  if (proc.exitCode !== 0) return [];
  return proc.stdout
    .toString()
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
}

function formatText(reports: FileAgingAuditReport[]): string {
  const lines: string[] = [];
  let total = 0;
  for (const r of reports) {
    total += r.findings.length;
    if (r.passed) {
      lines.push(`PASS [${r.language}] ${r.fileName} (0 aging findings)`);
    } else {
      lines.push(`REFUSE [${r.language}] ${r.fileName} (${r.findings.length} aging findings)`);
      for (const f of r.findings) {
        const rem = getAgingRemediation(f);
        lines.push(`  ${r.fileName}:${f.line} [${f.mechanism}/${f.ruleId}] ${f.message}`);
        lines.push(`    -> C2: ${rem.c2SteadyReplacement}`);
      }
    }
  }
  lines.push(`Summary: audited=${reports.length} agingFindings=${total}`);
  return lines.join('\n');
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const targetFiles =
    opts.mode === 'diff'
      ? collectDiffFiles(opts.staged)
      : opts.mode === 'dir'
        ? collectFilesFromDirs(opts.dirs, opts.langs, opts.excludeTests)
        : opts.files;

  if (opts.mode !== 'diff' && targetFiles.length === 0) {
    console.error(
      'Usage: agent-stability-audit.ts --files <path...> | --dir <dir...> [--lang=rust,go,ts,c,cpp] [--exclude-tests] | --diff [--staged] [--json|--sarif|--agent-feedback]',
    );
    process.exit(2);
  }

  const reports: FileAgingAuditReport[] = [];
  for (const file of targetFiles) {
    if (!existsSync(file)) {
      console.error(`File not found: ${file}`);
      process.exit(2);
    }
    const rep = auditFileForAging(file, readFileSync(file, 'utf8'));
    if (rep) reports.push(rep);
  }

  if (opts.format === 'json') {
    console.log(JSON.stringify({reports}, null, 2));
  } else if (opts.format === 'sarif') {
    console.log(JSON.stringify(formatAgingSarif(reports), null, 2));
  } else if (opts.format === 'agent-feedback') {
    console.log(JSON.stringify(formatAgingRepairPacket(reports), null, 2));
  } else {
    console.log(formatText(reports));
  }

  const anyFailed = reports.some((r) => !r.passed);
  process.exit(anyFailed ? 1 : 0);
}

main();
