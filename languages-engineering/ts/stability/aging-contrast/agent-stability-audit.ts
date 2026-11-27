#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * `agent-stability-audit` CLI — Multi-Language AI Agent Software Aging Gate (SM2-SM5).
 *
 * Usage:
 *   bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts --files <path...> [--json|--sarif|--agent-feedback]
 *   bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts --diff [--staged] [--json|--sarif|--agent-feedback]
 *
 * Exit codes:
 *   0 -> Clean (0 software aging findings)
 *   1 -> Refused (1+ SM2-SM5 aging findings)
 *   2 -> Invalid CLI usage / unreadable input
 */

import {existsSync, readFileSync} from 'node:fs';
import {auditFileForAging, type FileAgingAuditReport} from './aging-ast-auditor.ts';
import {
  formatAgingRepairPacket,
  formatAgingSarif,
  getAgingRemediation,
} from './aging-governance-harness.ts';

interface CliOpts {
  mode: 'files' | 'diff';
  files: string[];
  staged: boolean;
  format: 'text' | 'json' | 'sarif' | 'agent-feedback';
}

function parseArgs(argv: string[]): CliOpts {
  const opts: CliOpts = {mode: 'files', files: [], staged: false, format: 'text'};
  for (const a of argv) {
    if (a === '--json') opts.format = 'json';
    else if (a === '--sarif') opts.format = 'sarif';
    else if (a === '--agent-feedback') opts.format = 'agent-feedback';
    else if (a === '--diff') opts.mode = 'diff';
    else if (a === '--staged') opts.staged = true;
    else if (a === '--files') opts.mode = 'files';
    else if (!a.startsWith('--')) opts.files.push(a);
  }
  return opts;
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
  const targetFiles = opts.mode === 'diff' ? collectDiffFiles(opts.staged) : opts.files;
  if (opts.mode === 'files' && targetFiles.length === 0) {
    console.error('Usage: agent-stability-audit.ts --files <path...> | --diff [--staged] [--json|--sarif|--agent-feedback]');
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
