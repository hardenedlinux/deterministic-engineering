#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E3.3: `agent-defense-audit` CLI — AI Agent Patch / PR Defensive Hallucination Gate.
 *
 * Usage:
 *   bun languages-engineering/ts/defense/agent-audit/agent-defense-audit.ts --files <path...> [--json]
 *   bun languages-engineering/ts/defense/agent-audit/agent-defense-audit.ts --diff [--staged] [--json]
 *   bun languages-engineering/ts/defense/agent-audit/agent-defense-audit.ts --diff-file <patch> [--json]
 *   bun languages-engineering/ts/defense/agent-audit/agent-defense-audit.ts --probe-quint <file.qnt> --action=<name> --guard=<expr> [--max-steps=6] [--json]
 *
 * Exit codes:
 *   0 -> Clean (0 G2 hallucination findings; Quint guard-probe classified `essential` if invoked)
 *   1 -> Refused (G2 hallucination found, or Quint guard classified `redundant-or-under-modeled`)
 *   2 -> Invalid CLI usage / unreadable input
 */

import {existsSync, readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {
  auditSourceByPath,
  auditUnifiedDiff,
  parseUnifiedDiffHunks,
  type MultiLangAuditReport,
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
  mode: 'files' | 'diff' | 'diff-file' | 'probe-quint';
  files: string[];
  staged: boolean;
  diffFile?: string;
  scopeGlobs: string[];
  forbidGlobs: string[];
  quintFile?: string;
  quintAction?: string;
  quintGuard?: string;
  quintMaxSteps?: string;
  outputFormat: 'text' | 'json' | 'sarif' | 'agent-feedback';
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    mode: 'files',
    files: [],
    staged: false,
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
      opts.files.push(a);
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
    const repoRoot = resolve(dirname(new URL(import.meta.url).pathname), '../../../..');
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
    const diffReports = auditUnifiedDiff(diffText, relPath => {
      const full = resolve(process.cwd(), relPath);
      return existsSync(full) ? readFileSync(full, 'utf8') : null;
    });
    const touchedFiles = [...new Set(parseUnifiedDiffHunks(diffText).map(h => h.filePath))];
    const scopeReports =
      opts.scopeGlobs.length > 0 || opts.forbidGlobs.length > 0
        ? evaluateScopeFence(touchedFiles, {
            allowedPaths: opts.scopeGlobs.length > 0 ? opts.scopeGlobs : undefined,
            protectedGovernancePaths: opts.forbidGlobs.length > 0 ? opts.forbidGlobs : undefined,
          })
        : [];
    reports = [...scopeReports, ...diffReports];
  } else {
    if (opts.files.length === 0) {
      console.error('Usage: agent-defense-audit.ts --files <path...> | --diff [--staged] | --diff-file <patch> | --probe-quint ...');
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

main();
