// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E2.2: Automated Guard Necessity & Redundancy Probe (`guard-probe`).
 * Structurally locates a target action in a Quint module via Phase-1 AST,
 * prunes a specified guard expression inside that action (replacing it with `true`
 * or an explicit fallback expression), and invokes Apalache bounded verification:
 *   - Exit 1 (counterexample found) => `essential`
 *   - Exit 0 (safety still holds)   => `redundant-or-under-modeled`
 */

import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {basename, dirname, join, resolve} from 'node:path';
import {newIdGenerator, parsePhase1fromText} from '@informalsystems/quint';
import {expandExtendedQntFile} from './compose.ts';
import {parseQntHeaderDirectives} from './plan.ts';

export type GuardProbeClassification = 'essential' | 'redundant-or-under-modeled';

export interface GuardProbeOptions {
  action: string;
  guardExpr: string;
  fallbackExpr?: string;
  main?: string;
  invariant?: string;
  maxSteps?: number;
  cliPath?: string;
  timeoutMs?: number;
}

export interface GuardProbeReport {
  file: string;
  module: string;
  action: string;
  guardExpr: string;
  fallbackExpr: string;
  invariant: string;
  maxSteps: number;
  classification: GuardProbeClassification;
  counterexampleFound: boolean;
  durationMs: number;
}

export function probeGuardNecessity(qntPath: string, options: GuardProbeOptions): GuardProbeReport {
  const started = Date.now();
  const fullPath = resolve(process.cwd(), qntPath);
  const expanded = expandExtendedQntFile(fullPath).expandedText;
  const directives = parseQntHeaderDirectives(expanded);
  const parsed = parsePhase1fromText(newIdGenerator(), expanded, fullPath);
  if (parsed.errors.length > 0 || parsed.modules.length === 0) {
    throw new Error(`Failed to parse Quint module '${fullPath}' for guard-probe`);
  }
  const mod = options.main
    ? parsed.modules.find(m => m.name === options.main)
    : parsed.modules[0];
  if (!mod) {
    throw new Error(`Module '${options.main}' not found in '${fullPath}'`);
  }

  const targetDecl = mod.declarations.find(
    d => d.kind === 'def' && d.qualifier === 'action' && d.name === options.action,
  );
  if (!targetDecl || targetDecl.kind !== 'def') {
    throw new Error(`Action '${options.action}' not found in module '${mod.name}'`);
  }

  const loc = parsed.sourceMap.get(targetDecl.expr.id);
  if (!loc || !loc.end) {
    throw new Error(`Missing AST source span for action '${options.action}' body`);
  }

  const startIdx = loc.start.index;
  const endIdx = loc.end.index + 1;
  const actionSlice = expanded.slice(startIdx, endIdx);
  const guardPos = actionSlice.indexOf(options.guardExpr);
  if (guardPos < 0) {
    throw new Error(
      `Guard expression ${JSON.stringify(options.guardExpr)} not found inside action '${options.action}'`,
    );
  }

  const fallbackExpr = options.fallbackExpr ?? 'true';
  const prunedAction =
    actionSlice.slice(0, guardPos) +
    fallbackExpr +
    actionSlice.slice(guardPos + options.guardExpr.length);
  const prunedSource = expanded.slice(0, startIdx) + prunedAction + expanded.slice(endIdx);

  // Sanity-parse pruned source before invoking Apalache
  const reParsed = parsePhase1fromText(newIdGenerator(), prunedSource, fullPath);
  if (reParsed.errors.length > 0) {
    throw new Error(
      `Pruned module failed Phase-1 parse after replacing ${JSON.stringify(options.guardExpr)} with ${JSON.stringify(fallbackExpr)}`,
    );
  }

  const invariant = options.invariant ?? directives.verify?.invariant ?? 'safety';
  const maxSteps = options.maxSteps ?? directives.verify?.maxSteps ?? 6;
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');
  const timeoutMs = options.timeoutMs ?? 120_000;

  const tempDir = mkdtempSync(join(tmpdir(), 'qmr-guard-probe-'));
  const prunedFile = join(tempDir, basename(fullPath));
  writeFileSync(prunedFile, prunedSource, 'utf8');

  try {
    const proc = Bun.spawnSync(
      [
        'bun',
        cliPath,
        'verify',
        prunedFile,
        `--main=${mod.name}`,
        `--invariant=${invariant}`,
        `--max-steps=${maxSteps}`,
      ],
      {
        cwd: tempDir,
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: timeoutMs,
      },
    );

    if (proc.exitCode === 1) {
      return {
        file: fullPath,
        module: mod.name,
        action: options.action,
        guardExpr: options.guardExpr,
        fallbackExpr,
        invariant,
        maxSteps,
        classification: 'essential',
        counterexampleFound: true,
        durationMs: Date.now() - started,
      };
    }
    if (proc.exitCode === 0) {
      return {
        file: fullPath,
        module: mod.name,
        action: options.action,
        guardExpr: options.guardExpr,
        fallbackExpr,
        invariant,
        maxSteps,
        classification: 'redundant-or-under-modeled',
        counterexampleFound: false,
        durationMs: Date.now() - started,
      };
    }
    const out = proc.stdout.toString() + proc.stderr.toString();
    throw new Error(`guard-probe Apalache verify failed unexpectedly (exit=${proc.exitCode}):\n${out}`);
  } finally {
    rmSync(tempDir, {recursive: true, force: true});
  }
}
