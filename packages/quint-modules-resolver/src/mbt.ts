// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {
  newIdGenerator,
  parsePhase1fromText,
  type QuintEx,
  type QuintModule,
} from '@informalsystems/quint';
import {parseQntHeaderDirectives} from './plan.ts';
import {expandExtendedQntFile} from './compose.ts';

export interface MbtAuditOptions {
  main?: string;
  invariant?: string;
  nTraces?: number;
  maxSteps?: number;
  seed?: string;
  minCoverage?: number;
  cliPath?: string;
  timeoutMs?: number;
}

export interface MbtAuditReport {
  file: string;
  module: string;
  modelIdentity?: string;
  tracesGenerated: number;
  totalTransitions: number;
  uniqueStates: number;
  declaredStepActions: string[];
  coveredActions: string[];
  uncoveredActions: string[];
  actionCounts: Record<string, number>;
  actionCoverage: number;
  minCoverage: number;
  passed: boolean;
}

export interface FleetOptions {
  domain?: string;
  subdomain?: string;
  verify?: boolean;
  concurrency?: number;
  cliPath?: string;
}

export interface FleetModelResult {
  file: string;
  modelIdentity?: string;
  passed: boolean;
  durationMs: number;
  output: string;
}

export interface FleetReport {
  root: string;
  verify: boolean;
  concurrency: number;
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
  results: FleetModelResult[];
}

function collectActionRefs(ex: QuintEx, declaredActions: Set<string>, out: Set<string>): void {
  if (ex.kind === 'name') {
    if (declaredActions.has(ex.name)) {
      out.add(ex.name);
    }
    return;
  }
  if (ex.kind === 'app') {
    if (declaredActions.has(ex.opcode)) {
      out.add(ex.opcode);
    }
    for (const arg of ex.args) {
      collectActionRefs(arg, declaredActions, out);
    }
    return;
  }
  if (ex.kind === 'let') {
    collectActionRefs(ex.opdef.expr, declaredActions, out);
    collectActionRefs(ex.expr, declaredActions, out);
    return;
  }
  if (ex.kind === 'lambda') {
    collectActionRefs(ex.expr, declaredActions, out);
  }
}

export function extractDeclaredStepActions(mod: QuintModule, stepName: string = 'step'): string[] {
  const declaredActions = new Set<string>();
  let stepExpr: QuintEx | undefined;
  for (const decl of mod.declarations) {
    if (decl.kind === 'def' && decl.qualifier === 'action') {
      declaredActions.add(decl.name);
      if (decl.name === stepName) {
        stepExpr = decl.expr;
      }
    }
  }
  if (!stepExpr) return [];
  const referenced = new Set<string>();
  collectActionRefs(stepExpr, declaredActions, referenced);
  return [...referenced].sort();
}

export function auditMbtCoverage(qntPath: string, options: MbtAuditOptions = {}): MbtAuditReport {
  const fullPath = resolve(process.cwd(), qntPath);
  const source = expandExtendedQntFile(fullPath).expandedText;
  const directives = parseQntHeaderDirectives(source);
  const parsed = parsePhase1fromText(newIdGenerator(), source, fullPath);
  if (parsed.errors.length > 0 || parsed.modules.length === 0) {
    throw new Error(`Failed to parse Quint module '${fullPath}' for MBT audit`);
  }
  const mod = options.main
    ? parsed.modules.find(m => m.name === options.main)
    : parsed.modules[0];
  if (!mod) {
    throw new Error(`Module '${options.main}' not found in '${fullPath}'`);
  }

  const declaredStepActions = extractDeclaredStepActions(mod, 'step');
  if (declaredStepActions.length === 0) {
    throw new Error(`Module '${mod.name}' in '${fullPath}' declares no step actions for MBT audit`);
  }

  const nTraces = options.nTraces ?? 10;
  const maxSteps = options.maxSteps ?? directives.verify?.maxSteps ?? 12;
  const seed = options.seed ?? '7';
  const invariant = options.invariant ?? directives.verify?.invariant ?? 'safety';
  const minCoverage = options.minCoverage ?? 0.5;
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');
  const timeoutMs = options.timeoutMs ?? 120_000;

  const workDir = mkdtempSync(join(tmpdir(), 'qmr-mbt-audit-'));
  try {
    const outItf = join(workDir, 'trace.itf.json');
    const proc = Bun.spawnSync(
      [
        'bun',
        cliPath,
        'run',
        fullPath,
        `--main=${mod.name}`,
        `--invariant=${invariant}`,
        '--mbt',
        `--n-traces=${nTraces}`,
        `--max-steps=${maxSteps}`,
        `--seed=${seed}`,
        `--out-itf=${outItf}`,
      ],
      {
        cwd: workDir,
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: timeoutMs,
      },
    );
    if (proc.exitCode !== 0) {
      const output = proc.stdout.toString() + proc.stderr.toString();
      throw new Error(`MBT simulation failed for '${mod.name}' (exit ${proc.exitCode}):\n${output}`);
    }

    const itfFiles = readdirSync(workDir)
      .filter(f => f.endsWith('.itf.json'))
      .sort()
      .map(f => join(workDir, f));
    if (itfFiles.length === 0) {
      throw new Error(`MBT simulation for '${mod.name}' produced zero ITF traces`);
    }

    const actionCounts: Record<string, number> = {};
    const stateDigests = new Set<string>();
    let totalTransitions = 0;

    for (const file of itfFiles) {
      const trace = JSON.parse(readFileSync(file, 'utf8')) as {
        states?: Array<Record<string, unknown>>;
      };
      const states = trace.states ?? [];
      for (let i = 0; i < states.length; i++) {
        const st = states[i]!;
        const domainState: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(st)) {
          if (!k.startsWith('mbt::') && k !== '#meta') {
            domainState[k] = v;
          }
        }
        stateDigests.add(JSON.stringify(domainState));
        if (i === 0) continue;
        totalTransitions++;
        const actionTaken = st['mbt::actionTaken'];
        if (typeof actionTaken === 'string' && actionTaken.length > 0) {
          actionCounts[actionTaken] = (actionCounts[actionTaken] ?? 0) + 1;
        }
      }
    }

    const coveredActions = declaredStepActions.filter(a => (actionCounts[a] ?? 0) > 0);
    const uncoveredActions = declaredStepActions.filter(a => (actionCounts[a] ?? 0) === 0);
    const actionCoverage = declaredStepActions.length === 0
      ? 1
      : coveredActions.length / declaredStepActions.length;
    const passed = actionCoverage + 1e-9 >= minCoverage;

    return {
      file: fullPath,
      module: mod.name,
      modelIdentity: directives.modelIdentity,
      tracesGenerated: itfFiles.length,
      totalTransitions,
      uniqueStates: stateDigests.size,
      declaredStepActions,
      coveredActions,
      uncoveredActions,
      actionCounts,
      actionCoverage,
      minCoverage,
      passed,
    };
  } finally {
    rmSync(workDir, {recursive: true, force: true});
  }
}

function walkQntUnder(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...walkQntUnder(full));
    } else if (entry.name.endsWith('.qnt')) {
      found.push(full);
    }
  }
  return found.sort();
}

export async function runFleetPlans(rootDir: string, options: FleetOptions = {}): Promise<FleetReport> {
  const absRoot = resolve(process.cwd(), rootDir);
  const verify = options.verify ?? false;
  const concurrency = Math.max(1, options.concurrency ?? 4);
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');

  const allFiles = walkQntUnder(absRoot).filter(file => {
    const rel = relative(absRoot, file).replaceAll('\\', '/');
    const parts = rel.split('/');
    if (options.domain && !parts.includes(options.domain)) return false;
    if (options.subdomain && !parts.includes(options.subdomain)) return false;
    return true;
  });

  const startedAt = Date.now();
  const results: FleetModelResult[] = new Array(allFiles.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (true) {
      const idx = cursor++;
      if (idx >= allFiles.length) return;
      const file = allFiles[idx]!;
      const directives = parseQntHeaderDirectives(readFileSync(file, 'utf8'));
      const t0 = Date.now();
      const args = ['bun', cliPath, 'run-plan', file];
      if (verify) args.push('--verify');
      const proc = Bun.spawn(args, {
        cwd: process.cwd(),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);
      results[idx] = {
        file: relative(absRoot, file).replaceAll('\\', '/'),
        modelIdentity: directives.modelIdentity,
        passed: exitCode === 0,
        durationMs: Date.now() - t0,
        output: (stdout + stderr).trim(),
      };
    }
  }

  await Promise.all(
    Array.from({length: Math.min(concurrency, Math.max(1, allFiles.length))}, () => worker()),
  );

  const passed = results.filter(r => r.passed).length;
  const failed = results.length - passed;
  return {
    root: absRoot,
    verify,
    concurrency,
    total: results.length,
    passed,
    failed,
    durationMs: Date.now() - startedAt,
    results,
  };
}
