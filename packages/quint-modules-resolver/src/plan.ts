// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {basename, dirname, join, resolve} from 'node:path';
import {newIdGenerator, parsePhase1fromText} from '@informalsystems/quint';
import {type ItfTrace, traceSatisfiesItfPredicate} from './itf.ts';

export interface PlanStep {
  label: string;
  command: string[];
  expectedExit: number;
  kind: 'typecheck' | 'deterministic-traces' | 'bounded-safety' | 'required-countermodel';
  droppedGuard?: string;
  expectedItfPredicate?: string;
}

export interface QuintPlan {
  module: string;
  file: string;
  quintVersion: string;
  apalacheVersion: string;
  seed: number;
  positiveDepth: number;
  negativeDepth: number;
  timeout: number;
  steps: PlanStep[];
}

export interface PlanRunOptions {
  verify?: boolean;
  cliPath?: string;
}

export interface QntHeaderDirectives {
  modelIdentity?: string;
  quintVersion: string;
  apalacheVersion: string;
  verify?: {invariant: string; maxSteps: number};
  countermodels: Array<{
    droppedGuard: string;
    stepAction: string;
    maxSteps: number;
    expectedItfPredicate?: string;
  }>;
}

export function parseQntHeaderDirectives(source: string): QntHeaderDirectives {
  const result: QntHeaderDirectives = {
    quintVersion: '0.33.0',
    apalacheVersion: '0.62.1',
    countermodels: [],
  };
  for (const rawLine of source.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('//')) {
      if (line.startsWith('module ')) break;
      continue;
    }
    const modelMatch = line.match(/^\/\/\s*@quint-model\s+(\S+)/);
    if (modelMatch) {
      result.modelIdentity = modelMatch[1];
      continue;
    }
    const verMatch = line.match(/^\/\/\s*@quint-version\s+(\S+)/);
    if (verMatch) {
      result.quintVersion = verMatch[1]!;
      continue;
    }
    const apaMatch = line.match(/^\/\/\s*@apalache-version\s+(\S+)/);
    if (apaMatch) {
      result.apalacheVersion = apaMatch[1]!;
      continue;
    }
    const verifyMatch = line.match(/^\/\/\s*@verify\s+(\S+)(?:\s+max-steps=(\d+))?/);
    if (verifyMatch) {
      result.verify = {
        invariant: verifyMatch[1]!,
        maxSteps: verifyMatch[2] ? Number(verifyMatch[2]) : 12,
      };
      continue;
    }
    const cmMatch = line.match(
      /^\/\/\s*@countermodel\s+(\S+)\s+step=(\S+)(?:\s+max-steps=(\d+))?(?:\s+itf="([^"]*)")?/,
    );
    if (cmMatch) {
      result.countermodels.push({
        droppedGuard: cmMatch[1]!,
        stepAction: cmMatch[2]!,
        maxSteps: cmMatch[3] ? Number(cmMatch[3]) : 6,
        expectedItfPredicate: cmMatch[4],
      });
    }
  }
  return result;
}

export function parsePlanFromQnt(qntPath: string): QuintPlan {
  const fullPath = resolve(process.cwd(), qntPath);
  const source = readFileSync(fullPath, 'utf8');
  const fileName = basename(fullPath);
  const directives = parseQntHeaderDirectives(source);

  const parsed = parsePhase1fromText(newIdGenerator(), source, fullPath);
  if (parsed.errors.length > 0 || parsed.modules.length === 0) {
    throw new Error(`Failed to parse Quint module '${fullPath}' while building plan`);
  }
  const mod = parsed.modules[0]!;
  const hasRuns = mod.declarations.some(d => d.kind === 'def' && d.qualifier === 'run');
  const steps: PlanStep[] = [
    {label: 'typecheck', command: ['typecheck', fileName], expectedExit: 0, kind: 'typecheck'},
  ];
  if (hasRuns) {
    steps.push({
      label: 'traces',
      command: ['test', fileName, `--main=${mod.name}`, '--max-samples=1', '--seed=7', '--backend=typescript'],
      expectedExit: 0,
      kind: 'deterministic-traces',
    });
  }
  if (directives.verify) {
    steps.push({
      label: directives.verify.invariant,
      command: [
        'verify',
        fileName,
        `--main=${mod.name}`,
        `--invariant=${directives.verify.invariant}`,
        `--max-steps=${directives.verify.maxSteps}`,
      ],
      expectedExit: 0,
      kind: 'bounded-safety',
    });
  }
  for (const cm of directives.countermodels) {
    steps.push({
      label: `countermodel-${cm.droppedGuard}`,
      command: [
        'verify',
        fileName,
        `--main=${mod.name}`,
        `--step=${cm.stepAction}`,
        '--invariant=safety',
        `--max-steps=${cm.maxSteps}`,
      ],
      expectedExit: 1,
      kind: 'required-countermodel',
      droppedGuard: cm.droppedGuard,
      expectedItfPredicate: cm.expectedItfPredicate,
    });
  }
  return {
    module: mod.name,
    file: fileName,
    quintVersion: directives.quintVersion,
    apalacheVersion: directives.apalacheVersion,
    seed: 7,
    positiveDepth: directives.verify?.maxSteps ?? 12,
    negativeDepth: directives.countermodels[0]?.maxSteps ?? 6,
    timeout: 120,
    steps,
  };
}

function hasUnboundConst(qntPath: string): boolean {
  const source = readFileSync(qntPath, 'utf8');
  return /^\s*const\s+[A-Za-z0-9_]+\s*:/m.test(source);
}

export function executePlan(planOrQntPath: string, options: PlanRunOptions = {}): {passed: number; skipped: number} {
  const fullPath = resolve(process.cwd(), planOrQntPath);
  const planDir = dirname(fullPath);
  const plan = fullPath.endsWith('.qnt')
    ? parsePlanFromQnt(fullPath)
    : (JSON.parse(readFileSync(fullPath, 'utf8')) as QuintPlan);
  const qntPath = fullPath.endsWith('.qnt') ? fullPath : join(planDir, plan.file);
  const parameterized = hasUnboundConst(qntPath);
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');

  let passed = 0;
  let skipped = 0;
  const workDir = mkdtempSync(join(tmpdir(), 'qmr-plan-'));
  try {
    for (const step of plan.steps) {
      const isVerify = step.kind === 'bounded-safety' || step.kind === 'required-countermodel';
      if (isVerify && !options.verify) {
        skipped++;
        continue;
      }
      if (parameterized && step.kind !== 'typecheck') {
        skipped++;
        continue;
      }

      const cmdArgs = step.command.map((token, idx) => (idx === 1 ? qntPath : token));
      let itfOut: string | undefined;
      if (isVerify) {
        cmdArgs.push('--backend=apalache', `--apalache-version=${plan.apalacheVersion}`);
      }
      if (step.kind === 'required-countermodel') {
        itfOut = join(workDir, `${step.label}.itf.json`);
        cmdArgs.push(`--out-itf=${itfOut}`);
      }

      const proc = Bun.spawnSync(['bun', cliPath, ...cmdArgs], {
        cwd: workDir,
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: plan.timeout * 1000,
      });

      if (proc.exitCode !== step.expectedExit) {
        const out = proc.stdout.toString() + proc.stderr.toString();
        throw new Error(
          `Plan step '${step.label}' (${plan.module}) exited ${proc.exitCode}, expected ${step.expectedExit}:\n${out}`,
        );
      }
      if (itfOut) {
        if (!existsSync(itfOut)) {
          throw new Error(`Countermodel step '${step.label}' did not emit ITF file: ${itfOut}`);
        }
        const itf = JSON.parse(readFileSync(itfOut, 'utf8')) as ItfTrace;
        if (!Array.isArray(itf.vars) || itf.vars.length === 0 || !Array.isArray(itf.states) || itf.states.length === 0) {
          throw new Error(`Countermodel step '${step.label}' emitted empty ITF trace`);
        }
        if (step.expectedItfPredicate && !traceSatisfiesItfPredicate(itf, step.expectedItfPredicate)) {
          throw new Error(
            `Countermodel step '${step.label}' ITF trace did not satisfy expected predicate: ${step.expectedItfPredicate}`,
          );
        }
      }
      passed++;
    }
  } finally {
    rmSync(workDir, {recursive: true, force: true});
  }
  return {passed, skipped};
}
