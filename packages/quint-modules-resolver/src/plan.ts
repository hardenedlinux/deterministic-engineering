// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {createHash} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';

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

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function hasUnboundConst(qntPath: string): boolean {
  const source = readFileSync(qntPath, 'utf8');
  return /^\s*const\s+[A-Za-z0-9_]+\s*:/m.test(source);
}

export function verifyPlanReceipt(planDir: string): void {
  const receiptPath = join(planDir, 'receipt.json');
  if (!existsSync(receiptPath)) {
    throw new Error(`Missing sibling receipt.json in ${planDir}`);
  }
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8')) as {
    artifacts?: Record<string, string>;
  };
  for (const [rel, expected] of Object.entries(receipt.artifacts ?? {})) {
    const actual = sha256File(join(planDir, rel));
    if (actual !== expected) {
      throw new Error(`Stale artifact ${rel} in ${planDir}: ${actual} !== ${expected}`);
    }
  }
}

export function executePlan(planPath: string, options: PlanRunOptions = {}): {passed: number; skipped: number} {
  const fullPlanPath = resolve(process.cwd(), planPath);
  const planDir = dirname(fullPlanPath);
  verifyPlanReceipt(planDir);

  const plan = JSON.parse(readFileSync(fullPlanPath, 'utf8')) as QuintPlan;
  const qntPath = join(planDir, plan.file);
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
        const itf = JSON.parse(readFileSync(itfOut, 'utf8')) as {vars?: unknown[]; states?: unknown[]};
        if (!Array.isArray(itf.vars) || itf.vars.length === 0 || !Array.isArray(itf.states) || itf.states.length === 0) {
          throw new Error(`Countermodel step '${step.label}' emitted empty ITF trace`);
        }
      }
      passed++;
    }
  } finally {
    rmSync(workDir, {recursive: true, force: true});
  }
  return {passed, skipped};
}
