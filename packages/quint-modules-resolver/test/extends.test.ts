// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {type MbtAuditReport} from '../src/mbt.ts';

const pkgRoot = resolve(import.meta.dir, '..');
const repoRoot = resolve(pkgRoot, '../..');
const cliPath = join(pkgRoot, 'src/cli.ts');
const modelsRoot = join(repoRoot, 'packages/quint-models');

function run(cmd: string[], cwd: string) {
  const proc = Bun.spawnSync(cmd, {cwd, stdout: 'pipe', stderr: 'pipe'});
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

test('transparent @quint-extends runs typecheck, test, mbt-audit, expand, and live Apalache run-plan with zero temp files', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-extends-oauth-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');

    const derivedPath = join(work, 'PolicyGuardedOAuth.qnt');
    writeFileSync(
      derivedPath,
      [
        '// @quint-model consumer.auth.policy-guarded-oauth',
        '// @quint-extends "@deterministic-engineering/quint-models/threat/identity/oauth-token-lifecycle/OAuthTokenLifecycle"',
        '// @verify safety max-steps=6',
        'module policy_guarded_oauth {',
        '  type State = { policyEpoch: int }',
        "  action init = h' = { policyEpoch: 1 }",
        '  action bumpPolicy = if (h.policyEpoch < 3) h\' = h.with("policyEpoch", h.policyEpoch + 1) else h\' = h',
        '  action step = any { bumpPolicy }',
        '  val safety = h.policyEpoch >= 1 and h.policyEpoch <= 3',
        '  run consumerPolicyTraceTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(bumpPolicy).then(all { assert(h.policyEpoch == 2), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );

    const tc = run(['bun', cliPath, 'typecheck', derivedPath], work);
    expect(tc.exitCode).toBe(0);

    const tst = run(
      ['bun', cliPath, 'test', derivedPath, '--main=policy_guarded_oauth', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(tst.exitCode).toBe(0);
    // 5 inherited OAuth tests + 1 child policy test = 6 passing.
    expect(tst.stdout + tst.stderr).toContain('6 passing');

    const mbt = run(
      ['bun', cliPath, 'mbt-audit', derivedPath, '--n-traces=10', '--max-steps=10', '--seed=7', '--min-coverage=0.8', '--json'],
      work,
    );
    expect(mbt.exitCode).toBe(0);
    const mbtReport = JSON.parse(mbt.stdout) as MbtAuditReport;
    expect(mbtReport.passed).toBe(true);
    expect(mbtReport.declaredStepActions).toContain('bumpPolicy');
    expect(mbtReport.declaredStepActions).toContain('beginOAuth');

    // Live Apalache run-plan proves strengthened safety + all 3 inherited OAuth countermodels!
    const plan = run(['bun', cliPath, 'run-plan', derivedPath, '--verify'], work);
    expect(plan.exitCode).toBe(0);
    expect(plan.stdout).toContain('PLAN-OK');
    expect(plan.stdout).toContain('passed=6, skipped=0, verify=true');

    // Optional `expand --out` materializes the canonical expanded pure Quint.
    const expandedOut = join(work, 'PolicyGuardedOAuthExpanded.qnt');
    const exp = run(['bun', cliPath, 'expand', derivedPath, `--out=${expandedOut}`], work);
    expect(exp.exitCode).toBe(0);
    expect(exp.stdout).toContain('EXPAND-OK policy_guarded_oauth');
    expect(readFileSync(expandedOut, 'utf8')).toContain('// Extended from: policy_guarded_oauth -> oauth_token_lifecycle');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 180000);

test('transparent @quint-extends + @quint-const specializes StateRollback (MaxSends=1) and runs live Apalache run-plan', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-extends-const-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');

    const hostPath = join(work, 'SingleEmitHost.qnt');
    writeFileSync(
      hostPath,
      [
        '// @quint-extends "@deterministic-engineering/quint-models/threat/execution/state-rollback/StateRollback"',
        '// @quint-const MaxSends=1',
        '// @verify safety max-steps=6',
        'module single_emit_host {',
        '  type State = { audited: bool }',
        "  action init = h' = { audited: true }",
        '  val safety = h.audited',
        '  run auditedEmitTest = init.then(prepare).then(commitAs(true)).then(emit).then(all { assert(h.audited), assert(h.sent == 1), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );

    const plan = run(['bun', cliPath, 'run-plan', hostPath, '--verify'], work);
    expect(plan.exitCode).toBe(0);
    expect(plan.stdout).toContain('PLAN-OK');
    // typecheck + traces + safety + inherited stepNoDurability + inherited stepRollback = 5!
    expect(plan.stdout).toContain('passed=5, skipped=0, verify=true');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 120000);

test('linear 2-level @quint-extends chain and transitive import expand seamlessly in packageSourceResolver', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-extends-chain-'));
  try {
    writeFileSync(
      join(work, 'Base.qnt'),
      [
        'module base_mod {',
        '  type State = { a: int }',
        '  var h: State',
        "  action init = h' = { a: 0 }",
        '  action incA = if (h.a < 2) h\' = h.with("a", h.a + 1) else h\' = h',
        '  action step = any { incA }',
        '  val safety = h.a <= 2',
        '}',
        '',
      ].join('\n'),
    );
    writeFileSync(
      join(work, 'Mid.qnt'),
      [
        '// @quint-extends "./Base"',
        'module mid_mod {',
        '  type State = { b: int }',
        "  action init = h' = { b: 1 }",
        '  action incB = if (h.b < 3) h\' = h.with("b", h.b + 1) else h\' = h',
        '  action step = any { incB }',
        '  val safety = h.b <= 3',
        '}',
        '',
      ].join('\n'),
    );
    const leafPath = join(work, 'Leaf.qnt');
    writeFileSync(
      leafPath,
      [
        '// @quint-extends "./Mid"',
        'module leaf_mod {',
        '  type State = { c: bool }',
        "  action init = h' = { c: true }",
        '  val safety = h.c',
        '  run chainTest = init.then(incA).then(incB).then(all { assert(h.a == 1), assert(h.b == 2), assert(h.c), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );
    const consumerPath = join(work, 'Consumer.qnt');
    writeFileSync(
      consumerPath,
      [
        'module consumer_mod {',
        '  import leaf_mod.* from "./Leaf"',
        '  run importedChainTest = chainTest',
        '}',
        '',
      ].join('\n'),
    );

    const tst = run(
      ['bun', cliPath, 'test', consumerPath, '--main=consumer_mod', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(tst.exitCode).toBe(0);
    // Both imported `chainTest` and local `importedChainTest` pass.
    expect(tst.stdout + tst.stderr).toContain('2 passing');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 45000);

test('Option A negative controls fail closed on multi-parent @quint-extends, cycles, and unknown @quint-const', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-extends-neg-'));
  try {
    writeFileSync(join(work, 'P1.qnt'), 'module p1 { val v1 = 1 }\n');
    writeFileSync(join(work, 'P2.qnt'), 'module p2 { val v2 = 2 }\n');
    writeFileSync(
      join(work, 'Multi.qnt'),
      '// @quint-extends "./P1"\n// @quint-extends "./P2"\nmodule multi { val v3 = 3 }\n',
    );
    const multi = run(['bun', cliPath, 'expand', join(work, 'Multi.qnt')], work);
    expect(multi.exitCode).not.toBe(0);
    expect(multi.stderr + multi.stdout).toContain('only single-parent extension is supported');

    writeFileSync(join(work, 'CycA.qnt'), '// @quint-extends "./CycB"\nmodule cyc_a { val a = 1 }\n');
    writeFileSync(join(work, 'CycB.qnt'), '// @quint-extends "./CycA"\nmodule cyc_b { val b = 2 }\n');
    const cyc = run(['bun', cliPath, 'expand', join(work, 'CycA.qnt')], work);
    expect(cyc.exitCode).not.toBe(0);
    expect(cyc.stderr + cyc.stdout).toContain('Cycle detected');

    writeFileSync(
      join(work, 'BadConst.qnt'),
      '// @quint-extends "./P1"\n// @quint-const NoSuchConst=1\nmodule bad_const { val ok = true }\n',
    );
    const badConst = run(['bun', cliPath, 'expand', join(work, 'BadConst.qnt')], work);
    expect(badConst.exitCode).not.toBe(0);
    expect(badConst.stderr + badConst.stdout).toContain('not a declared const');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 30000);
