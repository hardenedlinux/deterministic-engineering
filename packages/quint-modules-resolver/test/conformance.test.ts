// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const pkgRoot = resolve(import.meta.dir, '..');
const repoRoot = resolve(pkgRoot, '../..');
const cliPath = join(pkgRoot, 'src/cli.ts');
const nativeQuint = join(pkgRoot, 'node_modules/.bin/quint');
const modelsRoot = join(repoRoot, 'packages/quint-models');

function walkFiles(dir: string, predicate: (name: string) => boolean): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...walkFiles(full, predicate));
    } else if (predicate(entry.name)) {
      found.push(full);
    }
  }
  return found.sort();
}

function run(cmd: string[], cwd: string) {
  const proc = Bun.spawnSync(cmd, {cwd, stdout: 'pipe', stderr: 'pipe'});
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

test('bare package specifier import typechecks and runs all 9 traces while native quint rejects', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-case-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');
    const caseFile = join(work, 'wallet_host_case.qnt');
    writeFileSync(
      caseFile,
      [
        'module wallet_host_case {',
        '  import state_rollback(MaxSends = 1).* from "@deterministic-engineering/quint-models/threat/state-rollback/StateRollback"',
        '}',
        '',
      ].join('\n'),
    );
    const tc = run(['bun', cliPath, 'typecheck', caseFile], work);
    expect(tc.exitCode).toBe(0);

    const tst = run(
      ['bun', cliPath, 'test', caseFile, '--main=wallet_host_case', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(tst.exitCode).toBe(0);
    expect(tst.stdout + tst.stderr).toContain('9 passing');

    // Control: native quint cannot resolve bare package specifiers.
    const nat = run([nativeQuint, 'typecheck', caseFile], work);
    expect(nat.exitCode).not.toBe(0);
    expect(nat.stdout + nat.stderr).toContain('QNT013');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 30000);

test('conformance: relative-only models match native quint exit code and pass count', () => {
  const targets = [
    {file: join(modelsRoot, 'threat/capabilities/Capabilities.qnt'), main: 'threat_capabilities', expected: '1 passing'},
    {file: join(modelsRoot, 'threat/authority-currentness/AuthorityCurrentness.qnt'), main: 'authority_currentness', expected: '1 passing'},
  ];
  for (const t of targets) {
    const resTc = run(['bun', cliPath, 'typecheck', t.file], repoRoot);
    const natTc = run([nativeQuint, 'typecheck', t.file], repoRoot);
    expect(resTc.exitCode).toBe(0);
    expect(resTc.exitCode).toBe(natTc.exitCode);

    const resTest = run(['bun', cliPath, 'test', t.file, `--main=${t.main}`, '--max-samples=1', '--seed=7', '--backend=typescript'], repoRoot);
    const natTest = run([nativeQuint, 'test', t.file, `--main=${t.main}`, '--max-samples=1', '--seed=7', '--backend=typescript'], repoRoot);
    expect(resTest.exitCode).toBe(0);
    expect(resTest.exitCode).toBe(natTest.exitCode);
    expect(resTest.stdout + resTest.stderr).toContain(t.expected);
    expect(natTest.stdout + natTest.stderr).toContain(t.expected);
  }
}, 30000);

test('all projected pure .qnt models in packages/quint-models pass run-plan with zero JSON sidecars', () => {
  const qntFiles = walkFiles(modelsRoot, name => name.endsWith('.qnt'));
  const planFiles = walkFiles(modelsRoot, name => name === 'plan.json');
  const receipts = walkFiles(modelsRoot, name => name === 'receipt.json');
  expect(qntFiles.length).toBeGreaterThanOrEqual(20);
  expect(planFiles.length).toBe(0);
  expect(receipts.length).toBe(0);

  for (const qntPath of qntFiles) {
    const res = run(['bun', cliPath, 'run-plan', qntPath], repoRoot);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('PLAN-OK');
  }
  const ver = run(['bun', cliPath, '--version'], repoRoot);
  expect(ver.exitCode).toBe(0);
  expect(ver.stdout.trim()).toBe('0.33.0');
}, 300000);
