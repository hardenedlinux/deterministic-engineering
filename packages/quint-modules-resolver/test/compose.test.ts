// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

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

test('pure .qnt structural AST compose extends upstream model without JSON IR or Scheme', async () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-ast-compose-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');

    // 1. Package manager commands: list and verify-deps (pure .qnt, no prototype.json).
    const listed = run(['bun', cliPath, 'list'], work);
    expect(listed.exitCode).toBe(0);
    expect(listed.stdout).toContain('@deterministic-engineering/quint-models/threat/oauth-token-lifecycle/OAuthTokenLifecycle');

    const verified = run(['bun', cliPath, 'verify-deps'], work);
    expect(verified.exitCode).toBe(0);
    expect(verified.stdout).toContain('DEPS-OK');

    // 2. Pure .qnt overlay extending upstream OAuthTokenLifecycle.qnt via structural AST merge.
    const baseSpec = '@deterministic-engineering/quint-models/threat/oauth-token-lifecycle/OAuthTokenLifecycle';
    const overlayPath = join(work, 'ConsumerAuthOverlay.qnt');
    const outQnt = join(work, 'ConsumerAuthComposed.qnt');
    const outPlan = join(work, 'plan.json');
    writeFileSync(
      overlayPath,
      [
        'module consumer_auth_composed {',
        '  type State = { cedarPolicyEpoch: int }',
        "  action init = h' = { cedarPolicyEpoch: 1 }",
        '  action bumpCedarPolicy = if (h.cedarPolicyEpoch < 3) h\' = h.with("cedarPolicyEpoch", h.cedarPolicyEpoch + 1) else h\' = h',
        '  action step = any { bumpCedarPolicy }',
        '  val safety = h.cedarPolicyEpoch >= 1',
        '  run consumerCedarPolicyTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(bumpCedarPolicy).then(all { assert(h.cedarPolicyEpoch == 2), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );

    const comp = run(['bun', cliPath, 'compose', baseSpec, overlayPath, `--out=${outQnt}`, `--plan=${outPlan}`], work);
    expect(comp.exitCode).toBe(0);
    expect(comp.stdout).toContain('COMPOSE-OK consumer_auth_composed');

    const tc = run(['bun', cliPath, 'typecheck', outQnt], work);
    expect(tc.exitCode).toBe(0);

    const tst = run(
      ['bun', cliPath, 'test', outQnt, '--main=consumer_auth_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(tst.exitCode).toBe(0);
    expect(tst.stdout + tst.stderr).toContain('6 passing');

    // 3. Negative control: State field type conflict must refuse.
    const badTypeOverlay = join(work, 'BadTypeOverlay.qnt');
    writeFileSync(
      badTypeOverlay,
      [
        'module bad_type_composed {',
        '  type State = { authEpoch: bool }',
        "  action init = h' = { authEpoch: false }",
        '}',
      ].join('\n'),
    );
    const badType = run(['bun', cliPath, 'compose', baseSpec, badTypeOverlay, `--out=${join(work, 'BadType.qnt')}`], work);
    expect(badType.exitCode).not.toBe(0);
    expect(badType.stderr + badType.stdout).toContain('type conflict');

    // 4. Negative control: new State field without init initializer must refuse.
    const badInitOverlay = join(work, 'BadInitOverlay.qnt');
    writeFileSync(
      badInitOverlay,
      [
        'module bad_init_composed {',
        '  type State = { extraFlag: bool }',
        '}',
      ].join('\n'),
    );
    const badInit = run(['bun', cliPath, 'compose', baseSpec, badInitOverlay, `--out=${join(work, 'BadInit.qnt')}`], work);
    expect(badInit.exitCode).not.toBe(0);
    expect(badInit.stderr + badInit.stdout).toContain("defines no 'action init'");

    // 5. Negative control: colliding non-mergeable action name must refuse.
    const badCollideOverlay = join(work, 'BadCollideOverlay.qnt');
    writeFileSync(
      badCollideOverlay,
      [
        'module bad_collide_composed {',
        "  action beginOAuth = h' = h",
        '}',
      ].join('\n'),
    );
    const badCollide = run(['bun', cliPath, 'compose', baseSpec, badCollideOverlay, `--out=${join(work, 'BadCollide.qnt')}`], work);
    expect(badCollide.exitCode).not.toBe(0);
    expect(badCollide.stderr + badCollide.stdout).toContain('redeclares non-mergeable symbol');

    // 6. MBT simulator run with --mbt --out-itf emits mbt::actionTaken and mbt::nondetPicks.
    const itfOut = join(work, 'oauth-mbt.itf.json');
    const sim = run(
      [
        'bun',
        cliPath,
        'run',
        outQnt,
        '--main=consumer_auth_composed',
        '--invariant=safety',
        '--max-steps=8',
        '--max-samples=5',
        '--n-traces=1',
        '--seed=7',
        '--mbt',
        `--out-itf=${itfOut}`,
      ],
      work,
    );
    expect(sim.exitCode).toBe(0);
    const itfRaw = JSON.parse(Bun.file(itfOut).text ? await Bun.file(itfOut).text() : '{}');
    expect(Array.isArray(itfRaw.states)).toBe(true);
    expect(itfRaw.states.length).toBeGreaterThan(1);
    expect(itfRaw.vars).toContain('mbt::actionTaken');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 45000);
