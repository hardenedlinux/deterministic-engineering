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

test('downstream POO compose extends upstream prototype.json without Scheme and runs traces', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-poo-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');

    // 1. Package manager commands: list and verify-deps.
    const listed = run(['bun', cliPath, 'list'], work);
    expect(listed.exitCode).toBe(0);
    expect(listed.stdout).toContain('@deterministic-engineering/quint-models/threat/oauth-token-lifecycle/OAuthTokenLifecycle');
    expect(listed.stdout).toContain('[POO]');

    const verified = run(['bun', cliPath, 'verify-deps'], work);
    expect(verified.exitCode).toBe(0);
    expect(verified.stdout).toContain('DEPS-OK');

    // 2. Downstream POO overlay extending oauth-token-lifecycle without installing Scheme.
    const overlayPath = join(work, 'marlin-auth.proto.json');
    const outQnt = join(work, 'MarlinAuthComposed.qnt');
    const outPlan = join(work, 'plan.json');
    writeFileSync(
      overlayPath,
      JSON.stringify(
        {
          extends: '@deterministic-engineering/quint-models/threat/oauth-token-lifecycle/prototype.json',
          identity: 'downstream.marlin-auth',
          module: 'marlin_auth_composed',
          addState: [['cedarPolicyEpoch', 'int', '1']],
          addGuards: [['cedar-policy-active', 'h.cedarPolicyEpoch >= 1']],
          addTransitions: [
            [
              'bumpCedarPolicy',
              'action bumpCedarPolicy = if (h.cedarPolicyEpoch < 3) h\' = h.with("cedarPolicyEpoch", h.cedarPolicyEpoch + 1) else h\' = h',
            ],
          ],
          addStepActions: ['bumpCedarPolicy'],
          strengthenSafety: 'h.cedarPolicyEpoch >= 1',
          addTraces: [
            [
              'marlinCedarPolicyTest',
              'run marlinCedarPolicyTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(bumpCedarPolicy).then(all { assert(h.cedarPolicyEpoch == 2), assert(safety), h\' = h })',
            ],
          ],
        },
        null,
        2,
      ),
    );

    const comp = run(['bun', cliPath, 'compose', overlayPath, `--out=${outQnt}`, `--plan=${outPlan}`], work);
    expect(comp.exitCode).toBe(0);
    expect(comp.stdout).toContain('COMPOSE-OK downstream.marlin-auth');

    const tc = run(['bun', cliPath, 'typecheck', outQnt], work);
    expect(tc.exitCode).toBe(0);

    const tst = run(
      ['bun', cliPath, 'test', outQnt, '--main=marlin_auth_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(tst.exitCode).toBe(0);
    expect(tst.stdout + tst.stderr).toContain('6 passing');

    // 3. Negative control: undeclared droppedGuard in overlay countermodel must refuse.
    const badOverlay = join(work, 'bad.proto.json');
    writeFileSync(
      badOverlay,
      JSON.stringify({
        extends: '@deterministic-engineering/quint-models/threat/oauth-token-lifecycle/prototype.json',
        module: 'bad_composed',
        addCountermodels: [
          {
            identity: 'bad.cm',
            droppedGuard: 'nonexistent-guard',
            stepAction: 'stepBad',
            counterAction: 'action stepBad = step',
            expectedItfPredicate: 'h.unsafe == true',
          },
        ],
      }),
    );
    const badRes = run(['bun', cliPath, 'compose', badOverlay, `--out=${join(work, 'Bad.qnt')}`], work);
    expect(badRes.exitCode).not.toBe(0);
    expect(badRes.stderr + badRes.stdout).toContain('undeclared droppedGuard');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 45000);
