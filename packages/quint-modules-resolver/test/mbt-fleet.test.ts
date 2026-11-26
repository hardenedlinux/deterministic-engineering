// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {auditMbtCoverage, type MbtAuditReport, type FleetReport} from '../src/mbt.ts';

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

test('mbt-audit extracts step actions from Quint AST and measures coverage on new consensus & threat models', () => {
  const targets = [
    join(modelsRoot, 'engineering/consensus/bft-quorum-lock/BftQuorumLock.qnt'),
    join(modelsRoot, 'threat/supply-chain/slsa-hermetic-provenance/SlsaHermeticProvenance.qnt'),
    join(modelsRoot, 'threat/protocol/mls-ratchet-pcs/MlsRatchetPcs.qnt'),
  ];
  for (const modelPath of targets) {
    const res = run(
      ['bun', cliPath, 'mbt-audit', modelPath, '--n-traces=12', '--max-steps=12', '--seed=7', '--min-coverage=0.8', '--json'],
      repoRoot,
    );
    expect(res.exitCode).toBe(0);
    const report = JSON.parse(res.stdout) as MbtAuditReport;
    expect(report.passed).toBe(true);
    expect(report.tracesGenerated).toBe(12);
    expect(report.declaredStepActions.length).toBeGreaterThanOrEqual(5);
    expect(report.actionCoverage).toBeGreaterThanOrEqual(0.8);
    expect(report.uniqueStates).toBeGreaterThan(2);
  }
}, 60000);

test('mbt-audit fails closed when min-coverage threshold rejects unreachable dead action', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-dead-mbt-'));
  try {
    const specFile = join(work, 'dead_action.qnt');
    writeFileSync(
      specFile,
      [
        'module dead_action {',
        '  var x: int',
        '  action init = x\' = 0',
        '  action inc = all { x < 3, x\' = x + 1 }',
        '  action deadBranch = all { x == 999, x\' = 1000 }',
        '  action step = any { inc, deadBranch }',
        '  val safety = x <= 3',
        '}',
        '',
      ].join('\n'),
    );
    const report = auditMbtCoverage(specFile, {
      nTraces: 4,
      maxSteps: 6,
      seed: '7',
      minCoverage: 1.0,
      cliPath,
    });
    expect(report.passed).toBe(false);
    expect(report.declaredStepActions).toEqual(['deadBranch', 'inc']);
    expect(report.coveredActions).toEqual(['inc']);
    expect(report.uncoveredActions).toEqual(['deadBranch']);
    expect(report.actionCoverage).toBe(0.5);

    const cliRes = run(
      ['bun', cliPath, 'mbt-audit', specFile, '--n-traces=4', '--max-steps=6', '--seed=7', '--min-coverage=1.0'],
      work,
    );
    expect(cliRes.exitCode).toBe(1);
    expect(cliRes.stdout).toContain('MBT-AUDIT-FAIL');
    expect(cliRes.stdout).toContain('deadBranch');
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 30000);

test('run-fleet executes filtered subdomain models concurrently with structured JSON summary', () => {
  const res = run(
    ['bun', cliPath, 'run-fleet', modelsRoot, '--domain=engineering', '--subdomain=consensus', '--concurrency=2', '--json'],
    repoRoot,
  );
  expect(res.exitCode).toBe(0);
  const report = JSON.parse(res.stdout) as FleetReport;
  expect(report.total).toBe(2);
  expect(report.passed).toBe(2);
  expect(report.failed).toBe(0);
  expect(report.results.map(r => r.modelIdentity).sort()).toEqual([
    'engineering.consensus.bft-quorum-lock',
    'engineering.consensus.raft-leader-commitment',
  ]);
}, 60000);
