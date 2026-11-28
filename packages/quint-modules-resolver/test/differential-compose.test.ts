// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {expect, test} from 'bun:test';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const pkgRoot = resolve(import.meta.dir, '..');
const repoRoot = resolve(pkgRoot, '../..');
const cliPath = join(pkgRoot, 'src/cli.ts');
const modelsRoot = join(repoRoot, 'packages/quint-models');
const schemeComposeScript = join(repoRoot, 't/support/quint-scheme-compose.ss');

function run(cmd: string[], cwd: string) {
  const proc = Bun.spawnSync(cmd, {cwd, stdout: 'pipe', stderr: 'pipe', stdin: 'ignore'});
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

function runSchemeCompose(basePath: string, overlayPath: string, outPath: string) {
  return run(
    [
      'gerbil',
      '-:max-heap=2G,debug=q',
      'env',
      'gxi',
      '-:max-heap=2G,debug=q',
      schemeComposeScript,
      basePath,
      overlayPath,
      outPath,
    ],
    repoRoot,
  );
}

function runTsCompose(basePath: string, overlayPath: string, outPath: string) {
  return run(['bun', cliPath, 'compose', basePath, overlayPath, `--out=${outPath}`], repoRoot);
}

function passingCount(output: string): number {
  const m = output.match(/(\d+)\s+passing/);
  return m ? Number(m[1]) : -1;
}

test('differential equivalence: Scheme gerbil-parser compose matches TS @informalsystems/quint compose on typecheck, traces, and Apalache safety', () => {
  const work = mkdtempSync(join(tmpdir(), 'qmr-diff-compose-'));
  try {
    mkdirSync(join(work, 'node_modules/@deterministic-engineering'), {recursive: true});
    symlinkSync(modelsRoot, join(work, 'node_modules/@deterministic-engineering/quint-models'), 'dir');

    // 1. Safe overlay on OAuthTokenLifecycle.qnt (adds State field, init, action, step, safety, run).
    const oauthBase = join(modelsRoot, 'threat/identity/oauth-token-lifecycle/OAuthTokenLifecycle.qnt');
    const oauthOverlay = join(work, 'OAuthDiffOverlay.qnt');
    writeFileSync(
      oauthOverlay,
      [
        'module diff_oauth_composed {',
        '  type State = { policyEpoch: int }',
        "  action init = h' = { policyEpoch: 1 }",
        '  action bumpPolicy = if (h.policyEpoch < 3) h\' = h.with("policyEpoch", h.policyEpoch + 1) else h\' = h',
        '  action step = any { bumpPolicy }',
        '  val safety = h.policyEpoch >= 1',
        '  run diffPolicyTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(bumpPolicy).then(all { assert(h.policyEpoch == 2), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );

    const oauthSchemeOut = join(work, 'OAuthScheme.qnt');
    const oauthTsOut = join(work, 'OAuthTs.qnt');
    const s1 = runSchemeCompose(oauthBase, oauthOverlay, oauthSchemeOut);
    const t1 = runTsCompose(oauthBase, oauthOverlay, oauthTsOut);
    expect(s1.exitCode).toBe(0);
    expect(t1.exitCode).toBe(0);
    expect(readFileSync(oauthSchemeOut, 'utf8')).toContain('module diff_oauth_composed');
    expect(readFileSync(oauthTsOut, 'utf8')).toContain('module diff_oauth_composed');

    // Typecheck equivalence
    const stc1 = run(['bun', cliPath, 'typecheck', oauthSchemeOut], work);
    const ttc1 = run(['bun', cliPath, 'typecheck', oauthTsOut], work);
    expect(stc1.exitCode).toBe(0);
    expect(ttc1.exitCode).toBe(0);

    // Deterministic trace equivalence (exact same passing run count)
    const stst1 = run(
      ['bun', cliPath, 'test', oauthSchemeOut, '--main=diff_oauth_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    const ttst1 = run(
      ['bun', cliPath, 'test', oauthTsOut, '--main=diff_oauth_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(stst1.exitCode).toBe(0);
    expect(ttst1.exitCode).toBe(0);
    expect(passingCount(stst1.stdout + stst1.stderr)).toBe(6);
    expect(passingCount(stst1.stdout + stst1.stderr)).toBe(passingCount(ttst1.stdout + ttst1.stderr));

    // Apalache bounded safety equivalence (both prove safety up to 5 steps)
    const sv1 = run(
      ['bun', cliPath, 'verify', oauthSchemeOut, '--main=diff_oauth_composed', '--invariant=safety', '--max-steps=5'],
      work,
    );
    const tv1 = run(
      ['bun', cliPath, 'verify', oauthTsOut, '--main=diff_oauth_composed', '--invariant=safety', '--max-steps=5'],
      work,
    );
    expect(sv1.exitCode).toBe(0);
    expect(tv1.exitCode).toBe(0);

    // 2. State field dedup + init override on MvccSsiWriteSkew.qnt.
    const mvccBase = join(modelsRoot, 'engineering/storage/mvcc-ssi-write-skew/MvccSsiWriteSkew.qnt');
    const mvccOverlay = join(work, 'MvccDiffOverlay.qnt');
    writeFileSync(
      mvccOverlay,
      [
        'module diff_mvcc_composed {',
        '  type State = { balX: int, auditSeq: int }',
        "  action init = h' = { balX: 1, auditSeq: 0 }",
        '  action recordAudit = if (h.auditSeq < 3) h\' = h.with("auditSeq", h.auditSeq + 1) else h\' = h',
        '  action step = recordAudit',
        '  val safety = h.auditSeq >= 0',
        '  run mvccAuditOverlayTest = init.then(recordAudit).then(all { assert(h.auditSeq == 1), assert(safety), h\' = h })',
        '}',
        '',
      ].join('\n'),
    );

    const mvccSchemeOut = join(work, 'MvccScheme.qnt');
    const mvccTsOut = join(work, 'MvccTs.qnt');
    const s2 = runSchemeCompose(mvccBase, mvccOverlay, mvccSchemeOut);
    const t2 = runTsCompose(mvccBase, mvccOverlay, mvccTsOut);
    expect(s2.exitCode).toBe(0);
    expect(t2.exitCode).toBe(0);

    const stc2 = run(['bun', cliPath, 'typecheck', mvccSchemeOut], work);
    const ttc2 = run(['bun', cliPath, 'typecheck', mvccTsOut], work);
    expect(stc2.exitCode).toBe(0);
    expect(ttc2.exitCode).toBe(0);

    const stst2 = run(
      ['bun', cliPath, 'test', mvccSchemeOut, '--main=diff_mvcc_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    const ttst2 = run(
      ['bun', cliPath, 'test', mvccTsOut, '--main=diff_mvcc_composed', '--max-samples=1', '--seed=7', '--backend=typescript'],
      work,
    );
    expect(stst2.exitCode).toBe(0);
    expect(ttst2.exitCode).toBe(0);
    expect(passingCount(stst2.stdout + stst2.stderr)).toBe(5);
    expect(passingCount(stst2.stdout + stst2.stderr)).toBe(passingCount(ttst2.stdout + ttst2.stderr));

    // 3. Negative behavioral equivalence on Tls13ZeroRttForwardSecrecy.qnt:
    // intentionally unsafe overlay must be rejected by Apalache on BOTH Scheme and TS outputs!
    const tlsBase = join(modelsRoot, 'threat/protocol/tls13-0rtt-forward-secrecy/Tls13ZeroRttForwardSecrecy.qnt');
    const unsafeOverlay = join(work, 'TlsUnsafeOverlay.qnt');
    writeFileSync(
      unsafeOverlay,
      [
        'module diff_tls_unsafe {',
        '  type State = { auditIntact: bool }',
        "  action init = h' = { auditIntact: true }",
        "  action corruptAudit = h' = h.with(\"auditIntact\", false)",
        '  action step = any { corruptAudit }',
        '  val safety = h.auditIntact',
        '}',
        '',
      ].join('\n'),
    );

    const tlsSchemeOut = join(work, 'TlsUnsafeScheme.qnt');
    const tlsTsOut = join(work, 'TlsUnsafeTs.qnt');
    expect(runSchemeCompose(tlsBase, unsafeOverlay, tlsSchemeOut).exitCode).toBe(0);
    expect(runTsCompose(tlsBase, unsafeOverlay, tlsTsOut).exitCode).toBe(0);

    const sv3 = run(
      ['bun', cliPath, 'verify', tlsSchemeOut, '--main=diff_tls_unsafe', '--invariant=safety', '--max-steps=3'],
      work,
    );
    const tv3 = run(
      ['bun', cliPath, 'verify', tlsTsOut, '--main=diff_tls_unsafe', '--invariant=safety', '--max-steps=3'],
      work,
    );
    expect(sv3.exitCode).toBe(1);
    expect(tv3.exitCode).toBe(1);

    // 4. Refusal parity: all 4 invalid overlay classes must fail closed in BOTH Scheme and TS engines.
    const invalidOverlays: Array<{name: string; body: string}> = [
      {
        name: 'type-conflict',
        body: [
          'module err_type_conflict {',
          '  type State = { authEpoch: bool }',
          "  action init = h' = { authEpoch: false }",
          '}',
        ].join('\n'),
      },
      {
        name: 'missing-init',
        body: [
          'module err_missing_init {',
          '  type State = { extraFlag: bool }',
          '}',
        ].join('\n'),
      },
      {
        name: 'uninitialized-field',
        body: [
          'module err_uninit_field {',
          '  type State = { extraA: bool, extraB: int }',
          "  action init = h' = { extraA: false }",
          '}',
        ].join('\n'),
      },
      {
        name: 'symbol-collision',
        body: [
          'module err_collision {',
          "  action beginOAuth = h' = h",
          '}',
        ].join('\n'),
      },
    ];

    for (const bad of invalidOverlays) {
      const ovPath = join(work, `${bad.name}.qnt`);
      writeFileSync(ovPath, bad.body + '\n');
      const sBad = runSchemeCompose(oauthBase, ovPath, join(work, `${bad.name}-s.qnt`));
      const tBad = runTsCompose(oauthBase, ovPath, join(work, `${bad.name}-t.qnt`));
      expect(sBad.exitCode).not.toBe(0);
      expect(tBad.exitCode).not.toBe(0);
    }
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}, 360000);
