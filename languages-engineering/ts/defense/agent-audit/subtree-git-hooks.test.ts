// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import { describe, expect, test } from 'bun:test';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');

interface CmdResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

function runCmd(cmd: readonly string[], cwd: string, envOverrides?: Record<string, string>, stdinText?: string): CmdResult {
  const proc = Bun.spawnSync([...cmd], {
    cwd,
    env: { ...process.env, ...envOverrides },
    stdin: stdinText !== undefined ? new TextEncoder().encode(stdinText) : undefined,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return {
    exitCode: proc.exitCode,
    stdout: new TextDecoder().decode(proc.stdout),
    stderr: new TextDecoder().decode(proc.stderr),
  };
}

function initTempMonorepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'de-subtree-hooks-'));
  expect(runCmd(['git', 'init', '-b', 'main'], dir).exitCode).toBe(0);
  expect(runCmd(['git', 'config', 'user.name', 'Test Bot'], dir).exitCode).toBe(0);
  expect(runCmd(['git', 'config', 'user.email', 'test@example.com'], dir).exitCode).toBe(0);

  // Copy root hooks, installer, and per-package hooks from the real repository.
  cpSync(join(REPO_ROOT, '.githooks'), join(dir, '.githooks'), { recursive: true });
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  cpSync(join(REPO_ROOT, 'scripts/install-git-hooks.sh'), join(dir, 'scripts/install-git-hooks.sh'));
  chmodSync(join(dir, 'scripts/install-git-hooks.sh'), 0o755);

  for (const pkg of ['lean-models', 'render', 'quint-models', 'quint-modules-resolver']) {
    mkdirSync(join(dir, 'packages', pkg), { recursive: true });
    cpSync(
      join(REPO_ROOT, 'packages', pkg, '.githooks'),
      join(dir, 'packages', pkg, '.githooks'),
      { recursive: true },
    );
  }

  // Minimal valid package manifests for all 4 packages.
  writeFileSync(
    join(dir, 'packages/lean-models/lakefile.toml'),
    '# SPDX-FileCopyrightText: 2026 Test\n# SPDX-License-Identifier: LGPL-2.1-or-later\nname = "DeterministicEngineering"\n[[lean_lib]]\nname = "DeterministicEngineering"\n',
  );
  mkdirSync(join(dir, 'packages/render/src'), { recursive: true });
  writeFileSync(
    join(dir, 'packages/render/src/index.ts'),
    '// SPDX-License-Identifier: LGPL-2.1-or-later\nexport const ok = true;\n',
  );
  writeFileSync(
    join(dir, 'packages/render/package.json'),
    JSON.stringify({
      name: '@deterministic-engineering/render',
      version: '1.0.2',
      license: 'LGPL-2.1-or-later',
      exports: { '.': './src/index.ts' },
    }, null, 2),
  );
  writeFileSync(
    join(dir, 'packages/quint-models/package.json'),
    JSON.stringify({
      name: '@deterministic-engineering/quint-models',
      version: '0.1.0',
      license: 'LGPL-2.1-or-later',
    }, null, 2),
  );
  mkdirSync(join(dir, 'packages/quint-modules-resolver/src'), { recursive: true });
  writeFileSync(
    join(dir, 'packages/quint-modules-resolver/src/resolver.ts'),
    '// SPDX-License-Identifier: LGPL-2.1-or-later\nexport const r = 1;\n',
  );
  writeFileSync(
    join(dir, 'packages/quint-modules-resolver/package.json'),
    JSON.stringify({
      name: '@deterministic-engineering/quint-modules-resolver',
      version: '0.1.0',
      license: 'LGPL-2.1-or-later',
      exports: { '.': './src/resolver.ts' },
    }, null, 2),
  );

  // Install hooks using the repo installer script.
  const install = runCmd(['bash', 'scripts/install-git-hooks.sh', '--repo'], dir);
  expect(install.exitCode).toBe(0);
  expect(runCmd(['git', 'add', '.'], dir).exitCode).toBe(0);
  expect(runCmd(['git', 'commit', '-m', 'chore: initial fixture'], dir).exitCode).toBe(0);
  return dir;
}

describe('Layered Subtree Git Hooks & Branch-Mirrored CI Sync', () => {
  test('H1: root pre-commit dispatches ONLY touched subtree hook and blocks forbidden Lean imports/sorry', () => {
    const dir = initTempMonorepo();
    try {
      // 1. Forbidden `import Mathlib` inside packages/lean-models/ must be blocked.
      const badLean = join(dir, 'packages/lean-models/Bad.lean');
      writeFileSync(
        badLean,
        '-- SPDX-License-Identifier: LGPL-2.1-or-later\nimport Mathlib.Data.Nat.Basic\ntheorem t : True := trivial\n',
      );
      expect(runCmd(['git', 'add', 'packages/lean-models/Bad.lean'], dir).exitCode).toBe(0);
      const blockedMathlib = runCmd(['git', 'commit', '-m', 'bad lean mathlib'], dir);
      expect(blockedMathlib.exitCode).not.toBe(0);
      expect(blockedMathlib.stderr).toContain('packages/lean-models/.githooks/pre-commit');
      expect(blockedMathlib.stderr).toContain("forbidden 'import Mathlib'");
      expect(blockedMathlib.stderr).not.toContain('packages/render/.githooks/pre-commit');

      // 2. Incomplete `sorry` proof must also be blocked.
      writeFileSync(
        badLean,
        '-- SPDX-License-Identifier: LGPL-2.1-or-later\ntheorem t : True := by sorry\n',
      );
      expect(runCmd(['git', 'add', 'packages/lean-models/Bad.lean'], dir).exitCode).toBe(0);
      const blockedSorry = runCmd(['git', 'commit', '-m', 'bad lean sorry'], dir);
      expect(blockedSorry.exitCode).not.toBe(0);
      expect(blockedSorry.stderr).toContain('incomplete proof token (sorry/admit)');

      // 3. Clean Lean file (even mentioning sorry in a comment) must succeed.
      writeFileSync(
        badLean,
        '-- SPDX-License-Identifier: LGPL-2.1-or-later\n-- Zero sorry and zero Mathlib comment\ntheorem t : True := trivial\n',
      );
      expect(runCmd(['git', 'add', 'packages/lean-models/Bad.lean'], dir).exitCode).toBe(0);
      const okCommit = runCmd(['git', 'commit', '-m', 'good lean proof'], dir);
      expect(okCommit.exitCode).toBe(0);
      expect(okCommit.stderr).toContain('packages/lean-models/.githooks/pre-commit');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('H2: root pre-commit enforces SPDX headers and per-package manifest/Quint guards', () => {
    const dir = initTempMonorepo();
    try {
      // Missing SPDX header must be blocked by root pre-commit.
      writeFileSync(join(dir, 'packages/quint-models/Demo.qnt'), 'module Demo { val x = 1 }\n');
      expect(runCmd(['git', 'add', 'packages/quint-models/Demo.qnt'], dir).exitCode).toBe(0);
      const noSpdx = runCmd(['git', 'commit', '-m', 'missing spdx'], dir);
      expect(noSpdx.exitCode).not.toBe(0);
      expect(noSpdx.stderr).toContain('missing SPDX-License-Identifier');

      // Present SPDX but missing Quint `module` declaration must be blocked by quint-models hook.
      writeFileSync(
        join(dir, 'packages/quint-models/Demo.qnt'),
        '// SPDX-License-Identifier: LGPL-2.1-or-later\nval broken = 1\n',
      );
      expect(runCmd(['git', 'add', 'packages/quint-models/Demo.qnt'], dir).exitCode).toBe(0);
      const badQnt = runCmd(['git', 'commit', '-m', 'missing module'], dir);
      expect(badQnt.exitCode).not.toBe(0);
      expect(badQnt.stderr).toContain('missing Quint module declaration');

      // Valid Quint model passes.
      writeFileSync(
        join(dir, 'packages/quint-models/Demo.qnt'),
        '// SPDX-License-Identifier: LGPL-2.1-or-later\nmodule Demo {\n  val ok = true\n}\n',
      );
      expect(runCmd(['git', 'add', 'packages/quint-models/Demo.qnt'], dir).exitCode).toBe(0);
      const goodQnt = runCmd(['git', 'commit', '-m', 'valid quint model'], dir);
      expect(goodQnt.exitCode).toBe(0);

      // Broken export in packages/render/package.json must be blocked by render hook.
      writeFileSync(
        join(dir, 'packages/render/package.json'),
        JSON.stringify({
          name: '@deterministic-engineering/render',
          version: '1.0.3',
          license: 'LGPL-2.1-or-later',
          exports: { './missing': './src/does-not-exist.ts' },
        }, null, 2),
      );
      expect(runCmd(['git', 'add', 'packages/render/package.json'], dir).exitCode).toBe(0);
      const badExport = runCmd(['git', 'commit', '-m', 'broken render export'], dir);
      expect(badExport.exitCode).not.toBe(0);
      expect(badExport.stderr).toContain('export "./missing" target missing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('H3: exported standalone subtree mirror executes packages/lean-models/.githooks/pre-commit identically', () => {
    const dir = initTempMonorepo();
    const standalone = mkdtempSync(join(tmpdir(), 'de-standalone-mirror-'));
    try {
      const split = runCmd(['git', 'subtree', 'split', '--prefix=packages/lean-models', 'HEAD'], dir);
      expect(split.exitCode).toBe(0);
      const splitSha = split.stdout.trim();
      expect(splitSha.length).toBeGreaterThanOrEqual(40);

      expect(runCmd(['git', 'init', '-b', 'main'], standalone).exitCode).toBe(0);
      expect(runCmd(['git', 'config', 'user.name', 'Mirror Bot'], standalone).exitCode).toBe(0);
      expect(runCmd(['git', 'config', 'user.email', 'mirror@example.com'], standalone).exitCode).toBe(0);
      expect(runCmd(['git', 'fetch', dir, splitSha], standalone).exitCode).toBe(0);
      expect(runCmd(['git', 'reset', '--hard', 'FETCH_HEAD'], standalone).exitCode).toBe(0);
      expect(runCmd(['git', 'config', 'core.hooksPath', '.githooks'], standalone).exitCode).toBe(0);
      chmodSync(join(standalone, '.githooks/pre-commit'), 0o755);

      // Verify standalone hook rejects `import Cedar` without any monorepo root dispatcher.
      writeFileSync(
        join(standalone, 'CedarLeak.lean'),
        '-- SPDX-License-Identifier: LGPL-2.1-or-later\nimport Cedar.Spec\ntheorem x : True := trivial\n',
      );
      expect(runCmd(['git', 'add', 'CedarLeak.lean'], standalone).exitCode).toBe(0);
      const blockedCedar = runCmd(['git', 'commit', '-m', 'forbidden cedar'], standalone);
      expect(blockedCedar.exitCode).not.toBe(0);
      expect(blockedCedar.stderr).toContain("forbidden 'import Cedar'");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(standalone, { recursive: true, force: true });
    }
  });

  test('H4: installer supports linked Git worktree scoping without modifying parent repo local config', () => {
    const dir = initTempMonorepo();
    const wtDir = mkdtempSync(join(tmpdir(), 'de-linked-wt-'));
    rmSync(wtDir, { recursive: true, force: true });
    try {
      // Unset repo-level hooksPath in parent first so we can verify worktree isolation.
      expect(runCmd(['bash', 'scripts/install-git-hooks.sh', '--uninstall'], dir).exitCode).toBe(0);
      expect(runCmd(['git', 'worktree', 'add', '-b', 'dev', wtDir, 'main'], dir).exitCode).toBe(0);

      const installWt = runCmd(['bash', 'scripts/install-git-hooks.sh', '--auto'], wtDir);
      expect(installWt.exitCode).toBe(0);
      expect(installWt.stdout).toContain('Detected linked worktree');

      const wtHooks = runCmd(['git', 'config', 'core.hooksPath'], wtDir);
      expect(wtHooks.exitCode).toBe(0);
      expect(wtHooks.stdout.trim()).toBe('.githooks');

      // Parent worktree remains cleanly unaffected.
      const parentHooks = runCmd(['git', 'config', 'core.hooksPath'], dir);
      expect(parentHooks.exitCode).not.toBe(0);

      const status = runCmd(['bash', 'scripts/install-git-hooks.sh', '--status'], wtDir);
      expect(status.exitCode).toBe(0);
      expect(status.stdout).toContain('linked_worktree=yes');
      expect(status.stdout).toContain('packages/lean-models/.githooks/pre-commit');
    } finally {
      runCmd(['git', 'worktree', 'remove', '--force', wtDir], dir);
      rmSync(dir, { recursive: true, force: true });
      rmSync(wtDir, { recursive: true, force: true });
    }
  });

  test('H5: root pre-push blocks non-fast-forward force push to main and dispatches touched subtree pre-push', () => {
    const dir = initTempMonorepo();
    try {
      const headSha = runCmd(['git', 'rev-parse', 'HEAD'], dir).stdout.trim();
      // Create an unrelated orphan commit to simulate a non-fast-forward push to main.
      expect(runCmd(['git', 'checkout', '--orphan', 'diverged'], dir).exitCode).toBe(0);
      expect(runCmd(['git', 'commit', '--allow-empty', '-m', 'diverged history'], dir).exitCode).toBe(0);
      const orphanSha = runCmd(['git', 'rev-parse', 'HEAD'], dir).stdout.trim();

      const blockedForce = runCmd(
        ['bash', '.githooks/pre-push', 'origin', 'https://example.invalid/repo.git'],
        dir,
        undefined,
        `refs/heads/diverged ${orphanSha} refs/heads/main ${headSha}\n`,
      );
      expect(blockedForce.exitCode).not.toBe(0);
      expect(blockedForce.stderr).toContain('non-fast-forward push to refs/heads/main blocked');

      // Return to main, commit a change in packages/lean-models/, and verify pre-push dispatches lean-models hook.
      expect(runCmd(['git', 'checkout', 'main'], dir).exitCode).toBe(0);
      const baseSha = runCmd(['git', 'rev-parse', 'HEAD'], dir).stdout.trim();
      writeFileSync(
        join(dir, 'packages/lean-models/Ok.lean'),
        '-- SPDX-License-Identifier: LGPL-2.1-or-later\ntheorem ok : True := trivial\n',
      );
      expect(runCmd(['git', 'add', 'packages/lean-models/Ok.lean'], dir).exitCode).toBe(0);
      expect(runCmd(['git', 'commit', '-m', 'add lean ok'], dir).exitCode).toBe(0);
      const nextSha = runCmd(['git', 'rev-parse', 'HEAD'], dir).stdout.trim();

      const pushOk = runCmd(
        ['bash', '.githooks/pre-push', 'origin', 'https://example.invalid/repo.git'],
        dir,
        undefined,
        `refs/heads/main ${nextSha} refs/heads/main ${baseSha}\n`,
      );
      expect(pushOk.exitCode).toBe(0);
      expect(pushOk.stderr).toContain('Dispatching subtree hook: packages/lean-models/.githooks/pre-push');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('H6: publish-packages.yml satisfies all 4 packages, concurrency lock, branch isolation, and fast-forward safety', () => {
    const workflow = readFileSync(join(REPO_ROOT, '.github/workflows/publish-packages.yml'), 'utf8');
    expect(workflow).toContain('SPDX-License-Identifier: LGPL-2.1-or-later');
    expect(workflow).toContain('concurrency:');
    expect(workflow).toContain('cancel-in-progress: false');
    expect(workflow).toContain("'lean-models-v*'");
    expect(workflow).toContain('"lean-models": "lakefile.toml"');
    expect(workflow).toContain('"render": "package.json"');
    expect(workflow).toContain('"quint-models": "package.json"');
    expect(workflow).toContain('"quint-modules-resolver": "package.json"');
    expect(workflow).toContain('target_branch = "main" if ref_name == "main" else ref_name');
    expect(workflow).toContain('dry_run');
    expect(workflow).not.toContain('git push --force');
    expect(workflow).not.toContain('git push -f');
    // Must not combine `paths:` with `tags:` under `on.push` (GitHub Actions silently skips tag events).
    expect(workflow).not.toMatch(/^\s+paths:\s*$/m);
  });
});
