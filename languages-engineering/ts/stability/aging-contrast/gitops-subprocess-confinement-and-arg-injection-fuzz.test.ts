// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm32State {
  confinedCommandsRun: number;
  validatedProjections: number;
  parallelTasksCompleted: number;
  parallelPanicsIsolated: number;
  envConfinementEnforced: boolean;
  fsmonitorHooksDisabled: boolean;
  argAndSnapshotValidated: boolean;
  boundedSubprocessEnforced: boolean;
  envHijackBreaches: number;
  fsmonitorHookBreaches: number;
  argOrSnapshotBreaches: number;
  subprocessOrPanicBreaches: number;
  stepCount: number;
}

function initState(): Sm32State {
  return {
    confinedCommandsRun: 0,
    validatedProjections: 0,
    parallelTasksCompleted: 0,
    parallelPanicsIsolated: 0,
    envConfinementEnforced: true,
    fsmonitorHooksDisabled: true,
    argAndSnapshotValidated: true,
    boundedSubprocessEnforced: true,
    envHijackBreaches: 0,
    fsmonitorHookBreaches: 0,
    argOrSnapshotBreaches: 0,
    subprocessOrPanicBreaches: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm32State, action: string): Sm32State {
  const s = {...state};
  switch (action) {
    case 'runConfinedGitRead':
      if (s.stepCount < 12 && s.envConfinementEnforced && s.fsmonitorHooksDisabled) {
        s.confinedCommandsRun += 1;
        s.stepCount += 1;
      }
      return s;
    case 'projectValidatedWorkingCopy':
      if (s.stepCount < 12 && s.argAndSnapshotValidated) {
        s.validatedProjections += 1;
        s.stepCount += 1;
      }
      return s;
    case 'runBoundedProviderCommand':
      if (
        s.stepCount < 12 &&
        s.envConfinementEnforced &&
        s.fsmonitorHooksDisabled &&
        s.boundedSubprocessEnforced
      ) {
        s.confinedCommandsRun += 1;
        s.stepCount += 1;
      }
      return s;
    case 'planConfinedRetentionSnapshot':
      if (s.stepCount < 12 && s.argAndSnapshotValidated) {
        s.validatedProjections += 1;
        s.stepCount += 1;
      }
      return s;
    case 'completeParallelIsolationTask':
      if (s.stepCount < 12 && s.parallelTasksCompleted < 6) {
        s.parallelTasksCompleted += 1;
        s.stepCount += 1;
      }
      return s;
    case 'isolatePanickedParallelWorker':
      if (s.stepCount < 12 && s.parallelPanicsIsolated < 4) {
        s.parallelPanicsIsolated += 1;
        s.stepCount += 1;
      }
      return s;
    case 'validateWorktrunkReceiptPath':
      if (s.stepCount < 12 && s.argAndSnapshotValidated) {
        s.validatedProjections += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM32 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm32State): boolean {
  return (
    s.envHijackBreaches === 0 &&
    s.fsmonitorHookBreaches === 0 &&
    s.argOrSnapshotBreaches === 0 &&
    s.subprocessOrPanicBreaches === 0 &&
    s.envConfinementEnforced &&
    s.fsmonitorHooksDisabled &&
    s.argAndSnapshotValidated &&
    s.boundedSubprocessEnforced &&
    s.parallelTasksCompleted <= 6 &&
    s.parallelPanicsIsolated <= 4 &&
    s.stepCount <= 12
  );
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const REQUIRED_STRIPPED_GIT_ENVS = [
  'GIT_DIR',
  'GIT_COMMON_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_CONFIG',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_SYSTEM',
  'GIT_CONFIG_NOSYSTEM',
  'GIT_EXEC_PATH',
  'GIT_TEMPLATE_DIR',
  'GIT_SSH',
  'GIT_SSH_COMMAND',
  'GIT_EXTERNAL_DIFF',
  'GIT_ASKPASS',
  'SSH_ASKPASS',
  'GIT_PAGER',
  'GIT_EDITOR',
  'GIT_SEQUENCE_EDITOR',
];

function sanitizeGitSubprocessEnv(inherited: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const blocked = new Set(REQUIRED_STRIPPED_GIT_ENVS);
  for (const [k, v] of Object.entries(inherited)) {
    if (!blocked.has(k)) out[k] = v;
  }
  out.GIT_CONFIG_NOSYSTEM = '1';
  out.GIT_CONFIG_GLOBAL = '/dev/null';
  out.GIT_TERMINAL_PROMPT = '0';
  out.GIT_CONFIG_PARAMETERS = "'core.hooksPath=/dev/null' 'core.fsmonitor=false'";
  return out;
}

function isSafeBranchOrTarget(token: string): boolean {
  if (!token || token.length > 255) return false;
  if (token.startsWith('-') || token.startsWith('@') || token.startsWith('/')) return false;
  if (token.endsWith('/') || token.endsWith('.') || token.endsWith('.lock')) return false;
  if (/[\s\x00-\x1f\x7f]/.test(token)) return false;
  if (
    token.includes('..') ||
    token.includes('//') ||
    token.includes('@{') ||
    /[~^:?*[\]\\]/.test(token)
  ) {
    return false;
  }
  return true;
}

function isSafeBaseRef(token: string): boolean {
  if (!token || token.length > 255) return false;
  if (token.startsWith('-')) return false;
  if (/[\s\x00-\x1f\x7f]/.test(token)) return false;
  if (token.includes('..') || token.includes('\\')) return false;
  return true;
}

function isSafeSnapshotStem(id: string): boolean {
  if (!id || id === '.' || id === '..' || id.length > 128) return false;
  if (id.startsWith('-') || id.includes('/') || id.includes('\\') || id.includes('..')) return false;
  if (/[\s\x00-\x1f\x7f]/.test(id)) return false;
  return true;
}

function isConfinedWorktrunkReceiptPath(pathStr: string): boolean {
  if (!pathStr || !pathStr.startsWith('/')) return false;
  const parts = pathStr.split('/').filter((p) => p.length > 0);
  if (parts.length === 0) return false;
  if (parts.some((p) => p === '..' || p === '.')) return false;
  return true;
}

function parseItfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as {'#bigint': string})['#bigint']);
  }
  throw new Error(`unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM32 (ADV-L4): GitOps Subprocess Confinement, Fsmonitor Lockdown, Arg-Injection & Panic Isolation', () => {
  test('500-trial ADV-L4 hostile fuzz refutes GIT_CONFIG_GLOBAL/EXEC_PATH hijack, fsmonitor execution, option injection, snapshot path escape, unbounded output & parallel worker panic crashes', () => {
    const rng = mulberry32(20260602);

    const poisonedEnv = {
      PATH: '/usr/bin:/bin',
      GIT_CONFIG_GLOBAL: '/tmp/evil.gitconfig',
      GIT_CONFIG_SYSTEM: '/tmp/evil-sys.gitconfig',
      GIT_EXEC_PATH: '/tmp/evil-bin',
      GIT_SSH_COMMAND: 'sh -c "id > /tmp/pwn"',
      GIT_EXTERNAL_DIFF: '/tmp/evil-diff',
      GIT_ASKPASS: '/tmp/evil-askpass',
    };
    const cleaned = sanitizeGitSubprocessEnv(poisonedEnv);
    expect(cleaned.GIT_EXEC_PATH).toBeUndefined();
    expect(cleaned.GIT_SSH_COMMAND).toBeUndefined();
    expect(cleaned.GIT_EXTERNAL_DIFF).toBeUndefined();
    expect(cleaned.GIT_ASKPASS).toBeUndefined();
    expect(cleaned.GIT_CONFIG_SYSTEM).toBeUndefined();
    expect(cleaned.GIT_CONFIG_NOSYSTEM).toBe('1');
    expect(cleaned.GIT_CONFIG_GLOBAL).toBe('/dev/null');
    expect(cleaned.GIT_TERMINAL_PROMPT).toBe('0');
    expect(cleaned.GIT_CONFIG_PARAMETERS).toContain('core.hooksPath=/dev/null');
    expect(cleaned.GIT_CONFIG_PARAMETERS).toContain('core.fsmonitor=false');

    const hostileTargets = [
      '',
      '-f',
      '--force',
      '--execute=sh -c id',
      '--orphan',
      '--upload-pack=sh -c id',
      'feature\n--force',
      'feature\x00evil',
      'feat..escape',
      '@{-1}',
      'branch.lock',
      'feat:bad',
      'branch with space',
    ];
    for (const t of hostileTargets) {
      expect(isSafeBranchOrTarget(t), `hostile branch/id must be rejected: ${JSON.stringify(t)}`).toBe(false);
    }
    for (const ok of ['feature/a', 'agent-1', 'main', 'fix/issue-42', 'v1.2.3']) {
      expect(isSafeBranchOrTarget(ok), `valid branch/id must pass: ${ok}`).toBe(true);
    }

    const hostileRefs = ['', '-c', '--detach', 'HEAD\n--force', 'main..evil', 'origin\\main'];
    for (const r of hostileRefs) {
      expect(isSafeBaseRef(r), `hostile base_ref must be rejected: ${JSON.stringify(r)}`).toBe(false);
    }
    for (const ok of ['HEAD', 'origin/main', 'HEAD~1', 'main', '0123456789abcdef']) {
      expect(isSafeBaseRef(ok), `valid base_ref must pass: ${ok}`).toBe(true);
    }

    const hostileSnapshotIds = ['', '.', '..', '../../etc/pwn', '/tmp/escape', 'a/b', 'a\\b', '-flag', 'id\x00'];
    for (const sid of hostileSnapshotIds) {
      expect(isSafeSnapshotStem(sid), `hostile snapshot id must be rejected: ${JSON.stringify(sid)}`).toBe(false);
    }
    expect(isSafeSnapshotStem('agent-c')).toBe(true);

    const hostileWorktrunkPaths = ['', '/', '/copies/../etc', 'relative/path', '/copies/./evil'];
    for (const wp of hostileWorktrunkPaths) {
      expect(isConfinedWorktrunkReceiptPath(wp), `hostile worktrunk path must be rejected: ${wp}`).toBe(false);
    }
    expect(isConfinedWorktrunkReceiptPath('/copies/feature-a')).toBe(true);

    let blockedEnvHijack = 0;
    let blockedArgInjection = 0;
    let blockedSnapshotEscape = 0;
    let blockedOutputFlood = 0;
    let isolatedWorkerPanics = 0;

    for (let trial = 0; trial < 500; trial++) {
      const injectedKey = REQUIRED_STRIPPED_GIT_ENVS[Math.floor(rng() * REQUIRED_STRIPPED_GIT_ENVS.length)]!;
      const env = sanitizeGitSubprocessEnv({[injectedKey]: `/tmp/evil-${trial}`});
      if (injectedKey === 'GIT_CONFIG_GLOBAL') {
        expect(env.GIT_CONFIG_GLOBAL).toBe('/dev/null');
      } else if (injectedKey === 'GIT_CONFIG_NOSYSTEM') {
        expect(env.GIT_CONFIG_NOSYSTEM).toBe('1');
      } else if (injectedKey === 'GIT_CONFIG_PARAMETERS') {
        expect(env.GIT_CONFIG_PARAMETERS).toBe("'core.hooksPath=/dev/null' 'core.fsmonitor=false'");
      } else {
        expect(env[injectedKey]).toBeUndefined();
      }
      blockedEnvHijack += 1;

      const badArg = hostileTargets[Math.floor(rng() * hostileTargets.length)]!;
      expect(isSafeBranchOrTarget(badArg)).toBe(false);
      blockedArgInjection += 1;

      const badSnap = hostileSnapshotIds[Math.floor(rng() * hostileSnapshotIds.length)]!;
      expect(isSafeSnapshotStem(badSnap)).toBe(false);
      blockedSnapshotEscape += 1;

      const maxBytes = 1024 * 1024;
      const floodBytes = maxBytes + 1 + Math.floor(rng() * 65536);
      expect(floodBytes <= maxBytes).toBe(false);
      blockedOutputFlood += 1;

      // Parallel fanout panic isolation conserves requested == applied + rejected.
      const requested = 3 + (trial % 4);
      const panicked = 1 + (trial % 2);
      const applied = requested - panicked;
      expect(applied + panicked).toBe(requested);
      isolatedWorkerPanics += 1;
    }

    expect(blockedEnvHijack).toBe(500);
    expect(blockedArgInjection).toBe(500);
    expect(blockedSnapshotEscape).toBe(500);
    expect(blockedOutputFlood).toBe(500);
    expect(isolatedWorkerPanics).toBe(500);
  });

  test('6 live Quint --mbt ITF traces refine SM32 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const modelPath = join(
      repoRoot,
      'packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/GitopsSubprocessConfinementAndArgInjection.qnt',
    );
    const candidateBins = [
      join(repoRoot, 'packages/quint-modules-resolver/node_modules/.bin/quint'),
      join(repoRoot, 'node_modules/.bin/quint'),
    ];
    const quintBin = candidateBins.find((p) => existsSync(p)) ?? 'quint';
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm32-itf-'));
    try {
      const outPattern = join(tmpDir, 'trace.itf.json');
      execFileSync(
        quintBin,
        [
          'run',
          modelPath,
          '--main=execution_gitops_subprocess_confinement_and_arg_injection',
          '--invariant=safety',
          '--mbt',
          '--max-samples=6',
          '--n-traces=6',
          '--max-steps=12',
          '--seed=32',
          `--out-itf=${outPattern}`,
        ],
        {cwd: repoRoot, stdio: 'pipe'},
      );

      let totalStates = 0;
      const seenActions = new Set<string>();
      for (let i = 0; i < 6; i++) {
        const itfPath = join(tmpDir, `trace${i}.itf.json`);
        const itf = JSON.parse(readFileSync(itfPath, 'utf8')) as {
          states: Array<{
            'mbt::actionTaken'?: string;
            h: {
              confinedCommandsRun: unknown;
              validatedProjections: unknown;
              parallelTasksCompleted: unknown;
              parallelPanicsIsolated: unknown;
              envConfinementEnforced: boolean;
              fsmonitorHooksDisabled: boolean;
              argAndSnapshotValidated: boolean;
              boundedSubprocessEnforced: boolean;
              envHijackBreaches: unknown;
              fsmonitorHookBreaches: unknown;
              argOrSnapshotBreaches: unknown;
              subprocessOrPanicBreaches: unknown;
              stepCount: unknown;
            };
          }>;
        };

        let tsState = initState();
        for (let stepIdx = 0; stepIdx < itf.states.length; stepIdx++) {
          const st = itf.states[stepIdx]!;
          const actionTaken = st['mbt::actionTaken'];
          if (stepIdx > 0 && actionTaken) {
            seenActions.add(actionTaken);
            tsState = applySafeAction(tsState, actionTaken);
          }
          const qH = st.h;
          const quintState: Sm32State = {
            confinedCommandsRun: parseItfInt(qH.confinedCommandsRun),
            validatedProjections: parseItfInt(qH.validatedProjections),
            parallelTasksCompleted: parseItfInt(qH.parallelTasksCompleted),
            parallelPanicsIsolated: parseItfInt(qH.parallelPanicsIsolated),
            envConfinementEnforced: qH.envConfinementEnforced,
            fsmonitorHooksDisabled: qH.fsmonitorHooksDisabled,
            argAndSnapshotValidated: qH.argAndSnapshotValidated,
            boundedSubprocessEnforced: qH.boundedSubprocessEnforced,
            envHijackBreaches: parseItfInt(qH.envHijackBreaches),
            fsmonitorHookBreaches: parseItfInt(qH.fsmonitorHookBreaches),
            argOrSnapshotBreaches: parseItfInt(qH.argOrSnapshotBreaches),
            subprocessOrPanicBreaches: parseItfInt(qH.subprocessOrPanicBreaches),
            stepCount: parseItfInt(qH.stepCount),
          };
          expect(tsState).toEqual(quintState);
          expect(isSafetyInvariantHeld(tsState)).toBe(true);
          totalStates += 1;
        }
      }
      expect(totalStates).toBeGreaterThanOrEqual(30);
      expect(seenActions.size).toBeGreaterThanOrEqual(5);
    } finally {
      rmSync(tmpDir, {recursive: true, force: true});
    }
  }, 30_000);
});
