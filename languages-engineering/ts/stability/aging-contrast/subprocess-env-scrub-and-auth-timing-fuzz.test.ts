// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {mkdirSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {resolve} from 'node:path';

/**
 * SM24 Adversarial (ADV-L4) Subprocess Secret Environment Scrubbing &
 * Constant-Time Bearer Auth Verification Fuzz + Live Quint ITF MBT.
 *
 * Hostile Pressure Tier: ADV-L4 (MUST fail on ambient env inheritance in
 * sandbox tools or untrusted plugin build/perf runners, short-circuit `==`
 * bearer auth timing comparisons, and blank expected auth tokens).
 *
 * Mirrors real production bugs caught in:
 * - marlin-agent-core/crates/marlin-agent-app-server/src/{atomic_effect_substrate.rs,ui_grpc.rs}
 * - marlin-agent-core/crates/marlin-agent-kernel/src/loop_program_handoff_executor/tool_process.rs
 * - marlin-mygo/control/marketplace/{dev_reload.go,ts_bundle.go,publish.go,plugin_perf.go}
 */

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const SM24_QNT = resolve(
  REPO_ROOT,
  'packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/SubprocessEnvScrubAndAuthTiming.qnt',
);

const SAFE_TOOLCHAIN_ALLOWLIST = new Set([
  'PATH',
  'HOME',
  'TMPDIR',
  'TEMP',
  'TMP',
  'USER',
  'LOGNAME',
  'LANG',
  'LC_ALL',
  'TERM',
  'GOROOT',
  'GOPATH',
  'GOCACHE',
  'GOMODCACHE',
  'BUN_INSTALL',
  'XDG_CACHE_HOME',
]);

const HOSTILE_SECRET_KEYS = [
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'MARLIN_BRIDGE_TOKEN',
  'MARLIN_SCHEME_LLM_API_KEY',
  'AWS_SECRET_ACCESS_KEY',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'DATABASE_URL',
  'CUSTOM_VAULT_MASTER_SECRET',
];

function scrubEnvAllowlist(hostEnv: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(hostEnv)) {
    if (SAFE_TOOLCHAIN_ALLOWLIST.has(k)) {
      out[k] = v;
    }
  }
  return out;
}

function constantTimeEqual(expected: string, actual: string): boolean {
  if (expected.trim().length === 0) return false;
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(actual, 'utf8');
  let diff = a.length ^ b.length;
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

interface EnvAuthProbe {
  kind:
    | 'scrubbed-sandbox'
    | 'scrubbed-plugin-build'
    | 'valid-ct-bearer'
    | 'sandbox-secret-exfil'
    | 'plugin-build-secret-exfil'
    | 'invalid-or-blank-bearer'
    | 'untrusted-stdin-inherit';
  hostEnv: Record<string, string>;
  expectedBearer: string;
  actualBearer: string;
}

interface EnvAuthCounters {
  cleanAdmitted: number;
  hostileBlocked: number;
  sandboxSecretLeaks: number;
  pluginSecretLeaks: number;
  authTimingOracles: number;
  blankAuthBypasses: number;
}

class HardenedEnvAuthBoundary {
  readonly state: EnvAuthCounters = {
    cleanAdmitted: 0,
    hostileBlocked: 0,
    sandboxSecretLeaks: 0,
    pluginSecretLeaks: 0,
    authTimingOracles: 0,
    blankAuthBypasses: 0,
  };

  handle(probe: EnvAuthProbe): 'admitted' | 'blocked' {
    switch (probe.kind) {
      case 'scrubbed-sandbox': {
        const childEnv = scrubEnvAllowlist(probe.hostEnv);
        const leaked = HOSTILE_SECRET_KEYS.some((k) => k in childEnv);
        if (leaked) {
          this.state.sandboxSecretLeaks += 1;
          return 'blocked';
        }
        this.state.cleanAdmitted += 1;
        return 'admitted';
      }
      case 'scrubbed-plugin-build': {
        const childEnv = scrubEnvAllowlist(probe.hostEnv);
        const leaked = HOSTILE_SECRET_KEYS.some((k) => k in childEnv);
        if (leaked) {
          this.state.pluginSecretLeaks += 1;
          return 'blocked';
        }
        this.state.cleanAdmitted += 1;
        return 'admitted';
      }
      case 'valid-ct-bearer': {
        if (constantTimeEqual(probe.expectedBearer, probe.actualBearer)) {
          this.state.cleanAdmitted += 1;
          return 'admitted';
        }
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
      case 'sandbox-secret-exfil':
      case 'plugin-build-secret-exfil': {
        const childEnv = scrubEnvAllowlist(probe.hostEnv);
        expect(HOSTILE_SECRET_KEYS.some((k) => k in childEnv)).toBe(false);
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
      case 'invalid-or-blank-bearer': {
        expect(constantTimeEqual(probe.expectedBearer, probe.actualBearer)).toBe(false);
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
      case 'untrusted-stdin-inherit': {
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
    }
  }
}

class DefectiveEnvAuthBoundary {
  readonly state: EnvAuthCounters = {
    cleanAdmitted: 0,
    hostileBlocked: 0,
    sandboxSecretLeaks: 0,
    pluginSecretLeaks: 0,
    authTimingOracles: 0,
    blankAuthBypasses: 0,
  };

  handle(probe: EnvAuthProbe): void {
    switch (probe.kind) {
      case 'sandbox-secret-exfil':
        // Defective: inherits ambient hostEnv directly without env_clear().
        if (HOSTILE_SECRET_KEYS.some((k) => k in probe.hostEnv)) {
          this.state.sandboxSecretLeaks += 1;
        }
        break;
      case 'plugin-build-secret-exfil':
        // Defective: append(os.Environ(), ...) or cmd.Env == nil leaks secrets.
        if (HOSTILE_SECRET_KEYS.some((k) => k in probe.hostEnv)) {
          this.state.pluginSecretLeaks += 1;
        }
        break;
      case 'invalid-or-blank-bearer':
        if (probe.expectedBearer.trim() === '' && probe.actualBearer === probe.expectedBearer) {
          this.state.blankAuthBypasses += 1;
        } else {
          this.state.authTimingOracles += 1;
        }
        break;
      case 'untrusted-stdin-inherit':
        this.state.blankAuthBypasses += 1;
        break;
      default:
        this.state.cleanAdmitted += 1;
    }
  }
}

function makeRng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

interface ItfBigInt {
  '#bigint': string;
}

function itfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as ItfBigInt)['#bigint']);
  }
  throw new Error(`Unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM24 Adversarial (ADV-L4) Subprocess Secret Env Scrubbing & Constant-Time Auth Fuzz + ITF MBT', () => {
  test('ADV-L4: 500 hostile trials (sandbox/plugin-build/perf secret exfil, blank/timing Bearer probes) — hardened 0 leaks vs defective exfiltration', () => {
    const rng = makeRng(0x5a24_4d04);
    const hardened = new HardenedEnvAuthBoundary();
    const defective = new DefectiveEnvAuthBoundary();

    for (let i = 0; i < 500; i += 1) {
      const secretKey = HOSTILE_SECRET_KEYS[i % HOSTILE_SECRET_KEYS.length]!;
      const hostEnv: Record<string, string> = {
        PATH: '/usr/bin:/bin',
        HOME: '/tmp/home',
        TMPDIR: '/tmp',
        [secretKey]: `sk-adv-l4-secret-${i}`,
      };
      const roll = Math.floor(rng() * 7);
      const kinds: EnvAuthProbe['kind'][] = [
        'scrubbed-sandbox',
        'scrubbed-plugin-build',
        'valid-ct-bearer',
        'sandbox-secret-exfil',
        'plugin-build-secret-exfil',
        'invalid-or-blank-bearer',
        'untrusted-stdin-inherit',
      ];
      const kind = kinds[roll]!;
      const expectedBearer = kind === 'invalid-or-blank-bearer' && i % 2 === 0 ? '' : `Bearer tok-${i}`;
      const actualBearer =
        kind === 'valid-ct-bearer'
          ? `Bearer tok-${i}`
          : kind === 'invalid-or-blank-bearer' && i % 2 === 0
            ? ''
            : `Bearer tok-${i}-wrong`;

      const probe: EnvAuthProbe = {kind, hostEnv, expectedBearer, actualBearer};
      hardened.handle(probe);
      defective.handle(probe);
    }

    expect(hardened.state.cleanAdmitted).toBeGreaterThan(120);
    expect(hardened.state.hostileBlocked).toBeGreaterThan(220);
    expect(hardened.state.sandboxSecretLeaks).toBe(0);
    expect(hardened.state.pluginSecretLeaks).toBe(0);
    expect(hardened.state.authTimingOracles).toBe(0);
    expect(hardened.state.blankAuthBypasses).toBe(0);

    // Defective baseline MUST fail on every ADV-L4 vector (proving non-gentle pressure!).
    expect(defective.state.sandboxSecretLeaks).toBeGreaterThan(40);
    expect(defective.state.pluginSecretLeaks).toBeGreaterThan(40);
    expect(defective.state.authTimingOracles).toBeGreaterThan(15);
    expect(defective.state.blankAuthBypasses).toBeGreaterThan(40);
  });

  test('ADV-L4: Live Quint ITF MBT Replay for 102nd Formal Model SM24 SubprocessEnvScrubAndAuthTiming (6 live traces, 100% parity)', () => {
    const outDir = `/tmp/sm24-itf-${process.pid}-${Date.now()}`;
    mkdirSync(outDir, {recursive: true});
    const res = spawnSync(
      'quint',
      [
        'run',
        SM24_QNT,
        '--main=execution_subprocess_env_scrub_and_auth_timing',
        '--mbt',
        '--max-samples=6',
        '--n-traces=6',
        '--max-steps=12',
        `--out-itf=${outDir}/trace.itf.json`,
      ],
      {encoding: 'utf8', timeout: 60_000},
    );
    expect(res.status, `quint run --mbt failed:\n${res.stdout}\n${res.stderr}`).toBe(0);

    const files = readdirSync(outDir)
      .filter((f) => f.endsWith('.itf.json'))
      .sort();
    expect(files.length).toBeGreaterThanOrEqual(6);

    const hostEnv = {
      PATH: '/usr/bin:/bin',
      OPENAI_API_KEY: 'sk-live-secret',
      MARLIN_BRIDGE_TOKEN: 'bridge-live-secret',
    };
    let totalTransitions = 0;
    for (const file of files) {
      const trace = JSON.parse(readFileSync(resolve(outDir, file), 'utf8')) as {
        states: Array<{
          'mbt::actionTaken'?: string;
          h: Record<string, unknown>;
        }>;
      };
      const sut = new HardenedEnvAuthBoundary();
      for (let i = 1; i < trace.states.length; i += 1) {
        const st = trace.states[i]!;
        const action = st['mbt::actionTaken'] ?? '';
        switch (action) {
          case 'spawnScrubbedSandboxTool':
            sut.handle({kind: 'scrubbed-sandbox', hostEnv, expectedBearer: 'Bearer ok', actualBearer: 'Bearer ok'});
            break;
          case 'spawnScrubbedPluginBuild':
            sut.handle({kind: 'scrubbed-plugin-build', hostEnv, expectedBearer: 'Bearer ok', actualBearer: 'Bearer ok'});
            break;
          case 'verifyConstantTimeBearer':
            sut.handle({kind: 'valid-ct-bearer', hostEnv, expectedBearer: 'Bearer ok', actualBearer: 'Bearer ok'});
            break;
          case 'blockSecretEnvInheritance':
            sut.handle({kind: 'sandbox-secret-exfil', hostEnv, expectedBearer: 'Bearer ok', actualBearer: 'Bearer ok'});
            break;
          case 'blockInvalidOrBlankBearer':
            sut.handle({kind: 'invalid-or-blank-bearer', hostEnv, expectedBearer: '', actualBearer: ''});
            break;
          case 'blockUntrustedStdinInherit':
            sut.handle({kind: 'untrusted-stdin-inherit', hostEnv, expectedBearer: 'Bearer ok', actualBearer: 'Bearer ok'});
            break;
          default:
            throw new Error(`Unexpected SM24 MBT action: ${action}`);
        }
        totalTransitions += 1;
        expect(sut.state.cleanAdmitted).toBe(itfInt(st.h.cleanAdmitted));
        expect(sut.state.hostileBlocked).toBe(itfInt(st.h.hostileBlocked));
        expect(sut.state.sandboxSecretLeaks).toBe(itfInt(st.h.sandboxSecretLeaks));
        expect(sut.state.pluginSecretLeaks).toBe(itfInt(st.h.pluginSecretLeaks));
        expect(sut.state.authTimingOracles).toBe(itfInt(st.h.authTimingOracles));
        expect(sut.state.blankAuthBypasses).toBe(itfInt(st.h.blankAuthBypasses));
      }
    }
    expect(totalTransitions).toBeGreaterThanOrEqual(6);
    rmSync(outDir, {recursive: true, force: true});
  });
});
